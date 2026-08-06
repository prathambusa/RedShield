from __future__ import annotations

import time

from fastapi import Depends, FastAPI, HTTPException, Request

from app.gateway.deps import AppDeps, get_deps
from app.gateway.schemas import (
    ChatRequest,
    ChatResponse,
    HealthResponse,
    StatsResponse,
    VerdictModel,
)
from app.policy.risk import aggregate

VERSION = "0.1.0"
CANNED_REFUSAL = "I can't help with that request."

app = FastAPI(title="RedShield Gateway", version=VERSION)


def _deps() -> AppDeps:
    return get_deps()


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", version=VERSION)


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest, deps: AppDeps = Depends(_deps)) -> ChatResponse:
    started = time.perf_counter()

    if not deps.rate_limiter.is_allowed(req.session_id):
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    # Raw path: bypass defenders entirely. For demo + eval only.
    if not req.defended:
        reply = _call_backend(req, deps)
        latency_ms = int((time.perf_counter() - started) * 1000)
        deps.audit.record(
            session_id=req.session_id,
            direction="input",
            text=req.message,
            action="allow",
            score=0.0,
            reasons=["raw_path"],
            latency_ms=latency_ms,
        )
        deps.audit.record(
            session_id=req.session_id,
            direction="output",
            text=reply,
            action="allow",
            score=0.0,
            reasons=["raw_path"],
            latency_ms=latency_ms,
        )
        return ChatResponse(
            reply=reply,
            verdict=VerdictModel(action="allow", score=0.0, reasons=["raw_path"]),
            latency_ms=latency_ms,
        )

    # Defended path.
    allowlisted = deps.allowlist.matches(req.message)
    blocklist_match = deps.blocklist.match(req.message)
    rule_hits = deps.matcher.match(req.message)

    # Hard-block rules and blocklist short-circuit BEFORE calling the classifier.
    hard_signal = blocklist_match is not None or any(h.severity >= 9 for h in rule_hits)
    classifier_verdict = None
    if not hard_signal and not allowlisted and deps.classifier is not None:
        classifier_verdict = deps.classifier.classify(req.message)

    verdict = aggregate(
        rule_hits,
        classifier_verdict,
        allowlisted=allowlisted,
        blocklist_match=blocklist_match,
    )

    if verdict.action == "block":
        latency_ms = int((time.perf_counter() - started) * 1000)
        deps.audit.record(
            session_id=req.session_id,
            direction="input",
            text=req.message,
            action="block",
            score=verdict.score,
            reasons=verdict.reasons,
            latency_ms=latency_ms,
        )
        return ChatResponse(
            reply=CANNED_REFUSAL,
            verdict=VerdictModel(action="block", score=verdict.score, reasons=verdict.reasons),
            latency_ms=latency_ms,
        )

    # allow OR review → call the LLM, then output-filter.
    raw_reply = _call_backend(req, deps)
    out = deps.output_filter.filter(raw_reply)
    latency_ms = int((time.perf_counter() - started) * 1000)

    input_action = verdict.action  # "allow" or "review"
    deps.audit.record(
        session_id=req.session_id,
        direction="input",
        text=req.message,
        action=input_action,
        score=verdict.score,
        reasons=verdict.reasons,
        latency_ms=latency_ms,
    )

    leaked = out.leak_ratio >= deps.output_filter._leak_threshold

    if out.action == "block":
        deps.audit.record(
            session_id=req.session_id,
            direction="output",
            text=raw_reply,
            action="block",
            score=1.0,
            reasons=out.reasons,
            latency_ms=latency_ms,
        )
        return ChatResponse(
            reply=out.text,
            verdict=VerdictModel(
                action="block",
                score=1.0,
                reasons=verdict.reasons + out.reasons,
            ),
            latency_ms=latency_ms,
            output_leaked_system_prompt=leaked,
        )

    deps.audit.record(
        session_id=req.session_id,
        direction="output",
        text=out.text,
        action=out.action,  # "allow" or "redact"
        score=verdict.score,
        reasons=out.reasons,
        latency_ms=latency_ms,
    )

    final_reasons = verdict.reasons + out.reasons
    return ChatResponse(
        reply=out.text,
        verdict=VerdictModel(
            action=verdict.action,
            score=verdict.score,
            reasons=final_reasons,
        ),
        latency_ms=latency_ms,
        output_leaked_system_prompt=leaked,
    )


@app.get("/admin/stats", response_model=StatsResponse)
def admin_stats(
    request: Request,
    window_seconds: int | None = 3600,
    deps: AppDeps = Depends(_deps),
) -> StatsResponse:
    _authorize_admin(request, deps)
    counts = deps.audit.stats(since_seconds=window_seconds)
    recent = [
        {
            "id": r.id,
            "ts": r.ts.isoformat(),
            "session_id": r.session_id,
            "direction": r.direction,
            "action": r.action,
            "score": r.score,
            "reasons": r.reasons,
            "latency_ms": r.latency_ms,
        }
        for r in deps.audit.recent(25)
    ]
    return StatsResponse(window_seconds=window_seconds, counts=counts, recent=recent)


def _authorize_admin(request: Request, deps: AppDeps) -> None:
    token = deps.settings.admin_token
    if token:
        header = request.headers.get("x-admin-token", "")
        if header != token:
            raise HTTPException(status_code=401, detail="invalid admin token")
        return
    client = request.client.host if request.client else None
    if client not in {"127.0.0.1", "::1", "testclient", None}:
        raise HTTPException(status_code=403, detail="admin endpoint is localhost-only")


def _call_backend(req: ChatRequest, deps: AppDeps) -> str:
    messages = []
    for turn in req.history:
        messages.append({"role": turn.role, "content": turn.content})
    messages.append({"role": "user", "content": req.message})
    try:
        return deps.chat_backend(system=deps.settings.system_prompt, messages=messages)
    except Exception as e:
        detail = str(e).strip()
        if not detail:
            detail = type(e).__name__
        return f"⚠️ upstream error ({type(e).__name__}): {detail[:500]}"
