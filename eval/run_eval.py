from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from app.audit import AuditLog
from app.config import get_settings
from app.detectors.classifier import ClassifierVerdict, LLMClassifier
from app.detectors.output_filter import OutputFilter
from app.detectors.rules import default_matcher
from app.gateway import main as gateway_main
from app.gateway.deps import AppDeps, build_default_deps, reset_deps, set_deps
from app.policy.allowlist import Allowlist, load_allowlist
from app.policy.blocklist import Blocklist, load_blocklist
from eval.report import render_report

ROOT = Path(__file__).resolve().parent
DATASETS = ROOT / "datasets"
REPORTS = ROOT / "reports"


@dataclass
class EvalRow:
    id: str
    dataset: str  # "attack" | "benign"
    taxonomy: str | None
    owasp_category: str | None
    expected_action: str
    mode: str  # "raw" | "defended"
    got_action: str
    score: float
    reasons: list[str] = field(default_factory=list)
    latency_ms: int = 0
    prompt: str = ""
    reply: str = ""


def _stub_backend() -> "Callable":
    def backend(*, system: str, messages: list[dict]) -> str:
        return "Your order is on the way. Let me know if you need anything else."

    return backend


def _stub_classifier() -> LLMClassifier:
    # Deterministic "benign" classifier so metrics reflect pure rule coverage
    # unless --live is set.
    def fake(sys: str, usr: str) -> str:
        return '{"verdict":"benign","confidence":0.5,"reason":"stub"}'

    return LLMClassifier(completion_fn=fake)


def _build_deps(live: bool) -> AppDeps:
    if live:
        return build_default_deps()
    settings = get_settings()
    return AppDeps(
        settings=settings,
        matcher=default_matcher(),
        classifier=_stub_classifier(),
        output_filter=OutputFilter(system_prompt=settings.system_prompt),
        allowlist=load_allowlist(settings.allowlist_file),
        blocklist=load_blocklist(settings.blocklist_file),
        audit=AuditLog(":memory:"),
        chat_backend=_stub_backend(),
    )


def _load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _run_dataset(
    rows: list[dict],
    dataset_label: str,
    mode: str,
    client,
) -> list[EvalRow]:
    out: list[EvalRow] = []
    for row in rows:
        prompt = row["text"]
        t0 = time.perf_counter()
        resp = client.post(
            "/chat",
            json={
                "session_id": f"eval-{dataset_label}-{mode}",
                "message": prompt,
                "defended": mode == "defended",
            },
        )
        wall_ms = int((time.perf_counter() - t0) * 1000)
        body = resp.json() if resp.status_code == 200 else {}
        verdict = body.get("verdict", {})
        out.append(
            EvalRow(
                id=row["id"],
                dataset=dataset_label,
                taxonomy=row.get("taxonomy"),
                owasp_category=row.get("owasp_category"),
                expected_action=row["expected_action"],
                mode=mode,
                got_action=verdict.get("action", "error"),
                score=float(verdict.get("score", 0.0)),
                reasons=list(verdict.get("reasons", [])),
                latency_ms=int(body.get("latency_ms", wall_ms)),
                prompt=prompt,
                reply=body.get("reply", ""),
            )
        )
    return out


def run(
    *,
    attacks_path: Path,
    benign_path: Path,
    modes: Iterable[str],
    live: bool,
) -> list[EvalRow]:
    from fastapi.testclient import TestClient

    deps = _build_deps(live)
    set_deps(deps)
    try:
        client = TestClient(gateway_main.app)
        attacks = _load_jsonl(attacks_path)
        benign = _load_jsonl(benign_path)

        results: list[EvalRow] = []
        for mode in modes:
            results.extend(_run_dataset(attacks, "attack", mode, client))
            results.extend(_run_dataset(benign, "benign", mode, client))
        return results
    finally:
        reset_deps()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["raw", "defended", "both"], default="both")
    ap.add_argument("--attacks", type=Path, default=DATASETS / "attacks.jsonl")
    ap.add_argument("--benign", type=Path, default=DATASETS / "benign.jsonl")
    ap.add_argument("--out", type=Path, default=REPORTS / "latest.md")
    ap.add_argument(
        "--live",
        action="store_true",
        help="Use real OpenAI backend + classifier (requires OPENAI_API_KEY).",
    )
    ap.add_argument(
        "--raw-file",
        type=Path,
        default=None,
        help="Optional path to save raw per-row results as JSONL alongside the report.",
    )
    args = ap.parse_args()

    modes = ["raw", "defended"] if args.mode == "both" else [args.mode]

    rows = run(
        attacks_path=args.attacks,
        benign_path=args.benign,
        modes=modes,
        live=args.live,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    previous = args.out.read_text(encoding="utf-8") if args.out.exists() else None
    report = render_report(rows, modes=modes, live=args.live, previous=previous)
    args.out.write_text(report, encoding="utf-8")

    if args.raw_file:
        args.raw_file.parent.mkdir(parents=True, exist_ok=True)
        with args.raw_file.open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r.__dict__) + "\n")

    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
