from __future__ import annotations

import argparse
import dataclasses
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
    leaked_system_prompt: bool = False
    turns: int = 0  # number of prior turns in multi-turn rows


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
    deps: AppDeps,
) -> list[EvalRow]:
    out: list[EvalRow] = []
    for row in rows:
        prompt = row["text"]
        history = row.get("turns", [])
        stub_reply = row.get("stub_reply")

        # For rows with stub_reply, temporarily swap the chat backend so the
        # output filter sees the injected content rather than the default stub.
        if stub_reply is not None:
            patched = dataclasses.replace(
                deps,
                chat_backend=lambda *, system, messages, _r=stub_reply: _r,
            )
            set_deps(patched)

        t0 = time.perf_counter()
        resp = client.post(
            "/chat",
            json={
                "session_id": f"eval-{dataset_label}-{mode}-{row['id']}",
                "message": prompt,
                "history": history,
                "defended": mode == "defended",
            },
        )
        wall_ms = int((time.perf_counter() - t0) * 1000)

        if stub_reply is not None:
            set_deps(deps)

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
                leaked_system_prompt=bool(body.get("output_leaked_system_prompt", False)),
                turns=len(history),
            )
        )
    return out


def run(
    *,
    attacks_path: Path,
    benign_path: Path,
    modes: Iterable[str],
    live: bool,
    multiturn_path: Path | None = None,
) -> list[EvalRow]:
    from fastapi.testclient import TestClient

    deps = _build_deps(live)
    set_deps(deps)
    try:
        client = TestClient(gateway_main.app)
        attacks = _load_jsonl(attacks_path)
        if multiturn_path and multiturn_path.exists():
            attacks = attacks + _load_jsonl(multiturn_path)
        benign = _load_jsonl(benign_path)

        results: list[EvalRow] = []
        for mode in modes:
            results.extend(_run_dataset(attacks, "attack", mode, client, deps))
            results.extend(_run_dataset(benign, "benign", mode, client, deps))
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
        help="Use real API backend + classifier.",
    )
    ap.add_argument(
        "--multiturn",
        type=Path,
        default=None,
        nargs="?",
        const=DATASETS / "multiturn_attacks.jsonl",
        help="Also run multi-turn attack dataset (default: eval/datasets/multiturn_attacks.jsonl).",
    )
    ap.add_argument(
        "--fail-on-asr",
        type=float,
        default=None,
        metavar="THRESHOLD",
        help="Exit 1 if defended ASR exceeds THRESHOLD (e.g. 0.0 means any miss fails).",
    )
    ap.add_argument(
        "--raw-file",
        type=Path,
        default=None,
        help="Optional path to save raw per-row results as JSONL.",
    )
    args = ap.parse_args()

    modes = ["raw", "defended"] if args.mode == "both" else [args.mode]

    rows = run(
        attacks_path=args.attacks,
        benign_path=args.benign,
        modes=modes,
        live=args.live,
        multiturn_path=args.multiturn,
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

    if args.fail_on_asr is not None:
        defended_attacks = [r for r in rows if r.mode == "defended" and r.dataset == "attack"]
        if defended_attacks:
            blocked = sum(1 for r in defended_attacks if r.got_action == "block")
            asr = (len(defended_attacks) - blocked) / len(defended_attacks)
            if asr > args.fail_on_asr:
                print(f"FAIL: defended ASR {asr:.1%} exceeds threshold {args.fail_on_asr:.1%}")
                return 1
            print(f"PASS: defended ASR {asr:.1%} within threshold {args.fail_on_asr:.1%}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
