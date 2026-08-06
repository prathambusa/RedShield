from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATASETS = ROOT / "datasets"
REPORTS = ROOT / "reports"


@dataclass
class ProbeResult:
    seed_id: str
    seed_text: str
    seed_taxonomy: str
    seed_owasp: str
    mutation: "Mutation"
    action: str
    score: float
    reasons: list[str] = field(default_factory=list)
    latency_ms: int = 0

    @property
    def bypassed(self) -> bool:
        return self.action != "block"


def _load_seeds(path: Path, taxonomy: str | None, limit: int | None) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("expected_action") != "block":
                continue
            if "stub_reply" in row:
                # Output-side tests — not meaningful to mutate the input
                continue
            if taxonomy and row.get("taxonomy") != taxonomy:
                continue
            rows.append(row)
    if limit:
        rows = rows[:limit]
    return rows


def _build_deps(stub: bool):
    from app.audit import AuditLog
    from app.config import get_settings
    from app.detectors.classifier import LLMClassifier
    from app.detectors.output_filter import OutputFilter
    from app.detectors.rules import default_matcher
    from app.gateway.deps import AppDeps, build_default_deps
    from app.policy.allowlist import load_allowlist
    from app.policy.blocklist import load_blocklist

    if not stub:
        return build_default_deps()

    settings = get_settings()

    def _stub_fn(sys_prompt: str, user: str) -> str:
        return '{"verdict":"benign","confidence":0.5,"reason":"stub"}'

    return AppDeps(
        settings=settings,
        matcher=default_matcher(),
        classifier=LLMClassifier(completion_fn=_stub_fn),
        output_filter=OutputFilter(system_prompt=settings.system_prompt),
        allowlist=load_allowlist(settings.allowlist_file),
        blocklist=load_blocklist(settings.blocklist_file),
        audit=AuditLog(":memory:"),
        chat_backend=lambda *, system, messages: "Your order is on the way.",
    )


def run(
    *,
    seeds_path: Path,
    mutations_per_seed: int,
    propose_rules: bool,
    stub: bool,
    taxonomy: str | None,
    limit: int | None,
    mutation_fn=None,
    propose_fn=None,
) -> tuple[list[ProbeResult], list]:
    from fastapi.testclient import TestClient

    from app.gateway import main as gateway_main
    from app.gateway.deps import reset_deps, set_deps
    from eval.red_team.mutator import Mutation, generate as generate_mutations
    from eval.red_team.proposer import RuleProposal, propose as propose_rule

    seeds = _load_seeds(seeds_path, taxonomy, limit)
    if not seeds:
        print("No seeds found matching the given filters.", file=sys.stderr)
        return [], []

    deps = _build_deps(stub)
    set_deps(deps)

    results: list[ProbeResult] = []
    proposals: list[RuleProposal] = []

    try:
        client = TestClient(gateway_main.app)

        for i, seed in enumerate(seeds, 1):
            seed_id = seed["id"]
            seed_text = seed["text"]
            taxonomy_val = seed.get("taxonomy", "unknown")
            owasp_val = seed.get("owasp_category", "")

            print(
                f"  [{i:>3}/{len(seeds)}] {seed_id:<12} ({taxonomy_val}) — mutating...",
                file=sys.stderr,
                end=" ",
                flush=True,
            )

            mutations = generate_mutations(seed_text, n=mutations_per_seed, completion_fn=mutation_fn)

            if not mutations:
                print("no mutations returned", file=sys.stderr)
                continue

            print(f"{len(mutations)} mutations", file=sys.stderr, flush=True)

            seed_bypasses: list[ProbeResult] = []

            for mutation in mutations:
                resp = client.post(
                    "/chat",
                    json={
                        "session_id": f"redteam-{seed_id}-{mutation.strategy}",
                        "message": mutation.text,
                        "defended": True,
                    },
                )

                if resp.status_code == 200:
                    body = resp.json()
                    verdict = body.get("verdict", {})
                    result = ProbeResult(
                        seed_id=seed_id,
                        seed_text=seed_text,
                        seed_taxonomy=taxonomy_val,
                        seed_owasp=owasp_val,
                        mutation=mutation,
                        action=verdict.get("action", "error"),
                        score=float(verdict.get("score", 0.0)),
                        reasons=list(verdict.get("reasons", [])),
                        latency_ms=int(body.get("latency_ms", 0)),
                    )
                else:
                    result = ProbeResult(
                        seed_id=seed_id,
                        seed_text=seed_text,
                        seed_taxonomy=taxonomy_val,
                        seed_owasp=owasp_val,
                        mutation=mutation,
                        action="error",
                        score=0.0,
                    )

                results.append(result)
                if result.bypassed:
                    seed_bypasses.append(result)

            if seed_bypasses:
                strats = ", ".join(r.mutation.strategy for r in seed_bypasses)
                print(
                    f"    ⚠  {len(seed_bypasses)} bypass(es) from `{seed_id}`: {strats}",
                    file=sys.stderr,
                )

        # Generate rule proposals for all bypasses
        if propose_rules:
            bypasses = [r for r in results if r.bypassed]
            if bypasses:
                print(f"\nGenerating rule proposals for {len(bypasses)} bypass(es)...", file=sys.stderr)
                for bypass in bypasses:
                    proposal = propose_rule(
                        seed_text=bypass.seed_text,
                        bypass_text=bypass.mutation.text,
                        strategy=bypass.mutation.strategy,
                        seed_id=bypass.seed_id,
                        completion_fn=propose_fn,
                    )
                    if proposal:
                        existing = next((p for p in proposals if p.pattern == proposal.pattern), None)
                        if existing:
                            existing.triggered_by.append(bypass.seed_id)
                        else:
                            proposals.append(proposal)

    finally:
        reset_deps()

    return results, proposals


def main() -> int:
    ap = argparse.ArgumentParser(
        description="RedShield adversarial red-team fuzzer — mutates known attacks and probes the defender.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full run against all seeds, 8 mutations each
  python -m eval.run_red_team

  # Quick smoke test — 5 seeds, 3 mutations, no LLM classifier
  python -m eval.run_red_team --limit 5 --mutations-per-seed 3 --stub

  # Target jailbreak attacks only and propose rules for bypasses
  python -m eval.run_red_team --taxonomy jailbreak --propose-rules
        """,
    )
    ap.add_argument("--seeds-file", type=Path, default=DATASETS / "attacks.jsonl")
    ap.add_argument("--mutations-per-seed", type=int, default=8, metavar="N")
    ap.add_argument("--limit", type=int, default=None, metavar="N", help="Use only first N seeds")
    ap.add_argument("--taxonomy", default=None, help="Filter to a single taxonomy")
    ap.add_argument("--propose-rules", action="store_true", help="LLM-generate rule patches for bypasses")
    ap.add_argument(
        "--stub",
        action="store_true",
        help="Stub the gateway classifier (tests rule layer only, no API cost for gateway)",
    )
    ap.add_argument("--out", type=Path, default=REPORTS / "red_team.md")
    ap.add_argument("--raw-file", type=Path, default=None, help="Save raw results as JSONL")
    args = ap.parse_args()

    classifier_mode = "stub (rules-only)" if args.stub else "live (rules + classifier)"
    print("RedShield Red Team Fuzzer", file=sys.stderr)
    print(f"  Seeds:     {args.seeds_file}", file=sys.stderr)
    print(f"  Mutations: {args.mutations_per_seed} per seed", file=sys.stderr)
    print(f"  Classifier: {classifier_mode}", file=sys.stderr)
    if args.taxonomy:
        print(f"  Taxonomy filter: {args.taxonomy}", file=sys.stderr)
    if args.limit:
        print(f"  Seed limit: {args.limit}", file=sys.stderr)
    print(file=sys.stderr)

    results, proposals = run(
        seeds_path=args.seeds_file,
        mutations_per_seed=args.mutations_per_seed,
        propose_rules=args.propose_rules,
        stub=args.stub,
        taxonomy=args.taxonomy,
        limit=args.limit,
    )

    if not results:
        return 1

    n_probes = len(results)
    n_bypassed = sum(1 for r in results if r.bypassed)

    print(
        f"\nDone. {n_probes} probes | {n_bypassed} bypassed ({n_bypassed/n_probes:.1%})",
        file=sys.stderr,
    )

    from eval.red_team.report import render_red_team_report

    args.out.parent.mkdir(parents=True, exist_ok=True)
    report = render_red_team_report(results, proposals)
    args.out.write_text(report, encoding="utf-8")
    print(f"Report → {args.out}", file=sys.stderr)

    if args.raw_file:
        args.raw_file.parent.mkdir(parents=True, exist_ok=True)
        with args.raw_file.open("w", encoding="utf-8") as f:
            for r in results:
                f.write(
                    json.dumps(
                        {
                            "seed_id": r.seed_id,
                            "seed_taxonomy": r.seed_taxonomy,
                            "seed_owasp": r.seed_owasp,
                            "strategy": r.mutation.strategy,
                            "mutation_text": r.mutation.text,
                            "action": r.action,
                            "score": r.score,
                            "reasons": r.reasons,
                            "bypassed": r.bypassed,
                        }
                    )
                    + "\n"
                )
        print(f"Raw results → {args.raw_file}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
