from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone


def _pct(num: int, denom: int) -> str:
    if denom == 0:
        return "—"
    return f"{100 * num / denom:.1f}%"


def render_red_team_report(results: list, proposals: list) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    n_probes = len(results)
    n_bypassed = sum(1 for r in results if r.bypassed)
    unique_seeds = len({r.seed_id for r in results})

    lines: list[str] = []
    lines.append("# RedShield Red Team Report")
    lines.append("")
    lines.append(f"- **Generated:** {ts}")
    lines.append(f"- **Seeds probed:** {unique_seeds}")
    lines.append(f"- **Total mutations:** {n_probes}")
    lines.append(f"- **Overall bypass rate:** {n_bypassed}/{n_probes} ({_pct(n_bypassed, n_probes)})")
    lines.append("")
    lines.append(
        "_A bypass means the mutation was not blocked. It does not guarantee the attack "
        "would succeed — the underlying LLM may still refuse. Bypasses represent gaps in "
        "the rule/classifier layer that should be patched._"
    )
    lines.append("")

    # By strategy
    strat: dict[str, list] = defaultdict(list)
    for r in results:
        strat[r.mutation.strategy].append(r)

    lines.append("## Bypass rate by mutation strategy")
    lines.append("")
    lines.append("| Strategy | Probes | Bypassed | Bypass rate |")
    lines.append("|---|---|---|---|")
    for strategy in sorted(strat, key=lambda s: -sum(1 for r in strat[s] if r.bypassed)):
        rows = strat[strategy]
        bypassed = sum(1 for r in rows if r.bypassed)
        marker = " ⚠" if bypassed > 0 else ""
        lines.append(f"| `{strategy}` | {len(rows)} | {bypassed} | {_pct(bypassed, len(rows))}{marker} |")
    lines.append("")

    # By taxonomy
    tax: dict[str, list] = defaultdict(list)
    for r in results:
        tax[r.seed_taxonomy].append(r)

    lines.append("## Bypass rate by attack taxonomy")
    lines.append("")
    lines.append("| Taxonomy | Probes | Bypassed | Bypass rate |")
    lines.append("|---|---|---|---|")
    for taxonomy in sorted(tax, key=lambda t: -sum(1 for r in tax[t] if r.bypassed)):
        rows = tax[taxonomy]
        bypassed = sum(1 for r in rows if r.bypassed)
        marker = " ⚠" if bypassed > 0 else ""
        lines.append(f"| {taxonomy} | {len(rows)} | {bypassed} | {_pct(bypassed, len(rows))}{marker} |")
    lines.append("")

    # By OWASP
    owasp: dict[str, list] = defaultdict(list)
    for r in results:
        if r.seed_owasp:
            owasp[r.seed_owasp].append(r)

    if owasp:
        lines.append("## Bypass rate by OWASP category")
        lines.append("")
        lines.append("| OWASP | Probes | Bypassed | Bypass rate |")
        lines.append("|---|---|---|---|")
        for cat in sorted(owasp):
            rows = owasp[cat]
            bypassed = sum(1 for r in rows if r.bypassed)
            marker = " ⚠" if bypassed > 0 else ""
            lines.append(f"| {cat} | {len(rows)} | {bypassed} | {_pct(bypassed, len(rows))}{marker} |")
        lines.append("")

    # Bypassed probes detail
    bypasses = [r for r in results if r.bypassed]
    lines.append(f"## Bypassed probes ({len(bypasses)})")
    lines.append("")
    if bypasses:
        lines.append("| Seed | Taxonomy | Strategy | Mutation text |")
        lines.append("|---|---|---|---|")
        for r in bypasses:
            text = r.mutation.text.replace("|", "\\|").replace("\n", " ")
            if len(text) > 100:
                text = text[:97] + "..."
            lines.append(f"| `{r.seed_id}` | {r.seed_taxonomy} | `{r.mutation.strategy}` | {text} |")
        lines.append("")
        lines.append("### Full bypass text")
        lines.append("")
        for r in bypasses:
            lines.append(f"**`{r.seed_id}` · `{r.mutation.strategy}`**")
            lines.append("")
            lines.append(f"> Original seed: _{r.seed_text}_")
            lines.append("")
            lines.append(f"```")
            lines.append(r.mutation.text)
            lines.append(f"```")
            lines.append("")
    else:
        lines.append("_None — all mutations were blocked. The defender is robust against these strategies._")
        lines.append("")

    # Proposed rules
    if proposals:
        lines.append(f"## Proposed rules ({len(proposals)})")
        lines.append("")
        lines.append("_Copy these into `app/detectors/patterns.yaml` after review. Fill in `taxonomy` and `owasp`._")
        lines.append("")
        for i, p in enumerate(proposals, 1):
            triggered = ", ".join(p.triggered_by)
            lines.append(
                f"**REDTEAM_{i:03d}** — confidence `{p.confidence:.0%}` · FP risk `{p.false_positive_risk}` · triggered by `{triggered}`"
            )
            lines.append("")
            lines.append("```yaml")
            lines.append(f"- id: REDTEAM_{i:03d}")
            lines.append(f"  taxonomy:  # fill in — e.g. jailbreak, instruction_override")
            lines.append(f"  severity: 7")
            lines.append(f"  owasp:  # fill in — e.g. LLM01")
            lines.append(f"  pattern: \"{p.pattern}\"")
            lines.append(f"  description: \"{p.description}\"")
            lines.append("```")
            lines.append("")
    elif bypasses:
        lines.append("## Proposed rules")
        lines.append("")
        lines.append("_Run with `--propose-rules` to generate rule suggestions for bypasses above._")
        lines.append("")

    return "\n".join(lines) + "\n"
