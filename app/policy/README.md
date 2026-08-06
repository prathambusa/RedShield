# Policy

Turns raw detector signals into a single `Verdict`.

## `allowlist.py` + `allowlist.yaml`

Substrings/regex that **bypass** deeper checks when they match. Keep this small and high-trust.

## `blocklist.py` + `blocklist.yaml`

Substrings/regex that **hard-deny** on match (before classifier, before LLM).

## `risk.py`

`aggregate(rule_hits, classifier_verdict, *, allowlisted, blocklist_match)` returns a `Verdict(action, score, reasons, rule_hits, classifier)`.

Pipeline:

1. `blocklist_match` → immediate `block`, score 1.0.
2. `allowlisted=True` → immediate `allow`, score 0.0.
3. Any rule hit with `severity >= 9` → hard `block`, score 1.0.
4. Classifier `malicious` with confidence ≥ 0.85 → hard `block`.
5. Otherwise, soft score = `max(sum(severity) / 10, classifier_confidence_if_non_benign)`.
6. Thresholds from [`app/config.py`](../config.py): `block_threshold` (default 0.7) and `review_threshold` (0.4).

Thresholds are env-configurable (`REDSHIELD_BLOCK_THRESHOLD`, `REDSHIELD_REVIEW_THRESHOLD`) so the eval harness can sweep them.
