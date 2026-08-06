# Eval Harness

Measures how well RedShield blocks attacks without breaking benign traffic.

## Datasets

- `datasets/attacks.jsonl` — 50 labeled prompt-injection attacks spanning `instruction_override`, `jailbreak`, `prompt_leak`, `refusal_bypass`, `obfuscation`.
- `datasets/benign.jsonl` — 51 customer-support-style control prompts that must not trip the defenders.
- `regressions/must_block.jsonl` — 10 canonical attacks that must stay 100% blocked across commits.

Each row: `{"id": "...", "text": "...", "expected_action": "block|allow", "taxonomy": "..." }`.

## Run

```bash
# Stub backend (no network, pure rule coverage):
python -m eval.run_eval --mode both --out eval/reports/latest.md

# Live backend (real OpenAI for chat + classifier):
python -m eval.run_eval --mode both --live --out eval/reports/latest.md
```

Or `make eval`.

## What the report contains

- **Headline metrics** per mode (raw, defended): ASR, FPR, precision, recall, F1, latency p50/p95.
- **Raw vs Defended delta** — how much the middleware actually moves the needle.
- **Per-taxonomy recall** (defended mode) — which attack families still leak through.
- **Miss / false-positive tables** — specific prompts to investigate.
- **Diff vs previous report** — headline numbers compared to the prior `latest.md`.

## Definitions

- **ASR (Attack Success Rate, ↓ is good):** fraction of attacks the defended pipeline did *not* block. MVP uses the strict proxy "block = defense success"; it does not additionally judge whether the model's reply was harmful when the attack slipped past.
- **FPR (False Positive Rate, ↓ is good):** fraction of benign prompts that were blocked.
- **Precision / Recall / F1:** treat `block` as the positive class, pooled across both attacks and benign controls.
- **Latency p50 / p95:** end-to-end gateway latency in ms; dominated by the upstream LLM call in live mode, by pure rule evaluation in stub mode.

## Regression set

`regressions/must_block.jsonl` is intentionally small and canonical. If anything in this file ever stops blocking, that's a regression, not a metric movement.
