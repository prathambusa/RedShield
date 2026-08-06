# Detectors

Three layers of input/output analysis, each importable independently.

## `rules.py` + `patterns.yaml`

Regex-based attack library. `patterns.yaml` is the source of truth — each entry is tagged with a taxonomy (`instruction_override`, `jailbreak`, `prompt_leak`, `refusal_bypass`, `obfuscation`) and a severity (1–10).

```python
from app.detectors.rules import match
hits = match("ignore all previous instructions")
# [Hit(rule_id='INSTR_OVERRIDE_001', taxonomy='instruction_override', severity=9, ...)]
```

Severity convention:
- 9–10 → hard-block on match (policy/risk.py short-circuits).
- 7–8  → strong signal, combines with classifier.
- 5–6  → weak signal, mostly review-worthy.
- 1–4  → weak hint, usually noise on its own.

## `classifier.py`

LLM-based second opinion. Calls a cheap model (default `gpt-4o-mini`), asks for JSON `{verdict, confidence, reason}`, parses with a forgiving parser, caches by SHA-256 of the input to avoid re-classifying during eval. Graceful fallback returns `{"suspicious", 0.2, "classifier_error:..."}` on any exception.

For unit tests, inject a fake completion function via the constructor:

```python
from app.detectors.classifier import LLMClassifier
cls = LLMClassifier(completion_fn=lambda sys, usr: '{"verdict":"benign","confidence":0.9,"reason":"ok"}')
```

## `output_filter.py`

Runs on the LLM's reply before it reaches the client:
1. **System-prompt-leak detection** — n-gram overlap + SequenceMatcher fallback against the configured system prompt. Leaks block.
2. **Phrase blocklist** — substring match; blocks.
3. **PII redaction** — email, SSN, phone, credit card, OpenAI/AWS API keys, generic secret patterns → replaced with `[REDACTED_*]` markers; action becomes `redact`.

Blocks return a canned refusal. Redactions return the scrubbed text.
