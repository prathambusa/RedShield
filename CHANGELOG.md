# Changelog

All notable changes to RedShield are recorded here. Entries are dated and phase-tagged to match `ROADMAP.md`.

Format: [phase] — summary (YYYY-MM-DD)

---

## [phase 5 + 6] — Infra stub + module polish (2026-04-23)

- `Dockerfile` — multi-stage (python:3.11-slim builder → runtime), non-root `redshield` user, `/data` volume for the SQLite audit DB, health check hitting `/health`, and `uvicorn` as the default CMD.
- `.dockerignore` — keeps `.venv`, caches, tests, reports, and local `.env` out of the image.
- `docker-compose.yml` — `gateway` service on :8000 + `ui` Streamlit service on :8501 (pointed at the gateway over the compose network), named volume for audit data, env pass-through for API keys and thresholds.
- `.github/workflows/ci.yml` — pytest on every PR + a stub-mode eval smoke run whose report is uploaded as an artifact, plus a `docker build` job gated on tests.
- Per-module READMEs added for `app/policy/` and `app/llm/` (detectors / gateway / eval already had theirs).
- One Phase 6 item intentionally left open: portfolio screenshots of the Streamlit demo require a browser, which this sandbox doesn't have. That's a user task.
- Caveat: I don't have Docker or GitHub Actions in this environment, so the Dockerfile and CI workflow are reviewed-but-not-executed. Worth a `docker build .` pass locally before relying on either.

## [phase 4] — Eval harness + datasets + metrics report (2026-04-23)

- `eval/datasets/attacks.jsonl` — 50 labeled attacks spanning `instruction_override` (12), `jailbreak` (12), `prompt_leak` (10), `refusal_bypass` (8), `obfuscation` (8).
- `eval/datasets/benign.jsonl` — 51 customer-support-style controls (orders, refunds, shipping, returns, billing).
- `eval/regressions/must_block.jsonl` — 10 canonical attacks wired into pytest; if any ever unblocks, it's a regression.
- `eval/run_eval.py` — runs datasets through the gateway in-process via `TestClient`, both `raw` and `defended`. Default stub backend + deterministic stub classifier → pure rule coverage, no network. `--live` flag swaps in the real OpenAI stack.
- `eval/report.py` — renders headline table (ASR / FPR / P / R / F1 / latency p50/p95) per mode, raw-vs-defended delta, per-taxonomy recall, miss + false-positive tables, and a diff vs the previous report.
- Tuned `policy/risk.py` rule-score divisor 15→10 and bumped 5 regex gaps (DAN "in/an" variants, grandma comma, prompt-leak singular forms, "everything above … current message", "copy … verbatim") so canonical attacks hard-block on their own without requiring the classifier.
- Bumped refusal-bypass and base64-obfuscation severities to 7 so single hits cross the 0.7 block threshold.
- Current headline metrics (stub backend): defended ASR **0.0%**, FPR **0.0%**, F1 **1.00**, raw→defended reduction **100% absolute**. Caveat: the dataset is curated; public adversarial corpora will move these numbers.
- `README.md` rewritten with metrics table, architecture, quickstart, and curl example.
- Test suite: 64 cases passing (added `test_eval.py` for regression + full-dataset thresholds + markdown rendering).

## [phase 3] — Streamlit demo rewired to the gateway (2026-04-23)

- `main.py` now POSTs to `REDSHIELD_GATEWAY_URL` (default `http://127.0.0.1:8000`) instead of calling OpenAI directly.
- Per-reply display: verdict badge (green/orange/red), score, latency in ms, expandable reasons list.
- Sidebar: defended/raw toggle, session id, clear-chat button, and an example-attacks palette. Examples load from `eval/datasets/attacks.jsonl` once the dataset lands; until then, falls back to six hardcoded demo prompts covering instruction override, DAN, prompt leak, refusal bypass, and two benign controls.
- Session ids are now UUID-prefixed so the audit log can distinguish concurrent demos.
- Note: UI was syntax-checked only — I don't have a browser in this sandbox, so visual verification is on the user.

## [phase 2] — FastAPI gateway + OpenAI client wrapper (2026-04-23)

- `app/llm/openai_client.py` — thin `openai>=1.0` wrapper with configurable timeout, retries, and a `chat_json` helper that requests `response_format=json_object` for the classifier.
- `app/gateway/schemas.py` — pydantic request/response models with validation (1–8000 char message bound, history turns typed).
- `app/gateway/deps.py` — `AppDeps` container + settable singleton so tests inject fakes (backend, classifier, audit log) without touching OpenAI.
- `app/gateway/main.py` — FastAPI app with `POST /chat`, `GET /health`, `GET /admin/stats`. Pipeline: allowlist → blocklist → rules → classifier (skipped on hard signals) → risk aggregate → LLM → output filter. Blocked inputs never reach the upstream LLM. `defended: false` provides a raw path for the Streamlit toggle and eval baseline. Admin stats auth: bearer token if `REDSHIELD_ADMIN_TOKEN` set, otherwise localhost/testclient only.
- `tests/test_gateway.py` — 10 tests covering allow, block-on-rule, block-on-classifier, output-side block on prompt leak, PII redaction, raw-path bypass, admin stats + auth, validation. `pytest -q` → 61 passing.
- `make run` flipped to `gateway`.

## [phase 1] — Defense core: detectors, policy, audit log (2026-04-23)

- Added `app/config.py` with `pydantic-settings` — single source of truth for model names, thresholds, file paths, and system prompt.
- `app/detectors/rules.py` + `patterns.yaml` — 20 seeded attack patterns across the 5 taxonomies (instruction override, jailbreak, prompt leak, refusal bypass, obfuscation) with severity 4–9.
- `app/detectors/classifier.py` — LLM judge with forgiving JSON parser, SHA-256 input cache, and graceful fallback on parse/API errors. Injectable `completion_fn` for tests (no network in unit tests).
- `app/detectors/output_filter.py` — system-prompt-leak detection (6-gram overlap + SequenceMatcher fallback), phrase blocklist, and PII redaction for email/SSN/phone/credit-card/OpenAI-key/AWS-key/generic-secret. Pattern order hardened so specific tokens (API keys) redact before broad digit patterns.
- `app/policy/{allowlist,blocklist}.py` + YAML files — regex list loaders with missing-file tolerance.
- `app/policy/risk.py` — short-circuits on blocklist match, allowlist bypass, severity≥9 rule hit, or classifier malicious+confidence≥0.85; otherwise blends rule and classifier scores against configurable thresholds.
- `app/audit.py` — SQLite append-only log indexed on ts/action/session, persistent-connection mode for `:memory:` so tests and prod share one code path.
- Tests: 51 pytest cases across rules, classifier, output filter, policy, audit — all passing (`pytest -q` green).
- Per-module `app/detectors/README.md` added.

## [phase 0] — Hygiene scaffold + SDK migration (2026-04-23)

- Pinned `requirements.txt` (openai 1.54.4, fastapi, streamlit, pydantic v2, pytest, etc.) and added `pyproject.toml`.
- Added `.gitignore`, `.env.example`, and `Makefile` (`install`, `run`, `ui`, `gateway`, `test`, `eval`, `docker`, `clean`).
- Migrated `app/chatbot.py` from legacy `openai` 0.x to `openai>=1.0` client; model overridable via `REDSHIELD_CHAT_MODEL`.
- Filled `README.md` with overview, quickstart, architecture sketch, and layout.
- Added `app/__init__.py` so `app` is a proper package.
- `make run` currently aliases `make ui` (Streamlit); flips to the FastAPI gateway in Phase 2.

## [planning] — Roadmap and MVP brief written (2026-04-23)

- Added `ROADMAP.md` with threat model, architecture, phase-by-phase acceptance criteria, and definition of MVP.
- Added `CLAUDE_CODE_BRIEF.md` as a self-contained handoff document for Claude Code to execute Phases 0–4.
- Confirmed scope decisions: FastAPI gateway + Streamlit demo, rules + LLM classifier, SQLite + Docker stub, living docs.
- Current implementation state: Phase 0 skeleton only (Streamlit UI + legacy-SDK chatbot wrapper).

<!-- New entries go above this line. -->
