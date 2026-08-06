# RedShield — Roadmap

**Status:** Phase 0 (scaffold exists, no defense logic built yet)
**Goal:** Ship an MVP of a prompt-injection defense middleware that sits in front of an LLM, blocks known attacks, filters risky outputs, logs everything, and has an eval harness that produces real safety metrics.

---

## Product in one paragraph

RedShield is an HTTP middleware between a client and an LLM. Every request passes through an **input defender** (rule-based pattern matcher + LLM classifier + allow/blocklists) that emits a verdict — `allow`, `review`, or `block`. Allowed requests go to the model; the response passes through an **output defender** (PII redaction, system-prompt-leak detection, policy phrase filter). Every step is logged to SQLite with a structured schema. An **eval harness** replays a labeled attack dataset through the gateway and reports attack-success-rate, false-positive-rate, and per-taxonomy precision/recall.

---

## Architecture (MVP)

```
┌──────────────┐       ┌─────────────────────────────────────────────┐       ┌──────────┐
│  Streamlit   │       │             RedShield Gateway               │       │          │
│  demo UI     │       │  ┌──────────┐   ┌────────┐   ┌──────────┐   │       │  OpenAI  │
│              │──────▶│  │  Input   │──▶│  LLM   │──▶│  Output  │───┼──────▶│  (gpt-4  │
│  (calls      │       │  │ Defender │   │ Client │   │ Defender │   │       │  or cheap│
│   FastAPI)   │◀──────│  └──────────┘   └────────┘   └──────────┘   │◀──────│  model)  │
└──────────────┘       │        │              │             │       │       └──────────┘
                       │        └──────────────┬─────────────┘       │
                       │                       ▼                     │
                       │                 Audit Log (SQLite)          │
                       └─────────────────────────────────────────────┘
                                        ▲
                                        │ replays
                       ┌────────────────┴────────────┐
                       │        Eval Harness         │
                       │  (labeled attack dataset    │
                       │   → metrics report)         │
                       └─────────────────────────────┘
```

**Input defender stages** (short-circuit on hard block, otherwise accumulate signals):
1. Length / format sanity checks.
2. Allowlist (trusted patterns bypass deep checks).
3. Blocklist (hard deny).
4. Rule-based attack pattern matcher (regex + keyword library, taxonomy-tagged).
5. LLM classifier (small/cheap model, structured verdict).
6. Risk aggregator: combine rule severity + classifier confidence → `allow | review | block`.

**Output defender stages:**
1. System-prompt-leak detection (fuzzy overlap against the configured system prompt).
2. PII scan (email, phone, SSN-like, credit-card-like, API-key-like patterns) with configurable redaction or block.
3. Policy phrase blocklist (configurable).

---

## Threat model (what MVP defends against)

In scope for MVP:
- **Instruction override** — "ignore all previous instructions", "you are now…", "new system prompt:".
- **Role-play / persona jailbreaks** — DAN, developer-mode, grandma-exploit shapes.
- **System prompt exfiltration** — "repeat your instructions", "what's above this line", encoding tricks.
- **Refusal bypass** — "hypothetically", "for educational purposes", split-payload attacks.
- **Output-side leakage** — model regurgitating the system prompt or PII it saw.
- **Obfuscation** — base64, leetspeak, unicode homoglyphs, zero-width characters (basic detection).

Explicitly out of scope for MVP (note as post-MVP):
- Multi-turn state attacks across long histories.
- Tool/function-call abuse (no tools wired up yet).
- Indirect prompt injection via RAG documents.
- Adversarial token-level attacks (GCG-style).

---

## Phases & acceptance criteria

### Phase 0 — Hygiene (day 0)
- [ ] Populate `requirements.txt` with pinned versions.
- [ ] Add `.gitignore`, `.env.example`, `pyproject.toml` (or keep flat), `Makefile` with `run`, `test`, `eval`, `docker` targets.
- [ ] Migrate `app/chatbot.py` off the legacy `openai` 0.x SDK to `openai>=1.0`.
- [ ] Fill `README.md` with overview + setup + usage.
- [ ] Create this `ROADMAP.md` (done) and a `CHANGELOG.md`.
- **Done when:** `make run` starts Streamlit, talks to GPT-4 via the new SDK, logs an interaction.

### Phase 1 — Defense core (the heart of RedShield)
- [x] `app/detectors/rules.py` — attack pattern library with taxonomy tags + severity; `match(text) -> list[Hit]`.
- [x] `app/detectors/classifier.py` — LLM judge returning `{verdict, confidence, reason}`; cached; graceful fallback on API error.
- [x] `app/detectors/output_filter.py` — PII redaction, system-prompt-leak detection, phrase blocklist.
- [x] `app/policy/allowlist.py`, `blocklist.py` — simple list loaders (YAML or JSON).
- [x] `app/policy/risk.py` — combine signals into `Verdict(action, score, reasons)`.
- [x] `app/audit.py` — SQLite schema + append-only writer; indexed on timestamp, verdict, session.
- [x] Unit tests for each detector with positive and negative examples.
- **Done when:** all modules importable, unit tests pass, `pytest -q` is green.

### Phase 2 — FastAPI gateway
- [x] `app/gateway/main.py` — FastAPI app.
- [x] `POST /chat` — request: `{session_id, message, history?}`; response: `{reply, verdict, reasons, latency_ms}`.
- [x] `GET /health` — liveness.
- [x] `GET /admin/stats` — recent verdicts, rolling attack-block-rate (dev-only auth or localhost-only).
- [x] `app/llm/openai_client.py` — thin wrapper around `openai>=1.0`, timeout, retry, model override.
- [x] Pydantic schemas in `app/gateway/schemas.py`.
- **Done when:** `uvicorn app.gateway.main:app` serves `/docs`, a curl round-trip works, a known attack returns `verdict: block` with reasons.

### Phase 3 — Streamlit demo as gateway client
- [x] Rewire `main.py` to POST to the FastAPI gateway instead of calling OpenAI directly.
- [x] Surface verdict, reasons, and latency next to each bot reply.
- [x] Add a "Raw vs Defended" toggle so you can demo the difference live.
- [x] Example-attacks sidebar (pre-filled prompts from the dataset).
- **Done when:** pasting a canned jailbreak into the UI shows the block verdict + matched rules, and toggling "Raw" shows the chatbot actually getting exploited.

### Phase 4 — Evaluation harness (the resume-worthy artifact)
- [ ] `eval/datasets/attacks.jsonl` — ~50 labeled attacks across taxonomy (instruction-override, jailbreak, prompt-leak, refusal-bypass, obfuscation) + ~50 benign controls.
- [ ] `eval/run_eval.py` — iterate dataset through raw and defended paths, record outcomes.
- [ ] `eval/report.py` — emit markdown report: ASR (attack-success-rate), FPR (false-positive on benign), per-taxonomy precision/recall/F1, latency p50/p95.
- [ ] `eval/regressions/` — small curated set that must stay at 100% blocked across commits.
- **Done when:** `make eval` produces `eval/reports/latest.md` with metrics and a diff vs. previous run.

### Phase 5 — Infra stub
- [ ] `Dockerfile` — multi-stage build, non-root user.
- [ ] `docker-compose.yml` — gateway service + volume for SQLite db.
- [ ] `.github/workflows/ci.yml` — lint + tests + eval smoke on PRs (optional).
- **Done when:** `docker compose up` serves the gateway and Streamlit locally.

### Phase 6 — Polish
- [ ] Per-module `README.md` in `app/detectors/`, `app/gateway/`, `eval/`.
- [ ] Root `README.md` with architecture diagram, metrics table from latest eval, quickstart.
- [ ] `CHANGELOG.md` updated each phase.
- [ ] Screenshots of the Streamlit demo blocking an attack (for the portfolio).
- **Done when:** a reviewer can clone, run one command, see metrics, and understand the design from docs alone.

---

## Definition of MVP (the line in the sand)

MVP = end of Phase 4. Specifically:

1. FastAPI gateway with input + output defenders wired end-to-end.
2. Rule library covering the in-scope threat-model categories above.
3. LLM classifier integrated and falling back gracefully.
4. SQLite audit log with queryable schema.
5. Streamlit demo showing raw-vs-defended side by side.
6. Eval harness producing a markdown report with real numbers.
7. README that ties it all together.

Everything past that (Docker polish, CI, per-module READMEs, fancy dashboards) is post-MVP polish and doesn't block "claim this on a resume."

---

## Post-MVP backlog (do not block MVP)

- Streaming output filter (token-by-token abort).
- Multi-turn attack detection (cross-turn signal aggregation).
- Indirect prompt injection defense (taint-tracking on RAG context).
- Tool/function-call allowlists.
- Rate limiting + per-session risk budgets.
- Pluggable classifier backends (local model, Llama Guard, etc.).
- Postgres + AWS deploy (currently SQLite + local Docker).
- Admin dashboard (replace `/admin/stats` JSON with a real UI).
- Adversarial regression fuzzer (mutate known attacks and replay nightly).

---

## Non-goals

- Not building a new foundation model.
- Not re-implementing LangChain / Guardrails / NeMo — RedShield is opinionated middleware, not a framework.
- Not aiming for production SLAs in MVP (no HA, no horizontal scaling, no secrets manager integration).
