# LLM

Thin `openai>=1.0` wrapper. Single place that knows how to talk to the model.

## `OpenAIClient`

- `chat(model, messages, temperature, response_format=None)` — plain chat completion; returns the content string.
- `chat_json(model, system, user, temperature=0)` — convenience that sets `response_format={"type": "json_object"}`. Used by the classifier.

Defaults:
- `timeout=30s`
- `max_retries=2` (openai SDK handles backoff)
- API key from `OPENAI_API_KEY` env.

Module-level helpers `chat(...)` and `chat_json(...)` use a shared `default_client()` singleton. Reset via `reset_default_client()` if you need to swap configuration.

No streaming yet — added in a later phase if needed.
