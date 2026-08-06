from __future__ import annotations

from app.config import get_settings


class OpenAIClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 2,
    ) -> None:
        import anthropic  # lazy import so tests don't need the package at import time

        settings = get_settings()
        key = api_key or settings.anthropic_api_key or None
        self._client = anthropic.Anthropic(
            api_key=key,
            timeout=timeout,
            max_retries=max_retries,
        )
        self._timeout = timeout
        self._max_retries = max_retries

    def chat(
        self,
        *,
        model: str,
        messages: list[dict],
        temperature: float = 0.7,
        response_format: dict | None = None,
    ) -> str:
        system = ""
        user_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system = msg["content"]
            else:
                user_messages.append(msg)

        kwargs: dict = {
            "model": model,
            "max_tokens": 1024,
            "messages": user_messages,
            "temperature": temperature,
        }
        if system:
            kwargs["system"] = system

        response = self._client.messages.create(**kwargs)
        return response.content[0].text

    def chat_json(self, *, model: str, system: str, user: str, temperature: float = 0.0) -> str:
        messages = [{"role": "user", "content": user}]
        kwargs: dict = {
            "model": model,
            "max_tokens": 512,
            "messages": messages,
            "temperature": temperature,
            "system": system,
        }
        response = self._client.messages.create(**kwargs)
        return response.content[0].text


_default: OpenAIClient | None = None


def default_client() -> OpenAIClient:
    global _default
    if _default is None:
        _default = OpenAIClient()
    return _default


def reset_default_client() -> None:
    global _default
    _default = None


def chat(*, model: str, messages: list[dict], temperature: float = 0.7) -> str:
    return default_client().chat(model=model, messages=messages, temperature=temperature)


def chat_json(*, model: str, system: str, user: str, temperature: float = 0.0) -> str:
    return default_client().chat_json(model=model, system=system, user=user, temperature=temperature)
