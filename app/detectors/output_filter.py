from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Iterable

from app.config import get_settings

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)(\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_OPENAI_KEY_RE = re.compile(r"sk-[A-Za-z0-9]{20,}")
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_GENERIC_KEY_RE = re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?")

# Order matters: high-specificity tokens (API keys, emails, SSN) run before
# broad digit patterns (phone, credit card) that would otherwise eat digit tails.
_PII_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("openai_key", _OPENAI_KEY_RE, "[REDACTED_API_KEY]"),
    ("aws_key", _AWS_KEY_RE, "[REDACTED_AWS_KEY]"),
    ("generic_key", _GENERIC_KEY_RE, "[REDACTED_SECRET]"),
    ("email", _EMAIL_RE, "[REDACTED_EMAIL]"),
    ("ssn", _SSN_RE, "[REDACTED_SSN]"),
    ("credit_card", _CREDIT_CARD_RE, "[REDACTED_CARD]"),
    ("phone", _PHONE_RE, "[REDACTED_PHONE]"),
]


@dataclass
class OutputFilterResult:
    text: str
    action: str
    reasons: list[str] = field(default_factory=list)
    redactions: list[str] = field(default_factory=list)
    leak_ratio: float = 0.0


def _ngrams(text: str, n: int = 6) -> set[str]:
    words = re.findall(r"\S+", text.lower())
    return {" ".join(words[i : i + n]) for i in range(len(words) - n + 1)} if len(words) >= n else set()


def _detect_system_prompt_leak(output: str, system_prompt: str, threshold: float = 0.6) -> float:
    if not system_prompt.strip() or not output.strip():
        return 0.0
    sys_grams = _ngrams(system_prompt, n=6)
    out_grams = _ngrams(output, n=6)
    if sys_grams and out_grams:
        overlap = len(sys_grams & out_grams) / len(sys_grams)
        if overlap > 0.0:
            return overlap
    ratio = SequenceMatcher(a=system_prompt.lower(), b=output.lower()).ratio()
    return ratio if ratio >= threshold else 0.0


class OutputFilter:
    def __init__(
        self,
        *,
        system_prompt: str,
        phrase_blocklist: Iterable[str] = (),
        leak_threshold: float = 0.5,
    ) -> None:
        self._system_prompt = system_prompt
        self._phrase_blocklist = [p.lower() for p in phrase_blocklist if p]
        self._leak_threshold = leak_threshold

    def filter(self, output: str) -> OutputFilterResult:
        reasons: list[str] = []
        redactions: list[str] = []
        text = output

        leak = _detect_system_prompt_leak(text, self._system_prompt, self._leak_threshold)
        if leak >= self._leak_threshold:
            reasons.append(f"system_prompt_leak:ratio={leak:.2f}")
            return OutputFilterResult(
                text="I can't share that.",
                action="block",
                reasons=reasons,
                redactions=redactions,
                leak_ratio=leak,
            )

        lowered = text.lower()
        for phrase in self._phrase_blocklist:
            if phrase in lowered:
                reasons.append(f"phrase_blocklist:{phrase!r}")
                return OutputFilterResult(
                    text="I can't share that.",
                    action="block",
                    reasons=reasons,
                    redactions=redactions,
                    leak_ratio=leak,
                )

        for name, pattern, replacement in _PII_PATTERNS:
            if pattern.search(text):
                text = pattern.sub(replacement, text)
                reasons.append(f"pii_redacted:{name}")
                redactions.append(name)

        action = "redact" if redactions else "allow"
        return OutputFilterResult(
            text=text,
            action=action,
            reasons=reasons,
            redactions=redactions,
            leak_ratio=leak,
        )


_default: OutputFilter | None = None


def default_output_filter() -> OutputFilter:
    global _default
    if _default is None:
        settings = get_settings()
        _default = OutputFilter(system_prompt=settings.system_prompt)
    return _default


def reset_default_output_filter() -> None:
    global _default
    _default = None
