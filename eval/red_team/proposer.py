from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

_SYSTEM = """You are a security rule engineer for an LLM gateway that uses Python regex patterns to block prompt-injection attacks.

A known attack was caught by the existing detector. A mutated variant of that attack was NOT caught. Your job: suggest a new regex pattern to catch the variant without causing false-positives on normal customer-support queries (order status, refunds, product questions, shipping inquiries).

Rules for a good regex:
- Case-insensitive (the system applies re.IGNORECASE automatically)
- Target the distinctive phrasing of the bypass, not overly broad words like "show" or "tell"
- Should NOT match: "where is my order", "can I get a refund", "do you have this in blue"

Return ONLY a JSON object, no markdown fences:
{"pattern":"<Python re pattern>","description":"<one sentence explaining what it catches>","confidence":0.0-1.0,"false_positive_risk":"low|medium|high"}"""


@dataclass
class RuleProposal:
    pattern: str
    description: str
    confidence: float
    false_positive_risk: str
    triggered_by: list[str] = field(default_factory=list)


def propose(
    seed_text: str,
    bypass_text: str,
    strategy: str,
    seed_id: str,
    completion_fn=None,
) -> RuleProposal | None:
    user = (
        f"Original attack (CAUGHT by detector):\n{seed_text}\n\n"
        f"Bypass variant (NOT caught):\n{bypass_text}\n\n"
        f"Evasion strategy used: {strategy}"
    )

    if completion_fn is not None:
        raw = completion_fn(_SYSTEM, user)
    else:
        from app.config import get_settings
        from app.llm.openai_client import chat_json

        raw = chat_json(
            model=get_settings().classifier_model,
            system=_SYSTEM,
            user=user,
            temperature=0.0,
        )

    text = _FENCE_RE.sub("", raw).strip()
    try:
        data = json.loads(text)
        return RuleProposal(
            pattern=str(data.get("pattern", "")),
            description=str(data.get("description", "")),
            confidence=float(data.get("confidence", 0.0)),
            false_positive_risk=str(data.get("false_positive_risk", "unknown")),
            triggered_by=[seed_id],
        )
    except Exception:
        return None
