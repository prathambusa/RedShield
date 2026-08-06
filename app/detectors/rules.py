from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

from app.config import get_settings

VALID_TAXONOMIES = {
    "instruction_override",
    "jailbreak",
    "prompt_leak",
    "refusal_bypass",
    "obfuscation",
    "pii_extraction",
    "excessive_agency",
    "indirect_injection",
}


@dataclass(frozen=True)
class Hit:
    rule_id: str
    taxonomy: str
    severity: int
    matched_span: str
    reason: str


@dataclass
class _CompiledRule:
    rule_id: str
    taxonomy: str
    severity: int
    description: str
    regex: re.Pattern[str]


class RuleMatcher:
    def __init__(self, rules: Iterable[_CompiledRule] | None = None) -> None:
        self._rules: list[_CompiledRule] = list(rules) if rules is not None else []

    @classmethod
    def from_yaml(cls, path: str | Path) -> "RuleMatcher":
        path = Path(path)
        if not path.exists():
            return cls([])
        with path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or []
        compiled: list[_CompiledRule] = []
        for entry in raw:
            rule_id = entry["id"]
            taxonomy = entry["taxonomy"]
            if taxonomy not in VALID_TAXONOMIES:
                raise ValueError(f"Rule {rule_id}: invalid taxonomy {taxonomy!r}")
            severity = int(entry["severity"])
            if not 1 <= severity <= 10:
                raise ValueError(f"Rule {rule_id}: severity {severity} out of range")
            pattern = entry["pattern"]
            description = entry.get("description", "")
            regex = re.compile(pattern, re.IGNORECASE | re.UNICODE)
            compiled.append(
                _CompiledRule(
                    rule_id=rule_id,
                    taxonomy=taxonomy,
                    severity=severity,
                    description=description,
                    regex=regex,
                )
            )
        return cls(compiled)

    def match(self, text: str) -> list[Hit]:
        if not text:
            return []
        hits: list[Hit] = []
        for rule in self._rules:
            m = rule.regex.search(text)
            if m:
                span = m.group(0)[:200]
                hits.append(
                    Hit(
                        rule_id=rule.rule_id,
                        taxonomy=rule.taxonomy,
                        severity=rule.severity,
                        matched_span=span,
                        reason=rule.description or f"matched {rule.rule_id}",
                    )
                )
        return hits

    def __len__(self) -> int:
        return len(self._rules)


_default: RuleMatcher | None = None


def default_matcher() -> RuleMatcher:
    global _default
    if _default is None:
        _default = RuleMatcher.from_yaml(get_settings().patterns_file)
    return _default


def reset_default_matcher() -> None:
    global _default
    _default = None


def match(text: str) -> list[Hit]:
    return default_matcher().match(text)
