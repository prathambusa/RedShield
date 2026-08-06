from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml


@dataclass
class Allowlist:
    patterns: list[re.Pattern[str]]

    def matches(self, text: str) -> bool:
        if not text:
            return False
        return any(p.search(text) for p in self.patterns)


def load_allowlist(path: str | Path) -> Allowlist:
    path = Path(path)
    if not path.exists():
        return Allowlist(patterns=[])
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    patterns: Iterable[str] = raw.get("patterns") or []
    compiled = [re.compile(p, re.IGNORECASE | re.UNICODE) for p in patterns]
    return Allowlist(patterns=compiled)
