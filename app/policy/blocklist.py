from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml


@dataclass
class Blocklist:
    patterns: list[re.Pattern[str]]

    def match(self, text: str) -> str | None:
        if not text:
            return None
        for p in self.patterns:
            m = p.search(text)
            if m:
                return m.group(0)
        return None


def load_blocklist(path: str | Path) -> Blocklist:
    path = Path(path)
    if not path.exists():
        return Blocklist(patterns=[])
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    patterns: Iterable[str] = raw.get("patterns") or []
    compiled = [re.compile(p, re.IGNORECASE | re.UNICODE) for p in patterns]
    return Blocklist(patterns=compiled)
