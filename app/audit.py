from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Iterable, Iterator

from app.config import get_settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT    NOT NULL,
    session_id   TEXT    NOT NULL,
    direction    TEXT    NOT NULL,
    text         TEXT    NOT NULL,
    action       TEXT    NOT NULL,
    score        REAL    NOT NULL,
    reasons_json TEXT    NOT NULL,
    latency_ms   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit(session_id);
"""


@dataclass
class AuditRecord:
    id: int
    ts: datetime
    session_id: str
    direction: str
    text: str
    action: str
    score: float
    reasons: list[str]
    latency_ms: int


class AuditLog:
    def __init__(self, db_path: str | Path) -> None:
        self._is_memory = str(db_path) == ":memory:"
        if not self._is_memory:
            self._db_path: Path = Path(db_path)
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._db_path_str = str(self._db_path)
        else:
            self._db_path_str = ":memory:"
        self._lock = Lock()
        # :memory: databases are per-connection. Hold one persistent connection.
        self._persistent: sqlite3.Connection | None = (
            sqlite3.connect(":memory:", check_same_thread=False) if self._is_memory else None
        )
        if self._persistent is not None:
            self._persistent.row_factory = sqlite3.Row
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        if self._persistent is not None:
            return self._persistent
        conn = sqlite3.connect(self._db_path_str)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            if self._persistent is None:
                conn.close()

    def record(
        self,
        *,
        session_id: str,
        direction: str,
        text: str,
        action: str,
        score: float,
        reasons: Iterable[str],
        latency_ms: int,
    ) -> int:
        if direction not in {"input", "output"}:
            raise ValueError(f"invalid direction: {direction!r}")
        if action not in {"allow", "review", "block", "redact"}:
            raise ValueError(f"invalid action: {action!r}")
        ts = datetime.now(timezone.utc).isoformat()
        payload = (
            ts,
            session_id,
            direction,
            text,
            action,
            float(score),
            json.dumps(list(reasons)),
            int(latency_ms),
        )
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO audit (ts, session_id, direction, text, action, score, reasons_json, latency_ms) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    payload,
                )
                conn.commit()
                return int(cur.lastrowid)
            finally:
                if self._persistent is None:
                    conn.close()

    def recent(self, limit: int = 100) -> list[AuditRecord]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (int(limit),)
            ).fetchall()
        finally:
            if self._persistent is None:
                conn.close()
        return [_row_to_record(r) for r in rows]

    def stats(self, since_seconds: int | None = None) -> dict[str, int]:
        q = "SELECT action, COUNT(*) as n FROM audit"
        params: tuple = ()
        if since_seconds is not None:
            q += " WHERE ts >= datetime('now', ?)"
            params = (f"-{int(since_seconds)} seconds",)
        q += " GROUP BY action"
        conn = self._connect()
        try:
            rows = conn.execute(q, params).fetchall()
        finally:
            if self._persistent is None:
                conn.close()
        return {r["action"]: int(r["n"]) for r in rows}


def _row_to_record(r: sqlite3.Row) -> AuditRecord:
    return AuditRecord(
        id=int(r["id"]),
        ts=datetime.fromisoformat(r["ts"]),
        session_id=r["session_id"],
        direction=r["direction"],
        text=r["text"],
        action=r["action"],
        score=float(r["score"]),
        reasons=json.loads(r["reasons_json"]),
        latency_ms=int(r["latency_ms"]),
    )


_default: AuditLog | None = None


def default_audit_log() -> AuditLog:
    global _default
    if _default is None:
        _default = AuditLog(get_settings().audit_db)
    return _default


def reset_default_audit_log() -> None:
    global _default
    _default = None


@contextmanager
def in_memory_audit_log() -> Iterator[AuditLog]:
    yield AuditLog(":memory:")
