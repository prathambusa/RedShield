from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock


class RateLimiter:
    def __init__(self, max_requests: int = 10000, window_seconds: int = 60) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._sessions: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def is_allowed(self, session_id: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._sessions[session_id]
            while q and q[0] <= now - self._window:
                q.popleft()
            if len(q) >= self._max:
                return False
            q.append(now)
            return True
