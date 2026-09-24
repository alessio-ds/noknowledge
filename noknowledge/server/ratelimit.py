"""In-memory sliding-window rate limiter.

Keyed by client IP. A single relay process is the deployment target, so an
in-process limiter is sufficient; a multi-process deployment would move this to
the database or a shared cache.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = max(0, limit)
        self.window = float(window_seconds)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        if self.limit == 0:
            return True
        current = time.monotonic() if now is None else now
        cutoff = current - self.window
        with self._lock:
            events = self._events[key]
            while events and events[0] < cutoff:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(current)
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


class RateLimiters:
    """The set of limits a relay applies, grouped by operation."""

    def __init__(
        self,
        creates_per_hour: int,
        writes_per_minute: int,
        bundles_per_hour: int,
    ) -> None:
        self.create = SlidingWindowLimiter(creates_per_hour, 3600)
        self.write = SlidingWindowLimiter(writes_per_minute, 60)
        self.bundle = SlidingWindowLimiter(bundles_per_hour, 3600)

    def reset(self) -> None:
        self.create.reset()
        self.write.reset()
        self.bundle.reset()