import asyncio
import time
from collections import defaultdict, deque
from typing import DefaultDict, Deque, Optional
from fastapi import Request
from app.config import settings
from app.core.errors import RateLimitExceededException


class SlidingWindowRateLimiter:
    """In-memory thread-safe sliding-window rate limiter."""

    def __init__(self, requests_per_minute: int = 60, window_seconds: int = 60):
        self.requests_per_minute = requests_per_minute
        self.window_seconds = window_seconds
        self._clients: DefaultDict[str, Deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()
        self._last_cleanup = time.time()

    async def check_rate_limit(self, identifier: str) -> None:
        """Check whether the given client identifier exceeds the allowed quota."""
        if not settings.ARGUS_RATE_LIMIT_ENABLED:
            return

        now = time.time()
        window_start = now - self.window_seconds

        async with self._lock:
            # Periodic cleanup of stale client buckets every 5 minutes
            if now - self._last_cleanup > 300:
                self._cleanup_stale(window_start)
                self._last_cleanup = now

            timestamps = self._clients[identifier]

            # Remove timestamps outside the sliding window
            while timestamps and timestamps[0] < window_start:
                timestamps.popleft()

            if len(timestamps) >= self.requests_per_minute:
                oldest_in_window = timestamps[0]
                retry_after = int(max(1, self.window_seconds - (now - oldest_in_window)))
                raise RateLimitExceededException(
                    detail=f"Rate limit of {self.requests_per_minute} req/min exceeded. Retry after {retry_after}s.",
                    retry_after=retry_after,
                )

            # Record this request timestamp
            timestamps.append(now)

    def _cleanup_stale(self, threshold: float) -> None:
        stale_keys = [k for k, v in self._clients.items() if not v or v[-1] < threshold]
        for k in stale_keys:
            del self._clients[k]


rate_limiter = SlidingWindowRateLimiter(
    requests_per_minute=settings.ARGUS_RATE_LIMIT_REQUESTS_PER_MINUTE,
    window_seconds=60,
)


async def rate_limit_dependency(request: Request, client_key: Optional[str] = None):
    """FastAPI dependency for rate limiting by API key or Client IP."""
    client_id = client_key or (request.client.host if request.client else "unknown_client")
    await rate_limiter.check_rate_limit(client_id)
