"""
API Rate Limiting Infrastructure (STEP 12B)

This module defines:
1. InMemoryRateLimiter: Thread-safe sliding window rate limiter per client key/identifier.
2. set_rate_limiter / get_rate_limiter: Composition root dependency providers.
3. require_rate_limit: FastAPI dependency enforcing rate limiting on scan-triggering endpoints.

SECURITY INVARIANTS:
1. Evaluates AFTER authentication (`require_api_key`), so invalid/unauthenticated requests (401)
   do not consume rate limiter quotas for valid client API keys.
2. Quotas are tracked independently per API key (client isolation).
3. Exceeding quota returns safe HTTP 429 Too Many Requests with Retry-After header.
4. Allows disabling rate limiting when rate limit is set to 0 or None.
"""

from collections import defaultdict
import math
import threading
import time
from typing import Dict, List, Optional, Tuple

from fastapi import HTTPException, Request, status

from app.security.auth import extract_api_key


class InMemoryRateLimiter:
    """
    Thread-safe sliding window in-memory rate limiter.
    """

    def __init__(
        self,
        requests_per_window: int = 60,
        window_seconds: float = 60.0,
        enabled: bool = True,
    ) -> None:
        """
        Initialize InMemoryRateLimiter.

        Args:
            requests_per_window (int): Maximum allowed requests within sliding window.
            window_seconds (float): Duration of sliding window in seconds.
            enabled (bool): Whether rate limiting is active.
        """
        self.requests_per_window = max(0, requests_per_window)
        self.window_seconds = max(0.1, window_seconds)
        self.enabled = enabled and self.requests_per_window > 0

        self._history: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check_and_record(self, client_id: str, now: Optional[float] = None) -> Tuple[bool, float]:
        """
        Check if client_id exceeds rate limit and record current request timestamp.

        Args:
            client_id (str): Unique client identifier (e.g. API key or client IP).
            now (Optional[float]): Optional current timestamp (defaults to time.time()).

        Returns:
            Tuple[bool, float]: (is_rate_limited, retry_after_seconds)
        """
        if not self.enabled or not client_id:
            return False, 0.0

        if now is None:
            now = time.time()

        cutoff = now - self.window_seconds

        with self._lock:
            timestamps = self._history[client_id]

            # Prune timestamps older than window cutoff
            valid_timestamps = [ts for ts in timestamps if ts > cutoff]
            self._history[client_id] = valid_timestamps

            if len(valid_timestamps) >= self.requests_per_window:
                # Rate limit exceeded: calculate retry-after based on oldest active timestamp
                oldest = valid_timestamps[0]
                retry_after = max(0.1, (oldest + self.window_seconds) - now)
                return True, retry_after

            # Quota available: record request
            valid_timestamps.append(now)
            return False, 0.0

    def clear(self) -> None:
        """
        Clear tracked rate limiting history (testing utility).
        """
        with self._lock:
            self._history.clear()


# Global rate limiter instance for FastAPI dependency injection
_rate_limiter_instance: Optional[InMemoryRateLimiter] = None


def set_rate_limiter(limiter: InMemoryRateLimiter) -> None:
    """
    Set global InMemoryRateLimiter instance in composition root.
    """
    global _rate_limiter_instance
    _rate_limiter_instance = limiter


def get_rate_limiter() -> InMemoryRateLimiter:
    """
    Dependency provider returning configured InMemoryRateLimiter instance.
    """
    if _rate_limiter_instance is None:
        return InMemoryRateLimiter(enabled=False)
    return _rate_limiter_instance


def require_rate_limit(request: Request) -> None:
    """
    FastAPI route dependency enforcing rate limiting.

    Raises:
        HTTPException(429): If client exceeds allowed rate limit.
    """
    limiter = get_rate_limiter()
    if not limiter.enabled:
        return

    # Derive client_id from API key header, or fallback to client host IP
    client_id = extract_api_key(request)
    if not client_id and request.client:
        client_id = request.client.host
    if not client_id:
        client_id = "anonymous"

    is_limited, retry_after = limiter.check_and_record(client_id)
    if is_limited:
        retry_seconds = math.ceil(retry_after)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
            headers={"Retry-After": str(retry_seconds)},
        )
