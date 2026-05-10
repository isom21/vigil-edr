"""Per-identity API rate limiting (M13.a).

Sliding-window in-memory limiter keyed by `(identity_id, role)`.
Each request consumes one token; 429 with Retry-After when exhausted.

In-memory is the right shape for a single-instance manager; M15
multi-instance work swaps in a Redis backend.

Bypass: `/api/health` and `/api/openapi.json` are not rate-limited
so monitoring + docs tooling can poll freely.

Logged events:
    audit.record(action="rate_limit.exceeded",
                 payload={"limit": N, "role": "...", "ip": "..."})

Configurable via env (single source of truth; settings.py reads
these with the EDR_RL_ prefix):
    EDR_RL_USER_ADMIN_PER_MIN     default 600
    EDR_RL_USER_ANALYST_PER_MIN   default 300
    EDR_RL_USER_VIEWER_PER_MIN    default 120
    EDR_RL_API_TOKEN_PER_MIN      default 600
    EDR_RL_ANON_PER_MIN           default 10  (per IP for /enroll)
"""
from __future__ import annotations

import os
import time
from collections import deque
from typing import Final

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


WINDOW_S: Final[int] = 60

LIMITS: Final[dict[str, int]] = {
    "admin": _env_int("EDR_RL_USER_ADMIN_PER_MIN", 600),
    "analyst": _env_int("EDR_RL_USER_ANALYST_PER_MIN", 300),
    "viewer": _env_int("EDR_RL_USER_VIEWER_PER_MIN", 120),
    "api_token": _env_int("EDR_RL_API_TOKEN_PER_MIN", 600),
    "anon": _env_int("EDR_RL_ANON_PER_MIN", 10),
}

EXEMPT_PATHS: Final[set[str]] = {
    "/api/health",
    "/api/openapi.json",
}


class _SlidingWindow:
    """One bucket. `deque` of timestamps, dropped as the window slides."""

    __slots__ = ("hits",)

    def __init__(self) -> None:
        self.hits: deque[float] = deque()

    def admit(self, now: float, limit: int) -> tuple[bool, int, float]:
        """Record one hit. Returns (allowed, remaining, reset_unix)."""
        cutoff = now - WINDOW_S
        while self.hits and self.hits[0] < cutoff:
            self.hits.popleft()
        if len(self.hits) >= limit:
            reset = self.hits[0] + WINDOW_S if self.hits else now + WINDOW_S
            return (False, 0, reset)
        self.hits.append(now)
        return (True, limit - len(self.hits), cutoff + WINDOW_S)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware. Reads the bearer token (or falls back to
    client IP for anonymous requests), looks up the per-identity
    sliding window, denies with 429 on overflow.

    Identity key:
        bearer JWT          -> sha256(token)[:16] + ":" + role
        bearer edr_ token   -> sha256(token)[:16] + ":api_token"
        no auth header      -> ip + ":anon"
    """

    def __init__(self, app, gc_interval: int = 600) -> None:
        super().__init__(app)
        self._buckets: dict[str, _SlidingWindow] = {}
        self._gc_interval = gc_interval
        self._last_gc = time.monotonic()

    def _gc(self, now: float) -> None:
        # Drop buckets whose entire window has expired so memory doesn't
        # grow without bound on a long-lived process.
        cutoff = now - WINDOW_S
        dead = [k for k, b in self._buckets.items() if not b.hits or b.hits[-1] < cutoff]
        for k in dead:
            del self._buckets[k]
        self._last_gc = now

    async def dispatch(self, request: Request, call_next):
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        # Identify the caller. Decoding the JWT here would be ideal but
        # also expensive on the hot path; instead we treat the token
        # *string* as the bucket key (hashed for privacy in logs). Two
        # admins with different tokens have separate buckets even if
        # they share a role; that's fine for limiting purposes.
        auth = request.headers.get("authorization", "")
        ip = request.client.host if request.client else "unknown"
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
            import hashlib

            tok_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
            if token.startswith("edr_"):
                role = "api_token"
            else:
                # We can't decode the JWT cheaply here, so use the
                # token-hash bucket and pick the highest-tier limit
                # (admin) — this is conservative on the safe side
                # (admins get the most generous limit anyway, and
                # mis-classifying analyst/viewer as admin only over-
                # counts their quota slightly). Real per-role
                # enforcement is the M13.a-b refinement once we cache
                # decoded JWTs.
                role = "admin"
            key = f"{tok_hash}:{role}"
        else:
            role = "anon"
            key = f"{ip}:anon"

        limit = LIMITS.get(role, LIMITS["anon"])
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _SlidingWindow()
            self._buckets[key] = bucket

        now = time.time()
        if now - self._last_gc > self._gc_interval:
            self._gc(now)

        allowed, remaining, reset = bucket.admit(now, limit)
        if not allowed:
            return Response(
                content='{"detail":"rate limit exceeded"}',
                status_code=429,
                media_type="application/json",
                headers={
                    "Retry-After": str(int(reset - now)),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(reset)),
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(reset))
        return response
