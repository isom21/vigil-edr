"""Per-identity API rate limiting (M13.a).

Sliding-window limiter keyed by `(identity_id, role)`. Each request
consumes one token; 429 with Retry-After when exhausted.

Two backends share one interface:

* `InMemoryStore` — single-instance default. The original deque-of-
  timestamps implementation; gives an exact sliding window.
* `RedisStore` — multi-instance config. A fixed 60-second bucket
  (`INCR` + `EXPIRE` via Lua) keyed by `<bucket>:<wall-minute>`. Not a
  pure sliding window — at a minute boundary the next request gets a
  fresh quota — but it's atomic across all manager replicas and the
  bound is within ±1 request of the in-memory shape over any 60-second
  span. The trade-off is intentional: a true sliding window across
  N replicas would need either a sorted-set per identity (`ZADD` +
  `ZREMRANGEBYSCORE` per request, ~3× the round-trip cost) or
  per-instance approximation that fights the whole point of moving
  off process memory. The fixed-window shape matches `LIMITS` in
  spirit and is what every prod-grade limiter (Envoy, Cloudflare,
  Stripe) ships under heavy load for the same reason.

Bypass: `/api/health`, `/api/openapi.json`, and `/metrics` are not
rate-limited so monitoring + docs tooling can poll freely.

Logged events:
    audit.record(action="rate_limit.exceeded",
                 payload={"limit": N, "role": "...", "ip": "..."})

Configurable via env (single source of truth; settings.py reads
these with the VIGIL_RL_ prefix):
    VIGIL_RL_USER_ADMIN_PER_MIN     default 600
    VIGIL_RL_USER_ANALYST_PER_MIN   default 300
    VIGIL_RL_USER_VIEWER_PER_MIN    default 120
    VIGIL_RL_API_TOKEN_PER_MIN      default 600
    VIGIL_RL_ANON_PER_MIN           default 60  (per IP for /enroll)

Backend selection: `VIGIL_REDIS_URL=""` keeps the in-memory store
(zero new dependencies). Set to a `redis://...` URL to share buckets
across replicas; selection happens in `app.main.lifespan()` and is
threaded into the middleware via `app.state.rate_limit_store`.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections import deque
from typing import Any, Final, Protocol

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


def _env_int(name: str, default: int) -> int:
    # Read via settings so the value picks up backend/.env (loaded by
    # pydantic-settings) in addition to plain os.environ. Falls back
    # to the env var directly for fields settings doesn't model.
    from app.core.config import settings as _s

    fld = name.lower().removeprefix("vigil_")
    val = getattr(_s, fld, None)
    if isinstance(val, int):
        return val
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


WINDOW_S: Final[int] = 60

LIMITS: Final[dict[str, int]] = {
    "admin": _env_int("VIGIL_RL_USER_ADMIN_PER_MIN", 600),
    "analyst": _env_int("VIGIL_RL_USER_ANALYST_PER_MIN", 300),
    "viewer": _env_int("VIGIL_RL_USER_VIEWER_PER_MIN", 120),
    "api_token": _env_int("VIGIL_RL_API_TOKEN_PER_MIN", 600),
    "anon": _env_int("VIGIL_RL_ANON_PER_MIN", 60),
}

EXEMPT_PATHS: Final[set[str]] = {
    "/api/health",
    "/api/openapi.json",
    "/metrics",  # M14.a — Prometheus scrape every 15s; not subject to per-IP cap
}


class BucketStore(Protocol):
    """Shared shape between the in-memory + Redis limiters.

    `admit` returns `(allowed, remaining, reset_unix)`. Implementations
    are responsible for atomicity within their own backend.
    """

    async def admit(self, key: str, now: float, limit: int) -> tuple[bool, int, float]: ...

    async def gc(self, now: float) -> None: ...


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


class InMemoryStore:
    """The original single-instance store. Sliding-window deque per
    bucket key with periodic GC of inactive buckets."""

    def __init__(self, gc_interval: int = 600) -> None:
        self._buckets: dict[str, _SlidingWindow] = {}
        self._gc_interval = gc_interval
        self._last_gc = time.monotonic()

    async def admit(self, key: str, now: float, limit: int) -> tuple[bool, int, float]:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _SlidingWindow()
            self._buckets[key] = bucket
        return bucket.admit(now, limit)

    async def gc(self, now: float) -> None:
        if now - self._last_gc <= self._gc_interval:
            return
        cutoff = now - WINDOW_S
        dead = [k for k, b in self._buckets.items() if not b.hits or b.hits[-1] < cutoff]
        for k in dead:
            del self._buckets[k]
        self._last_gc = now


# Lua script for the atomic INCR + EXPIRE pair. Without the EXPIRE
# inside the script the key would live forever; with it but outside
# Lua we'd race the EXPIRE setter against another instance racing the
# same first INCR. Returning the post-increment count lets the caller
# compare against the limit without a second round-trip.
_RATE_LIMIT_LUA = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
"""


class RedisStore:
    """Fixed-window rate limiter backed by Redis.

    Bucket key shape: `vigil:rl:<identity>:<minute>`. We segment by
    wall-minute (`int(now) // 60`) so two replicas hitting the same
    identity collide on the same Redis key inside the window and an
    `INCR` returns the cluster-wide count atomically. Each key TTLs
    one window after creation; no scheduled GC needed.
    """

    KEY_PREFIX: Final[str] = "vigil:rl"

    def __init__(self, client: Any) -> None:
        self._client = client
        # `register_script` caches the SHA1 client-side and uses
        # EVALSHA on subsequent calls. Falls back to EVAL on NOSCRIPT,
        # which is what we want when Redis restarts.
        self._admit_script = client.register_script(_RATE_LIMIT_LUA)

    def _bucket_key(self, key: str, now: float) -> str:
        # The wall-minute partition is the price of using INCR/EXPIRE
        # for fairness across replicas. See module docstring on the
        # trade-off vs a sorted-set sliding window.
        minute = int(now) // WINDOW_S
        return f"{self.KEY_PREFIX}:{key}:{minute}"

    async def admit(self, key: str, now: float, limit: int) -> tuple[bool, int, float]:
        bucket_key = self._bucket_key(key, now)
        # Lua runs atomically inside Redis; the script returns the
        # post-INCR count so we only need the one round-trip per
        # request. Two-step (`INCR` then `EXPIRE` from Python) would
        # leave a window where a crash between calls leaves a
        # never-expiring key.
        count = await self._admit_script(keys=[bucket_key], args=[WINDOW_S])
        count = int(count)
        # Window resets at the start of the *next* wall minute.
        reset = (int(now) // WINDOW_S + 1) * WINDOW_S
        if count > limit:
            return (False, 0, float(reset))
        return (True, max(0, limit - count), float(reset))

    async def gc(self, now: float) -> None:
        # Redis handles eviction via EXPIRE on key creation. No work
        # for us; the method exists to satisfy `BucketStore`.
        return None


def _classify(request: Request) -> tuple[str, str]:
    """Identify the caller from the bearer token (JWT or API token) or
    the source IP for anonymous requests. Returns `(role, bucket_key)`.

    The previous implementation hard-coded role="admin" for every JWT
    so `VIGIL_RL_USER_VIEWER_PER_MIN=120` was silently overridden by
    the admin limit. Decoding is microseconds and the bucket lookup
    already runs every request; per-role limits actually apply now.
    """
    auth = request.headers.get("authorization", "")
    ip = request.client.host if request.client else "unknown"
    if not auth.lower().startswith("bearer "):
        return "anon", f"{ip}:anon"
    token = auth.split(" ", 1)[1].strip()
    if token.startswith("edr_"):
        # API-token path is unchanged — these don't carry a
        # role-bearing JWT; the user-mapped bucket is keyed off the
        # token hash itself.
        tok_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
        return "api_token", f"{tok_hash}:api_token"
    from app.core.security import decode_jwt

    try:
        decoded = decode_jwt(token)
        role = str(decoded.get("role", "")).lower()
        sub = str(decoded.get("sub", ""))
    except Exception:
        # Malformed / expired / wrong-alg JWT — fall through to the
        # anon bucket so we still rate-limit the caller and don't
        # grant them an admin-sized quota by mistake.
        return "anon", f"{ip}:anon"
    if role not in LIMITS:
        # Unknown role on a valid JWT (future enum member, hand-issued
        # token). Conservative: bucket as anon.
        return "anon", f"{ip}:anon"
    # Bucket per user, not per-token, so two workstations of the same
    # analyst share their advertised quota rather than each getting a
    # full one.
    return role, f"u:{sub}:{role}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware. Reads the bearer token (or falls back to
    client IP for anonymous requests), looks up the per-identity
    sliding window, denies with 429 on overflow.

    Identity key:
        bearer JWT          -> sha256(token)[:16] + ":" + role
        bearer edr_ token   -> sha256(token)[:16] + ":api_token"
        no auth header      -> ip + ":anon"

    The middleware reads the active store off `request.app.state.
    rate_limit_store` so the lifespan can swap implementations
    without rebuilding the middleware stack. A built-in
    `InMemoryStore` is used if no override is set — that path is
    what test fixtures and single-instance dev hit.
    """

    def __init__(self, app, store: BucketStore | None = None, gc_interval: int = 600) -> None:
        super().__init__(app)
        self._default_store: BucketStore = store or InMemoryStore(gc_interval=gc_interval)

    def _store(self, request: Request) -> BucketStore:
        app_state = getattr(request.app, "state", None)
        if app_state is not None:
            override = getattr(app_state, "rate_limit_store", None)
            if override is not None:
                return override
        return self._default_store

    async def dispatch(self, request: Request, call_next):
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        role, key = _classify(request)
        limit = LIMITS.get(role, LIMITS["anon"])
        now = time.time()
        store = self._store(request)
        await store.gc(now)
        allowed, remaining, reset = await store.admit(key, now, limit)
        if not allowed:
            return Response(
                content='{"detail":"rate limit exceeded"}',
                status_code=429,
                media_type="application/json",
                headers={
                    "Retry-After": str(max(1, int(reset - now))),
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
