"""Shared Redis client for HA primitives.

The manager has three pieces of state that, in a single-instance
deployment, can live in process memory:

* Per-identity API rate-limit buckets (`app/core/rate_limit.py`)
* Per-email failed-login counter (`app/api/auth.py`)
* Newly-inserted alert fan-out queue (`app/services/alert_broker.py`)

When two or more manager instances run behind a load balancer, each of
those pieces needs to be shared across processes — otherwise an
attacker who lands their 11th login attempt on a different instance
than the previous 10 sidesteps the throttle, the rate limiter caps
each instance independently (effectively multiplying the quota by N),
and SSE subscribers only see alerts the poll on *their* instance
happened to read first.

This module owns the singleton `redis.asyncio.Redis` connection used
by all three. It returns `None` when `VIGIL_REDIS_URL` is empty (the
default), and every consumer treats that as the signal to fall back
to its in-memory implementation. That's why this is a runtime opt-in
rather than a hard dependency: solo / small-team deployments keep
working with the single-instance defaults; multi-instance operators
flip the URL once and all three primitives transparently swap stores.
"""

from __future__ import annotations

from typing import Any

import structlog

log = structlog.get_logger()


_client: Any = None
"""Module-level singleton. Populated by `init_redis_client()` from the
FastAPI lifespan; cleared by `close_redis_client()` at shutdown.

Type is `redis.asyncio.Redis | None` but we keep it loose so callers
that import this module don't pay for the `redis` import when the
feature is disabled."""


async def init_redis_client(url: str) -> Any:
    """Open a Redis connection pool. Returns the client, or ``None`` if
    ``url`` is empty (the disabled / single-instance config).

    Idempotent: calling twice with the same URL returns the existing
    client; calling with an empty URL after a previous init is a noop
    that leaves the existing client in place so the lifespan's
    enter/exit pairing stays balanced even when settings get mutated
    by a test fixture.
    """
    global _client
    if not url:
        return _client
    if _client is not None:
        return _client
    # Imported lazily so the dependency is only required when actually
    # configured. Operators that run single-instance never need to
    # install redis.
    from redis.asyncio import Redis, from_url

    # `decode_responses=False` keeps the API a pure bytes-in / bytes-out
    # shape. We pay a `.decode()` in the few places we need strings,
    # but we never have to second-guess what `INCR` returned. The
    # Lua-scripted rate limiter also returns an int either way.
    _client = from_url(url, decode_responses=False)
    # Verify the connection up-front so a misconfigured URL fails the
    # lifespan boot rather than the first request that lands on the
    # rate limiter. PING is cheap; if Redis is reachable we're done,
    # otherwise the exception propagates to `lifespan()`.
    await _client.ping()
    log.info("redis.connected", url_host=_redact(url))
    assert isinstance(_client, Redis)
    return _client


async def close_redis_client() -> None:
    """Close the pool. Safe to call multiple times."""
    global _client
    if _client is None:
        return
    try:
        await _client.aclose()
    except Exception:  # noqa: BLE001
        # Shutdown path — we already logged. Don't mask the original
        # exit reason with a tear-down error.
        log.exception("redis.close_failed")
    _client = None


def redis_client() -> Any:
    """Return the current Redis client (or ``None`` if disabled).

    Consumers branch on the return value:

        client = redis_client()
        if client is None:
            return self._inmemory_path(...)
        return await self._redis_path(client, ...)
    """
    return _client


def _redact(url: str) -> str:
    """Strip the password from a `redis://user:pass@host:port/db` URL
    for log output. Falls back to the original string if there's no
    auth segment."""
    if "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    auth, _, hostpart = rest.partition("@")
    if ":" in auth:
        user, _, _pw = auth.partition(":")
        return f"{scheme}://{user}:***@{hostpart}"
    return url
