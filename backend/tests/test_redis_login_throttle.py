"""Phase 1 #1.13: Redis-backed login-throttle tests.

The per-email failed-login throttle gained an optional Redis backend
so a multi-instance manager deployment shares the failure counter
across replicas — without this, an attacker who lands their 11th
attempt on a different instance than the previous 10 sidesteps the
gate.

These tests inject a fakeredis client into `app.core.redis_client`
so the Redis path runs without a live container. The in-memory
fallback is covered separately in `test_login_throttle.py`.
"""

from __future__ import annotations

import pytest
from fakeredis import aioredis as fakeredis_aio


@pytest.fixture
async def fake_redis_singleton():
    """Install a fakeredis client into the module-level singleton so
    `_record_login_failure` / `_clear_login_failures` / `_is_login_blocked`
    take the Redis path."""
    from app.core import redis_client as redis_module

    prior = redis_module._client
    client = fakeredis_aio.FakeRedis(decode_responses=False)
    redis_module._client = client
    try:
        yield client
    finally:
        redis_module._client = prior
        await client.aclose()


async def test_redis_record_below_limit_does_not_block(fake_redis_singleton) -> None:
    """N-1 failures stay under the gate."""
    from app.api import auth as auth_api

    email = "throttle-redis-low@local"
    await auth_api._clear_login_failures(email)
    for _ in range(auth_api._LOGIN_FAIL_LIMIT - 1):
        blocked, _ = await auth_api._record_login_failure(email)
        assert blocked is False
    await auth_api._clear_login_failures(email)


async def test_redis_record_over_limit_blocks_with_retry_after(fake_redis_singleton) -> None:
    """The (limit+1)th failure flips the gate; retry-after is non-zero."""
    from app.api import auth as auth_api

    email = "throttle-redis-trip@local"
    await auth_api._clear_login_failures(email)
    blocked = False
    retry = 0
    for _ in range(auth_api._LOGIN_FAIL_LIMIT + 1):
        blocked, retry = await auth_api._record_login_failure(email)
    assert blocked is True
    assert retry >= 1
    # `_is_login_blocked` should report the same gate without
    # consuming a new attempt.
    assert await auth_api._is_login_blocked(email) is True
    await auth_api._clear_login_failures(email)


async def test_redis_clear_drops_strikes(fake_redis_singleton) -> None:
    """A successful login resets the bucket so the legitimate user
    isn't penalised on the next attempt."""
    from app.api import auth as auth_api

    email = "throttle-redis-clear@local"
    await auth_api._clear_login_failures(email)
    for _ in range(auth_api._LOGIN_FAIL_LIMIT):
        await auth_api._record_login_failure(email)
    await auth_api._clear_login_failures(email)
    blocked, _ = await auth_api._record_login_failure(email)
    assert blocked is False
    await auth_api._clear_login_failures(email)


async def test_redis_per_email_isolation(fake_redis_singleton) -> None:
    """One email's strike count doesn't lock out unrelated accounts."""
    from app.api import auth as auth_api

    email_a = "throttle-redis-a@local"
    email_b = "throttle-redis-b@local"
    await auth_api._clear_login_failures(email_a)
    await auth_api._clear_login_failures(email_b)
    for _ in range(auth_api._LOGIN_FAIL_LIMIT + 1):
        await auth_api._record_login_failure(email_a)
    assert await auth_api._is_login_blocked(email_a) is True
    blocked_b, _ = await auth_api._record_login_failure(email_b)
    assert blocked_b is False
    await auth_api._clear_login_failures(email_a)
    await auth_api._clear_login_failures(email_b)


async def test_redis_key_expires_after_window(fake_redis_singleton) -> None:
    """Each failure refreshes the key TTL so a quiet email's bucket
    eventually evicts without an explicit GC sweep."""
    from app.api import auth as auth_api

    email = "throttle-redis-ttl@local"
    await auth_api._clear_login_failures(email)
    await auth_api._record_login_failure(email)
    key = auth_api._redis_login_key(email)
    ttl = await fake_redis_singleton.ttl(key)
    # Expect the TTL within window+slack (we set window + 60).
    assert 0 < ttl <= auth_api._LOGIN_FAIL_WINDOW_S + 60
    await auth_api._clear_login_failures(email)


async def test_redis_two_replicas_share_the_counter(fake_redis_singleton) -> None:
    """Hit `_record_login_failure` LIMIT times while pretending to be
    instance A, then once more pretending to be instance B (same
    underlying fakeredis). The second instance sees the gate already
    closed — which is exactly the property the in-memory store can't
    provide.

    In practice we don't have two manager instances in this test
    process; the shared fakeredis IS the shared state, so calling
    the function LIMIT+1 times in succession is the cluster-wide
    replay every replica would observe.
    """
    from app.api import auth as auth_api

    email = "throttle-redis-shared@local"
    await auth_api._clear_login_failures(email)
    # First N from "instance A".
    for _ in range(auth_api._LOGIN_FAIL_LIMIT):
        blocked, _ = await auth_api._record_login_failure(email)
        assert blocked is False
    # (N+1)th from "instance B" — would slip through the in-memory
    # gate if each instance had its own dict, but here it's caught.
    blocked, _ = await auth_api._record_login_failure(email)
    assert blocked is True
    await auth_api._clear_login_failures(email)
