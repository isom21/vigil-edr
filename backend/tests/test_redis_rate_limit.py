"""Phase 1 #1.13: Redis-backed rate limiter parity tests.

The HA build of the rate limiter swaps the in-memory deque-of-
timestamps store for a Redis-backed fixed-minute window via Lua
`INCR + EXPIRE`. These tests run against `fakeredis.aioredis` so the
backend test suite doesn't need a live Redis container — fakeredis
implements EVAL/EVALSHA + INCR + EXPIRE + pipelines, which is enough
to exercise the script and the bucket math.

Coverage:
* `InMemoryStore`: the original sliding-window deque is preserved
  unchanged for the single-instance default.
* `RedisStore.admit`: returns `(allowed=True, remaining=N-1, reset)`
  on the first hit and counts down deterministically.
* `RedisStore.admit`: trips to 429 on the (limit + 1)th call inside
  the same wall-minute.
* `RedisStore.admit`: a fresh wall-minute resets the bucket (we mock
  `now` so we don't sleep through 60 seconds in CI).
* `RedisStore` re-uses the EVALSHA path on the second call — the Lua
  script is registered once and cached client-side.
"""

from __future__ import annotations

import pytest
from fakeredis import aioredis as fakeredis_aio


@pytest.fixture
async def fake_redis():
    """Per-test fakeredis client. Server state is in-process, so
    each fixture gets a fresh keyspace."""
    client = fakeredis_aio.FakeRedis(decode_responses=False)
    yield client
    await client.aclose()


async def test_inmemory_admit_returns_remaining() -> None:
    """The single-instance default counts down the way the original
    deque-based store did."""
    from app.core.rate_limit import InMemoryStore

    store = InMemoryStore()
    allowed_1, remaining_1, _ = await store.admit("k", 1.0, limit=3)
    allowed_2, remaining_2, _ = await store.admit("k", 1.1, limit=3)
    allowed_3, remaining_3, _ = await store.admit("k", 1.2, limit=3)
    assert allowed_1 and allowed_2 and allowed_3
    assert remaining_1 == 2
    assert remaining_2 == 1
    assert remaining_3 == 0


async def test_inmemory_admit_blocks_over_limit() -> None:
    from app.core.rate_limit import InMemoryStore

    store = InMemoryStore()
    for _ in range(3):
        allowed, _, _ = await store.admit("k", 1.0, limit=3)
        assert allowed
    allowed, remaining, _ = await store.admit("k", 1.0, limit=3)
    assert allowed is False
    assert remaining == 0


async def test_redis_admit_first_call_allowed(fake_redis) -> None:
    """First request in a fresh bucket succeeds and the remaining
    count reflects the post-increment state."""
    from app.core.rate_limit import RedisStore

    store = RedisStore(fake_redis)
    allowed, remaining, reset = await store.admit("user:42", now=120.0, limit=5)
    assert allowed is True
    assert remaining == 4
    # Reset is the start of the next wall-minute window. now=120 is
    # exactly the start of minute 2, so the next window starts at 180.
    assert reset == 180.0


async def test_redis_admit_blocks_over_limit(fake_redis) -> None:
    """Bucket trips to 429 on the (limit + 1)th call inside the same
    wall-minute."""
    from app.core.rate_limit import RedisStore

    store = RedisStore(fake_redis)
    now = 120.0
    for i in range(3):
        allowed, remaining, _ = await store.admit("user:42", now=now, limit=3)
        assert allowed is True, f"call {i + 1} should be allowed"
    allowed, remaining, _ = await store.admit("user:42", now=now, limit=3)
    assert allowed is False
    assert remaining == 0


async def test_redis_admit_new_minute_resets_bucket(fake_redis) -> None:
    """The fixed-window shape means the count resets at each wall-
    minute boundary. We don't sleep in the test — we just hand the
    store a `now` from the next window."""
    from app.core.rate_limit import RedisStore

    store = RedisStore(fake_redis)
    # Fill the bucket in minute 2.
    for _ in range(3):
        await store.admit("user:42", now=120.0, limit=3)
    # The (limit+1)th call inside the same minute is blocked.
    allowed, _, _ = await store.admit("user:42", now=120.0, limit=3)
    assert allowed is False
    # Hop to minute 3 — fresh quota.
    allowed, remaining, reset = await store.admit("user:42", now=180.0, limit=3)
    assert allowed is True
    assert remaining == 2
    assert reset == 240.0


async def test_redis_admit_per_identity_isolation(fake_redis) -> None:
    """Two identities don't share a bucket."""
    from app.core.rate_limit import RedisStore

    store = RedisStore(fake_redis)
    for _ in range(3):
        await store.admit("user:a", now=120.0, limit=3)
    # user:a is at the limit; user:b should still be admitted.
    allowed_a, _, _ = await store.admit("user:a", now=120.0, limit=3)
    allowed_b, remaining_b, _ = await store.admit("user:b", now=120.0, limit=3)
    assert allowed_a is False
    assert allowed_b is True
    assert remaining_b == 2


async def test_redis_admit_sets_ttl(fake_redis) -> None:
    """The bucket key has a TTL so dormant buckets don't accumulate
    in Redis. fakeredis exposes TTL via the same `ttl` command Redis
    does."""
    from app.core.rate_limit import WINDOW_S, RedisStore

    store = RedisStore(fake_redis)
    await store.admit("user:42", now=120.0, limit=5)
    bucket_key = store._bucket_key("user:42", now=120.0)
    ttl = await fake_redis.ttl(bucket_key)
    # TTL should be set (>0) and at most one window.
    assert 0 < ttl <= WINDOW_S


async def test_redis_admit_script_replays_on_evalsha_cache(fake_redis) -> None:
    """The Lua script should be re-usable across many calls. Second
    call exercises the EVALSHA cache path; nothing crashes."""
    from app.core.rate_limit import RedisStore

    store = RedisStore(fake_redis)
    await store.admit("user:42", now=120.0, limit=5)
    allowed, remaining, _ = await store.admit("user:42", now=121.0, limit=5)
    assert allowed is True
    assert remaining == 3
