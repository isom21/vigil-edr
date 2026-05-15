"""Coverage backfill for `app.services.host_cache`.

The cache sits in front of the Host PG lookup so the normalizer doesn't
re-query for every event from the same host. Tests pin:

  1. Cache miss hits PG, populates the entry with a future expiry, and
     returns the (hostname, os_family) tuple.
  2. An unknown host_id returns (None, None) without raising (the
     normalizer must keep flowing even when telemetry arrives for a
     host that was just decommissioned).
  3. `invalidate()` clears entries and is a no-op for unknown keys.

The cache opens its own `SessionLocal` for each miss; the test
fixture monkey-patches that to point at the SAVEPOINT-isolated test
session so we can see seeded rows without committing past the
rollback boundary.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import pytest
import pytest_asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_cache():
    from app.services import host_cache

    host_cache._CACHE.clear()
    yield
    host_cache._CACHE.clear()


@pytest_asyncio.fixture
async def _patched_cache(db_session, monkeypatch):
    """Point the module-level `SessionLocal` at the test session so the
    cache's miss-path lookup runs against the SAVEPOINT-isolated rows
    the test seeds via `db_session`. Without this patch, the cache
    opens a fresh pool connection that's invisible to the test data.
    """
    from app.services import host_cache

    @asynccontextmanager
    async def _maker():
        yield db_session

    monkeypatch.setattr(host_cache, "SessionLocal", _maker)
    return host_cache


@pytest_asyncio.fixture
async def _seeded_host(db_session):
    from app.models import Host, HostStatus, OsFamily

    h = Host(
        hostname=f"cache-host-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(h)
    await db_session.flush()
    return h


@pytest.mark.asyncio
async def test_cache_miss_hits_db_and_populates(_patched_cache, _seeded_host) -> None:
    hostname, os_family = await _patched_cache.hostname_for(_seeded_host.id)
    assert hostname == _seeded_host.hostname
    assert os_family == "linux"
    # Cache entry persisted with future expiry.
    assert _seeded_host.id in _patched_cache._CACHE
    _, _, _, expires_at = _patched_cache._CACHE[_seeded_host.id]
    import time

    assert expires_at > time.monotonic()


@pytest.mark.asyncio
async def test_unknown_host_returns_none_none(_patched_cache) -> None:
    """A host_id we never seeded must come back (None, None) rather
    than raising. The normalizer relies on this — telemetry from a
    host that was just decommissioned shouldn't crash the worker."""
    import uuid

    random_id = uuid.uuid4()
    hostname, os_family = await _patched_cache.hostname_for(random_id)
    assert hostname is None
    assert os_family is None
    # Negative result is also cached so we don't hammer PG every event.
    assert random_id in _patched_cache._CACHE


@pytest.mark.asyncio
async def test_invalidate_clears_entry(_patched_cache, _seeded_host) -> None:
    await _patched_cache.hostname_for(_seeded_host.id)
    assert _seeded_host.id in _patched_cache._CACHE
    _patched_cache.invalidate(_seeded_host.id)
    assert _seeded_host.id not in _patched_cache._CACHE


@pytest.mark.asyncio
async def test_invalidate_on_missing_key_is_no_op() -> None:
    """`invalidate()` is best-effort: calling it for a host we never
    cached must not raise (the future caller doing optimistic
    invalidation on host update shouldn't have to check first)."""
    import uuid

    from app.services import host_cache

    host_cache.invalidate(uuid.uuid4())
