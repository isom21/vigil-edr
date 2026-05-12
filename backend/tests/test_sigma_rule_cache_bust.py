"""sigma_realtime rule cache busts on rule.revision change.

Review MEDIUM #16: pre-fix the worker cached `Rule` objects forever
(only on cache miss / on percolator sync) and used `rule.severity`,
`rule.action`, `rule.name` from the cached object. A rule edited from
`low → critical` kept emitting `low` alerts until the worker restarted.

`_get_rule_fresh` now compares the cached rule's `revision` with the
current DB revision and refreshes on mismatch.

These tests run the helper directly against an injected fake session
so they don't need a committed Postgres row (the per-test SAVEPOINT
rolls back, and the worker's `SessionLocal()` is a separate
connection pool from the fixture's `db_session`).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest


class _FakeResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeSession:
    """Mimics just enough of AsyncSession for `_get_rule_fresh`."""

    def __init__(self, revision_lookup):
        self._lookup = revision_lookup

    async def execute(self, *_args, **_kwargs):
        # The helper only ever runs `SELECT Rule.revision WHERE Rule.id == :id`.
        return _FakeResult(self._lookup())

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _install_fake_session(monkeypatch: pytest.MonkeyPatch, lookup):
    @asynccontextmanager
    async def _factory(*_args, **_kwargs):
        yield _FakeSession(lookup)

    monkeypatch.setattr("app.workers.sigma_realtime.SessionLocal", _factory)


@pytest.fixture
def _cached_rule():
    # We're not exercising any DB-typed fields here — a SimpleNamespace
    # is enough because the helper only reads `id` and `revision`.
    return SimpleNamespace(id=uuid4(), revision=1, severity="low", name="r1")


@pytest.mark.asyncio
async def test_get_rule_fresh_returns_cached_when_revision_matches(
    monkeypatch: pytest.MonkeyPatch, _cached_rule
):
    from app.workers.sigma_realtime import SigmaRealtime

    _install_fake_session(monkeypatch, lambda: 1)
    w = SigmaRealtime.__new__(SigmaRealtime)
    w._rule_cache = {_cached_rule.id: _cached_rule}  # type: ignore[attr-defined]

    fresh = await w._get_rule_fresh(_cached_rule.id)
    assert fresh is _cached_rule


@pytest.mark.asyncio
async def test_get_rule_fresh_refetches_when_revision_bumped(
    monkeypatch: pytest.MonkeyPatch, _cached_rule
):
    from app.workers.sigma_realtime import SigmaRealtime

    _install_fake_session(monkeypatch, lambda: 2)
    refreshed = SimpleNamespace(id=_cached_rule.id, revision=2, severity="critical", name="r1")
    w = SigmaRealtime.__new__(SigmaRealtime)
    w._rule_cache = {_cached_rule.id: _cached_rule}  # type: ignore[attr-defined]
    w._refresh_rule_cache = AsyncMock(return_value=refreshed)  # type: ignore[attr-defined]

    fresh = await w._get_rule_fresh(_cached_rule.id)
    assert fresh is refreshed
    w._refresh_rule_cache.assert_awaited_once_with(_cached_rule.id)  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_get_rule_fresh_drops_cache_when_rule_deleted(
    monkeypatch: pytest.MonkeyPatch, _cached_rule
):
    from app.workers.sigma_realtime import SigmaRealtime

    _install_fake_session(monkeypatch, lambda: None)
    w = SigmaRealtime.__new__(SigmaRealtime)
    w._rule_cache = {_cached_rule.id: _cached_rule}  # type: ignore[attr-defined]

    fresh = await w._get_rule_fresh(_cached_rule.id)
    assert fresh is None
    assert _cached_rule.id not in w._rule_cache  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_get_rule_fresh_on_cache_miss_loads_from_db(
    monkeypatch: pytest.MonkeyPatch, _cached_rule
):
    from app.workers.sigma_realtime import SigmaRealtime

    _install_fake_session(monkeypatch, lambda: 1)
    w = SigmaRealtime.__new__(SigmaRealtime)
    w._rule_cache = {}  # empty
    w._refresh_rule_cache = AsyncMock(return_value=_cached_rule)  # type: ignore[attr-defined]

    fresh = await w._get_rule_fresh(_cached_rule.id)
    assert fresh is _cached_rule
    w._refresh_rule_cache.assert_awaited_once_with(_cached_rule.id)  # type: ignore[attr-defined]
