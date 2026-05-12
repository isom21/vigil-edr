"""Coverage backfill for `app.workers.silence`.

M12.d agent silence detector. The worker walks `hosts` periodically
and fires a HIGH-severity Alert for each ONLINE host whose
`last_seen_at` is older than `VIGIL_SILENCE_THRESHOLD_SECONDS`. The
synthetic rule id is stable so all such alerts share one rule row.

Tests pin the load-bearing unit (`_tick_once`):
  * Stale online host → exactly one Alert + the host_id latched in
    `_open_alerts` so a second tick doesn't double-fire.
  * Host that recovers (last_seen_at refreshed) → latch drops.
  * Non-online host is ignored even when stale (those have a
    separate signal path via `host.status == OFFLINE`).
  * `_ensure_pseudo_rule` is idempotent.

Same SAVEPOINT-isolation trick as the host_cache / dispatch_watchdog
suites: monkey-patch `SessionLocal` to the test session.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def _patched_silence(db_session, monkeypatch):
    """Point the silence worker's `SessionLocal` reference at the test
    session so `_tick_once` and `_ensure_pseudo_rule` write through
    the SAVEPOINT-isolated transaction the test owns."""
    from app.workers import silence

    @asynccontextmanager
    async def _maker():
        yield db_session

    monkeypatch.setattr(silence, "SessionLocal", _maker)
    return silence


@pytest_asyncio.fixture
async def _silent_host(db_session):
    """A host that's been ONLINE but hasn't been seen in 30 min — well
    over the default 10-min silence threshold."""
    from app.models import Host, HostStatus, OsFamily

    h = Host(
        hostname=f"silent-host-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
        last_seen_at=datetime.now(UTC) - timedelta(minutes=30),
    )
    db_session.add(h)
    await db_session.flush()
    return h


@pytest_asyncio.fixture
async def _fresh_host(db_session):
    """A host last seen 1 s ago — comfortably under threshold."""
    from app.models import Host, HostStatus, OsFamily

    h = Host(
        hostname=f"fresh-host-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
        last_seen_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    db_session.add(h)
    await db_session.flush()
    return h


@pytest_asyncio.fixture
async def _offline_host(db_session):
    """A host that hasn't checked in for hours but is marked OFFLINE.
    Silence shouldn't fire — the offline state already represents the
    explicit disconnect."""
    from app.models import Host, HostStatus, OsFamily

    h = Host(
        hostname=f"offline-host-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.OFFLINE,
        last_seen_at=datetime.now(UTC) - timedelta(hours=3),
    )
    db_session.add(h)
    await db_session.flush()
    return h


@pytest.mark.asyncio
async def test_tick_fires_alert_for_silent_online_host(
    _patched_silence, _silent_host, db_session
) -> None:
    from sqlalchemy import select

    from app.models import Alert
    from app.workers.silence import SILENCE_RULE_ID

    worker = _patched_silence.SilenceWorker()
    await worker._ensure_pseudo_rule()
    await worker._tick_once()

    stmt = select(Alert).where(Alert.host_id == _silent_host.id)
    alerts = (await db_session.execute(stmt)).scalars().all()
    assert len(alerts) == 1
    assert alerts[0].rule_id == SILENCE_RULE_ID
    assert alerts[0].severity.value == "high"
    assert _silent_host.id in worker._open_alerts


@pytest.mark.asyncio
async def test_tick_is_idempotent_under_open_latch(
    _patched_silence, _silent_host, db_session
) -> None:
    """Second tick must NOT fire a second alert — the latch in
    `_open_alerts` is the dedup mechanism."""
    from sqlalchemy import select

    from app.models import Alert

    worker = _patched_silence.SilenceWorker()
    await worker._ensure_pseudo_rule()
    await worker._tick_once()
    await worker._tick_once()

    count = (
        (await db_session.execute(select(Alert).where(Alert.host_id == _silent_host.id)))
        .scalars()
        .all()
    )
    assert len(count) == 1


@pytest.mark.asyncio
async def test_tick_skips_fresh_online_host(_patched_silence, _fresh_host, db_session) -> None:
    from sqlalchemy import select

    from app.models import Alert

    worker = _patched_silence.SilenceWorker()
    await worker._ensure_pseudo_rule()
    await worker._tick_once()

    alerts = (
        (await db_session.execute(select(Alert).where(Alert.host_id == _fresh_host.id)))
        .scalars()
        .all()
    )
    assert alerts == []
    assert _fresh_host.id not in worker._open_alerts


@pytest.mark.asyncio
async def test_tick_skips_offline_host_even_when_stale(
    _patched_silence, _offline_host, db_session
) -> None:
    """OFFLINE hosts are intentionally ignored — their disconnect
    signal is already covered by the host status itself; firing
    silence on top would double-page."""
    from sqlalchemy import select

    from app.models import Alert

    worker = _patched_silence.SilenceWorker()
    await worker._ensure_pseudo_rule()
    await worker._tick_once()

    alerts = (
        (await db_session.execute(select(Alert).where(Alert.host_id == _offline_host.id)))
        .scalars()
        .all()
    )
    assert alerts == []


@pytest.mark.asyncio
async def test_recovery_clears_latch(_patched_silence, _silent_host, db_session) -> None:
    """When a previously-silent host's last_seen_at moves into the
    fresh window, the latch must drop so the next silence event fires
    a fresh alert."""
    worker = _patched_silence.SilenceWorker()
    await worker._ensure_pseudo_rule()
    await worker._tick_once()
    assert _silent_host.id in worker._open_alerts

    # Host's heartbeat lands.
    _silent_host.last_seen_at = datetime.now(UTC)
    await db_session.flush()
    await worker._tick_once()
    assert _silent_host.id not in worker._open_alerts


@pytest.mark.asyncio
async def test_ensure_pseudo_rule_is_idempotent(_patched_silence, db_session) -> None:
    """Two starts in a row mustn't fail or insert duplicate rules."""
    from sqlalchemy import select

    from app.models import Rule
    from app.workers.silence import SILENCE_RULE_ID

    worker = _patched_silence.SilenceWorker()
    await worker._ensure_pseudo_rule()
    await worker._ensure_pseudo_rule()

    rules = (
        (await db_session.execute(select(Rule).where(Rule.id == SILENCE_RULE_ID))).scalars().all()
    )
    assert len(rules) == 1


def test_silence_rule_id_is_stable() -> None:
    """The synthetic rule id is hard-coded; pin the value so a future
    refactor doesn't fragment existing silence alerts across two rules."""
    from app.workers.silence import SILENCE_RULE_ID

    assert str(SILENCE_RULE_ID) == "a0a0a0a0-0000-0000-0000-000000000004"


def test_threshold_and_tick_pick_up_env_overrides(monkeypatch) -> None:
    """Operators tune the threshold via `VIGIL_SILENCE_THRESHOLD_SECONDS`
    and the cadence via `VIGIL_SILENCE_TICK_SECONDS`. Reach into a
    fresh worker after monkey-patching env to confirm the values are
    re-read, not frozen at import time."""
    monkeypatch.setenv("VIGIL_SILENCE_THRESHOLD_SECONDS", "120")
    monkeypatch.setenv("VIGIL_SILENCE_TICK_SECONDS", "5")
    from app.workers.silence import SilenceWorker

    w = SilenceWorker()
    assert int(w._threshold.total_seconds()) == 120
    assert w._tick == 5.0
