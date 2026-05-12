"""Top-20 #17: command-dispatch watchdog.

`app.workers.dispatch_watchdog._run_once` walks `commands`, finds
rows in DISPATCHED whose `dispatched_at` is older than
`VIGIL_DISPATCH_WATCHDOG_TIMEOUT_S` (default 600 s), and flips them
to FAILED with a watchdog reason. These tests exercise the unit
directly — the lifespan-mounted background task itself is hard to
drive deterministically from pytest, but the single-pass entrypoint
is the load-bearing logic.

Invariants:
  * PENDING rows are left alone (not yet handed to an agent).
  * Fresh DISPATCHED rows (younger than the timeout) are left alone.
  * Stale DISPATCHED rows flip to FAILED with completed_at + error.
  * SUCCEEDED / FAILED rows are inert (idempotent re-runs).
  * A row that races a real result mid-pass keeps the real result
    (the UPDATE re-asserts `status = DISPATCHED` in its WHERE clause).
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio


def _test_session_maker(db_session):
    """Build a session-maker compatible with the watchdog's signature
    (`Callable[[], AsyncContextManager[AsyncSession]]`) that hands the
    watchdog the same nested-transaction session the test fixtures
    write through. Without this, the watchdog opens a fresh pool
    connection that can't see SAVEPOINT-isolated rows."""

    @asynccontextmanager
    async def _maker():
        yield db_session

    return _maker


@pytest_asyncio.fixture
async def _commands_seed(db_session):
    """Seed one host + four commands in various states for the watchdog
    to chew on. dispatched_at is set on the rows the watchdog should
    notice; completed_at remains None there so we can assert it gets
    populated."""
    from app.models import (
        Command,
        CommandKind,
        CommandStatus,
        Host,
        HostStatus,
        OsFamily,
    )

    host = Host(
        hostname=f"watchdog-host-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(host)
    await db_session.flush()

    now = datetime.now(UTC)
    long_ago = now - timedelta(hours=2)
    recent = now - timedelta(seconds=30)

    stale_dispatched = Command(
        host_id=host.id,
        kind=CommandKind.KILL_PROCESS,
        status=CommandStatus.DISPATCHED,
        payload={"pid": 1234},
        dispatched_at=long_ago,
    )
    fresh_dispatched = Command(
        host_id=host.id,
        kind=CommandKind.KILL_PROCESS,
        status=CommandStatus.DISPATCHED,
        payload={"pid": 5678},
        dispatched_at=recent,
    )
    pending = Command(
        host_id=host.id,
        kind=CommandKind.BLOCK_PROCESS,
        status=CommandStatus.PENDING,
        payload={"pattern": "evil.exe"},
    )
    succeeded = Command(
        host_id=host.id,
        kind=CommandKind.BLOCK_FILE,
        status=CommandStatus.SUCCEEDED,
        payload={"pattern": "blocked.exe"},
        dispatched_at=long_ago,
        completed_at=long_ago + timedelta(seconds=1),
    )
    db_session.add_all([stale_dispatched, fresh_dispatched, pending, succeeded])
    await db_session.flush()
    return {
        "host": host,
        "stale": stale_dispatched,
        "fresh": fresh_dispatched,
        "pending": pending,
        "succeeded": succeeded,
    }


# ---------- env parsing ----------


def test_interval_floor_is_10s() -> None:
    """The scan itself is cheap (`WHERE status = DISPATCHED AND
    dispatched_at < cutoff` is an indexed range scan), but a 1-second
    poll is wasteful. Floor 10 s defends against a typo."""
    from app.workers.dispatch_watchdog import _interval_seconds

    os.environ["VIGIL_DISPATCH_WATCHDOG_INTERVAL_S"] = "1"
    try:
        assert _interval_seconds() == 10
    finally:
        os.environ.pop("VIGIL_DISPATCH_WATCHDOG_INTERVAL_S", None)


def test_interval_falls_back_to_default_on_garbage() -> None:
    from app.workers.dispatch_watchdog import _interval_seconds

    os.environ["VIGIL_DISPATCH_WATCHDOG_INTERVAL_S"] = "abc"
    try:
        assert _interval_seconds() == 60
    finally:
        os.environ.pop("VIGIL_DISPATCH_WATCHDOG_INTERVAL_S", None)


def test_timeout_clamps_to_floor_and_cap() -> None:
    """A 1-second timeout would expire commands faster than the
    average agent can reply; a 1-year timeout is operator typo. Clamp
    to [60, 86400]."""
    from app.workers.dispatch_watchdog import _timeout_seconds

    os.environ["VIGIL_DISPATCH_WATCHDOG_TIMEOUT_S"] = "1"
    try:
        assert _timeout_seconds() == 60
    finally:
        os.environ.pop("VIGIL_DISPATCH_WATCHDOG_TIMEOUT_S", None)

    os.environ["VIGIL_DISPATCH_WATCHDOG_TIMEOUT_S"] = "99999999"
    try:
        assert _timeout_seconds() == 86400
    finally:
        os.environ.pop("VIGIL_DISPATCH_WATCHDOG_TIMEOUT_S", None)


# ---------- one pass ----------


@pytest.mark.asyncio
async def test_run_once_expires_stale_dispatched_only(db_session, _commands_seed) -> None:
    from app.models import Command, CommandStatus
    from app.workers.dispatch_watchdog import _run_once

    expired = await _run_once(session_maker=_test_session_maker(db_session))
    assert expired == 1

    await db_session.refresh(_commands_seed["stale"])
    await db_session.refresh(_commands_seed["fresh"])
    await db_session.refresh(_commands_seed["pending"])
    await db_session.refresh(_commands_seed["succeeded"])

    assert _commands_seed["stale"].status == CommandStatus.FAILED
    assert _commands_seed["stale"].completed_at is not None
    assert _commands_seed["stale"].error is not None
    assert "dispatch watchdog" in _commands_seed["stale"].error

    # Untouched.
    assert _commands_seed["fresh"].status == CommandStatus.DISPATCHED
    assert _commands_seed["pending"].status == CommandStatus.PENDING
    assert _commands_seed["succeeded"].status == CommandStatus.SUCCEEDED
    # Use Command import so it's not flagged unused on test failure.
    _ = Command


@pytest.mark.asyncio
async def test_run_once_is_idempotent(db_session, _commands_seed) -> None:
    """Second pass should find nothing — the first pass moved the
    stale row out of DISPATCHED."""
    from app.workers.dispatch_watchdog import _run_once

    sm = _test_session_maker(db_session)
    first = await _run_once(session_maker=sm)
    second = await _run_once(session_maker=sm)
    assert first == 1
    assert second == 0


@pytest.mark.asyncio
async def test_run_once_skips_dispatched_at_null(db_session) -> None:
    """A DISPATCHED row with NULL dispatched_at shouldn't get clobbered
    — the watchdog only acts on rows that have an age it can compute."""
    from app.models import (
        Command,
        CommandKind,
        CommandStatus,
        Host,
        HostStatus,
        OsFamily,
    )
    from app.workers.dispatch_watchdog import _run_once

    host = Host(
        hostname=f"null-disp-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add(host)
    await db_session.flush()
    weird = Command(
        host_id=host.id,
        kind=CommandKind.KILL_PROCESS,
        status=CommandStatus.DISPATCHED,
        payload={"pid": 42},
        dispatched_at=None,
    )
    db_session.add(weird)
    await db_session.flush()

    expired = await _run_once(session_maker=_test_session_maker(db_session))
    # The stale row from any earlier test in this fixture chain isn't
    # in scope; we only care that THIS row was not touched.
    await db_session.refresh(weird)
    assert weird.status == CommandStatus.DISPATCHED
    # `expired` here may be 0 or >0 depending on global state — the
    # invariant we care about is that the NULL-dispatched_at row is
    # untouched.
    _ = expired
