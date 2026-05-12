"""Top-20 #17: dispatch watchdog.

Commands flow PENDING -> DISPATCHED (manager hands the pb to the agent
over gRPC) -> SUCCEEDED / FAILED (agent reports back). If the agent
dies between DISPATCHED and the result message — bidi stream drops
post-handoff, process crashes mid-action, etc. — the row sits in
DISPATCHED forever. From the alert console it looks like the action
is still in flight; from the operator's perspective the response
never lands and they never know.

The watchdog walks the `commands` table on a schedule, finds rows
that have been DISPATCHED longer than the timeout, and marks them
FAILED with `error="dispatch watchdog: no result before {iso}"`. The
operator sees the failure in the host commands UI and can retry
manually (no auto-requeue — double-dispatch under flaky network is
worse than asking the operator).

Tuning knobs:

  * `VIGIL_DISPATCH_WATCHDOG_INTERVAL_S` — how often to scan. Default
    60 s. Floor 10 s (the scan itself is cheap, but tighter than this
    just burns CPU for no benefit).
  * `VIGIL_DISPATCH_WATCHDOG_TIMEOUT_S` — DISPATCHED age beyond which
    a row expires. Default 600 s (10 min) — long enough for slow
    response-action handlers (large quarantine moves, IOC scans),
    short enough that operators don't stare at a stuck row for an
    hour. Floor 60 s; cap 86400 s.

Wired in `app.main.lifespan` next to the audit-verifier loop.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.core.metrics import (
    dispatch_watchdog_expired_total,
    dispatch_watchdog_last_run_timestamp,
)
from app.models import Command, CommandStatus

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()

__all__ = ("run_forever", "_run_once", "_interval_seconds", "_timeout_seconds")


def _interval_seconds() -> int:
    raw = os.environ.get("VIGIL_DISPATCH_WATCHDOG_INTERVAL_S", "60")
    try:
        return max(10, int(raw))
    except ValueError:
        return 60


def _timeout_seconds() -> int:
    raw = os.environ.get("VIGIL_DISPATCH_WATCHDOG_TIMEOUT_S", "600")
    try:
        v = int(raw)
        # Floor 60 s; cap 1 day. Anything outside that range is almost
        # certainly a typo — clamp rather than crash the loop.
        return max(60, min(86400, v))
    except ValueError:
        return 600


async def _run_once(session_maker: SessionMaker | None = None) -> int:
    """One pass. Returns the number of commands expired this pass so
    tests can assert on it without poking the global counter.

    `session_maker` defaults to `SessionLocal` (the runtime pool). The
    tests pass a factory that hands back the test's nested-transaction
    session so the watchdog sees the same un-committed rows the test
    just inserted via SAVEPOINT isolation.
    """
    timeout = timedelta(seconds=_timeout_seconds())
    cutoff = datetime.now(UTC) - timeout
    expired = 0
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    async with sm() as db:
        # Find candidates first so we can log them; bulk UPDATE wouldn't
        # let us emit per-row breadcrumbs and the volume here is small
        # (DISPATCHED is a transient state, usually <1 s in practice).
        stmt = select(Command).where(
            Command.status == CommandStatus.DISPATCHED,
            Command.dispatched_at.is_not(None),
            Command.dispatched_at < cutoff,
        )
        rows = (await db.execute(stmt)).scalars().all()
        if not rows:
            dispatch_watchdog_last_run_timestamp.set(datetime.now(UTC).timestamp())
            return 0
        now = datetime.now(UTC)
        ids = [r.id for r in rows]
        # Single bulk UPDATE keyed by id list — preserves the
        # `WHERE status = DISPATCHED` guard so a concurrent dispatcher
        # commit that just flipped one of these to SUCCEEDED won't get
        # clobbered. The status guard is repeated in the UPDATE WHERE
        # for the same reason.
        await db.execute(
            update(Command)
            .where(
                Command.id.in_(ids),
                Command.status == CommandStatus.DISPATCHED,
            )
            .values(
                status=CommandStatus.FAILED,
                completed_at=now,
                error=f"dispatch watchdog: no result before {now.isoformat()}",
            )
        )
        await db.commit()
        for r in rows:
            log.warning(
                "dispatch_watchdog.expired",
                command_id=str(r.id),
                host_id=str(r.host_id),
                kind=r.kind.value,
                dispatched_at=r.dispatched_at.isoformat() if r.dispatched_at else None,
                age_s=(now - r.dispatched_at).total_seconds() if r.dispatched_at else None,
            )
        expired = len(rows)
        dispatch_watchdog_expired_total.inc(expired)
    dispatch_watchdog_last_run_timestamp.set(datetime.now(UTC).timestamp())
    return expired


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    timeout = _timeout_seconds()
    log.info(
        "dispatch_watchdog.loop.starting",
        interval_s=interval,
        timeout_s=timeout,
    )
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("dispatch_watchdog.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("dispatch_watchdog.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("dispatch_watchdog.loop.cancelled")
            raise
