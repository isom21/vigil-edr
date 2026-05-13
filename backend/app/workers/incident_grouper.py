"""Phase 1 #1.11 — periodic incident grouper.

Walks recently-opened alerts and groups them into Incidents via
`app.services.incident_grouping.regroup_recent`. Same loop shape as
`dispatch_watchdog`: env-tunable interval + opt-out, `VIGIL_TEST_ENV=1`
opt-out so the pytest harness doesn't race the worker's UPDATEs, and
a `session_maker` parameter on `_run_once` for SAVEPOINT-isolated
testing.

Knobs:
  * `VIGIL_INCIDENT_GROUPER_INTERVAL_S` — scan cadence. Default 60 s.
    Floor 10 s (the query is a small indexed range — tighter just
    burns CPU). `=0` disables the loop entirely.
  * `VIGIL_INCIDENT_WINDOW_S` — grouping window. Default 600 s. Floor
    60 s; cap 86400 s. Anything outside is clamped rather than
    crashing the loop.

Wired in `app.main.lifespan`.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.services.incident_grouping import regroup_recent

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()

__all__ = ("run_forever", "_run_once", "_interval_seconds", "_window_seconds")


def _interval_seconds() -> int:
    raw = os.environ.get("VIGIL_INCIDENT_GROUPER_INTERVAL_S", "60")
    try:
        return max(10, int(raw))
    except ValueError:
        return 60


def _window_seconds() -> int:
    raw = os.environ.get("VIGIL_INCIDENT_WINDOW_S", "600")
    try:
        v = int(raw)
        return max(60, min(86400, v))
    except ValueError:
        return 600


async def _run_once(session_maker: SessionMaker | None = None) -> int:
    """One pass. Returns the number of alerts grouped this pass so tests
    can assert on it directly.

    `session_maker` defaults to `SessionLocal` (the runtime pool). The
    tests pass a factory that hands back the test's nested-transaction
    session so the worker sees the same un-committed rows the test
    just inserted via SAVEPOINT isolation.
    """
    window_s = _window_seconds()
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    async with sm() as db:
        grouped = await regroup_recent(db, window_s)
        if grouped:
            await db.commit()
    return grouped


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    window = _window_seconds()
    log.info(
        "incident_grouper.loop.starting",
        interval_s=interval,
        window_s=window,
    )
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("incident_grouper.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("incident_grouper.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("incident_grouper.loop.cancelled")
            raise
