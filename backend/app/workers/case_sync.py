"""Phase 3 #3.6: external case-tracker poller.

Periodic worker that walks every enabled `CaseDestination` and asks
each one whether its mirrored issues changed state. The state change
gets written back onto the `case_link` row, closing the loop so the
UI shows the analyst that the SOC ticket they opened in Jira moved
into "Done".

Inserts (alert → external issue) happen on the alert lifecycle path
(`app.api.alerts`), not here — this worker is read-only against the
trackers, write-only against `case_link`.

Lifecycle mirrors `intel_ingest.py`: wrapped in `app.main.lifespan`
as a background task, opts out via VIGIL_CASE_SYNC_INTERVAL_S=0 or
VIGIL_TEST_ENV=1.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import CaseDestination
from app.services.case_management import poll_destination

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()

__all__ = ("run_forever", "_run_once", "_interval_seconds")


def _interval_seconds() -> int:
    raw = os.environ.get("VIGIL_CASE_SYNC_INTERVAL_S")
    if raw is None:
        return max(30, int(settings.case_sync_interval_s))
    try:
        return max(30, int(raw))
    except ValueError:
        return max(30, int(settings.case_sync_interval_s))


async def _run_once(session_maker: SessionMaker | None = None) -> int:
    """One pass over every enabled destination. Returns the total
    number of links whose `sync_state` actually changed across all
    destinations (handy for tests + ops dashboards)."""
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    total_changed = 0
    async with sm() as db:
        dests = (
            (await db.execute(select(CaseDestination).where(CaseDestination.enabled.is_(True))))
            .scalars()
            .all()
        )
        for dest in dests:
            try:
                total_changed += await poll_destination(db, dest)
            except Exception:  # noqa: BLE001 — one flaky dest must not poison the loop
                log.exception(
                    "case_sync.destination_failed",
                    destination_id=str(dest.id),
                    destination_name=dest.name,
                )
        await db.commit()
    return total_changed


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    log.info("case_sync.loop.starting", interval_s=interval)
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("case_sync.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — keep the loop alive
            log.exception("case_sync.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("case_sync.loop.cancelled")
            raise
