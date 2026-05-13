"""Hunt scheduler worker (Phase 2 #2.11).

Every `VIGIL_HUNT_SCHEDULER_INTERVAL_S` (default 60 s, floor 10 s) the
scheduler walks `saved_hunt` rows with a non-NULL `schedule_cron` and
fires any whose cron string matches the current UTC minute.

Lifecycle mirrors `app.workers.intel_ingest.run_forever`: wrapped in
`app.main.lifespan` as a background task; cancellation is the only
shutdown signal. Single-instance — clustering multiple managers would
need a distributed lock to avoid double-firing scheduled hunts.

Tuning knobs:
  * `VIGIL_HUNT_SCHEDULER_INTERVAL_S` — outer tick. Default 60 s,
    floor 10 s.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.models import SavedHunt
from app.services.hunt import cron_matches, run_hunt

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()

__all__ = ("run_forever", "_run_once", "_interval_seconds")


def _interval_seconds() -> int:
    raw = os.environ.get("VIGIL_HUNT_SCHEDULER_INTERVAL_S", "60")
    try:
        return max(10, int(raw))
    except ValueError:
        return 60


def _is_due(hunt: SavedHunt, now: datetime) -> bool:
    if not hunt.schedule_cron:
        return False
    try:
        if not cron_matches(hunt.schedule_cron, now):
            return False
    except ValueError:
        log.warning(
            "hunt.scheduler.bad_cron",
            hunt_id=str(hunt.id),
            schedule_cron=hunt.schedule_cron,
        )
        return False
    # Suppress re-firing within the same minute when the tick interval
    # is shorter than 60 s — otherwise a 30 s interval would fire each
    # matching minute's hunt twice.
    last = hunt.last_run_at
    if last is not None:
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        if (
            last.year == now.year
            and last.month == now.month
            and last.day == now.day
            and last.hour == now.hour
            and last.minute == now.minute
        ):
            return False
    return True


async def _run_once(
    session_maker: SessionMaker | None = None,
    *,
    now: datetime | None = None,
    force_hunt_id: UUID | None = None,
) -> int:
    """One pass. Returns the number of hunts fired this tick."""
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    fired = 0
    now = now or datetime.now(UTC)
    async with sm() as db:
        stmt = select(SavedHunt)
        if force_hunt_id is not None:
            stmt = stmt.where(SavedHunt.id == force_hunt_id)
        else:
            stmt = stmt.where(SavedHunt.schedule_cron.is_not(None))
        hunts = (await db.execute(stmt)).scalars().all()
        for hunt in hunts:
            if force_hunt_id is None and not _is_due(hunt, now):
                continue
            try:
                await run_hunt(db, hunt.id, dry_run=False, now=now)
                fired += 1
            except Exception:  # pragma: no cover — one flaky hunt mustn't poison the pass
                log.exception("hunt.scheduler.run_failed", hunt_id=str(hunt.id))
        await db.commit()
    return fired


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    log.info("hunt.scheduler.starting", interval_s=interval)
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("hunt.scheduler.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("hunt.scheduler.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("hunt.scheduler.cancelled")
            raise
