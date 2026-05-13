"""Phase 3 #3.2: daily archive worker.

Walks OpenSearch ``_cat/indices`` for telemetry-/alerts- indices past
the cold-tier age and freezes each one to MinIO. Run cadence is daily
by default (``VIGIL_ARCHIVE_WORKER_INTERVAL_S``); the per-pass workload
is bounded by however many indices crossed the cold boundary since the
last tick — typically zero or one.

Same lifecycle template the other Phase 1+ workers use: env opt-out,
``VIGIL_TEST_ENV=1`` opt-out, cancellable shutdown, lazy SessionLocal.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.services.archive import already_frozen, freeze_index, list_cold_indices

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()


def _interval_seconds() -> int:
    raw = os.environ.get("VIGIL_ARCHIVE_WORKER_INTERVAL_S", str(settings.archive_worker_interval_s))
    try:
        # Floor at 60s — anything tighter just burns OpenSearch _cat
        # calls; there's no operational reason to scan the cluster
        # more often than once a minute.
        return max(60, int(raw))
    except ValueError:
        return settings.archive_worker_interval_s


async def _run_once(session_maker: SessionMaker | None = None) -> int:
    """One scan + freeze pass. Returns the number of indices frozen.

    Per-index errors are swallowed (recorded as ``failed`` rows by
    ``freeze_index``) so one bad index can't take the worker down.
    """
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    frozen = 0
    candidates = await list_cold_indices()
    if not candidates:
        return 0
    async with sm() as db:
        for name in candidates:
            if await already_frozen(db, name):
                continue
            job = await freeze_index(name, db)
            # `freeze_index` writes failure to the row; treat a non-
            # frozen result as a soft fail and keep going.
            if job.status == "frozen":
                frozen += 1
        await db.commit()
    return frozen


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    log.info("archive_worker.loop.starting", interval_s=interval)
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("archive_worker.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("archive_worker.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("archive_worker.loop.cancelled")
            raise
