"""Cloud IAM anomaly monitor (Phase 4 #4.2).

Periodic worker. On each tick:

  1. Load every enabled ``CloudSource`` row.
  2. For each source, decrypt config, list new S3 objects since
     ``last_event_ts``, fetch + parse each as CloudTrail JSON, and
     dispatch each event through the four detectors in
     ``app.services.cloud.iam_anomaly``.
  3. Update the source's ``last_polled_at`` and ``last_event_ts``
     watermark.

Per-source try/except isolation — a single misconfigured bucket can't
take the loop down.

Tuning knobs (mirror the env-opt-out shape used by every other Phase 1+
worker so operators can park the worker on a specific manager instance):

  * ``VIGIL_CLOUD_IAM_MONITOR_INTERVAL_S`` — outer loop tick. Default
    300 s. Floor 30 s.
  * ``VIGIL_CLOUD_IAM_MONITOR_ENABLED`` — set to ``0`` to keep the
    worker dormant on this manager instance.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.models import CloudSource
from app.services.cloud import cloudtrail, iam_anomaly
from app.services.encryption import decrypt_config

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()


def _interval_seconds() -> int:
    raw = os.environ.get("VIGIL_CLOUD_IAM_MONITOR_INTERVAL_S", "300")
    try:
        return max(30, int(raw))
    except ValueError:
        return 300


async def _process_source(db: AsyncSession, source: CloudSource) -> None:
    """Pull new objects + dispatch each event. All exceptions land here
    so the outer loop can keep going with the next source."""
    started = datetime.now(UTC)
    try:
        config = decrypt_config(source.config_encrypted)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "cloud_iam_monitor.decrypt_failed",
            source_id=str(source.id),
            error=str(exc),
        )
        source.last_polled_at = started
        return

    prefix = config.get("prefix", "") or ""
    after_ts = source.last_event_ts

    try:
        objects = await cloudtrail.list_objects(config, prefix=prefix, after_ts=after_ts)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "cloud_iam_monitor.list_failed",
            source_id=str(source.id),
            error=str(exc),
        )
        source.last_polled_at = started
        return

    newest_ts: datetime | None = after_ts
    processed = 0
    fired = 0
    for obj in objects:
        try:
            raw = await cloudtrail.fetch_object(config, obj["key"])
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "cloud_iam_monitor.fetch_failed",
                source_id=str(source.id),
                key=obj["key"],
                error=str(exc),
            )
            continue
        events = cloudtrail.parse_events(raw)
        for event in events:
            await iam_anomaly.detect_new_principal(
                db, tenant_id=source.tenant_id, source_id=source.id, event=event
            )
            if await iam_anomaly.detect_new_action(
                db, tenant_id=source.tenant_id, source_id=source.id, event=event
            ):
                fired += 1
            if await iam_anomaly.detect_new_region(
                db, tenant_id=source.tenant_id, source_id=source.id, event=event
            ):
                fired += 1
            if await iam_anomaly.detect_root_console_login(
                db, tenant_id=source.tenant_id, source_id=source.id, event=event
            ):
                fired += 1
            processed += 1
            if event.get("ts") is not None and (newest_ts is None or event["ts"] > newest_ts):
                newest_ts = event["ts"]

    source.last_polled_at = started
    if newest_ts is not None:
        source.last_event_ts = newest_ts
    log.info(
        "cloud_iam_monitor.source_ok",
        source_id=str(source.id),
        objects=len(objects),
        events=processed,
        alerts_fired=fired,
    )


async def _run_once(session_maker: SessionMaker | None = None) -> int:
    """One pass over every enabled source. Returns the number of sources
    processed. Used by tests to drive a deterministic tick."""
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    count = 0
    async with sm() as db:
        sources = (
            (await db.execute(select(CloudSource).where(CloudSource.enabled.is_(True))))
            .scalars()
            .all()
        )
        for source in sources:
            await _process_source(db, source)
            count += 1
        await db.commit()
    return count


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    interval = _interval_seconds()
    log.info("cloud_iam_monitor.loop.starting", interval_s=interval)
    while True:
        try:
            await _run_once()
        except asyncio.CancelledError:
            log.info("cloud_iam_monitor.loop.cancelled")
            raise
        except Exception:  # pragma: no cover — never let the loop die
            log.exception("cloud_iam_monitor.loop.iteration_failed")
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            log.info("cloud_iam_monitor.loop.cancelled")
            raise


__all__ = ("_interval_seconds", "_process_source", "_run_once", "run_forever")
