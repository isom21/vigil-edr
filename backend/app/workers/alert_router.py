"""Alert routing worker (Phase 1 #1.7).

For every newly-inserted Alert, look up matching `RoutingRule` rows
and fire the channels they list (Slack incoming webhook, PagerDuty
Events v2, or SMTP email).

Design choices:

  * Alerts aren't currently published to Kafka by any producer — the
    in-tree alert pipeline writes them straight to Postgres and the
    SSE alert_broker tails the table on `created_at`. Rather than
    push every existing producer (sigma_realtime, anomaly, silence,
    tamper, detector, …) onto a Kafka publisher we adopt the same
    poll-by-`created_at` shape here. The `alerts.raw` topic name in
    `settings.topic_alerts_raw` is reserved for a future bus that
    replaces this poll without API changes; until then this worker
    is the consumer.

  * Manual high-water mark + LIMIT'd window = bounded backfill on
    restart (`VIGIL_ALERT_ROUTER_BACKFILL_S`, default 60s). At boot
    we anchor `last_seen` that far in the past so an alert that
    arrived during the brief downtime window gets fired without
    re-emitting the entire historical backlog.

  * Per-alert dispatch is delegated to
    `app.services.routing.dispatch_for_alert`; this module is just
    the loop + offset bookkeeping.

  * Retry policy lives inside the service (3 attempts, exponential
    backoff). After exhaustion we log + advance the offset so
    head-of-line stalls don't block the rest of the queue.

Run with:
    python -m app.workers.alert_router
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from datetime import UTC, datetime, timedelta

import httpx
import structlog
from sqlalchemy import select

from app.core.db import SessionLocal
from app.models import Alert
from app.services.routing import dispatch_for_alert

log = structlog.get_logger()


_DEFAULT_TICK_S = 2.0
_DEFAULT_BACKFILL_S = 60
_DEFAULT_BATCH = 100


class AlertRouterWorker:
    def __init__(self) -> None:
        self._stop = asyncio.Event()
        self._tick_s = float(os.environ.get("VIGIL_ALERT_ROUTER_TICK_S", _DEFAULT_TICK_S))
        self._backfill_s = int(
            os.environ.get("VIGIL_ALERT_ROUTER_BACKFILL_S", _DEFAULT_BACKFILL_S)
        )
        self._batch = int(os.environ.get("VIGIL_ALERT_ROUTER_BATCH", _DEFAULT_BATCH))
        self._last_seen: datetime | None = None
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        self._last_seen = datetime.now(UTC) - timedelta(seconds=self._backfill_s)
        self._client = httpx.AsyncClient(timeout=10.0)
        log.info(
            "alert_router.start",
            tick_s=self._tick_s,
            backfill_s=self._backfill_s,
            batch=self._batch,
        )

    async def stop(self) -> None:
        self._stop.set()
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        log.info("alert_router.stop")

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                await self._tick_once()
            except Exception:
                log.exception("alert_router.tick_failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._tick_s)
                break
            except TimeoutError:
                continue

    async def _tick_once(self) -> None:
        if self._last_seen is None:
            return
        cutoff = self._last_seen
        async with SessionLocal() as db:
            stmt = (
                select(Alert)
                .where(Alert.created_at > cutoff)
                .order_by(Alert.created_at.asc())
                .limit(self._batch)
            )
            rows = list((await db.execute(stmt)).scalars().all())
            if not rows:
                return

            for alert in rows:
                try:
                    succeeded, failed = await dispatch_for_alert(
                        db, alert, client=self._client
                    )
                except Exception:
                    log.exception(
                        "alert_router.dispatch_crashed", alert_id=str(alert.id)
                    )
                    # Don't advance — retry on the next pass.
                    return
                if succeeded or failed:
                    log.info(
                        "alert_router.alert_dispatched",
                        alert_id=str(alert.id),
                        succeeded=succeeded,
                        failed=failed,
                    )

            self._last_seen = rows[-1].created_at


async def amain() -> None:
    worker = AlertRouterWorker()
    await worker.start()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(worker.stop()))
    try:
        await worker.run()
    finally:
        await worker.stop()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
    asyncio.run(amain())


if __name__ == "__main__":
    main()
