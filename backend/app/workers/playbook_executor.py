"""Playbook executor (Phase 3 #3.5).

Consumes `playbook.runs`, loads the referenced playbook + alert, and
walks the playbook's steps via `app.services.playbooks.execute_playbook`.
Each message produces exactly one PlaybookRun row.

Lifecycle shape mirrors `app.workers.intel_ingest` so the lifespan
wiring in `app/main.py` looks the same — `run_forever()` is the entry
point and never returns. The inner consume loop mirrors
`process_chain_indexer.py` (manual commits, decode-failure tolerance,
no head-of-line blocking on a poison message).
"""

from __future__ import annotations

import asyncio
import json
from uuid import UUID

import structlog
from aiokafka import AIOKafkaConsumer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.metrics import playbook_executor_handle_failures_total
from app.models import Playbook
from app.services.playbooks import execute_playbook

log = structlog.get_logger()

__all__ = ("PlaybookExecutor", "run_forever", "handle_message")


async def handle_message(db: AsyncSession, doc: dict) -> bool:
    """Route one decoded `playbook.runs` message. Returns True iff a
    PlaybookRun row was created. The test suite calls this directly
    so the Kafka path doesn't need a broker fixture."""
    pid_raw = doc.get("playbook_id")
    alert_raw = doc.get("alert_id")
    if not isinstance(pid_raw, str):
        return False
    try:
        playbook_id = UUID(pid_raw)
    except (TypeError, ValueError):
        return False
    alert_id: UUID | None = None
    if isinstance(alert_raw, str):
        try:
            alert_id = UUID(alert_raw)
        except (TypeError, ValueError):
            alert_id = None
    if alert_id is None:
        # Today's match path always carries an alert_id. Skipping
        # cleanly here keeps the worker forward-compatible with a
        # future "test fire" path that hands a synthetic envelope.
        log.warning("playbook.executor.missing_alert_id", playbook_id=str(playbook_id))
        return False

    playbook = await db.get(Playbook, playbook_id)
    if playbook is None:
        log.warning("playbook.executor.playbook_not_found", playbook_id=str(playbook_id))
        return False
    if not playbook.enabled:
        log.info("playbook.executor.disabled", playbook_id=str(playbook_id))
        return False

    run = await execute_playbook(db, playbook=playbook, alert_id=alert_id)
    log.info(
        "playbook.executor.completed",
        playbook_id=str(playbook_id),
        alert_id=str(alert_id),
        run_id=str(run.id),
        status=run.status,
    )
    return True


class PlaybookExecutor:
    def __init__(self) -> None:
        self.consumer: AIOKafkaConsumer | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        self.consumer = AIOKafkaConsumer(
            settings.topic_playbook_runs,
            bootstrap_servers=settings.kafka_brokers,
            group_id="playbook_executor",
            enable_auto_commit=False,
            auto_offset_reset="latest",
            session_timeout_ms=15_000,
            max_poll_interval_ms=300_000,
        )
        await self.consumer.start()
        log.info("playbook.executor.start", topic=settings.topic_playbook_runs)

    async def stop(self) -> None:
        self._stop.set()
        if self.consumer is not None:
            await self.consumer.stop()
        log.info("playbook.executor.stop")

    async def run(self) -> None:
        assert self.consumer is not None
        while not self._stop.is_set():
            try:
                msg = await asyncio.wait_for(self.consumer.getone(), timeout=1.0)
            except TimeoutError:
                continue
            if msg.value is None:
                await self.consumer.commit()
                continue
            try:
                doc = json.loads(msg.value)
            except Exception:
                log.exception("playbook.executor.decode_failed", offset=msg.offset)
                await self.consumer.commit()
                continue
            # CODE-28: only commit the Kafka offset when the playbook
            # run actually persisted. Pre-PR an exception in
            # `handle_message` (DB outage, validation error, etc.)
            # log-and-committed, dropping the alert that triggered the
            # playbook entirely. Now leaving the offset uncommitted
            # makes the consumer re-deliver the message on the next
            # poll cycle.
            try:
                async with SessionLocal() as db:
                    await handle_message(db, doc)
                    await db.commit()
            except Exception:
                log.exception("playbook.executor.handle_failed", offset=msg.offset)
                playbook_executor_handle_failures_total.inc()
                continue
            await self.consumer.commit()


async def run_forever() -> None:
    """Lifespan entry point. Mirrors `intel_ingest.run_forever`."""
    worker = PlaybookExecutor()
    try:
        await worker.start()
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("playbook.executor.start_failed")
        # Sleep before re-raising so the lifespan doesn't tight-loop on
        # a missing Kafka. Operators see the missing playbook fires in
        # the manager log; manual `gh fixes` to bring Kafka back up.
        await asyncio.sleep(30)
        raise
    try:
        await worker.run()
    finally:
        await worker.stop()
