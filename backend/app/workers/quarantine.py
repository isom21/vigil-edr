"""M20.c quarantine outcome worker.

Consumes `telemetry.normalized` and watches for `agent.quarantine.*`.
For QUARANTINED outcomes, inserts a quarantined_files row. For
RELEASED outcomes, flips the existing row's status to released.
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
from datetime import UTC, datetime
from uuid import UUID

import structlog
from aiokafka import AIOKafkaConsumer
from sqlalchemy import select

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import QuarantinedFile, QuarantineStatus

log = structlog.get_logger()


class QuarantineWorker:
    def __init__(self) -> None:
        self.consumer: AIOKafkaConsumer | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        self.consumer = AIOKafkaConsumer(
            settings.topic_telemetry_normalized,
            bootstrap_servers=settings.kafka_brokers,
            group_id="quarantine-tracker",
            enable_auto_commit=False,
            auto_offset_reset="latest",
        )
        await self.consumer.start()
        log.info("quarantine.start", topic=settings.topic_telemetry_normalized)

    async def stop(self) -> None:
        self._stop.set()
        if self.consumer is not None:
            await self.consumer.stop()
        log.info("quarantine.stop")

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
                log.exception("quarantine.decode_failed", offset=msg.offset)
                await self.consumer.commit()
                continue
            try:
                await self._handle(doc)
            except Exception:
                log.exception("quarantine.handle_failed", offset=msg.offset)
            await self.consumer.commit()

    async def _handle(self, doc: dict) -> None:
        agent = doc.get("agent") or {}
        q = agent.get("quarantine")
        if not q:
            return
        outcome = q.get("outcome")
        sha256 = q.get("sha256")
        if not sha256:
            return
        host_id_str = (doc.get("host") or {}).get("id")
        if not host_id_str:
            return
        try:
            host_id = UUID(host_id_str)
        except ValueError:
            return
        path = q.get("path") or ""
        size = int(q.get("size_bytes") or 0)
        deleted_original = bool(q.get("deleted_original"))

        async with SessionLocal() as db:
            if outcome == "quarantined":
                row = QuarantinedFile(
                    host_id=host_id,
                    original_path=path,
                    sha256=sha256,
                    size_bytes=size,
                    deleted_original=deleted_original,
                    quarantined_at=datetime.now(UTC),
                    status=QuarantineStatus.ACTIVE,
                )
                db.add(row)
                await db.commit()
                log.info(
                    "quarantine.row_created",
                    host_id=str(host_id),
                    sha256=sha256[:16],
                    path=path[:120],
                )
            elif outcome == "released":
                # Find the most recent active row for this (host, sha256).
                stmt = (
                    select(QuarantinedFile)
                    .where(
                        QuarantinedFile.host_id == host_id,
                        QuarantinedFile.sha256 == sha256,
                        QuarantinedFile.status == QuarantineStatus.ACTIVE,
                    )
                    .order_by(QuarantinedFile.quarantined_at.desc())
                    .limit(1)
                )
                row = (await db.execute(stmt)).scalar_one_or_none()
                if row is None:
                    log.warning(
                        "quarantine.released_unknown",
                        host_id=str(host_id),
                        sha256=sha256[:16],
                    )
                    return
                row.status = QuarantineStatus.RELEASED
                row.released_at = datetime.now(UTC)
                await db.commit()
                log.info(
                    "quarantine.row_released",
                    host_id=str(host_id),
                    sha256=sha256[:16],
                )
            elif outcome == "failed":
                log.warning(
                    "quarantine.agent_reported_failure",
                    host_id=str(host_id),
                    sha256=sha256[:16],
                    path=path[:120],
                )


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
    worker = QuarantineWorker()
    await worker.start()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(worker.stop()))
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
