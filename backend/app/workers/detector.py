"""Detector worker.

Reads ECS-normalized events from telemetry.normalized and runs the IOC
matcher against each. Sigma is evaluated separately by sigma-scheduler
(scheduled OpenSearch correlation), not in this worker.

Each match becomes:
- one Alert row in PG (state=new, action_taken=detect)
- one alerts-YYYYMMDD doc in OpenSearch

Run with:
    python -m app.workers.detector
"""
from __future__ import annotations

import asyncio
import json
import logging
import signal
from datetime import datetime, timezone
from uuid import UUID

import structlog
from aiokafka import AIOKafkaConsumer

from app.core.config import settings
from app.core.db import SessionLocal
from app.services import opensearch as os_svc
from app.services.detector import DetectorState, emit_alerts, evaluate

log = structlog.get_logger()


class Detector:
    def __init__(self) -> None:
        self.consumer: AIOKafkaConsumer | None = None
        self.os_client = os_svc._client()
        self.detector = DetectorState()
        self._stop = asyncio.Event()

    async def start(self) -> None:
        await os_svc.ensure_template(self.os_client)
        self.consumer = AIOKafkaConsumer(
            settings.topic_telemetry_normalized,
            bootstrap_servers=settings.kafka_brokers,
            group_id="detector",
            enable_auto_commit=False,
            auto_offset_reset="earliest",
        )
        await self.consumer.start()
        log.info("detector.start", topic=settings.topic_telemetry_normalized)

    async def stop(self) -> None:
        self._stop.set()
        if self.consumer is not None:
            await self.consumer.stop()
        await self.os_client.close()
        log.info("detector.stop")

    async def run(self) -> None:
        assert self.consumer is not None
        while not self._stop.is_set():
            try:
                msg = await asyncio.wait_for(self.consumer.getone(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            try:
                ecs = json.loads(msg.value)
            except Exception:
                log.exception("detector.decode_failed", offset=msg.offset)
                await self.consumer.commit()
                continue

            try:
                snap = await self.detector.get()
                matches = evaluate(ecs, snap)
            except Exception:
                log.exception("detector.eval_failed")
                matches = []

            if matches:
                host_id_str = ecs.get("host", {}).get("id")
                if host_id_str:
                    host_id = UUID(host_id_str)
                    async with SessionLocal() as db:
                        alert_ids = await emit_alerts(
                            db, host_id=host_id, matches=matches, ecs=ecs
                        )
                        await db.commit()

                    now = datetime.now(timezone.utc)
                    for alert_id, m in zip(alert_ids, matches):
                        alert_doc = {
                            "@timestamp": now.isoformat(),
                            "alert": {
                                "id": str(alert_id),
                                "summary": m.summary,
                                "severity": m.severity.value,
                                "action_taken": "detect",
                                "matched_field": m.matched_field,
                                "matched_value": m.matched_value,
                                "engine": "ioc",
                            },
                            "rule": {"id": str(m.rule_id), "name": m.rule_name},
                            "host": ecs.get("host", {}),
                            "event": {"id": ecs.get("event", {}).get("id")},
                        }
                        await self.os_client.index(
                            index=os_svc.alerts_index_for(now), body=alert_doc
                        )
                    log.info(
                        "detector.alerts_emitted",
                        n=len(matches),
                        host_id=host_id_str,
                        rules=[m.rule_name for m in matches],
                    )

            await self.consumer.commit()


async def amain() -> None:
    d = Detector()
    await d.start()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(d.stop()))
    try:
        await d.run()
    finally:
        await d.stop()


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
