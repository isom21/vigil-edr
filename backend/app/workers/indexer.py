"""Telemetry indexer + IOC detector worker.

Pipeline (single process for now):
  Kafka topic_telemetry_raw (proto-encoded EndpointEvent, key=host_id)
    -> normalize to ECS dict
    -> bulk-index into telemetry-YYYYMMDD
    -> evaluate IOC snapshot
    -> on match, write Alert rows + index alert docs in alerts-YYYYMMDD

Run with:
    python -m app.workers.indexer
"""
from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog
from aiokafka import AIOKafkaConsumer
from opensearchpy._async.helpers.actions import async_bulk

from app.core.config import settings
from app.core.db import SessionLocal
from app.proto_gen.edr.v1 import events_pb2
from app.services import opensearch as os_svc
from app.services.detector import DetectorState, emit_alerts, evaluate
from app.services.normalizer import to_ecs

log = structlog.get_logger()

BATCH_SIZE = 200
BATCH_LINGER_S = 1.0


async def _bulk_actions(docs: list[tuple[str, dict[str, Any]]]):
    for index, doc in docs:
        yield {"_op_type": "index", "_index": index, "_source": doc}


class Indexer:
    def __init__(self) -> None:
        self.consumer: AIOKafkaConsumer | None = None
        self.os_client = os_svc._client()
        self.detector = DetectorState()
        self._stop = asyncio.Event()

    async def start(self) -> None:
        await os_svc.ensure_template(self.os_client)
        self.consumer = AIOKafkaConsumer(
            settings.topic_telemetry_raw,
            bootstrap_servers=settings.kafka_brokers,
            group_id="indexer",
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            session_timeout_ms=15_000,
            max_poll_interval_ms=300_000,
        )
        await self.consumer.start()
        log.info(
            "indexer.start", topic=settings.topic_telemetry_raw, opensearch=settings.opensearch_url
        )

    async def stop(self) -> None:
        self._stop.set()
        if self.consumer is not None:
            await self.consumer.stop()
        await self.os_client.close()
        log.info("indexer.stop")

    async def run(self) -> None:
        assert self.consumer is not None
        buffered: list[tuple[str, dict[str, Any]]] = []
        last_flush = asyncio.get_event_loop().time()

        async def flush() -> None:
            nonlocal buffered, last_flush
            if not buffered:
                return
            try:
                await async_bulk(self.os_client, _bulk_actions(buffered), refresh=False)
            except Exception:
                log.exception("indexer.bulk_failed", n=len(buffered))
                # keep going — better to drop a batch than wedge the consumer
            else:
                log.debug("indexer.bulk_indexed", n=len(buffered))
            buffered = []
            last_flush = asyncio.get_event_loop().time()
            await self.consumer.commit()

        while not self._stop.is_set():
            try:
                msg = await asyncio.wait_for(self.consumer.getone(), timeout=BATCH_LINGER_S)
            except asyncio.TimeoutError:
                if buffered:
                    await flush()
                continue

            try:
                ev = events_pb2.EndpointEvent()
                ev.ParseFromString(msg.value)
            except Exception:
                log.exception("indexer.decode_failed", offset=msg.offset)
                continue

            ecs = to_ecs(ev)
            now = datetime.now(timezone.utc)
            buffered.append((os_svc.telemetry_index_for(now), ecs))

            # Run IOC detection synchronously per event. M2 volume is low.
            try:
                snap = await self.detector.get()
                matches = evaluate(ecs, snap)
            except Exception:
                log.exception("indexer.detector_error", event_id=ecs.get("event", {}).get("id"))
                matches = []

            if matches:
                host_id = UUID(ecs["host"]["id"])
                async with SessionLocal() as db:
                    alert_ids = await emit_alerts(db, host_id=host_id, matches=matches, ecs=ecs)
                    await db.commit()
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
                        },
                        "rule": {"id": str(m.rule_id), "name": m.rule_name},
                        "host": ecs.get("host", {}),
                        "event": {"id": ecs.get("event", {}).get("id")},
                    }
                    buffered.append((os_svc.alerts_index_for(now), alert_doc))
                log.info(
                    "indexer.alerts_emitted",
                    n=len(matches),
                    host_id=ecs["host"]["id"],
                    rules=[m.rule_name for m in matches],
                )

            if (
                len(buffered) >= BATCH_SIZE
                or (asyncio.get_event_loop().time() - last_flush) >= BATCH_LINGER_S
            ):
                await flush()


async def amain() -> None:
    indexer = Indexer()
    await indexer.start()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(indexer.stop()))

    try:
        await indexer.run()
    finally:
        await indexer.stop()


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
