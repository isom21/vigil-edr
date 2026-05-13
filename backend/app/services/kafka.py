"""Async Kafka producer wrapper.

Used by the gRPC ingest service (M2) to publish telemetry batches to
`telemetry.raw`. Single shared producer per process.

Phase 3 #3.5 adds `publish_playbook_run` — a fire-and-forget helper
the alert path uses to hand a matched playbook off to the executor
worker. The producer is started lazily; the caller swallows producer
unavailability so a Kafka outage doesn't break the alert pipeline.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import UUID

import structlog
from aiokafka import AIOKafkaProducer

from app.core.config import settings

_log = structlog.get_logger()


class KafkaProducer:
    def __init__(self) -> None:
        self._producer: AIOKafkaProducer | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        async with self._lock:
            if self._producer is not None:
                return
            self._producer = AIOKafkaProducer(
                bootstrap_servers=settings.kafka_brokers,
                acks="all",
                enable_idempotence=True,
                compression_type="gzip",
                linger_ms=20,
                max_batch_size=1024 * 1024,
            )
            await self._producer.start()

    async def stop(self) -> None:
        async with self._lock:
            if self._producer is None:
                return
            await self._producer.stop()
            self._producer = None

    async def send_json(self, topic: str, key: str | None, value: dict[str, Any]) -> None:
        assert self._producer is not None, "producer not started"
        await self._producer.send_and_wait(
            topic,
            value=json.dumps(value, separators=(",", ":")).encode("utf-8"),
            key=key.encode("utf-8") if key else None,
        )

    async def send_bytes(self, topic: str, key: str | None, value: bytes) -> None:
        assert self._producer is not None, "producer not started"
        await self._producer.send_and_wait(
            topic, value=value, key=key.encode("utf-8") if key else None
        )


producer = KafkaProducer()


async def publish_playbook_run(playbook_id: UUID, alert_id: UUID | None) -> bool:
    """Fan a matched (playbook, alert) onto the `playbook.runs` topic
    so the executor worker can pick it up out-of-band of the alert
    fire path.

    Returns True on publish, False when the producer wasn't reachable
    (Kafka outage, dev environment without a broker). The caller MUST
    treat False as "skipped" — playbooks are additive to the rule's
    own RuleAction, so missing a playbook fire is not a correctness
    bug, just a missed automation. We log a warning so the operator
    sees it in the manager log.
    """
    try:
        await producer.start()
        await producer.send_json(
            settings.topic_playbook_runs,
            key=str(playbook_id),
            value={
                "playbook_id": str(playbook_id),
                "alert_id": str(alert_id) if alert_id else None,
            },
        )
        return True
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "playbook.kafka.publish_failed",
            playbook_id=str(playbook_id),
            alert_id=str(alert_id) if alert_id else None,
            error=str(exc),
        )
        return False
