"""Async Kafka producer wrapper.

Used by the gRPC ingest service (M2) to publish telemetry batches to
`telemetry.raw`. Single shared producer per process.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from aiokafka import AIOKafkaProducer

from app.core.config import settings


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
                compression_type="lz4",
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
