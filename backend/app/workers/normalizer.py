"""Normalizer worker.

Reads protobuf-encoded EndpointEvents from telemetry.raw, converts to
ECS-shaped JSON, and writes to telemetry.normalized. All downstream
consumers (indexer, detector, sigma-scheduler) read JSON from there.

Run with:
    python -m app.workers.normalizer
"""

from __future__ import annotations

import asyncio
import signal

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from app.core.config import settings
from app.proto_gen.edr.v1 import events_pb2
from app.services.host_cache import hostname_for
from app.services.normalizer import to_ecs

log = structlog.get_logger()


class Normalizer:
    def __init__(self) -> None:
        self.consumer: AIOKafkaConsumer | None = None
        self.producer: AIOKafkaProducer | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        self.consumer = AIOKafkaConsumer(
            settings.topic_telemetry_raw,
            bootstrap_servers=settings.kafka_brokers,
            group_id="normalizer",
            enable_auto_commit=False,
            auto_offset_reset="earliest",
        )
        self.producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_brokers,
            acks="all",
            enable_idempotence=True,
            compression_type="gzip",
            linger_ms=20,
        )
        await self.consumer.start()
        await self.producer.start()
        log.info(
            "normalizer.start",
            input=settings.topic_telemetry_raw,
            output=settings.topic_telemetry_normalized,
        )

    async def stop(self) -> None:
        self._stop.set()
        if self.consumer is not None:
            await self.consumer.stop()
        if self.producer is not None:
            await self.producer.stop()
        log.info("normalizer.stop")

    async def run(self) -> None:
        assert self.consumer is not None and self.producer is not None
        import json as _json

        while not self._stop.is_set():
            try:
                msg = await asyncio.wait_for(self.consumer.getone(), timeout=1.0)
            except TimeoutError:
                continue
            if msg.value is None:
                await self.consumer.commit()
                continue
            try:
                ev = events_pb2.EndpointEvent()
                ev.ParseFromString(msg.value)
                ecs = to_ecs(ev)
            except Exception:
                log.exception("normalizer.decode_failed", offset=msg.offset)
                # Commit the offset anyway so we don't loop on a bad message.
                await self.consumer.commit()
                continue

            # M7.7: enrich host.hostname / host.os so analysts can search
            # by hostname in OpenSearch. Agents send only host.id on
            # individual events — the canonical hostname lives on the
            # Host row populated at enrollment time. Cached in-process
            # for ~60s so the DB cost amortises across the per-host
            # event burst.
            try:
                from uuid import UUID as _UUID

                hid_str = ecs.get("host", {}).get("id")
                if hid_str:
                    hn, osf = await hostname_for(_UUID(hid_str))
                    if hn:
                        ecs["host"]["hostname"] = hn
                    if osf:
                        ecs["host"].setdefault("os", {})["family"] = osf
            except Exception:
                # Best-effort; never block the normalizer on enrichment.
                log.exception("normalizer.enrich_failed", offset=msg.offset)

            payload = _json.dumps(ecs, separators=(",", ":")).encode("utf-8")
            try:
                # Key by host_id so each host's stream lands on the same partition,
                # preserving per-host ordering downstream.
                key = (ecs.get("host", {}).get("id") or "").encode("utf-8") or None
                await self.producer.send_and_wait(
                    settings.topic_telemetry_normalized, value=payload, key=key
                )
                await self.consumer.commit()
            except Exception:
                log.exception("normalizer.produce_failed", offset=msg.offset)
                # Don't commit — replay this message on restart.


async def amain() -> None:
    n = Normalizer()
    await n.start()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(n.stop()))
    try:
        await n.run()
    finally:
        await n.stop()


def main() -> None:
    from app.core.logging import configure as _configure_logging

    _configure_logging()
    asyncio.run(amain())


if __name__ == "__main__":
    main()
