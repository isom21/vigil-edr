"""Phase 4 #4.1: AI alert summariser worker.

Consumes ``settings.topic_webhook_events``. For each ``alert.opened``
envelope, calls ``summarise_and_persist`` to materialise the LLM
output into the ``alert_summary`` table and re-publish an
``alert.summary_ready`` envelope through the same bus.

Lifecycle copy of ``app/workers/intel_ingest.py``: a long-lived
asyncio task supervised by ``app.main.lifespan`` with an env-var
opt-out (``VIGIL_AI_SUMMARISER_ENABLED=0``) and the standard
``VIGIL_TEST_ENV=1`` short-circuit.

We piggy-back on the webhook event bus rather than carving a new
topic because the alert envelope is already there and the summariser
+ webhook dispatcher are independent consumers with their own group
ids — adding a new topic would just double the producer's work
without buying anything.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any
from uuid import UUID

import structlog
from aiokafka import AIOKafkaConsumer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.services.ai_client import AnthropicClient
from app.services.ai_summary import summarise_and_persist

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()


def _enabled() -> bool:
    if os.environ.get("VIGIL_TEST_ENV") == "1":
        return False
    raw = os.environ.get("VIGIL_AI_SUMMARISER_ENABLED")
    if raw is not None:
        return raw != "0"
    return settings.ai_summariser_enabled != "0"


async def handle_envelope(
    envelope: dict[str, Any],
    *,
    session_maker: SessionMaker | None = None,
    client: AnthropicClient | None = None,
) -> bool:
    """Process one Kafka envelope. Returns True when a summary row was
    written, False when the envelope was skipped (wrong event_type,
    bad shape, or the alert had vanished).

    Public so the test can drive a single envelope through without
    spinning up an aiokafka consumer.
    """
    event_type = envelope.get("event_type")
    if event_type != "alert.opened":
        return False
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return False
    alert_id_raw = payload.get("alert_id")
    if not isinstance(alert_id_raw, str):
        return False
    try:
        alert_id = UUID(alert_id_raw)
    except ValueError:
        log.warning("ai_summariser.bad_alert_id", value=alert_id_raw)
        return False

    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    async with sm() as db:
        row = await summarise_and_persist(db, alert_id, client=client)
        if row is None:
            return False
        await db.commit()
        return True


async def _consume(consumer: AIOKafkaConsumer) -> None:
    client = AnthropicClient()
    async for msg in consumer:
        if msg.value is None:
            continue
        try:
            envelope = json.loads(msg.value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.warning("ai_summariser.bad_message", error=str(exc))
            continue
        try:
            await handle_envelope(envelope, client=client)
        except Exception:  # pragma: no cover — never let the loop die
            log.exception(
                "ai_summariser.handle_failed",
                event_type=envelope.get("event_type") if isinstance(envelope, dict) else None,
            )


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    if not _enabled():
        log.info("ai_summariser.disabled")
        return

    consumer = AIOKafkaConsumer(
        settings.topic_webhook_events,
        bootstrap_servers=settings.kafka_brokers,
        enable_auto_commit=True,
        auto_offset_reset="latest",
        group_id="vigil-ai-summariser",
    )
    await consumer.start()
    log.info(
        "ai_summariser.starting",
        topic=settings.topic_webhook_events,
        model_id=settings.ai_model_id,
    )
    try:
        await _consume(consumer)
    except asyncio.CancelledError:
        log.info("ai_summariser.cancelled")
        raise
    finally:
        await consumer.stop()


__all__ = ["handle_envelope", "run_forever"]
