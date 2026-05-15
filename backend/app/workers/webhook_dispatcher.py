"""Phase 3 #3.7: webhook dispatcher worker.

Consumes ``settings.topic_webhook_events``. For each message:

  1. Decode the envelope ``{"event_type": str, "payload": dict}``.
  2. Load all enabled webhook subscriptions whose ``event_types``
     contains this event type.
  3. For each match, call
     :func:`app.services.webhook_dispatcher.deliver` with the
     subscription + payload. The dispatcher records a delivery row
     and mutates the subscription's failure counters; we commit
     after every batch so an operator sees deliveries land in
     near-real-time.

Lifecycle mirrors ``app/workers/intel_ingest.py`` — wired into
``app.main.lifespan`` as a long-lived background task. The opt-out
env var is ``VIGIL_WEBHOOK_DISPATCHER_ENABLED=0`` (and the same
``VIGIL_TEST_ENV=1`` short-circuit other workers use).
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any

import httpx
import structlog
from aiokafka import AIOKafkaConsumer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.metrics import webhook_dispatcher_handle_failures_total
from app.models import WebhookSubscription
from app.services.webhook_dispatcher import deliver

SessionMaker = Callable[[], AbstractAsyncContextManager[AsyncSession]]

log = structlog.get_logger()


async def _matching_subscriptions(db: AsyncSession, event_type: str) -> list[WebhookSubscription]:
    """Enabled subscriptions whose ``event_types`` array contains the
    given type. The Postgres-side ANY() does the membership probe so
    we don't scan and filter in Python."""
    stmt = (
        select(WebhookSubscription)
        .where(WebhookSubscription.enabled.is_(True))
        .where(WebhookSubscription.event_types.any(event_type))  # type: ignore[arg-type]
    )
    return list((await db.execute(stmt)).scalars().all())


async def dispatch_event(
    event_type: str,
    payload: dict[str, Any],
    *,
    session_maker: SessionMaker | None = None,
    client: httpx.AsyncClient | None = None,
) -> int:
    """Fan one event out to every matching subscription. Returns the
    number of deliveries attempted (regardless of success). The worker
    main loop calls this once per Kafka message; tests call it directly
    with an injected httpx client + session_maker.
    """
    sm: SessionMaker = session_maker if session_maker is not None else SessionLocal
    async with sm() as db:
        subs = await _matching_subscriptions(db, event_type)
        if not subs:
            return 0

        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient()
        try:
            for sub in subs:
                delivery = await deliver(sub, event_type, payload, client=client)
                db.add(delivery)
        finally:
            if owns_client:
                await client.aclose()

        await db.commit()
        return len(subs)


def _enabled() -> bool:
    if os.environ.get("VIGIL_TEST_ENV") == "1":
        return False
    return os.environ.get("VIGIL_WEBHOOK_DISPATCHER_ENABLED", "1") != "0"


async def _consume(consumer: AIOKafkaConsumer) -> None:
    async for msg in consumer:
        if msg.value is None:
            continue
        try:
            envelope = json.loads(msg.value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.warning("webhook.worker.bad_message", error=str(exc))
            continue
        event_type = envelope.get("event_type")
        payload = envelope.get("payload")
        if not isinstance(event_type, str) or not isinstance(payload, dict):
            log.warning(
                "webhook.worker.bad_envelope",
                keys=list(envelope.keys()) if isinstance(envelope, dict) else None,
            )
            continue
        # CODE-29: only commit the Kafka offset when dispatch_event
        # actually completed. The dispatcher used to run with
        # enable_auto_commit=True, so a transient subscriber failure
        # (broken HMAC secret, dead webhook URL) silently dropped the
        # event. Now consumer.commit() is the explicit success signal.
        try:
            n = await dispatch_event(event_type, payload)
        except Exception:
            log.exception("webhook.worker.dispatch_failed", event_type=event_type)
            webhook_dispatcher_handle_failures_total.inc()
            continue
        log.info("webhook.worker.dispatched", event_type=event_type, fanout=n)
        await consumer.commit()


async def run_forever() -> None:
    """Main loop. Wrapped in lifespan as a background task."""
    if not _enabled():
        log.info("webhook.worker.disabled")
        return

    consumer = AIOKafkaConsumer(
        settings.topic_webhook_events,
        bootstrap_servers=settings.kafka_brokers,
        # CODE-29: manual commit so we only acknowledge an event after
        # dispatch_event succeeded (see _consume above). The previous
        # auto-commit setting dropped events on any subscriber failure.
        enable_auto_commit=False,
        auto_offset_reset="latest",
        group_id="vigil-webhook-dispatcher",
    )
    await consumer.start()
    log.info("webhook.worker.starting", topic=settings.topic_webhook_events)
    try:
        await _consume(consumer)
    except asyncio.CancelledError:
        log.info("webhook.worker.cancelled")
        raise
    finally:
        await consumer.stop()


__all__ = ["dispatch_event", "run_forever"]
