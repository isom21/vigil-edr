"""Webhook event bus (Phase 3 #3.7).

Thin façade over the shared Kafka producer that publishes a webhook
event onto ``settings.topic_webhook_events``. The
``app.workers.webhook_dispatcher`` worker is the lone consumer.

State-transition hook sites (alert create / state-change handlers,
incident transitions, job terminal states, host enrollment) call
``publish_event(event_type, payload)``. The Kafka indirection keeps
the request path off the wire — the API handler doesn't wait for the
receiver to ack, it just enqueues. The worker handles retries,
back-off, and per-subscription disable-on-failure.

If Kafka isn't reachable (test env, single-instance dev where the
broker is down), ``publish_event`` swallows the producer's
exception, logs at WARNING, and returns. Webhooks are best-effort
out-of-band signals — dropping a single fire isn't worth blocking
the alert/incident/job state machine on. The receiver-side `GET
/deliveries` view is what an operator uses to confirm what actually
made it out.
"""

from __future__ import annotations

import os
from typing import Any

import structlog

from app.core.config import settings
from app.services.kafka import producer

log = structlog.get_logger()


def _enabled() -> bool:
    """The event bus is opt-out: set VIGIL_WEBHOOK_EVENT_BUS_ENABLED=0
    to disable producing events. Tests default to disabled
    (`VIGIL_TEST_ENV=1`) so the producer doesn't try to dial a Kafka
    that isn't there."""
    raw = os.environ.get("VIGIL_WEBHOOK_EVENT_BUS_ENABLED")
    if raw is not None:
        return raw != "0"
    return os.environ.get("VIGIL_TEST_ENV") != "1"


async def publish_event(event_type: str, payload: dict[str, Any]) -> None:
    """Enqueue a webhook event for the dispatcher worker. Best-effort:
    a producer failure is logged and silently swallowed rather than
    bubbled up to the state-transition caller."""
    if not _enabled():
        log.debug("webhook.event_bus.disabled", event_type=event_type)
        return
    try:
        await producer.send_json(
            settings.topic_webhook_events,
            key=event_type,
            value={"event_type": event_type, "payload": payload},
        )
        log.debug("webhook.event_bus.published", event_type=event_type)
    except Exception as exc:  # noqa: BLE001 — best-effort path
        log.warning(
            "webhook.event_bus.publish_failed",
            event_type=event_type,
            error=str(exc),
        )


__all__ = ["publish_event"]
