"""Pydantic schemas for webhook subscription CRUD + delivery views.

Plaintext secrets only ever surface in the create response. After
that the public projection only carries metadata + counters; rotating
the secret requires a dedicated rotate endpoint (POST /rotate) so the
operator does it consciously and the audit log captures the moment.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl, field_validator

from app.models import WEBHOOK_EVENT_TYPES
from app.schemas.common import ORMModel, Page

# A type alias the schemas + audit payloads share. Keep in sync with
# WEBHOOK_EVENT_TYPES at runtime — the field_validator below enforces.
WebhookEventType = Literal[
    "alert.opened",
    "alert.state_changed",
    # Phase 4 #4.1 — the AI summariser writes one of these per alert
    # when the row lands in `alert_summary`. Subscribers use it to
    # refresh the analyst UI without polling.
    "alert.summary_ready",
    "incident.opened",
    "incident.resolved",
    "job.completed",
    "job.failed",
    "host.enrolled",
    "host.disconnected",
]


class WebhookSubscriptionOut(ORMModel):
    """Public projection — never includes the signing secret."""

    id: UUID
    name: str
    url: str
    event_types: list[str]
    enabled: bool
    failure_count: int
    last_delivery_at: datetime | None
    last_failure_at: datetime | None
    created_at: datetime
    updated_at: datetime


class WebhookSubscriptionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: HttpUrl
    event_types: list[WebhookEventType] = Field(min_length=1)
    enabled: bool = True

    @field_validator("event_types")
    @classmethod
    def _no_duplicates(cls, v: list[str]) -> list[str]:
        # Postgres' array <@ check would accept duplicates; we collapse
        # them at the API boundary so the dispatcher doesn't fan out
        # the same event N times to the same subscription.
        seen: set[str] = set()
        out: list[str] = []
        for item in v:
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out


class WebhookSubscriptionCreateResponse(WebhookSubscriptionOut):
    """Create response carries the freshly-minted secret once. The
    receiver-side verifier should record this immediately — there's no
    way to retrieve it afterward; rotation issues a new value."""

    secret: str


class WebhookSubscriptionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    url: HttpUrl | None = None
    event_types: list[WebhookEventType] | None = Field(default=None, min_length=1)
    enabled: bool | None = None

    @field_validator("event_types")
    @classmethod
    def _no_duplicates(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        seen: set[str] = set()
        out: list[str] = []
        for item in v:
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out


class WebhookTestRequest(BaseModel):
    """Optional override of the event type the synthetic test fires.
    Defaults to alert.opened — every receiver subscribed to anything
    real should be able to ack a synthetic alert."""

    event_type: WebhookEventType = "alert.opened"


class WebhookDeliveryOut(ORMModel):
    id: UUID
    subscription_id: UUID
    event_type: str
    payload_json: dict[str, Any]
    status: str
    attempts: int
    response_status: int | None
    response_body_truncated: str | None
    delivered_at: datetime | None
    created_at: datetime


WebhookDeliveryPage = Page[WebhookDeliveryOut]


__all__ = [
    "WEBHOOK_EVENT_TYPES",
    "WebhookDeliveryOut",
    "WebhookDeliveryPage",
    "WebhookEventType",
    "WebhookSubscriptionCreate",
    "WebhookSubscriptionCreateResponse",
    "WebhookSubscriptionOut",
    "WebhookSubscriptionUpdate",
    "WebhookTestRequest",
]
