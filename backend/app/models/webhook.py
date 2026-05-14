"""Webhook subscriptions + delivery rows (Phase 3 #3.7).

A `WebhookSubscription` is an operator-registered URL that wants HMAC-
signed JSON notifications for a chosen subset of event types. A
`WebhookDelivery` records one attempted send (including retries
collapsed onto the same row via the `attempts` counter) so operators
can audit what their receivers actually saw.

The signing secret is stored Fernet-encrypted under the shared
notification encryption key — see
`app/services/webhook_dispatcher.py` for the helpers.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UuidPkMixin, utcnow

if TYPE_CHECKING:
    pass


# Keep in sync with the CHECK constraint in
# alembic/versions/20260513_2260_webhook_subscriptions.py and the
# WebhookEventType union in frontend/src/types/api.ts.
WEBHOOK_EVENT_TYPES: tuple[str, ...] = (
    "alert.opened",
    "alert.state_changed",
    # Phase 4 #4.1 — AI summariser writes one per alert when the row
    # lands in `alert_summary`. Subscribers use this to refresh the
    # analyst UI without polling the summary endpoint.
    "alert.summary_ready",
    "incident.opened",
    "incident.resolved",
    "job.completed",
    "job.failed",
    "host.enrolled",
    "host.disconnected",
)


# Module-level constants so callers don't typo a literal.
WEBHOOK_DELIVERY_STATUSES: tuple[str, ...] = (
    "pending",
    "delivered",
    "failed",
    "disabled",
)


class WebhookSubscription(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "webhook_subscription"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    # Fernet-ciphertext of the per-subscription HMAC signing secret.
    # Plaintext is generated server-side at create time, returned
    # once in the create response, and never round-tripped via GET.
    secret_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Plain text[] (not an enum) so adding a new event type doesn't
    # require an ALTER TYPE migration — the CHECK constraint enforces
    # membership instead.
    event_types: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Rolling consecutive-failure counter. Resets to 0 on the next
    # successful delivery; hits the threshold and the dispatcher
    # disables the subscription automatically so a wedged receiver
    # can't keep generating retry storms forever.
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_delivery_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    deliveries: Mapped[list[WebhookDelivery]] = relationship(
        back_populates="subscription",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint(
            "event_types <@ ARRAY['alert.opened','alert.state_changed',"
            "'alert.summary_ready','incident.opened','incident.resolved',"
            "'job.completed','job.failed','host.enrolled',"
            "'host.disconnected']::text[]",
            name="ck_webhook_subscription_event_types",
        ),
    )


class WebhookDelivery(UuidPkMixin, Base):
    __tablename__ = "webhook_delivery"

    subscription_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "webhook_subscription.id",
            ondelete="CASCADE",
            name="fk_webhook_delivery_subscription_id_webhook_subscription",
        ),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    payload_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # status is a string-with-CHECK rather than a PG enum so the dev
    # path adds new statuses without an ALTER TYPE dance. See module
    # docstring on `WEBHOOK_DELIVERY_STATUSES` for the valid values.
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_body_truncated: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # No updated_at on this table — once a delivery reaches a terminal
    # status (delivered/failed/disabled), the row is immutable. Tests
    # observing rows in flight read `attempts` instead.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        server_default=text("now()"),
        nullable=False,
    )

    subscription: Mapped[WebhookSubscription] = relationship(back_populates="deliveries")

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','delivered','failed','disabled')",
            name="ck_webhook_delivery_status",
        ),
    )
