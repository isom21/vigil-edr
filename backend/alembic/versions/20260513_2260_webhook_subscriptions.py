"""Webhook subscriptions (Phase 3 #3.7).

Operator-registered URLs that receive HMAC-signed JSON notifications
on enumerated event types (alert.opened, alert.state_changed,
incident.opened, incident.resolved, job.completed, job.failed,
host.enrolled, host.disconnected). Distinct from
`notification_channel` — that's the alert-routing alarm path with
per-kind sender semantics; webhooks fire on event-bus topics and
carry a generic JSON envelope the consumer parses.

Two tables:

  * ``webhook_subscription`` — one row per registered URL. Stores the
    URL, a Fernet-encrypted HMAC signing secret, the list of event
    types the subscriber is interested in, an enabled flag, and rolling
    delivery health counters. ``event_types`` is a text[] with a CHECK
    constraint enumerating the supported types — that way a typo at
    subscribe time is rejected by Postgres instead of silently never
    matching.
  * ``webhook_delivery`` — one row per attempted delivery, including
    retries. Status enumerates pending/delivered/failed/disabled (the
    last for deliveries that were aborted because the parent
    subscription got auto-disabled mid-flight). ``payload_json`` keeps
    the envelope we tried to send so an operator can re-fire from the
    UI; ``response_body_truncated`` keeps a snippet of the receiver's
    response for debugging without unbounded growth.

Indices:
  * ``(subscription_id, created_at DESC)`` — drives the per-subscription
    history view.
  * ``(status, created_at DESC)`` — drives the worker's "next pending"
    poll without scanning the whole table.

Revision ID: e7a8b9c0d1e2
Revises: e5e6f7a8b9c0
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e7a8b9c0d1e2"
down_revision: str | None = "e5e6f7a8b9c0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Keep in sync with WebhookEventType in app/models/webhook.py and the
# WebhookEventType union in frontend/src/types/api.ts.
_EVENT_TYPES = (
    "alert.opened",
    "alert.state_changed",
    "incident.opened",
    "incident.resolved",
    "job.completed",
    "job.failed",
    "host.enrolled",
    "host.disconnected",
)


def upgrade() -> None:
    quoted = ",".join(f"'{e}'" for e in _EVENT_TYPES)

    op.create_table(
        "webhook_subscription",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        # Fernet-ciphertext of the HMAC signing secret. Plaintext is
        # only ever shown once at create time so an operator can
        # configure the receiver's verifier; after that, rotation is
        # the only path back to the value.
        sa.Column("secret_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column(
            "event_types",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("ARRAY[]::text[]"),
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "failure_count", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_webhook_subscription"),
        sa.UniqueConstraint("name", name="uq_webhook_subscription_name"),
        # Postgres-side guard: every value of event_types must belong
        # to the enumerated set. `<@` is "is contained by" — the row's
        # array must be a subset of the constant whitelist. Empty array
        # is fine (the API rejects empty lists separately).
        sa.CheckConstraint(
            f"event_types <@ ARRAY[{quoted}]::text[]",
            name="ck_webhook_subscription_event_types",
        ),
    )

    op.create_table(
        "webhook_delivery",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("subscription_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column(
            "payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("response_body_truncated", sa.Text(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_webhook_delivery"),
        sa.ForeignKeyConstraint(
            ["subscription_id"],
            ["webhook_subscription.id"],
            ondelete="CASCADE",
            name="fk_webhook_delivery_subscription_id_webhook_subscription",
        ),
        sa.CheckConstraint(
            "status IN ('pending','delivered','failed','disabled')",
            name="ck_webhook_delivery_status",
        ),
    )
    op.create_index(
        "ix_webhook_delivery_subscription_id_created_at",
        "webhook_delivery",
        ["subscription_id", sa.text("created_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_webhook_delivery_status_created_at",
        "webhook_delivery",
        ["status", sa.text("created_at DESC")],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_webhook_delivery_status_created_at", table_name="webhook_delivery"
    )
    op.drop_index(
        "ix_webhook_delivery_subscription_id_created_at",
        table_name="webhook_delivery",
    )
    op.drop_table("webhook_delivery")
    op.drop_table("webhook_subscription")
