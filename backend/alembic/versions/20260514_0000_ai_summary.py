"""AI-assisted analyst (Phase 4 #4.1).

One new table — ``alert_summary`` — and an additive change to the
existing ``ck_webhook_subscription_event_types`` CHECK so the new
``alert.summary_ready`` event can be subscribed to like any other
webhook event.

The ``alert_summary`` table is a sidecar to ``alerts``: at most one
row per alert (UNIQUE ``alert_id``), so an analyst gets one canonical
LLM rendering rather than a churning history. If the summariser
worker re-runs because the model_id changed, the upstream service
deletes the old row first and inserts the new one in the same tx —
this table is INSERT-mostly, not UPDATE-friendly.

Tenant scoping is denormalised onto the row so the GET endpoint can
apply ``apply_tenant_scope`` without joining ``alerts``; the FK still
keeps cascade-on-delete semantics tight when the parent alert is
removed.

Token counts are stored verbatim from the Anthropic response so an
operator can audit cache effectiveness. The Anthropic SDK returns
``cache_read_input_tokens`` + ``cache_creation_input_tokens`` +
``input_tokens`` separately; we collapse to a single
``cached_input_tokens`` field (the cache-read count) because the
rule-pack catalogue we ship in the system prompt is the only piece
that ever caches — there's no other reason to break the bookkeeping
down further at this point.

Revision ID: f2a3b4c5d6e7
Revises: e7a8b9c0d1e2
Create Date: 2026-05-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f2a3b4c5d6e7"
down_revision: str | None = "e7a8b9c0d1e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Keep in sync with WEBHOOK_EVENT_TYPES in app/models/webhook.py and
# the WebhookEventType union in frontend/src/types/api.ts. The webhook
# subscription CHECK constraint is dropped + recreated rather than
# extended in place because Postgres has no ALTER CONSTRAINT for CHECK
# bodies — drop/add is the only option, and it's cheap.
_EVENT_TYPES = (
    "alert.opened",
    "alert.state_changed",
    "alert.summary_ready",
    "incident.opened",
    "incident.resolved",
    "job.completed",
    "job.failed",
    "host.enrolled",
    "host.disconnected",
)


def upgrade() -> None:
    op.create_table(
        "alert_summary",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column(
            "suggested_response_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("model_id", sa.Text(), nullable=False),
        sa.Column(
            "cached_input_tokens",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "output_tokens",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_alert_summary"),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            ondelete="CASCADE",
            name="fk_alert_summary_alert_id_alerts",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_alert_summary_tenant_id_tenant",
        ),
        sa.UniqueConstraint("alert_id", name="uq_alert_summary_alert_id"),
    )
    op.create_index(
        "ix_alert_summary_tenant_id",
        "alert_summary",
        ["tenant_id"],
        unique=False,
    )

    # Drop + recreate the webhook event_types CHECK so the dispatcher
    # accepts subscriptions for the new ``alert.summary_ready`` event.
    op.drop_constraint(
        "ck_webhook_subscription_event_types",
        "webhook_subscription",
        type_="check",
    )
    quoted = ",".join(f"'{e}'" for e in _EVENT_TYPES)
    op.create_check_constraint(
        "ck_webhook_subscription_event_types",
        "webhook_subscription",
        f"event_types <@ ARRAY[{quoted}]::text[]",
    )


def downgrade() -> None:
    # Revert the CHECK to its prior shape first — once the table is
    # gone we can't drop rows that reference the new event type.
    op.drop_constraint(
        "ck_webhook_subscription_event_types",
        "webhook_subscription",
        type_="check",
    )
    prior = (
        "alert.opened",
        "alert.state_changed",
        "incident.opened",
        "incident.resolved",
        "job.completed",
        "job.failed",
        "host.enrolled",
        "host.disconnected",
    )
    quoted = ",".join(f"'{e}'" for e in prior)
    op.create_check_constraint(
        "ck_webhook_subscription_event_types",
        "webhook_subscription",
        f"event_types <@ ARRAY[{quoted}]::text[]",
    )

    op.drop_index("ix_alert_summary_tenant_id", table_name="alert_summary")
    op.drop_table("alert_summary")
