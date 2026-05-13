"""Phase 3 #3.6 — external case management (Jira + ServiceNow).

Adds two tables that drive bidirectional sync between Vigil alerts
and an operator's external case-tracker of choice:

  * ``case_destination`` — one row per registered Jira / ServiceNow
    instance. ``config_encrypted`` is Fernet-ciphertext of a JSON blob
    holding the base URL + credential (API token / basic auth). The
    plaintext never lives on disk and is never round-tripped through
    the API.
  * ``case_link`` — links an Alert to the external issue it was
    mirrored into. One row per (alert, destination) so the same alert
    can be pushed to multiple trackers (e.g. Jira for the SOC + a
    ServiceNow CMDB record). ``sync_state`` mirrors the destination's
    own status; the poller worker updates it on its tick. Unique
    constraint on (alert_id, destination_id) so the lifecycle hook is
    idempotent against re-fires.

Revision ID: e6f7a8b9c0d1
Revises: e8b9c0d1e2f3
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e6f7a8b9c0d1"
down_revision: str | None = "e8b9c0d1e2f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "case_destination",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("config_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
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
        sa.PrimaryKeyConstraint("id", name="pk_case_destination"),
        sa.CheckConstraint(
            "kind IN ('jira', 'servicenow')",
            name="ck_case_destination_kind",
        ),
        sa.UniqueConstraint("name", name="uq_case_destination_name"),
    )

    op.create_table(
        "case_link",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("destination_id", sa.Uuid(), nullable=False),
        sa.Column("external_id", sa.Text(), nullable=False),
        sa.Column("external_url", sa.Text(), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sync_state", sa.Text(), nullable=False, server_default="open"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_case_link"),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            ondelete="CASCADE",
            name="fk_case_link_alert_id_alerts",
        ),
        sa.ForeignKeyConstraint(
            ["destination_id"],
            ["case_destination.id"],
            ondelete="CASCADE",
            name="fk_case_link_destination_id_case_destination",
        ),
        sa.CheckConstraint(
            "sync_state IN ('open', 'in_progress', 'resolved', 'closed', 'failed')",
            name="ck_case_link_sync_state",
        ),
        sa.UniqueConstraint(
            "alert_id",
            "destination_id",
            name="uq_case_link_alert_id_destination_id",
        ),
    )
    op.create_index(
        "ix_case_link_destination_id",
        "case_link",
        ["destination_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_case_link_destination_id", table_name="case_link")
    op.drop_table("case_link")
    op.drop_table("case_destination")
