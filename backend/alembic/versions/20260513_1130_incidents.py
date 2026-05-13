"""Incidents — alert grouping (Phase 1 #1.11).

Adds an `incidents` table and a nullable `incident_id` FK on `alerts`
so related alerts can be rolled up under a single triage object.

Grouping rule v1 (implemented in `app.services.incident_grouping`):
same `host_id`, alerts inside a sliding `VIGIL_INCIDENT_WINDOW_S`
window (default 600 s), any rule kind. A periodic worker
(`incident_grouper`) regroups recently-opened alerts every minute.

`incident.host_id` is nullable so we can later group synthetic /
multi-host incidents without another migration; v1 only writes
non-null host ids.

`alerts.incident_id` uses `ON DELETE SET NULL` so removing an
incident doesn't cascade-delete the alerts; the alerts simply
ungroup. The alerts FK is indexed for the grouping worker's lookup
on `WHERE incident_id IS NULL`.

Revision ID: 9a4f3b2c7d18
Revises: 7d3f8e1a2b4c
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "9a4f3b2c7d18"
down_revision: str | None = "9a4e2f6d3c81"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    incident_status = postgresql.ENUM(
        "open", "investigating", "resolved", "closed", name="incident_status"
    )
    incident_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        # Nullable so future multi-host / synthetic incidents don't need
        # another migration. v1 always writes a real host_id.
        sa.Column(
            "host_id",
            sa.Uuid(),
            sa.ForeignKey("hosts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column(
            "severity",
            postgresql.ENUM(
                "info",
                "low",
                "medium",
                "high",
                "critical",
                name="rule_severity",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            postgresql.ENUM(
                "open",
                "investigating",
                "resolved",
                "closed",
                name="incident_status",
                create_type=False,
            ),
            nullable=False,
            server_default="open",
        ),
        sa.Column(
            "opened_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "assignee_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_incidents_host_id", "incidents", ["host_id"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_opened_at", "incidents", ["opened_at"])

    op.add_column(
        "alerts",
        sa.Column(
            "incident_id",
            sa.Uuid(),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_alerts_incident_id", "alerts", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_alerts_incident_id", table_name="alerts")
    op.drop_column("alerts", "incident_id")
    op.drop_index("ix_incidents_opened_at", table_name="incidents")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_index("ix_incidents_host_id", table_name="incidents")
    op.drop_table("incidents")
    postgresql.ENUM(name="incident_status").drop(op.get_bind(), checkfirst=True)
