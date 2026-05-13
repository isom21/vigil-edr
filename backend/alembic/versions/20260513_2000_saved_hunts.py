"""Saved hunts + hunt run history (Phase 2 #2.11).

The hunt workbench lets analysts run ad-hoc OpenSearch queries against
the telemetry-* indices in three input languages: Lucene (pass-through
to query_string), KQL (a thin shim — implemented as Lucene for now,
parsed identically), and Sigma YAML (compiled via the same
OpensearchLuceneBackend the rule editor already uses).

Saved hunts can be scheduled (cron-string) and optionally `alert_on_hit`
— when true, the scheduler emits Alert rows under a managed Rule per
hunt, mirroring the intel feed pattern.

Tables:

  * `saved_hunt` — operator-authored hunts.
  * `hunt_run` — one row per execution (ad-hoc, scheduled, or manual).

Revision ID: d6f7a8b9c0d1
Revises: d3c4d5e6f7a8
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d6f7a8b9c0d1"
down_revision: str | None = "d3c4d5e6f7a8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "saved_hunt",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("query_dsl", sa.Text(), nullable=False),
        sa.Column("query_language", sa.Text(), nullable=False),
        sa.Column("schedule_cron", sa.Text(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_hit_count", sa.Integer(), nullable=True),
        sa.Column(
            "alert_on_hit",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("severity", sa.Text(), nullable=True),
        sa.Column("mitre_techniques", postgresql.JSONB(), nullable=True),
        sa.Column("host_scope_json", postgresql.JSONB(), nullable=True),
        sa.Column("managed_rule_id", sa.Uuid(), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["owner_user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name="fk_saved_hunt_owner_user_id_users",
        ),
        sa.ForeignKeyConstraint(
            ["managed_rule_id"],
            ["rules.id"],
            ondelete="SET NULL",
            name="fk_saved_hunt_managed_rule_id_rules",
        ),
        sa.CheckConstraint(
            "query_language IN ('lucene','kql','sigma')",
            name="query_language",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_saved_hunt"),
    )
    op.create_index(
        "ix_saved_hunt_owner_user_id",
        "saved_hunt",
        ["owner_user_id"],
        unique=False,
    )

    op.create_table(
        "hunt_run",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("hunt_id", sa.Uuid(), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hit_count", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("alert_count", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["hunt_id"],
            ["saved_hunt.id"],
            ondelete="CASCADE",
            name="fk_hunt_run_hunt_id_saved_hunt",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_hunt_run"),
    )
    op.create_index(
        "ix_hunt_run_hunt_id_started_at",
        "hunt_run",
        ["hunt_id", sa.text("started_at DESC")],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_hunt_run_hunt_id_started_at", table_name="hunt_run")
    op.drop_table("hunt_run")
    op.drop_index("ix_saved_hunt_owner_user_id", table_name="saved_hunt")
    op.drop_table("saved_hunt")
