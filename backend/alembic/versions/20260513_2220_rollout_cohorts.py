"""Agent rollout cohorts + auto-rollback (Phase 3 #3.3).

Adds three columns to ``policies`` and one new table ``rollout_event``.

  * ``rollout_cohort`` / ``cohort_target_version`` / ``cohort_rolled_out_pct``
    on ``policies`` drive the staged update gate. A host is eligible to
    receive a ``JobKind.UPDATE`` command only if its stable cohort bucket
    (0–99) falls under ``cohort_rolled_out_pct``. Operators advance the
    percentage through the API; the rollout monitor worker drops it back
    to 0 when failures pile up in a window.
  * ``rollout_event`` captures one row per host per update attempt. The
    monitor reads this table on its tick to compute the per-cohort
    failure rate; the API surfaces aggregates to the dashboard.

The cohort bucket is computed off ``host_id`` + a configurable seed
(``VIGIL_ROLLOUT_COHORT_SEED``) so the same host always lands in the
same bucket — operators can preview which fraction of the fleet a
given percentage will hit without committing the change.

Revision ID: e3c4d5e6f7a8
Revises: d5e6f7a8b9c0
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e3c4d5e6f7a8"
down_revision: str | None = "d5e6f7a8b9c0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "policies",
        sa.Column("rollout_cohort", sa.Text(), nullable=True),
    )
    op.add_column(
        "policies",
        sa.Column("cohort_target_version", sa.Text(), nullable=True),
    )
    op.add_column(
        "policies",
        sa.Column(
            "cohort_rolled_out_pct",
            sa.SmallInteger(),
            nullable=False,
            server_default="0",
        ),
    )
    op.create_check_constraint(
        "ck_policies_cohort_rolled_out_pct",
        "policies",
        "cohort_rolled_out_pct BETWEEN 0 AND 100",
    )

    op.create_table(
        "rollout_event",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("cohort", sa.Text(), nullable=False),
        sa.Column("version_from", sa.Text(), nullable=True),
        sa.Column("version_to", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_rollout_event"),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            ondelete="CASCADE",
            name="fk_rollout_event_host_id_hosts",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["policies.id"],
            ondelete="CASCADE",
            name="fk_rollout_event_policy_id_policies",
        ),
        sa.CheckConstraint(
            "status IN ('pending','in_flight','success','failed','rolled_back')",
            name="ck_rollout_event_status",
        ),
    )
    op.create_index(
        "ix_rollout_event_policy_status_started",
        "rollout_event",
        ["policy_id", "status", sa.text("started_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_rollout_event_host_started",
        "rollout_event",
        ["host_id", sa.text("started_at DESC")],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_rollout_event_host_started", table_name="rollout_event")
    op.drop_index("ix_rollout_event_policy_status_started", table_name="rollout_event")
    op.drop_table("rollout_event")
    op.drop_constraint("ck_policies_cohort_rolled_out_pct", "policies", type_="check")
    op.drop_column("policies", "cohort_rolled_out_pct")
    op.drop_column("policies", "cohort_target_version")
    op.drop_column("policies", "rollout_cohort")
