"""Cross-process correlation graph store (Phase 2 #2.6).

Persists per-host process start/exit events as a queryable graph so
the alert investigation view can walk ancestors/descendants in
Postgres rather than re-fetching OpenSearch every time. The indexer
worker tails `telemetry.normalized`, inserts on `process_started`,
and patches `ended_at` on `process_exited`.

`UNIQUE (host_id, pid, started_at)` is what lets the indexer fire-
and-forget with `ON CONFLICT DO NOTHING` — Kafka redelivery and the
process_started/exited fan-out from the agent both end up replaying
the same (host, pid, start_ts) tuple. The lineage queries in
`app.services.process_graph` use a recursive CTE keyed off
`(host_id, parent_pid)`, hence the dedicated index.

Revision ID: d3c4d5e6f7a8
Revises: d7a8b9c0d1e2
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d3c4d5e6f7a8"
down_revision: str | None = "d7a8b9c0d1e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "process_chain",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("parent_pid", sa.Integer(), nullable=True),
        sa.Column("exec_path", sa.Text(), nullable=True),
        sa.Column("image_sha256", sa.CHAR(length=64), nullable=True),
        sa.Column("command_line", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            ondelete="CASCADE",
            name="fk_process_chain_host_id_hosts",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "host_id",
            "pid",
            "started_at",
            name="uq_process_chain_host_id_pid_started_at",
        ),
    )
    op.create_index(
        "ix_process_chain_host_id_parent_pid",
        "process_chain",
        ["host_id", "parent_pid"],
        unique=False,
    )
    op.create_index(
        "ix_process_chain_host_id_started_at",
        "process_chain",
        ["host_id", sa.text("started_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_process_chain_image_sha256",
        "process_chain",
        ["image_sha256"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_process_chain_image_sha256", table_name="process_chain")
    op.drop_index("ix_process_chain_host_id_started_at", table_name="process_chain")
    op.drop_index("ix_process_chain_host_id_parent_pid", table_name="process_chain")
    op.drop_table("process_chain")
