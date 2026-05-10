"""M11.b: process_baseline table for per-host anomaly detection

Tracks counts of (host_id, exe, parent_exe) triples observed across
the fleet. The anomaly worker consumes telemetry.normalized; first-
time-seen triples whose parent isn't a known launcher fire an alert.

Revision ID: 8a4f2d6e0b71
Revises: 6d3e8f1a2c50
Create Date: 2026-05-10
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "8a4f2d6e0b71"
down_revision: Union[str, None] = "6d3e8f1a2c50"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "process_baseline",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("exe", sa.String(length=1024), nullable=False),
        sa.Column("parent_exe", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column("count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("host_id", "exe", "parent_exe", name="uq_process_baseline_triple"),
    )
    op.create_index("ix_process_baseline_host_id", "process_baseline", ["host_id"])


def downgrade() -> None:
    op.drop_index("ix_process_baseline_host_id", table_name="process_baseline")
    op.drop_table("process_baseline")
