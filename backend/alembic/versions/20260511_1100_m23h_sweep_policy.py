"""M23.h: sweep policy fields + host last_sweep_at.

Adds three columns:
  policies.sweep_interval_hours INT NOT NULL DEFAULT 4
  policies.sweep_categories     JSONB NOT NULL DEFAULT '...'
  hosts.last_sweep_at           TIMESTAMPTZ NULL

A new manager-side worker (`sweep_scheduler`) ticks every minute,
finds hosts whose last_sweep_at predates `now - interval`, and fans
out a HOST_SWEEP job per host.

Revision ID: c7a3f4e92b18
Revises: a93e7f218cd0
Create Date: 2026-05-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "c7a3f4e92b18"
down_revision: str | None = "a93e7f218cd0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


DEFAULT_SWEEP_CATEGORIES = [
    "process_snapshot",
    "network_snapshot",
    "account_audit",
    "installed_software",
    "persistence_audit",
    "service_audit",
]


def upgrade() -> None:
    op.add_column(
        "policies",
        sa.Column(
            "sweep_interval_hours",
            sa.Integer(),
            nullable=False,
            server_default="4",
        ),
    )
    # Server-side default is a JSON literal so existing rows get the
    # default category set without a Python-side update.
    import json as _json

    default_categories_json = _json.dumps(DEFAULT_SWEEP_CATEGORIES)
    op.add_column(
        "policies",
        sa.Column(
            "sweep_categories",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text(f"'{default_categories_json}'::jsonb"),
        ),
    )
    op.add_column(
        "hosts",
        sa.Column("last_sweep_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_hosts_last_sweep_at", "hosts", ["last_sweep_at"])


def downgrade() -> None:
    op.drop_index("ix_hosts_last_sweep_at", table_name="hosts")
    op.drop_column("hosts", "last_sweep_at")
    op.drop_column("policies", "sweep_categories")
    op.drop_column("policies", "sweep_interval_hours")
