"""Incident grouping_reason (Phase 2 #2.13).

Adds a `grouping_reason` column to the `incidents` table so the API
and UI can show *why* a set of alerts ended up under one incident:

  * `window` (default) — same host, sliding time window grouping (the
    v1 grouper from Phase 1 #1.11).
  * `process_tree` — the alerts share a common process ancestor on the
    same host (Phase 2 #2.13 refinement).
  * `rule_cluster` — reserved for a future pass that groups by rule
    family / MITRE technique.

Stored as `text` with a `CHECK` constraint rather than a PG ENUM so
adding new reasons later is just a constraint swap, no `ALTER TYPE`.

Revision ID: d8b9c0d1e2f3
Revises: d2b3c4d5e6f7
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d8b9c0d1e2f3"
down_revision: str | None = "d2b3c4d5e6f7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column(
            "grouping_reason",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'window'"),
        ),
    )
    op.create_check_constraint(
        "ck_incidents_grouping_reason",
        "incidents",
        "grouping_reason IN ('window', 'process_tree', 'rule_cluster')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_incidents_grouping_reason", "incidents", type_="check")
    op.drop_column("incidents", "grouping_reason")
