"""Add MITRE ATT&CK technique fields to rules + alerts.

Phase 1 #1.8: rules and alerts carry an optional `mitre_techniques`
JSON array of technique IDs (e.g. ["T1059.001", "T1547.001"]). When
an alert fires, the detector/sigma worker copies the rule's current
list onto the alert row so historical queries are stable when the
rule's tags change later.

JSONB nullable; default NULL so existing rows are unaffected.

Revision ID: 9a4e2f6d3c81
Revises: 8e2a5c1f4d09
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "9a4e2f6d3c81"
down_revision: str | None = "8e2a5c1f4d09"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "rules",
        sa.Column("mitre_techniques", postgresql.JSONB(), nullable=True),
    )
    op.add_column(
        "alerts",
        sa.Column("mitre_techniques", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("alerts", "mitre_techniques")
    op.drop_column("rules", "mitre_techniques")
