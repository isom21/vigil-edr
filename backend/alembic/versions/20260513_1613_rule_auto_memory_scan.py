"""Phase 2 #2.1: rules.auto_memory_scan + JobKind.MEMORY_YARA_SCAN.

Adds a boolean toggle on rules that auto-queues an in-memory YARA scan
against the alert's `process.pid` (when present) at fire time. Also
adds the new enum value to the `job_kind` Postgres type so Job rows
of the new kind round-trip.

The enum value add is wrapped in `COMMIT` boundaries — Postgres only
permits `ALTER TYPE ... ADD VALUE` outside a transaction block. We use
`op.execute(... ADD VALUE IF NOT EXISTS ...)` so re-running the
migration after a partial failure is idempotent.

Revision ID: d1a2b3c4e5f6
Revises: d7a8b9c0d1e2
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d1a2b3c4e5f6"
down_revision: str | None = "d7a8b9c0d1e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "rules",
        sa.Column(
            "auto_memory_scan",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    # ALTER TYPE ... ADD VALUE can't run inside a transaction. alembic
    # opens one per migration, so we commit first, add the value, then
    # let alembic open a new transaction for the next migration. The
    # IF NOT EXISTS clause keeps this idempotent on partial reruns.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("COMMIT")
        op.execute("ALTER TYPE job_kind ADD VALUE IF NOT EXISTS 'memory_yara_scan'")


def downgrade() -> None:
    op.drop_column("rules", "auto_memory_scan")
    # Postgres has no DROP VALUE for an enum; leaving the new label in
    # place is the conventional path. A subsequent upgrade reuses it.
