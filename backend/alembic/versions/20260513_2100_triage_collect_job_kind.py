"""Phase 2 #2.10: extend job_kind with `triage_collect`.

Standalone migration because `ALTER TYPE ADD VALUE` can't run inside
a tx that already touched the type. Mirrors the
`m23b_command_kind_run_job` and `m20c_command_kind_release` pattern.

Revision ID: d8b5f31a6c47
Revises: d2b3c4d5e6f7
Create Date: 2026-05-13
"""

from collections.abc import Sequence

from alembic import op

revision: str = "d8b5f31a6c47"
down_revision: str | None = "d2b3c4d5e6f7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # IF NOT EXISTS guard so re-running the migration in a partially-
    # applied environment doesn't break.
    op.execute("ALTER TYPE job_kind ADD VALUE IF NOT EXISTS 'triage_collect'")


def downgrade() -> None:
    # Postgres has no ALTER TYPE DROP VALUE; leaving the value in
    # place is safe — Python code stops emitting it after rollback.
    pass
