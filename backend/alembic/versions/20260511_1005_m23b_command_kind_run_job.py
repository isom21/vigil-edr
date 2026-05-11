"""M23.b: extend command_kind with `run_job`.

JobRun fanout dispatches a Command(kind=run_job, payload={...}) to
the agent until M23.j retires the Commands pipeline. Standalone
migration because ALTER TYPE ADD VALUE can't run inside a tx that
already touched the type.

Revision ID: a93e7f218cd0
Revises: f5b4a1d7e29c
Create Date: 2026-05-11
"""

from collections.abc import Sequence

from alembic import op

revision: str = "a93e7f218cd0"
down_revision: str | None = "f5b4a1d7e29c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE command_kind ADD VALUE IF NOT EXISTS 'run_job'")


def downgrade() -> None:
    # Postgres has no ALTER TYPE DROP VALUE; leaving the value in
    # place is safe — Python code stops emitting it after rollback.
    pass
