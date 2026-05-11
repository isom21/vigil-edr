"""M20.c: add `release_quarantine` to the command_kind enum.

A new CommandKind value can't be inserted via `op.create_table` and
doesn't go through the SA model definition automatically; Postgres
needs an explicit `ALTER TYPE ... ADD VALUE`. Standalone migration
because that statement can't run inside a transaction that already
modified the type.

Revision ID: e1d4a82c97bf
Revises: c8f1e93a204d
Create Date: 2026-05-10
"""

from typing import Sequence, Union

from alembic import op


revision: str = "e1d4a82c97bf"
down_revision: Union[str, None] = "c8f1e93a204d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # IF NOT EXISTS guard so re-running the migration in dev (or a
    # partially-applied environment) doesn't break.
    op.execute("ALTER TYPE command_kind ADD VALUE IF NOT EXISTS 'release_quarantine'")


def downgrade() -> None:
    # Postgres has no `ALTER TYPE ... DROP VALUE`. Leaving the value
    # in place is harmless — any rows that reference it become
    # orphaned at the schema level but invisible to the Python model.
    pass
