"""M17.c: audit_log.api_token_id FK

Adds a nullable FK from audit_log to api_tokens so per-token actions
are distinguishable from JWT actions by the same user. ON DELETE SET
NULL — when a token is revoked + later deleted, the audit row keeps
the historical record but loses the live link.

Revision ID: 6d3e8f1a2c50
Revises: 5e2b0c8d4f6a
Create Date: 2026-05-10
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "6d3e8f1a2c50"
down_revision: str | None = "5e2b0c8d4f6a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "audit_log",
        sa.Column("api_token_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_audit_log_api_token_id",
        "audit_log",
        "api_tokens",
        ["api_token_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_audit_log_api_token_id",
        "audit_log",
        ["api_token_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_audit_log_api_token_id", table_name="audit_log")
    op.drop_constraint("fk_audit_log_api_token_id", "audit_log", type_="foreignkey")
    op.drop_column("audit_log", "api_token_id")
