"""M7.5: host_groups + association tables

Adds the M7.5 RBAC scoping primitives: a `host_groups` table holding
named buckets of hosts, plus two many-to-many association tables that
say which hosts and users belong to which groups.

Migrated tables are intentionally narrow — admin-only API surface,
no per-row permissions, no per-cap bits. The Alert / Command APIs
join through `host_in_group` + `user_host_group` at query time
(see app.services.scoping.apply_host_scope).

Revision ID: 7a4f0c2e9fa1
Revises: 15fc3fa55e1f
Create Date: 2026-05-10
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "7a4f0c2e9fa1"
down_revision: Union[str, None] = "15fc3fa55e1f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "host_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_host_groups_name"),
    )
    op.create_index("ix_host_groups_name", "host_groups", ["name"], unique=False)

    op.create_table(
        "user_host_group",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("host_group_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["host_group_id"], ["host_groups.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "host_group_id"),
    )

    op.create_table(
        "host_in_group",
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("host_group_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["host_group_id"], ["host_groups.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("host_id", "host_group_id"),
    )


def downgrade() -> None:
    op.drop_table("host_in_group")
    op.drop_table("user_host_group")
    op.drop_index("ix_host_groups_name", table_name="host_groups")
    op.drop_table("host_groups")
