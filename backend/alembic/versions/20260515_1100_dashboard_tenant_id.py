"""Add tenant_id to dashboard (CODE-20).

The dashboard table predates Phase 3 multi-tenancy. Pre-PR, a
shared=true dashboard authored by a tenant-A admin showed up in
every other tenant's analysts' list views — the router checked
ownership but not tenant.

Adds ``tenant_id`` with a server default of the seed tenant so
existing rows backfill cleanly. The (owner_user_id WHERE is_default)
partial UNIQUE is unaffected (an owner belongs to one tenant, so
the per-owner-default invariant is already implicitly per-tenant).

Revision ID: b3c4d5e6f7a9
Revises: a1c2e3f4d5b6
Create Date: 2026-05-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b3c4d5e6f7a9"
down_revision: str | None = "a1c2e3f4d5b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


SEED_TENANT_ID = "00000000-0000-0000-0000-000000000001"


def upgrade() -> None:
    op.add_column(
        "dashboard",
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            nullable=False,
            server_default=SEED_TENANT_ID,
        ),
    )
    op.create_foreign_key(
        "fk_dashboard_tenant_id_tenant",
        "dashboard",
        "tenant",
        ["tenant_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_dashboard_tenant_id", "dashboard", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_dashboard_tenant_id", table_name="dashboard")
    op.drop_constraint("fk_dashboard_tenant_id_tenant", "dashboard", type_="foreignkey")
    op.drop_column("dashboard", "tenant_id")
