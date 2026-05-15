"""Add tenant_id to scim_token (CODE-33).

SCIM bearer tokens previously had no tenant binding. Users created
via SCIM landed on DEFAULT_TENANT_ID regardless of which IdP / token
provisioned them — making the SCIM bridge effectively single-tenant
even after Phase 3 multi-tenancy shipped.

Adds the column with a server default of the seed tenant for
backfill, then exposes it on the model so the SCIM resolver can
stamp the same tenant_id on every User the IdP creates.

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a9
Create Date: 2026-05-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4d5e6f7a8b9"
down_revision: str | None = "b3c4d5e6f7a9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


SEED_TENANT_ID = "00000000-0000-0000-0000-000000000001"


def upgrade() -> None:
    op.add_column(
        "scim_token",
        sa.Column(
            "tenant_id",
            sa.Uuid(),
            nullable=False,
            server_default=SEED_TENANT_ID,
        ),
    )
    op.create_foreign_key(
        "fk_scim_token_tenant_id_tenant",
        "scim_token",
        "tenant",
        ["tenant_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_scim_token_tenant_id", "scim_token", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_scim_token_tenant_id", table_name="scim_token")
    op.drop_constraint("fk_scim_token_tenant_id_tenant", "scim_token", type_="foreignkey")
    op.drop_column("scim_token", "tenant_id")
