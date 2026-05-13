"""Operator-authored dashboards (Phase 3 #3.4).

Replaces the hardcoded fleet-overview Dashboard with a drag-and-drop
grid that operators author and persist. One row per dashboard. The
`widgets_json` column stores the entire grid layout — widget type +
position + per-widget options — as a JSONB array so the schema can
absorb new widget types without a migration.

Sharing model: an owner can flip `shared=true` and any analyst+ in the
deployment can list / read / clone the dashboard, but only the owner
(or an admin) can edit / delete it. The parallel-batch ground rule
keeps `tenant_id` off — sharing here means "team-wide", not
"cross-tenant".

The partial UNIQUE index `(owner_user_id) WHERE is_default = true`
makes the per-user default unambiguous: there's at most one row marked
default for each owner, so `/api/dashboards/default` resolves with a
single query and the auto-create-on-first-call path can't race itself
into duplicate defaults.

Revision ID: e4d5e6f7a8b9
Revises: e3c4d5e6f7a8
Create Date: 2026-05-13

Parallel-batch note: spec says ``down_revision`` is ``d5e6f7a8b9c0``
(allowlist), but the Phase 3 parallel batch landed rollout cohorts
(``e3c4d5e6f7a8``) and webhook subscriptions (``e7a8b9c0d1e2``) at the
same parent. Following the same convention as commit ``107f74f``
(chain after the highest existing head to keep main single-headed),
dashboards chains after ``e3c4d5e6f7a8`` rather than directly off
allowlist.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "e4d5e6f7a8b9"
down_revision: str | None = "e3c4d5e6f7a8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dashboard",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "shared",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "widgets_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "is_default",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["owner_user_id"],
            ["users.id"],
            ondelete="CASCADE",
            name="fk_dashboard_owner_user_id_users",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_dashboard"),
    )
    op.create_index(
        "ix_dashboard_owner_user_id",
        "dashboard",
        ["owner_user_id"],
        unique=False,
    )
    # One default dashboard per owner. NULLs aren't constrained because
    # the partial WHERE filters them out — only rows with is_default
    # true participate in uniqueness.
    op.create_index(
        "ix_dashboard_owner_default_unique",
        "dashboard",
        ["owner_user_id"],
        unique=True,
        postgresql_where=sa.text("is_default = true"),
    )


def downgrade() -> None:
    op.drop_index("ix_dashboard_owner_default_unique", table_name="dashboard")
    op.drop_index("ix_dashboard_owner_user_id", table_name="dashboard")
    op.drop_table("dashboard")
