"""SCIM 2.0 user provisioning (Phase 3 #3.8).

Two surface changes:

  * ``users`` gains ``scim_external_id`` — the IdP's stable identifier
    for the user. Unique per ``(oidc_issuer, scim_external_id)`` so two
    different IdPs (or two different tenants of the same IdP, since
    each issues its own issuer URL) can both provision a user with the
    same externalId without collision. The unique index is partial —
    ``WHERE scim_external_id IS NOT NULL`` — so password-only / OIDC-
    only users aren't constrained.
  * ``scim_token`` is a new table holding bearer tokens the IdP uses
    against ``/scim/v2``. ``token_hash`` is the only thing we keep on
    disk (sha256 hex). The raw token is shown to the operator exactly
    once at creation.

Revision ID: e8b9c0d1e2f3
Revises: e9c0d1e2f3a4
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e8b9c0d1e2f3"
down_revision: str | None = "e9c0d1e2f3a4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("scim_external_id", sa.Text(), nullable=True))
    # Partial UNIQUE — NULL rows aren't constrained so non-SCIM users
    # keep co-existing. The pair (oidc_issuer, scim_external_id) is the
    # SCIM identity key; same externalId across two different IdP
    # issuers is fine.
    op.create_index(
        "ix_users_scim_external_id_unique",
        "users",
        ["oidc_issuer", "scim_external_id"],
        unique=True,
        postgresql_where=sa.text("scim_external_id IS NOT NULL"),
    )

    op.create_table(
        "scim_token",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("label", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "disabled",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scim_token"),
        sa.UniqueConstraint("token_hash", name="uq_scim_token_token_hash"),
    )


def downgrade() -> None:
    op.drop_table("scim_token")
    op.drop_index("ix_users_scim_external_id_unique", table_name="users")
    op.drop_column("users", "scim_external_id")
