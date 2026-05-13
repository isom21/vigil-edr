"""Add OIDC SSO columns to users (Phase 1 #1.6 — OIDC half).

Adds three nullable columns to support an authorization-code OIDC flow
alongside the existing password flow:

  * ``oidc_subject``  — the ``sub`` claim of the ID token, scoped to
    the issuer. Globally unique so subsequent OIDC logins land on the
    same local row deterministically.
  * ``oidc_issuer``   — the issuer URL the row was provisioned from
    (kept so an operator can tell at a glance which IdP a user belongs
    to and audit cross-IdP collisions if they ever switch).
  * ``oidc_email``    — the email claim at provisioning time. The local
    ``email`` column stays the canonical login identifier; this one
    captures whatever the IdP sent so a later mismatch is debuggable.

All three are NULL for password-only users, which keeps the existing
seed-admin row valid without a backfill. The UNIQUE index on
``oidc_subject`` is partial (NULL not indexed) so multiple password-only
users keep co-existing.

Revision ID: 9c4d2e6a8f1b
Revises: 7d3f8e1a2b4c
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9c4d2e6a8f1b"
down_revision: str | None = "b94e7d2f15c8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("oidc_subject", sa.String(length=256), nullable=True))
    op.add_column("users", sa.Column("oidc_issuer", sa.String(length=512), nullable=True))
    op.add_column("users", sa.Column("oidc_email", sa.String(length=256), nullable=True))
    # Partial UNIQUE index — NULLs aren't constrained so password-only
    # users coexist freely. Two OIDC users with the same `sub` cannot.
    op.create_index(
        "ix_users_oidc_subject_unique",
        "users",
        ["oidc_subject"],
        unique=True,
        postgresql_where=sa.text("oidc_subject IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_users_oidc_subject_unique", table_name="users")
    op.drop_column("users", "oidc_email")
    op.drop_column("users", "oidc_issuer")
    op.drop_column("users", "oidc_subject")
