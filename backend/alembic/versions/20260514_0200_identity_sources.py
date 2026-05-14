"""Identity threat detection sources (Phase 4 #4.3).

Adds the `identity_source` table that holds operator-registered
Okta + Azure AD integrations. A periodic worker
(`app.workers.identity_monitor`) polls each enabled source on its
configured cadence, pulls the source's audit/sign-in events, runs the
detectors in `app.services.identity.detectors` (impossible travel,
brute force, MFA bombing, password spray), and emits Alert rows under
a synthetic Rule per detector class.

Schema choices:

  * `kind` is constrained via CHECK to `('okta','azure_ad')` rather
    than a Postgres enum — same standalone-statement pattern as the
    case_destination + device_policy migrations, so adding a third
    identity provider later doesn't require an ALTER TYPE dance.
  * `config_encrypted` holds the Fernet ciphertext of the per-source
    JSON config (Okta domain + API token, or Azure tenant_id +
    client_id + client_secret). Plaintext only ever lives in process
    at poll time; never logged, never returned through the API.
  * `last_polled_at` drives the cadence gate ("is this source due?").
    `last_event_ts` carries the high-water mark of the latest event
    we ingested so the next poll can `?since=…` rather than re-fetch
    the world. Both nullable for "never polled" rows.
  * Unique `(tenant_id, name)` so two operators in the same tenant
    can't register two sources sharing a name. Same name across
    tenants is fine (the tenant_id is part of the composite key).

Revision ID: f3c4d5e6f7a8
Revises: f2a3b4c5d6e7
Create Date: 2026-05-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f3c4d5e6f7a8"
down_revision: str | None = "f2a3b4c5d6e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "identity_source",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("config_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_event_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
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
        sa.PrimaryKeyConstraint("id", name="pk_identity_source"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_identity_source_tenant_id_tenant",
        ),
        sa.CheckConstraint(
            "kind IN ('okta', 'azure_ad')",
            name="ck_identity_source_kind",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "name",
            name="uq_identity_source_tenant_id_name",
        ),
    )
    op.create_index(
        "ix_identity_source_tenant_id",
        "identity_source",
        ["tenant_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_identity_source_tenant_id", table_name="identity_source")
    op.drop_table("identity_source")
