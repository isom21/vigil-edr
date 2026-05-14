"""Deception / honeytokens (Phase 4 #4.5).

Operators register decoys (fake creds, fake docs, fake registry keys)
that fan out to hosts via `DEPLOY_HONEYTOKEN`. The agent plants the
artifact with a token-id tag (xattr on Linux files, NTFS Alternate Data
Stream on Windows, registry value name on Windows regkeys) and emits a
`HoneytokenHit` whenever something touches it. The manager raises a
critical-severity alert via the synthetic `HONEYTOKEN_HIT_RULE_ID`.

Two tables + one enum value:

  * `honeytoken` — the operator-registered decoy. Scoped per-tenant
    and optionally per-host-group; NULL `host_group_id` means
    "deploy to every host in the tenant". Unique `(tenant_id, name)`.
  * `honeytoken_hit` — append-only log of observed touches. Each row
    points back at the source `honeytoken_id`, the host, and the alert
    we raised (NULL for synthetic-rule bootstrap failures).
  * `command_kind += 'deploy_honeytoken'` — standalone `ALTER TYPE`
    inside the migration, mirroring `device_policies` and `dns_block`.

Revision ID: f5e6f7a8b9c0
Revises: f4d5e6f7a8b9
Create Date: 2026-05-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "f5e6f7a8b9c0"
down_revision: str | None = "f4d5e6f7a8b9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "honeytoken",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("host_group_id", sa.Uuid(), nullable=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("target_path", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("deployed_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
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
        sa.CheckConstraint(
            "kind IN ('creds_in_lsass', 'fake_file', 'fake_regkey')",
            name="ck_honeytoken_kind",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_honeytoken_tenant_id_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["host_group_id"],
            ["host_groups.id"],
            ondelete="CASCADE",
            name="fk_honeytoken_host_group_id_host_groups",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_honeytoken"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_honeytoken_tenant_id_name"),
    )
    op.create_index(
        "ix_honeytoken_tenant_id",
        "honeytoken",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_honeytoken_host_group_id",
        "honeytoken",
        ["host_group_id"],
        unique=False,
    )

    op.create_table(
        "honeytoken_hit",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("honeytoken_id", sa.Uuid(), nullable=False),
        sa.Column("host_id", sa.Uuid(), nullable=False),
        sa.Column("hit_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("process_pid", sa.Integer(), nullable=True),
        sa.Column("process_executable", sa.Text(), nullable=True),
        sa.Column("alert_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_honeytoken_hit_tenant_id_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["honeytoken_id"],
            ["honeytoken.id"],
            ondelete="CASCADE",
            name="fk_honeytoken_hit_honeytoken_id_honeytoken",
        ),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
            ondelete="CASCADE",
            name="fk_honeytoken_hit_host_id_hosts",
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            ondelete="SET NULL",
            name="fk_honeytoken_hit_alert_id_alerts",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_honeytoken_hit"),
    )
    op.create_index(
        "ix_honeytoken_hit_honeytoken_id_hit_at",
        "honeytoken_hit",
        ["honeytoken_id", sa.text("hit_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_honeytoken_hit_host_id_hit_at",
        "honeytoken_hit",
        ["host_id", sa.text("hit_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_honeytoken_hit_tenant_id",
        "honeytoken_hit",
        ["tenant_id"],
        unique=False,
    )

    # IF NOT EXISTS so a partial dev-env re-apply doesn't crash.
    op.execute("ALTER TYPE command_kind ADD VALUE IF NOT EXISTS 'deploy_honeytoken'")


def downgrade() -> None:
    op.drop_index("ix_honeytoken_hit_tenant_id", table_name="honeytoken_hit")
    op.drop_index("ix_honeytoken_hit_host_id_hit_at", table_name="honeytoken_hit")
    op.drop_index("ix_honeytoken_hit_honeytoken_id_hit_at", table_name="honeytoken_hit")
    op.drop_table("honeytoken_hit")
    op.drop_index("ix_honeytoken_host_group_id", table_name="honeytoken")
    op.drop_index("ix_honeytoken_tenant_id", table_name="honeytoken")
    op.drop_table("honeytoken")
    # Postgres has no `ALTER TYPE ... DROP VALUE`. Leaving the enum
    # value in place is safe — Python code stops emitting it after
    # rollback.
