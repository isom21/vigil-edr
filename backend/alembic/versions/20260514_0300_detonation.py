"""Network sandbox / detonation provider + jobs (Phase 4 #4.4).

Two tables drive automated sandbox detonation of suspicious file
hashes:

  * ``detonation_provider`` — one row per operator-registered sandbox
    instance (Cuckoo today; VMRay + ANY.RUN are stubbed). The
    ``config_encrypted`` blob holds the per-provider URL + API token
    via the shared Fernet helper in ``app/services/encryption.py``.
  * ``detonation_job`` — one row per submission. Status transitions
    ``queued → running → verdict``/``failed``. On a malicious verdict
    the poller worker materialises a fresh IocEntry under a per-tenant
    synthetic ``intel_feed`` (the "detonation" feed) so the regular
    IOC detector picks the sample up on subsequent host activity.

Schema choices match the existing case_destinations / siem_destinations
shape — TEXT + CHECK rather than a Postgres enum, so adding a fourth
provider (Hybrid Analysis, Joe Sandbox) doesn't require ALTER TYPE.

Revision ID: f4d5e6f7a8b9
Revises: f3c4d5e6f7a8
Create Date: 2026-05-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f4d5e6f7a8b9"
down_revision: str | None = "f3c4d5e6f7a8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detonation_provider",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("config_encrypted", sa.LargeBinary(), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name="pk_detonation_provider"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_detonation_provider_tenant_id_tenant",
        ),
        sa.CheckConstraint(
            "kind IN ('cuckoo', 'vmray', 'anyrun')",
            name="ck_detonation_provider_kind",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "name",
            name="uq_detonation_provider_tenant_id_name",
        ),
    )
    op.create_index(
        "ix_detonation_provider_tenant_id",
        "detonation_provider",
        ["tenant_id"],
        unique=False,
    )

    op.create_table(
        "detonation_job",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("sha256", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("verdict_score", sa.Float(), nullable=True),
        sa.Column("verdict_label", sa.Text(), nullable=True),
        sa.Column("external_id", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "submitted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_detonation_job"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_detonation_job_tenant_id_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["provider_id"],
            ["detonation_provider.id"],
            ondelete="CASCADE",
            name="fk_detonation_job_provider_id_detonation_provider",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'verdict', 'failed')",
            name="ck_detonation_job_status",
        ),
    )
    op.create_index(
        "ix_detonation_job_tenant_id",
        "detonation_job",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_detonation_job_provider_id_status",
        "detonation_job",
        ["provider_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_detonation_job_sha256",
        "detonation_job",
        ["sha256"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_detonation_job_sha256", table_name="detonation_job")
    op.drop_index("ix_detonation_job_provider_id_status", table_name="detonation_job")
    op.drop_index("ix_detonation_job_tenant_id", table_name="detonation_job")
    op.drop_table("detonation_job")
    op.drop_index("ix_detonation_provider_tenant_id", table_name="detonation_provider")
    op.drop_table("detonation_provider")
