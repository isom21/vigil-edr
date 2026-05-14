"""Cloud telemetry (AWS CloudTrail) ingest + per-principal baseline (Phase 4 #4.2).

Two tables:

  * ``cloud_source`` — one row per operator-registered S3 bucket holding
    CloudTrail logs. ``config_encrypted`` is a Fernet-ciphertext blob
    holding the bucket, optional prefix, AWS access key, AWS secret key,
    and region. Plaintext is never returned through the API; we surface
    ``has_credentials`` so the UI can render the right "rotate" affordance.
  * ``cloud_baseline`` — one row per (source, principal_arn) seen at
    least once. The IAM-anomaly detector compares each fresh event
    against the baseline and fires synthetic alerts on new-principal,
    new-action-for-principal, or new-region-for-principal.

Revision ID: f2b3c4d5e6f7
Revises: f5e6f7a8b9c0
Create Date: 2026-05-14
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f2b3c4d5e6f7"
down_revision: str | None = "f5e6f7a8b9c0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cloud_source",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("config_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_event_ts", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_cloud_source"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_cloud_source_tenant_id_tenant",
        ),
        sa.CheckConstraint(
            "kind IN ('aws_cloudtrail')",
            name="ck_cloud_source_kind",
        ),
        sa.UniqueConstraint("tenant_id", "name", name="uq_cloud_source_tenant_id_name"),
    )
    op.create_index("ix_cloud_source_tenant_id", "cloud_source", ["tenant_id"])

    op.create_table(
        "cloud_baseline",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("source_id", sa.Uuid(), nullable=False),
        sa.Column("principal_arn", sa.Text(), nullable=False),
        sa.Column(
            "observed_actions",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "observed_regions",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("ARRAY[]::text[]"),
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_cloud_baseline"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenant.id"],
            ondelete="RESTRICT",
            name="fk_cloud_baseline_tenant_id_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["cloud_source.id"],
            ondelete="CASCADE",
            name="fk_cloud_baseline_source_id_cloud_source",
        ),
        sa.UniqueConstraint(
            "source_id", "principal_arn", name="uq_cloud_baseline_source_id_principal_arn"
        ),
    )
    op.create_index("ix_cloud_baseline_tenant_id", "cloud_baseline", ["tenant_id"])
    op.create_index("ix_cloud_baseline_source_id", "cloud_baseline", ["source_id"])


def downgrade() -> None:
    op.drop_index("ix_cloud_baseline_source_id", table_name="cloud_baseline")
    op.drop_index("ix_cloud_baseline_tenant_id", table_name="cloud_baseline")
    op.drop_table("cloud_baseline")
    op.drop_index("ix_cloud_source_tenant_id", table_name="cloud_source")
    op.drop_table("cloud_source")
