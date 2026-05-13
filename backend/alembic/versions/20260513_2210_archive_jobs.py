"""Archive jobs (Phase 3 #3.2 — OpenSearch ILM + S3 cold archive).

OpenSearch indices roll daily (telemetry-YYYYMMDD, alerts-YYYYMMDD).
After the cold-tier age the archive worker streams each cold index out
to MinIO as ``.ndjson.zst`` and closes the OpenSearch index. Each
freeze/rehydrate cycle gets one row in ``archive_job`` so operators
can see what's in S3 and queue a rehydrate without poking ``mc``.

Two indices serve the UI: the status feed ordered by ``created_at`` and
a per-index lookup for "is this index already frozen?".

Revision ID: e2b3c4d5e6f7
Revises: e1a2b3c4d5e6
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e2b3c4d5e6f7"
down_revision: str | None = "e1a2b3c4d5e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "archive_job",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("index_name", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("doc_count", sa.BigInteger(), nullable=True),
        sa.Column("s3_key", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_archive_job"),
        sa.CheckConstraint(
            "status IN ('pending', 'freezing', 'frozen', 'rehydrating', 'rehydrated', 'failed')",
            name="ck_archive_job_status",
        ),
    )
    op.create_index(
        "ix_archive_job_status_created_at",
        "archive_job",
        ["status", sa.text("created_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_archive_job_index_name",
        "archive_job",
        ["index_name"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_archive_job_index_name", table_name="archive_job")
    op.drop_index("ix_archive_job_status_created_at", table_name="archive_job")
    op.drop_table("archive_job")
