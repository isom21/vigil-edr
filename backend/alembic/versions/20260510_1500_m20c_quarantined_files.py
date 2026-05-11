"""M20.c: quarantined_files table for the SOC quarantine inventory.

Adds quarantine_status enum + quarantined_files table. Each row
represents one file the agent moved into its quarantine directory in
response to a rule.action=quarantine match (or a manual operator
quarantine command). The /api/hosts/:id/quarantined endpoint lists
active rows; /api/quarantined/:id/release flips the row + queues a
release command back to the agent.

Revision ID: c8f1e93a204d
Revises: a7c1e4f9d23b
Create Date: 2026-05-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "c8f1e93a204d"
down_revision: str | None = "a7c1e4f9d23b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    quarantine_status = postgresql.ENUM(
        "active", "released", "deleted", name="quarantine_status"
    )
    quarantine_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "quarantined_files",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "host_id",
            sa.Uuid(),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "alert_id",
            sa.Uuid(),
            sa.ForeignKey("alerts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "command_id",
            sa.Uuid(),
            sa.ForeignKey("commands.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("original_path", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column(
            "size_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "deleted_original",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            postgresql.ENUM(
                "active", "released", "deleted", name="quarantine_status", create_type=False
            ),
            nullable=False,
            server_default="active",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_quarantined_files_host_id", "quarantined_files", ["host_id"]
    )
    op.create_index(
        "ix_quarantined_files_alert_id", "quarantined_files", ["alert_id"]
    )
    op.create_index(
        "ix_quarantined_files_sha256", "quarantined_files", ["sha256"]
    )
    op.create_index(
        "ix_quarantined_files_status", "quarantined_files", ["status"]
    )


def downgrade() -> None:
    op.drop_index("ix_quarantined_files_status", table_name="quarantined_files")
    op.drop_index("ix_quarantined_files_sha256", table_name="quarantined_files")
    op.drop_index("ix_quarantined_files_alert_id", table_name="quarantined_files")
    op.drop_index("ix_quarantined_files_host_id", table_name="quarantined_files")
    op.drop_table("quarantined_files")
    postgresql.ENUM(name="quarantine_status").drop(op.get_bind(), checkfirst=True)
