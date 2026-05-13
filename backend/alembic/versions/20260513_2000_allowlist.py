"""Application allowlist: learn → enforce (Phase 2 #2.8).

Adds two tables that drive a per-host-group application allowlist:

  * ``allowlist_mode``: one row per host group, storing the current
    mode (``off`` / ``learn`` / ``enforce``) plus the learn-window
    timestamps so the UI can render "learning for N hours". PK is the
    host_group_id itself — there's a 1:1 between group and mode, so a
    surrogate would just add a join.
  * ``allowlist_entry``: the actual ``sha256`` (hex) ↔ host-group
    bindings. The kernel-side enforcer compares against this set.
    ``learned`` and ``manual`` flags let the UI distinguish entries
    the learner auto-added from operator-added approvals; both count
    toward the synced set.

Plus a new ``command_kind`` enum value ``allowlist_sync`` for the
manager→agent push command. The ALTER TYPE has to live in this
migration even though Postgres rejects mixing ALTER TYPE ADD VALUE
with subsequent CREATE TABLE in one transaction — we run the ALTER
on a non-transactional connection and let the table creation run
inside the migration's normal transaction.

Revision ID: d5e6f7a8b9c0
Revises: d6f7a8b9c0d1
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d5e6f7a8b9c0"
down_revision: str | None = "d6f7a8b9c0d1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Postgres rejects ALTER TYPE ADD VALUE inside a transaction that
    # also touched the type. Migration env runs everything in one tx;
    # autocommit the ALTER on its own connection so the rest of the
    # upgrade (which creates tables that don't touch command_kind) can
    # stay in the migration tx.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE command_kind ADD VALUE IF NOT EXISTS 'allowlist_sync'")

    op.create_table(
        "allowlist_mode",
        sa.Column("host_group_id", sa.Uuid(), nullable=False),
        sa.Column("mode", sa.Text(), nullable=False, server_default="off"),
        sa.Column("enabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("learn_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("learn_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by_user_id", sa.Uuid(), nullable=True),
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
        sa.PrimaryKeyConstraint("host_group_id", name="pk_allowlist_mode"),
        sa.ForeignKeyConstraint(
            ["host_group_id"],
            ["host_groups.id"],
            ondelete="CASCADE",
            name="fk_allowlist_mode_host_group_id_host_groups",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
            name="fk_allowlist_mode_updated_by_user_id_users",
        ),
        sa.CheckConstraint(
            "mode IN ('off', 'learn', 'enforce')",
            name="ck_allowlist_mode_mode",
        ),
    )

    op.create_table(
        "allowlist_entry",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_group_id", sa.Uuid(), nullable=False),
        # SHA-256 as a 64-char lowercase hex string. char(64) over
        # bytea so EXPLAIN / pgAdmin reads are operator-friendly; the
        # agent translates to raw bytes at sync time.
        sa.Column("sha256", sa.CHAR(length=64), nullable=False),
        sa.Column("exec_path", sa.Text(), nullable=True),
        sa.Column("publisher", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("learned", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("manual", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_allowlist_entry"),
        sa.ForeignKeyConstraint(
            ["host_group_id"],
            ["host_groups.id"],
            ondelete="CASCADE",
            name="fk_allowlist_entry_host_group_id_host_groups",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
            name="fk_allowlist_entry_created_by_user_id_users",
        ),
        sa.UniqueConstraint(
            "host_group_id",
            "sha256",
            name="uq_allowlist_entry_host_group_id",
        ),
    )
    op.create_index(
        "ix_allowlist_entry_host_group_id",
        "allowlist_entry",
        ["host_group_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_allowlist_entry_host_group_id", table_name="allowlist_entry")
    op.drop_table("allowlist_entry")
    op.drop_table("allowlist_mode")
    # Postgres has no ALTER TYPE DROP VALUE; leaving 'allowlist_sync'
    # in command_kind is safe — Python code stops emitting it after
    # rollback.
