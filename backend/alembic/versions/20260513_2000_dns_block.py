"""DNS sinkhole / domain block list (Phase 2 #2.12).

Operators register one or more domains to block (or sinkhole, reserved
for a future local-resolver redirect). The agent receives the effective
set via a `DnsBlockSyncCmd` whole-list resync; the kernel side
(BPF on Linux, WFP callout at FWPM_LAYER_DATAGRAM_DATA_V4 on Windows)
drops the matching DNS queries on UDP port 53.

Schema choices:

  * `host_group_id` is nullable — NULL means "applies to every host".
    A non-NULL group scopes the entry to its members.
  * `(host_group_id, domain)` uniqueness — same group can't list the
    same domain twice, but a global entry doesn't collide with a
    group-specific one for the same domain because Postgres uniqueness
    treats NULL as distinct.
  * `hits` + `last_hit_at` are agent-reported counters surfaced in the
    UI as a "this rule is doing work" indicator. Wire-up of the report
    path is deferred to a follow-up; the columns exist now so the
    upgrade isn't needed.

The `dns_block_sync` `command_kind` enum value goes in via the
standalone-statement pattern (`ALTER TYPE ... ADD VALUE`) — Postgres
can't run that inside a transaction that already modified the type, so
we run it on its own connection via `op.execute` after the CREATE
TABLE completed.

Revision ID: d7a8b9c0d1e2
Revises: d8b9c0d1e2f3
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d7a8b9c0d1e2"
down_revision: str | None = "d8b9c0d1e2f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dns_block_entry",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_group_id", sa.Uuid(), nullable=True),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "action IN ('block', 'sinkhole')",
            name="ck_dns_block_entry_action",
        ),
        sa.ForeignKeyConstraint(
            ["host_group_id"],
            ["host_groups.id"],
            ondelete="CASCADE",
            name="fk_dns_block_entry_host_group_id_host_groups",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            ondelete="SET NULL",
            name="fk_dns_block_entry_created_by_user_id_users",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "host_group_id",
            "domain",
            name="uq_dns_block_entry_host_group_id_domain",
        ),
    )
    op.create_index(
        "ix_dns_block_entry_domain",
        "dns_block_entry",
        ["domain"],
        unique=False,
    )

    # IF NOT EXISTS guard so a partially-applied dev environment can
    # re-run the migration without crashing.
    op.execute("ALTER TYPE command_kind ADD VALUE IF NOT EXISTS 'dns_block_sync'")


def downgrade() -> None:
    op.drop_index("ix_dns_block_entry_domain", table_name="dns_block_entry")
    op.drop_table("dns_block_entry")
    # Postgres has no `ALTER TYPE ... DROP VALUE`. Leave the enum
    # value in place; it's harmless once the table is gone.
