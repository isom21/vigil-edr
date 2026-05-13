"""Device control (USB block) policies (Phase 3 #3.10).

Operators register per-host-group USB device policies. The agent
receives the effective policy via `DEVICE_CONTROL_SYNC` and applies it
kernel-side (udev rule on Linux, DeviceInstall registry restriction on
Windows).

Schema choices:

  * `host_group_id` is nullable — NULL means the policy applies to every
    host (global default). A non-NULL group scopes the policy to its
    members. Unique `(host_group_id, name)` so the same group can't
    register two policies under the same operator-visible name; same
    name across different scopes is fine because Postgres uniqueness
    treats NULL as distinct.
  * `kind` is constrained to the three primitives that map cleanly to
    OS-native enforcement. Anything finer (per-class, per-USB-port)
    would need agent-side machinery the MVP doesn't have.
  * `allowed_vendor_ids` + `allowed_product_ids` are JSONB lists of
    lowercase 4-hex-digit strings. Same-index entries form an
    exception pair (vid[i], pid[i]); the agent normalises this back
    into a udev rule / AllowDeviceIDs registry value.

A new `command_kind` enum value `device_control_sync` is added. Same
standalone-statement pattern as the DNS block migration — the ALTER
TYPE is benign even though it lives inside the migration transaction
because the table created afterwards doesn't touch the type.

Revision ID: e9c0d1e2f3a4
Revises: e1a2b3c4d5e6
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e9c0d1e2f3a4"
down_revision: str | None = "e1a2b3c4d5e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "device_policy",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("host_group_id", sa.Uuid(), nullable=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column(
            "allowed_vendor_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "allowed_product_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
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
            "kind IN ('usb_block', 'usb_read_only', 'usb_allow_only')",
            name="ck_device_policy_kind",
        ),
        sa.ForeignKeyConstraint(
            ["host_group_id"],
            ["host_groups.id"],
            ondelete="CASCADE",
            name="fk_device_policy_host_group_id_host_groups",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_device_policy"),
        sa.UniqueConstraint(
            "host_group_id",
            "name",
            name="uq_device_policy_host_group_id_name",
        ),
    )
    op.create_index(
        "ix_device_policy_host_group_id",
        "device_policy",
        ["host_group_id"],
        unique=False,
    )

    # IF NOT EXISTS so a partial dev-env re-apply doesn't crash.
    op.execute("ALTER TYPE command_kind ADD VALUE IF NOT EXISTS 'device_control_sync'")


def downgrade() -> None:
    op.drop_index("ix_device_policy_host_group_id", table_name="device_policy")
    op.drop_table("device_policy")
    # Postgres has no `ALTER TYPE ... DROP VALUE`. Leaving the enum
    # value in place is safe — Python code stops emitting it after
    # rollback.
