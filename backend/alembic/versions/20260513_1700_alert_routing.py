"""Alert routing: notification channels + routing rules (Phase 1 #1.7).

Operators define routing rules ("alerts matching severity ≥ X, optional
rule_kind, optional host_group → fire these channels"). Channels are
credentialed integrations: Slack incoming webhook, PagerDuty Events v2
integration key, or SMTP destination. The worker that fires them lives
in `app/workers/alert_router.py`.

Two tables:

  * `notification_channels`: credentialed destinations. The credentials
    blob is Fernet-encrypted under `VIGIL_NOTIFICATION_ENCRYPTION_KEY`
    so a DB dump alone doesn't leak webhook URLs / integration keys.
  * `routing_rules`: declarative match (min severity, optional rule
    kind, optional host group) + ordered list of channel ids to fire.

`channel_ids` is a UUID[] rather than a join table. Worst-case in the
matcher is a per-rule fan-out over the small array. Promoting to a
join table is the future refactor when (a) we want per-channel retry
state or (b) channel reuse across rules grows past 1:1.

Revision ID: 2c91a4f08b5d
Revises: 7d3f8e1a2b4c
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "2c91a4f08b5d"
down_revision: str | None = "9c4d2e6a8f1b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    notification_channel_kind = postgresql.ENUM(
        "slack",
        "pagerduty",
        "email",
        name="notification_channel_kind",
    )
    notification_channel_kind.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column(
            "kind",
            postgresql.ENUM(
                "slack",
                "pagerduty",
                "email",
                name="notification_channel_kind",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("encrypted_config", sa.LargeBinary(), nullable=False),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_notification_channels_name"),
    )
    op.create_index(
        "ix_notification_channels_name", "notification_channels", ["name"], unique=False
    )

    op.create_table(
        "routing_rules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        # Lowest severity that triggers the rule. Severity reuses the
        # existing rule_severity enum so we don't end up with two
        # parallel orderings.
        sa.Column(
            "min_severity",
            postgresql.ENUM(name="rule_severity", create_type=False),
            nullable=False,
            server_default="medium",
        ),
        # Optional filters. NULL == match-anything.
        sa.Column(
            "rule_kind",
            postgresql.ENUM(name="rule_kind", create_type=False),
            nullable=True,
        ),
        sa.Column(
            "host_group_id",
            sa.Uuid(),
            nullable=True,
        ),
        sa.Column(
            "channel_ids",
            postgresql.ARRAY(sa.Uuid()),
            nullable=False,
            server_default=sa.text("ARRAY[]::uuid[]"),
        ),
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
        sa.ForeignKeyConstraint(
            ["host_group_id"],
            ["host_groups.id"],
            ondelete="SET NULL",
            name="fk_routing_rules_host_group_id_host_groups",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_routing_rules_name"),
    )
    op.create_index("ix_routing_rules_name", "routing_rules", ["name"], unique=False)
    op.create_index(
        "ix_routing_rules_host_group_id",
        "routing_rules",
        ["host_group_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_routing_rules_host_group_id", table_name="routing_rules")
    op.drop_index("ix_routing_rules_name", table_name="routing_rules")
    op.drop_table("routing_rules")
    op.drop_index("ix_notification_channels_name", table_name="notification_channels")
    op.drop_table("notification_channels")
    op.execute("DROP TYPE IF EXISTS notification_channel_kind")
