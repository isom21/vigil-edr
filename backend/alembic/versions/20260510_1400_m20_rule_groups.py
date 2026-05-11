"""M20: simplified action enum (alert/block/quarantine) + rule groups.

Two pieces wrapped in one migration because they share enum surgery:

1. Renames RuleAction values:
       detect      -> alert
       kill        -> block
       block       -> block  (no-op, but explicit so the SQL is symmetric)
       quarantine  -> quarantine
   Affects two columns: rules.action and alerts.action_taken.

2. Adds rule_groups table + rules.group_id FK. A rule's effective
   action at fire time is clamped down to its group's max_action
   (see app.models.rule.clamp_action).

Postgres enums don't support ALTER TYPE … RENAME VALUE in a way that
also lets us drop values atomically, so the migration creates a new
type `rule_action_v2`, swaps both columns onto it, then drops the
old type.

Revision ID: a7c1e4f9d23b
Revises: 9b5f3e7c1d82
Create Date: 2026-05-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "a7c1e4f9d23b"
down_revision: str | None = "9b5f3e7c1d82"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ---- 1. swap rule_action enum onto the new value set ----
    op.execute("CREATE TYPE rule_action_v2 AS ENUM ('alert', 'block', 'quarantine')")

    # rules.action: detach default, retype, remap, reset default.
    op.execute("ALTER TABLE rules ALTER COLUMN action DROP DEFAULT")
    op.execute(
        """
        ALTER TABLE rules
        ALTER COLUMN action TYPE rule_action_v2 USING (
            CASE action::text
                WHEN 'detect'     THEN 'alert'::rule_action_v2
                WHEN 'kill'       THEN 'block'::rule_action_v2
                WHEN 'block'      THEN 'block'::rule_action_v2
                WHEN 'quarantine' THEN 'quarantine'::rule_action_v2
                ELSE 'alert'::rule_action_v2
            END
        )
        """
    )
    op.execute(
        "ALTER TABLE rules ALTER COLUMN action SET DEFAULT 'alert'::rule_action_v2"
    )

    # alerts.action_taken: same remap.
    op.execute("ALTER TABLE alerts ALTER COLUMN action_taken DROP DEFAULT")
    op.execute(
        """
        ALTER TABLE alerts
        ALTER COLUMN action_taken TYPE rule_action_v2 USING (
            CASE action_taken::text
                WHEN 'detect'     THEN 'alert'::rule_action_v2
                WHEN 'kill'       THEN 'block'::rule_action_v2
                WHEN 'block'      THEN 'block'::rule_action_v2
                WHEN 'quarantine' THEN 'quarantine'::rule_action_v2
                ELSE 'alert'::rule_action_v2
            END
        )
        """
    )
    op.execute(
        "ALTER TABLE alerts ALTER COLUMN action_taken SET DEFAULT 'alert'::rule_action_v2"
    )

    # policy_rules.action_override: nullable, no default to clear.
    op.execute(
        """
        ALTER TABLE policy_rules
        ALTER COLUMN action_override TYPE rule_action_v2 USING (
            CASE action_override::text
                WHEN 'detect'     THEN 'alert'::rule_action_v2
                WHEN 'kill'       THEN 'block'::rule_action_v2
                WHEN 'block'      THEN 'block'::rule_action_v2
                WHEN 'quarantine' THEN 'quarantine'::rule_action_v2
                ELSE NULL
            END
        )
        """
    )

    # Drop the old enum and rename the new one into its place. The
    # rename keeps the model's `name="rule_action"` mapping intact.
    op.execute("DROP TYPE rule_action")
    op.execute("ALTER TYPE rule_action_v2 RENAME TO rule_action")

    # ---- 2. rule_groups table + rules.group_id FK ----
    op.create_table(
        "rule_groups",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "kind",
            postgresql.ENUM(
                "yara", "sigma", "ioc", name="rule_kind", create_type=False
            ),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "max_action",
            postgresql.ENUM(
                "alert", "block", "quarantine", name="rule_action", create_type=False
            ),
            nullable=False,
            server_default="alert",
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
    op.create_index("ix_rule_groups_name", "rule_groups", ["name"])
    op.create_index("ix_rule_groups_kind", "rule_groups", ["kind"])

    op.add_column(
        "rules",
        sa.Column("group_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_rules_group_id",
        "rules",
        "rule_groups",
        ["group_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_rules_group_id", "rules", ["group_id"])


def downgrade() -> None:
    op.drop_index("ix_rules_group_id", table_name="rules")
    op.drop_constraint("fk_rules_group_id", "rules", type_="foreignkey")
    op.drop_column("rules", "group_id")
    op.drop_index("ix_rule_groups_kind", table_name="rule_groups")
    op.drop_index("ix_rule_groups_name", table_name="rule_groups")
    op.drop_table("rule_groups")

    # Roll the enum back. quarantine has no old equivalent — it's
    # been a wire value since M11.f — so we keep it as `block` on
    # downgrade (operator can recover the rows manually if needed).
    op.execute("CREATE TYPE rule_action_v1 AS ENUM ('detect', 'kill', 'block')")
    op.execute("ALTER TABLE rules ALTER COLUMN action DROP DEFAULT")
    op.execute(
        """
        ALTER TABLE rules
        ALTER COLUMN action TYPE rule_action_v1 USING (
            CASE action::text
                WHEN 'alert'      THEN 'detect'::rule_action_v1
                WHEN 'block'      THEN 'block'::rule_action_v1
                WHEN 'quarantine' THEN 'block'::rule_action_v1
                ELSE 'detect'::rule_action_v1
            END
        )
        """
    )
    op.execute(
        "ALTER TABLE rules ALTER COLUMN action SET DEFAULT 'detect'::rule_action_v1"
    )

    op.execute("ALTER TABLE alerts ALTER COLUMN action_taken DROP DEFAULT")
    op.execute(
        """
        ALTER TABLE alerts
        ALTER COLUMN action_taken TYPE rule_action_v1 USING (
            CASE action_taken::text
                WHEN 'alert'      THEN 'detect'::rule_action_v1
                WHEN 'block'      THEN 'block'::rule_action_v1
                WHEN 'quarantine' THEN 'block'::rule_action_v1
                ELSE 'detect'::rule_action_v1
            END
        )
        """
    )
    op.execute(
        "ALTER TABLE alerts ALTER COLUMN action_taken SET DEFAULT 'detect'::rule_action_v1"
    )

    op.execute(
        """
        ALTER TABLE policy_rules
        ALTER COLUMN action_override TYPE rule_action_v1 USING (
            CASE action_override::text
                WHEN 'alert'      THEN 'detect'::rule_action_v1
                WHEN 'block'      THEN 'block'::rule_action_v1
                WHEN 'quarantine' THEN 'block'::rule_action_v1
                ELSE NULL
            END
        )
        """
    )
    op.execute("DROP TYPE rule_action")
    op.execute("ALTER TYPE rule_action_v1 RENAME TO rule_action")
