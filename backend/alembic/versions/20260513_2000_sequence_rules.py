"""sequence_rules table (Phase 2 #2.3 — sequence/behavioral rules engine).

Adds the table the YAML-defined sequence rules persist into. The
worker (`app.workers.sequence_detector`) consumes the
`telemetry.normalized` topic, advances per-host state with TTL, and
emits an Alert when a sequence completes. The Alert's rule_id FK
points at a lazily-created managed `Rule` row (mirrors the intel-feed
pattern) so existing alert UI / dedup / routing don't need a new
code path.

Revision ID: d2b3c4d5e6f7
Revises: 2c91a4f08b5d
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "d2b3c4d5e6f7"
down_revision: str | None = "2c91a4f08b5d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # `rule_severity` enum already exists from the rules table; reuse
    # it here rather than creating a parallel type. The
    # postgresql.ENUM(...) helper with `create_type=False` is the
    # pattern the rest of the migrations use to bind to a pre-existing
    # type without emitting a CREATE TYPE.
    rule_severity = postgresql.ENUM(name="rule_severity", create_type=False)

    op.create_table(
        "sequence_rules",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("yaml_body", sa.Text(), nullable=False),
        sa.Column(
            "window_s",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("60"),
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column(
            "severity",
            rule_severity,
            nullable=False,
            server_default=sa.text("'medium'"),
        ),
        sa.Column("mitre_techniques", sa.JSON(), nullable=True),
        sa.Column(
            "hit_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("managed_rule_id", sa.Uuid(), nullable=True),
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
    op.create_unique_constraint("uq_sequence_rules_name", "sequence_rules", ["name"])
    op.create_foreign_key(
        "fk_sequence_rules_created_by_user_id_users",
        "sequence_rules",
        "users",
        ["created_by_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_sequence_rules_managed_rule_id_rules",
        "sequence_rules",
        "rules",
        ["managed_rule_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_sequence_rules_enabled", "sequence_rules", ["enabled"])


def downgrade() -> None:
    op.drop_index("ix_sequence_rules_enabled", table_name="sequence_rules")
    op.drop_constraint(
        "fk_sequence_rules_managed_rule_id_rules",
        "sequence_rules",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_sequence_rules_created_by_user_id_users",
        "sequence_rules",
        type_="foreignkey",
    )
    op.drop_constraint("uq_sequence_rules_name", "sequence_rules", type_="unique")
    op.drop_table("sequence_rules")
