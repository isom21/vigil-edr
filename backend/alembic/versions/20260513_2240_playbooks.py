"""Playbook / runbook automation (Phase 3 #3.5).

YAML-defined response chains. When an alert fires and a matching
playbook exists, the executor runs the playbook in addition to the
rule's RuleAction.

Tables:

  * `playbook` — operator-authored response chains. Trigger keys
    (rule_id, severity, mitre technique) determine which alerts fire
    which playbooks. All three are optional; a playbook with all NULL
    triggers is dormant.
  * `playbook_run` — append-only execution history. One row per
    triggered run. `steps_executed_json` records each step's outcome
    in order so the UI can render a per-run timeline.

Playbook runs aren't audited (high volume); operators audit the
`playbook.{create,update,delete}` writes in `audit_log`.

Revision ID: e5e6f7a8b9c0
Revises: e6f7a8b9c0d1
Create Date: 2026-05-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "e5e6f7a8b9c0"
down_revision: str | None = "e6f7a8b9c0d1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The playbook engine queues `isolate` + `quarantine_file` Commands
    # for the matching steps. Both labels live in the Python
    # `CommandKind` enum but were never added to the Postgres
    # `command_kind` enum by earlier migrations (originally created in
    # M5 with just the kill/block kinds). Adding them here keeps the
    # playbook flow working end-to-end; the values are no-ops for the
    # Commands UI / dispatch path until a playbook actually queues one.
    #
    # ALTER TYPE ADD VALUE can't run inside the same transaction that
    # then references the new label, so we use autocommit_block — same
    # pattern as the allowlist migration. The CREATE TABLE below
    # doesn't touch these labels, so the rest of the upgrade stays in
    # the normal migration transaction.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE command_kind ADD VALUE IF NOT EXISTS 'isolate'")
        op.execute("ALTER TYPE command_kind ADD VALUE IF NOT EXISTS 'quarantine_file'")

    op.create_table(
        "playbook",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("yaml_body", sa.Text(), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("trigger_rule_id", sa.Uuid(), nullable=True),
        sa.Column("trigger_severity", sa.Text(), nullable=True),
        sa.Column("trigger_mitre_techniques", postgresql.JSONB(), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_playbook"),
        sa.UniqueConstraint("name", name="uq_playbook_name"),
        sa.ForeignKeyConstraint(
            ["trigger_rule_id"],
            ["rules.id"],
            ondelete="SET NULL",
            name="fk_playbook_trigger_rule_id_rules",
        ),
        sa.CheckConstraint(
            "trigger_severity IS NULL OR trigger_severity IN ('low','medium','high','critical')",
            name="ck_playbook_trigger_severity",
        ),
    )

    op.create_table(
        "playbook_run",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("playbook_id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column(
            "steps_executed_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_playbook_run"),
        sa.ForeignKeyConstraint(
            ["playbook_id"],
            ["playbook.id"],
            ondelete="CASCADE",
            name="fk_playbook_run_playbook_id_playbook",
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            ondelete="SET NULL",
            name="fk_playbook_run_alert_id_alerts",
        ),
        sa.CheckConstraint(
            "status IN ('pending','running','succeeded','failed','partial')",
            name="ck_playbook_run_status",
        ),
    )
    op.create_index(
        "ix_playbook_run_playbook_id_started_at",
        "playbook_run",
        ["playbook_id", sa.text("started_at DESC")],
        unique=False,
    )
    op.create_index(
        "ix_playbook_run_alert_id_started_at",
        "playbook_run",
        ["alert_id", sa.text("started_at DESC")],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_playbook_run_alert_id_started_at", table_name="playbook_run")
    op.drop_index("ix_playbook_run_playbook_id_started_at", table_name="playbook_run")
    op.drop_table("playbook_run")
    op.drop_table("playbook")
    # Postgres has no ALTER TYPE DROP VALUE; leaving 'isolate' and
    # 'quarantine_file' on `command_kind` is safe — both labels match
    # what the Python `CommandKind` enum has always claimed, so a
    # rollback of this migration just leaves them as inert values the
    # rest of the codebase already references at the model level.
