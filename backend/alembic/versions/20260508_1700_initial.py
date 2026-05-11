"""initial schema

Revision ID: 20260508_1700
Revises:
Create Date: 2026-05-08 17:00:00
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "20260508_1700"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


user_role = postgresql.ENUM("admin", "analyst", "viewer", name="user_role")
os_family = postgresql.ENUM("windows", "linux", "macos", name="os_family")
host_status = postgresql.ENUM(
    "pending", "online", "offline", "isolated", "decommissioned", name="host_status"
)
rule_kind = postgresql.ENUM("yara", "sigma", "ioc", name="rule_kind")
rule_action = postgresql.ENUM("detect", "kill", "block", name="rule_action")
rule_severity = postgresql.ENUM(
    "info", "low", "medium", "high", "critical", name="rule_severity"
)
ioc_kind = postgresql.ENUM(
    "hash_sha256", "hash_md5", "hash_sha1", "filename", "filepath", name="ioc_kind"
)
alert_state = postgresql.ENUM(
    "new", "investigating", "false_positive", "true_positive", name="alert_state"
)


def upgrade() -> None:
    bind = op.get_bind()
    user_role.create(bind, checkfirst=True)
    os_family.create(bind, checkfirst=True)
    host_status.create(bind, checkfirst=True)
    rule_kind.create(bind, checkfirst=True)
    rule_action.create(bind, checkfirst=True)
    rule_severity.create(bind, checkfirst=True)
    ioc_kind.create(bind, checkfirst=True)
    alert_state.create(bind, checkfirst=True)

    # users
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column(
            "role",
            postgresql.ENUM(name="user_role", create_type=False),
            nullable=False,
            server_default="analyst",
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_email", "users", ["email"])

    # certificate_authority
    op.create_table(
        "certificate_authority",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cert_pem", sa.Text(), nullable=False),
        sa.Column("key_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fingerprint_sha256", sa.Text(), nullable=False),
    )

    # policies
    op.create_table(
        "policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name", name="uq_policies_name"),
    )

    # hosts
    op.create_table(
        "hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column(
            "os_family",
            postgresql.ENUM(name="os_family", create_type=False),
            nullable=False,
        ),
        sa.Column("os_version", sa.String(64)),
        sa.Column("os_platform", sa.String(128)),
        sa.Column("os_arch", sa.String(32)),
        sa.Column("agent_version", sa.String(32)),
        sa.Column("cert_fingerprint", sa.String(128)),
        sa.Column("enrolled_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column(
            "status",
            postgresql.ENUM(name="host_status", create_type=False),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id"], ["policies.id"], name="fk_hosts_policy_id_policies", ondelete="SET NULL"
        ),
        sa.UniqueConstraint("cert_fingerprint", name="uq_hosts_cert_fingerprint"),
    )
    op.create_index("ix_hosts_hostname", "hosts", ["hostname"])
    op.create_index("ix_hosts_cert_fingerprint", "hosts", ["cert_fingerprint"])

    # rules
    op.create_table(
        "rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "kind", postgresql.ENUM(name="rule_kind", create_type=False), nullable=False
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column(
            "severity",
            postgresql.ENUM(name="rule_severity", create_type=False),
            nullable=False,
            server_default="medium",
        ),
        sa.Column(
            "action",
            postgresql.ENUM(name="rule_action", create_type=False),
            nullable=False,
            server_default="detect",
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("body", sa.Text()),
        sa.Column("sigma_compiled", sa.Text()),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_rules_name", "rules", ["name"])

    # ioc_entries
    op.create_table(
        "ioc_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "kind", postgresql.ENUM(name="ioc_kind", create_type=False), nullable=False
        ),
        sa.Column("value", sa.String(1024), nullable=False),
        sa.Column("value_normalized", sa.String(1024), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"], ["rules.id"], name="fk_ioc_entries_rule_id_rules", ondelete="CASCADE"
        ),
    )
    op.create_index("ix_ioc_entries_rule_id", "ioc_entries", ["rule_id"])
    op.create_index("ix_ioc_entries_value_normalized", "ioc_entries", ["value_normalized"])

    # policy_rules
    op.create_table(
        "policy_rules",
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "action_override", postgresql.ENUM(name="rule_action", create_type=False)
        ),
        sa.Column("enabled_override", sa.Boolean()),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["policies.id"],
            name="fk_policy_rules_policy_id_policies",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["rules.id"],
            name="fk_policy_rules_rule_id_rules",
            ondelete="CASCADE",
        ),
    )

    # enrollment_tokens
    op.create_table(
        "enrollment_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("label", sa.String(128)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("used_by_host_id", postgresql.UUID(as_uuid=True)),
        sa.Column("created_by", postgresql.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["used_by_host_id"],
            ["hosts.id"],
            name="fk_enrollment_tokens_used_by_host_id_hosts",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name="fk_enrollment_tokens_created_by_users",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("token_hash", name="uq_enrollment_tokens_token_hash"),
    )
    op.create_index("ix_enrollment_tokens_token_hash", "enrollment_tokens", ["token_hash"])

    # api_tokens
    op.create_table(
        "api_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column(
            "scopes", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_api_tokens_user_id_users", ondelete="CASCADE"
        ),
    )
    op.create_index("ix_api_tokens_user_id", "api_tokens", ["user_id"])

    # alerts
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "severity",
            postgresql.ENUM(name="rule_severity", create_type=False),
            nullable=False,
        ),
        sa.Column(
            "action_taken",
            postgresql.ENUM(name="rule_action", create_type=False),
            nullable=False,
            server_default="detect",
        ),
        sa.Column(
            "state",
            postgresql.ENUM(name="alert_state", create_type=False),
            nullable=False,
            server_default="new",
        ),
        sa.Column("summary", sa.String(512), nullable=False),
        sa.Column("details", sa.JSON()),
        sa.Column("telemetry_index", sa.String(128)),
        sa.Column("telemetry_doc_ids", sa.JSON()),
        sa.Column(
            "opened_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("assignee_id", postgresql.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["host_id"], ["hosts.id"], name="fk_alerts_host_id_hosts", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"], ["rules.id"], name="fk_alerts_rule_id_rules", ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["assignee_id"],
            ["users.id"],
            name="fk_alerts_assignee_id_users",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_alerts_host_id", "alerts", ["host_id"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_state", "alerts", ["state"])

    # alert_state_history
    op.create_table(
        "alert_state_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "from_state", postgresql.ENUM(name="alert_state", create_type=False)
        ),
        sa.Column(
            "to_state", postgresql.ENUM(name="alert_state", create_type=False), nullable=False
        ),
        sa.Column("by_user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("comment", sa.Text()),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name="fk_alert_state_history_alert_id_alerts",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["by_user_id"],
            ["users.id"],
            name="fk_alert_state_history_by_user_id_users",
            ondelete="SET NULL",
        ),
    )
    op.create_index("ix_alert_state_history_alert_id", "alert_state_history", ["alert_id"])

    # audit_log
    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("actor_kind", sa.String(32), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource_type", sa.String(64)),
        sa.Column("resource_id", sa.String(64)),
        sa.Column("payload", sa.JSON()),
        sa.Column("ip", sa.String(64)),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_audit_log_user_id_users", ondelete="SET NULL"
        ),
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_resource_type", "audit_log", ["resource_type"])
    op.create_index("ix_audit_log_resource_id", "audit_log", ["resource_id"])
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("alert_state_history")
    op.drop_table("alerts")
    op.drop_table("api_tokens")
    op.drop_table("enrollment_tokens")
    op.drop_table("policy_rules")
    op.drop_table("ioc_entries")
    op.drop_table("rules")
    op.drop_table("hosts")
    op.drop_table("policies")
    op.drop_table("certificate_authority")
    op.drop_table("users")

    bind = op.get_bind()
    for enum_obj in (
        alert_state,
        ioc_kind,
        rule_severity,
        rule_action,
        rule_kind,
        host_status,
        os_family,
        user_role,
    ):
        enum_obj.drop(bind, checkfirst=True)
