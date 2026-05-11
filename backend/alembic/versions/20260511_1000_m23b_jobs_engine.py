"""M23.b: Jobs engine — jobs / job_runs / job_artifacts.

Adds the schema that supersedes Commands as the user-facing primitive
for response actions and incident-response work. JobRun.command_id
keeps a bridge to the existing Commands pipeline for the dispatch
path; M23.j fully retires Commands.

Revision ID: f5b4a1d7e29c
Revises: e1d4a82c97bf
Create Date: 2026-05-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "f5b4a1d7e29c"
down_revision: str | None = "e1d4a82c97bf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Listed once so the four enum creations stay in sync with the model.
_JOB_KINDS = [
    "kill_process",
    "delete_file",
    "isolate",
    "unisolate",
    "block_process",
    "unblock_process",
    "block_file",
    "unblock_file",
    "quarantine_file",
    "release_quarantine",
    "file_acquire",
    "process_memory_dump",
    "event_log_acquire",
    "crash_dump_collect",
    "process_snapshot",
    "network_snapshot",
    "installed_software",
    "persistence_audit",
    "service_audit",
    "account_audit",
    "dns_history",
    "usb_history",
    "registry_query",
    "browser_history",
    "host_sweep",
    "yara_fs_scan",
    "ioc_sweep",
    "hash_files",
    "agent_diagnostic",
    "shell_command",
    "scan_file",
    "scan_memory",
    "update",
]
_JOB_SCOPE_KINDS = ["host_ids", "host_group", "all_online"]
_JOB_STATUSES = ["queued", "running", "completed", "failed", "canceled"]
_JOB_RUN_STATUSES = [
    "queued",
    "dispatched",
    "running",
    "completed",
    "failed",
    "canceled",
    "timeout",
]
_JOB_ARTIFACT_KINDS = [
    "json",
    "file",
    "yara_matches",
    "ioc_matches",
    "hash_list",
    "shell_output",
    "diagnostic_bundle",
]


def upgrade() -> None:
    bind = op.get_bind()

    postgresql.ENUM(*_JOB_KINDS, name="job_kind").create(bind, checkfirst=True)
    postgresql.ENUM(*_JOB_SCOPE_KINDS, name="job_scope_kind").create(bind, checkfirst=True)
    postgresql.ENUM(*_JOB_STATUSES, name="job_status").create(bind, checkfirst=True)
    postgresql.ENUM(*_JOB_RUN_STATUSES, name="job_run_status").create(bind, checkfirst=True)
    postgresql.ENUM(*_JOB_ARTIFACT_KINDS, name="job_artifact_kind").create(bind, checkfirst=True)

    job_kind = postgresql.ENUM(name="job_kind", create_type=False)
    job_scope_kind = postgresql.ENUM(name="job_scope_kind", create_type=False)
    job_status = postgresql.ENUM(name="job_status", create_type=False)
    job_run_status = postgresql.ENUM(name="job_run_status", create_type=False)
    job_artifact_kind = postgresql.ENUM(name="job_artifact_kind", create_type=False)

    op.create_table(
        "jobs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("kind", job_kind, nullable=False),
        sa.Column("parameters", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("scope_kind", job_scope_kind, nullable=False),
        sa.Column("scope_host_ids", postgresql.JSONB(), nullable=True),
        sa.Column(
            "scope_group_id",
            sa.Uuid(),
            sa.ForeignKey("host_groups.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", job_status, nullable=False, server_default="queued"),
        sa.Column("summary", sa.String(256), nullable=False, server_default=""),
        sa.Column(
            "created_by_user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "triggered_by_alert_id",
            sa.Uuid(),
            sa.ForeignKey("alerts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("triggered_by", sa.String(32), nullable=False, server_default="manual"),
        sa.Column("canceled_at", sa.DateTime(timezone=True), nullable=True),
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
    op.create_index("ix_jobs_kind", "jobs", ["kind"])
    op.create_index("ix_jobs_status", "jobs", ["status"])
    op.create_index("ix_jobs_created_at", "jobs", [sa.text("created_at DESC")])

    op.create_table(
        "job_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "job_id",
            sa.Uuid(),
            sa.ForeignKey("jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "host_id",
            sa.Uuid(),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "command_id",
            sa.Uuid(),
            sa.ForeignKey("commands.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", job_run_status, nullable=False, server_default="queued"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("progress_pct", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("progress_message", sa.String(256), nullable=True),
        sa.Column("last_progress_at", sa.DateTime(timezone=True), nullable=True),
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
    op.create_index("ix_job_runs_job_id", "job_runs", ["job_id"])
    op.create_index("ix_job_runs_host_id", "job_runs", ["host_id"])
    op.create_index("ix_job_runs_status", "job_runs", ["status"])
    op.create_index(
        "ix_job_runs_host_status_created",
        "job_runs",
        ["host_id", "status", sa.text("created_at DESC")],
    )

    op.create_table(
        "job_artifacts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "job_run_id",
            sa.Uuid(),
            sa.ForeignKey("job_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", job_artifact_kind, nullable=False),
        sa.Column("bucket", sa.String(128), nullable=False),
        sa.Column("object_key", sa.String(512), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column(
            "artifact_metadata",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "downloaded_by_user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("downloaded_at", sa.DateTime(timezone=True), nullable=True),
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
    op.create_index("ix_job_artifacts_job_run_id", "job_artifacts", ["job_run_id"])
    op.create_index("ix_job_artifacts_kind", "job_artifacts", ["kind"])


def downgrade() -> None:
    op.drop_index("ix_job_artifacts_kind", table_name="job_artifacts")
    op.drop_index("ix_job_artifacts_job_run_id", table_name="job_artifacts")
    op.drop_table("job_artifacts")

    op.drop_index("ix_job_runs_host_status_created", table_name="job_runs")
    op.drop_index("ix_job_runs_status", table_name="job_runs")
    op.drop_index("ix_job_runs_host_id", table_name="job_runs")
    op.drop_index("ix_job_runs_job_id", table_name="job_runs")
    op.drop_table("job_runs")

    op.drop_index("ix_jobs_created_at", table_name="jobs")
    op.drop_index("ix_jobs_status", table_name="jobs")
    op.drop_index("ix_jobs_kind", table_name="jobs")
    op.drop_table("jobs")

    bind = op.get_bind()
    for name in (
        "job_artifact_kind",
        "job_run_status",
        "job_status",
        "job_scope_kind",
        "job_kind",
    ):
        postgresql.ENUM(name=name).drop(bind, checkfirst=True)
