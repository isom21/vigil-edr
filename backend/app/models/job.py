"""Jobs — user-initiated units of work fanned out to one or more hosts.

M23: Jobs supersede Commands as the user-facing primitive for response
actions, telemetry collection, and incident-response acquisition. A
Job describes WHAT to do; one JobRun row per target host tracks
per-host execution; JobArtifact rows reference uploaded blobs in
MinIO (file dumps, structured snapshots, YARA match lists, etc.).

Commands are kept for backwards compatibility with already-issued
operator actions and will be migrated in M23.j.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.tenant import DEFAULT_TENANT_ID


class JobKind(str, enum.Enum):
    """v1 job catalog. Grouped by purpose; values are the wire string."""

    # --- Containment (admin) ---
    KILL_PROCESS = "kill_process"
    DELETE_FILE = "delete_file"
    ISOLATE = "isolate"
    UNISOLATE = "unisolate"
    BLOCK_PROCESS = "block_process"
    UNBLOCK_PROCESS = "unblock_process"
    BLOCK_FILE = "block_file"
    UNBLOCK_FILE = "unblock_file"
    QUARANTINE_FILE = "quarantine_file"
    RELEASE_QUARANTINE = "release_quarantine"

    # --- Acquisition (analyst, read-only on disk) ---
    FILE_ACQUIRE = "file_acquire"
    PROCESS_MEMORY_DUMP = "process_memory_dump"
    EVENT_LOG_ACQUIRE = "event_log_acquire"
    CRASH_DUMP_COLLECT = "crash_dump_collect"
    # Phase 2 #2.10 — bulk disk forensics triage. Pulls registry hives,
    # MFT, prefetch, browser histories, event logs, journal, and
    # persistence artifacts into a single ZIP archive. Admin-only
    # because the bundle aggregates secrets-bearing files (browser
    # passwords DB, SAM-style hives) into one downloadable blob.
    TRIAGE_COLLECT = "triage_collect"

    # --- Survey (analyst) ---
    PROCESS_SNAPSHOT = "process_snapshot"
    NETWORK_SNAPSHOT = "network_snapshot"
    INSTALLED_SOFTWARE = "installed_software"
    PERSISTENCE_AUDIT = "persistence_audit"
    SERVICE_AUDIT = "service_audit"
    ACCOUNT_AUDIT = "account_audit"
    DNS_HISTORY = "dns_history"
    USB_HISTORY = "usb_history"
    REGISTRY_QUERY = "registry_query"
    BROWSER_HISTORY = "browser_history"
    HOST_SWEEP = "host_sweep"

    # --- Hunt (analyst) ---
    YARA_FS_SCAN = "yara_fs_scan"
    IOC_SWEEP = "ioc_sweep"
    HASH_FILES = "hash_files"
    # Phase 2 #2.1: in-memory YARA against a target pid. Walks the
    # process address space (readable anonymous regions on Linux,
    # VirtualQueryEx loop on Windows) and matches the agent's cached
    # YARA ruleset region-by-region.
    MEMORY_YARA_SCAN = "memory_yara_scan"

    # --- Diagnostic (admin) ---
    AGENT_DIAGNOSTIC = "agent_diagnostic"
    SHELL_COMMAND = "shell_command"

    # --- Legacy carryover from CommandKind ---
    SCAN_FILE = "scan_file"
    SCAN_MEMORY = "scan_memory"
    UPDATE = "update"


# Job kinds that require admin role. Anything not here is analyst-OK.
JOB_KIND_ADMIN_ONLY: set[JobKind] = {
    JobKind.KILL_PROCESS,
    JobKind.DELETE_FILE,
    JobKind.ISOLATE,
    JobKind.UNISOLATE,
    JobKind.BLOCK_PROCESS,
    JobKind.UNBLOCK_PROCESS,
    JobKind.BLOCK_FILE,
    JobKind.UNBLOCK_FILE,
    JobKind.QUARANTINE_FILE,
    JobKind.RELEASE_QUARANTINE,
    JobKind.SHELL_COMMAND,
    JobKind.UPDATE,
    # triage_collect aggregates secrets-bearing files (registry hives
    # incl. SAM/SECURITY, browser passwords DB, MFT) into one archive.
    # Restricting to admin matches the rest of the containment +
    # destructive-action policy and keeps the audit story clean.
    JobKind.TRIAGE_COLLECT,
}


class JobScopeKind(str, enum.Enum):
    """How `Job.scope_*` resolves to concrete hosts."""

    HOST_IDS = "host_ids"
    HOST_GROUP = "host_group"
    ALL_ONLINE = "all_online"


class JobStatus(str, enum.Enum):
    """Lifecycle of the Job as a whole. Aggregated from JobRun rows by
    the manager; once all runs reach a terminal state the Job follows."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class JobRunStatus(str, enum.Enum):
    """Per-host execution status."""

    QUEUED = "queued"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"
    TIMEOUT = "timeout"


class JobArtifactKind(str, enum.Enum):
    """How the artifact should be rendered + downloaded by the UI."""

    JSON = "json"  # structured payload (process snapshot, netstat, etc.)
    FILE = "file"  # opaque binary blob (acquired file, evtx, dump)
    YARA_MATCHES = "yara_matches"
    IOC_MATCHES = "ioc_matches"
    HASH_LIST = "hash_list"
    SHELL_OUTPUT = "shell_output"
    DIAGNOSTIC_BUNDLE = "diagnostic_bundle"


class Job(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "jobs"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    kind: Mapped[JobKind] = mapped_column(
        pg_enum(JobKind, name="job_kind"), nullable=False, index=True
    )
    parameters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    scope_kind: Mapped[JobScopeKind] = mapped_column(
        pg_enum(JobScopeKind, name="job_scope_kind"), nullable=False
    )
    # When scope_kind=host_ids, the resolved list at fan-out time.
    # Stored so cancelling/reporting doesn't depend on group membership
    # changes after the job was issued.
    scope_host_ids: Mapped[list[str] | None] = mapped_column(JSONB)
    scope_group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("host_groups.id", ondelete="SET NULL")
    )

    status: Mapped[JobStatus] = mapped_column(
        pg_enum(JobStatus, name="job_status"),
        nullable=False,
        default=JobStatus.QUEUED,
        index=True,
    )
    summary: Mapped[str] = mapped_column(String(256), nullable=False, default="")

    created_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    # Source-of-record breadcrumbs: a job may be triggered by a rule
    # match (auto-action path), by the sweep scheduler (HOST_SWEEP), or
    # manually.
    triggered_by_alert_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL")
    )
    triggered_by: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")

    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    runs: Mapped[list[JobRun]] = relationship(
        back_populates="job", cascade="all, delete-orphan", lazy="selectin"
    )


class JobRun(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "job_runs"

    # Phase 3 #3.1: tenant scoping. Denormalised onto the run row so
    # the JobRun -> Host join (needed for host_visible_to) doesn't
    # require a parent-job lookup.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    job_id: Mapped[UUID] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host_id: Mapped[UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Bridge to the existing Command pipeline until M23.j fully retires
    # Commands. Each JobRun maps to exactly one Command that carries the
    # `run_job` envelope down to the agent. NULL only during the brief
    # window between row insert and fanout.
    command_id: Mapped[UUID | None] = mapped_column(ForeignKey("commands.id", ondelete="SET NULL"))

    status: Mapped[JobRunStatus] = mapped_column(
        pg_enum(JobRunStatus, name="job_run_status"),
        nullable=False,
        default=JobRunStatus.QUEUED,
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    progress_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress_message: Mapped[str | None] = mapped_column(String(256))
    last_progress_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    job: Mapped[Job] = relationship(back_populates="runs")
    artifacts: Mapped[list[JobArtifact]] = relationship(
        back_populates="run", cascade="all, delete-orphan", lazy="selectin"
    )


class JobArtifact(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "job_artifacts"

    # Phase 3 #3.1: tenant scoping. Denormalised onto the artifact
    # row so the artifact download path can refuse cross-tenant
    # access without a JobRun -> Job join.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    job_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("job_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[JobArtifactKind] = mapped_column(
        pg_enum(JobArtifactKind, name="job_artifact_kind"), nullable=False
    )
    bucket: Mapped[str] = mapped_column(String(128), nullable=False)
    object_key: Mapped[str] = mapped_column(String(512), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # Agent-reported SHA-256. The manager re-stats the upload to confirm
    # length matches; the agent's hash is trusted because the bucket
    # presigned PUT is authenticated to that specific run.
    sha256: Mapped[str | None] = mapped_column(String(64))
    artifact_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Last-download breadcrumbs for the audit story.
    downloaded_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    downloaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    run: Mapped[JobRun] = relationship(back_populates="artifacts")
