"""Command — a response action queued for delivery to an agent.

Commands are written by the REST API (manual operator action) or the
auto-action path in detector/sigma_realtime (rule action_taken=kill|block).
The gRPC HostStream polls for pending commands per host and pushes them
down the bidi stream as ServerMessage(command=...).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.tenant import DEFAULT_TENANT_ID


class CommandKind(str, enum.Enum):
    KILL_PROCESS = "kill_process"
    BLOCK_PROCESS = "block_process"
    BLOCK_FILE = "block_file"
    UNBLOCK_PROCESS = "unblock_process"
    UNBLOCK_FILE = "unblock_file"
    ISOLATE = "isolate"
    QUARANTINE_FILE = "quarantine_file"
    RELEASE_QUARANTINE = "release_quarantine"
    # M23.b: bridge envelope used while Jobs fan out via the existing
    # Commands pipeline. Payload carries job_id + run_id + the real
    # JobKind + parameters; agents dispatch by JobKind.
    RUN_JOB = "run_job"
    # Phase 2 #2.8: push the current per-host-group application
    # allowlist + mode down to one agent. Payload carries
    # {"mode": "off|learn|enforce", "hashes": [hex...]}.
    ALLOWLIST_SYNC = "allowlist_sync"
    # Phase 2 #2.12: whole-list DNS block resync. Payload carries
    # `block_domains` + `sinkhole_domains` lists; the agent replaces
    # its kernel-side map atomically on receipt.
    DNS_BLOCK_SYNC = "dns_block_sync"
    # Phase 3 #3.10: per-host device control / USB block policy push.
    # Payload carries the effective `kind` + `allowed_vids` /
    # `allowed_pids` lists + `enabled` flag; the agent writes the
    # matching udev rule (Linux) or DeviceInstall registry value
    # (Windows). One command = one effective policy.
    DEVICE_CONTROL_SYNC = "device_control_sync"


class CommandStatus(str, enum.Enum):
    PENDING = "pending"
    DISPATCHED = "dispatched"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class Command(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "commands"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    host_id: Mapped[UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[CommandKind] = mapped_column(
        pg_enum(CommandKind, name="command_kind"), nullable=False
    )
    status: Mapped[CommandStatus] = mapped_column(
        pg_enum(CommandStatus, name="command_status"),
        nullable=False,
        default=CommandStatus.PENDING,
        index=True,
    )
    # Action-specific fields. For kill: {"pid": 1234}. For block_*: {"pattern": "..."}.
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Optional: which alert / rule triggered this. Useful for the auto-action
    # path to leave a breadcrumb. NULL for manual operator triggers.
    triggered_by_alert_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL")
    )
    triggered_by_rule_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("rules.id", ondelete="SET NULL")
    )
    issued_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(String(512))
