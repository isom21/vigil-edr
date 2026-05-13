"""M20.c: quarantine inventory.

Every file moved into the agent's quarantine directory produces one
`quarantined_files` row, written when the agent emits a
QuarantineCompleted event back to the manager. The row lets the SOC:

  * Inspect what's been quarantined on a host (the original_path
    explains *what* the offending file was, the sha256 explains *which*
    bytes).
  * Release a file back to its original_path via POST
    /api/quarantined/{id}/release, which queues a RELEASE_QUARANTINE
    command back to the agent.
  * Permanently delete the quarantine copy.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.tenant import DEFAULT_TENANT_ID


class QuarantineStatus(str, enum.Enum):
    ACTIVE = "active"
    RELEASED = "released"
    DELETED = "deleted"


class QuarantinedFile(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "quarantined_files"

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
    alert_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    command_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("commands.id", ondelete="SET NULL"), nullable=True
    )

    # The path on the endpoint before quarantine. We don't index it
    # because operators look this up via host_id + status, not by path.
    original_path: Mapped[str] = mapped_column(Text, nullable=False)
    # SHA-256 of the file's bytes at quarantine time. The agent's
    # storage uses this as the filename under {state_dir}/quarantine/.
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    deleted_original: Mapped[bool] = mapped_column(nullable=False, default=False)

    quarantined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[QuarantineStatus] = mapped_column(
        pg_enum(QuarantineStatus, name="quarantine_status"),
        nullable=False,
        default=QuarantineStatus.ACTIVE,
    )
