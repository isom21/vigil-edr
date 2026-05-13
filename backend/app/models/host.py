"""Endpoint / host model."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.tenant import DEFAULT_TENANT_ID


class HostStatus(str, enum.Enum):
    PENDING = "pending"  # enrolled but not yet connected
    ONLINE = "online"
    OFFLINE = "offline"
    ISOLATED = "isolated"
    DECOMMISSIONED = "decommissioned"


class OsFamily(str, enum.Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class Host(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "hosts"

    # Phase 3 #3.1: tenant scoping. The enrollment token a host
    # registered under stamps this value; agents are tenant-blind.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    os_family: Mapped[OsFamily] = mapped_column(pg_enum(OsFamily, name="os_family"), nullable=False)
    os_version: Mapped[str | None] = mapped_column(String(64))
    os_platform: Mapped[str | None] = mapped_column(String(128))
    os_arch: Mapped[str | None] = mapped_column(String(32))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    cert_fingerprint: Mapped[str | None] = mapped_column(String(128), unique=True, index=True)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[HostStatus] = mapped_column(
        pg_enum(HostStatus, name="host_status"), nullable=False, default=HostStatus.PENDING
    )
    policy_id: Mapped[UUID | None] = mapped_column(ForeignKey("policies.id", ondelete="SET NULL"))
    # M9.5: comma-separated capability flags from the agent's Hello.
    # NULL until the agent reconnects post-upgrade. Cap at 1024 chars.
    capabilities: Mapped[str | None] = mapped_column(String(1024))
    # M23.h: when the sweep scheduler last fired a HOST_SWEEP job for
    # this host. NULL until the first sweep completes.
    last_sweep_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
