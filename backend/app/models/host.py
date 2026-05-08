"""Endpoint / host model."""
from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin


class HostStatus(str, enum.Enum):
    PENDING = "pending"        # enrolled but not yet connected
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

    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    os_family: Mapped[OsFamily] = mapped_column(Enum(OsFamily, name="os_family"), nullable=False)
    os_version: Mapped[str | None] = mapped_column(String(64))
    os_platform: Mapped[str | None] = mapped_column(String(128))
    os_arch: Mapped[str | None] = mapped_column(String(32))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    cert_fingerprint: Mapped[str | None] = mapped_column(String(128), unique=True, index=True)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[HostStatus] = mapped_column(
        Enum(HostStatus, name="host_status"), nullable=False, default=HostStatus.PENDING
    )
    policy_id: Mapped[UUID | None] = mapped_column(ForeignKey("policies.id", ondelete="SET NULL"))
