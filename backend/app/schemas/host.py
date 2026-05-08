"""Host payloads."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import HostStatus, OsFamily
from app.schemas.common import ORMModel


class HostOut(ORMModel):
    id: UUID
    hostname: str
    os_family: OsFamily
    os_version: str | None
    os_platform: str | None
    os_arch: str | None
    agent_version: str | None
    status: HostStatus
    enrolled_at: datetime | None
    last_seen_at: datetime | None
    policy_id: UUID | None


class HostUpdate(BaseModel):
    policy_id: UUID | None = None
    status: HostStatus | None = None


class HostListFilter(BaseModel):
    status: HostStatus | None = None
    os_family: OsFamily | None = None
    q: str | None = Field(default=None, description="hostname substring")
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
