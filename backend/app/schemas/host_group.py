"""Pydantic schemas for the host-groups API (M7.5)."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class HostGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)


class HostGroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)


class HostGroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime
    host_count: int = 0
    user_count: int = 0


class HostGroupMembership(BaseModel):
    host_ids: list[UUID] = Field(default_factory=list)
    user_ids: list[UUID] = Field(default_factory=list)
