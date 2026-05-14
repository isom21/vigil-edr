"""Pydantic schemas for the honeytoken API (Phase 4 #4.5)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import HoneytokenKind
from app.schemas.common import ORMModel


class HoneytokenOut(ORMModel):
    id: UUID
    tenant_id: UUID
    host_group_id: UUID | None
    kind: HoneytokenKind
    name: str
    payload_json: dict[str, Any]
    target_path: str | None
    enabled: bool
    deployed_count: int
    hit_count: int
    created_at: datetime
    updated_at: datetime


class HoneytokenCreate(BaseModel):
    host_group_id: UUID | None = None
    kind: HoneytokenKind
    name: str = Field(min_length=1, max_length=128)
    payload_json: dict[str, Any] = Field(default_factory=dict)
    target_path: str | None = Field(default=None, max_length=1024)
    enabled: bool = True


class HoneytokenUpdate(BaseModel):
    kind: HoneytokenKind | None = None
    name: str | None = Field(default=None, min_length=1, max_length=128)
    payload_json: dict[str, Any] | None = None
    target_path: str | None = Field(default=None, max_length=1024)
    enabled: bool | None = None


class HoneytokenHitOut(ORMModel):
    id: UUID
    honeytoken_id: UUID
    host_id: UUID
    hit_at: datetime
    process_pid: int | None
    process_executable: str | None
    alert_id: UUID | None
    created_at: datetime


__all__ = [
    "HoneytokenCreate",
    "HoneytokenHitOut",
    "HoneytokenOut",
    "HoneytokenUpdate",
]
