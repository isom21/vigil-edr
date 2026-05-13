"""Pydantic schemas for the device control API (Phase 3 #3.10)."""

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.models import DevicePolicyKind
from app.schemas.common import ORMModel

# 4-hex-digit USB VID/PID. Stored lowercase so the comparison the agent
# does kernel-side (case-insensitive on Linux, but the udev rule
# rendering wants a stable form) stays deterministic.
_HEX4 = re.compile(r"^[0-9a-fA-F]{4}$")


def _normalise_id(value: str) -> str:
    v = value.strip().lower().removeprefix("0x")
    if not _HEX4.match(v):
        raise ValueError(f"expected 4 hex digits, got {value!r}")
    return v


class DevicePolicyOut(ORMModel):
    id: UUID
    host_group_id: UUID | None
    kind: DevicePolicyKind
    allowed_vendor_ids: list[str]
    allowed_product_ids: list[str]
    enabled: bool
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime


class DevicePolicyCreate(BaseModel):
    host_group_id: UUID | None = None
    kind: DevicePolicyKind
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)
    allowed_vendor_ids: list[str] = Field(default_factory=list, max_length=256)
    allowed_product_ids: list[str] = Field(default_factory=list, max_length=256)
    enabled: bool = True

    @field_validator("allowed_vendor_ids", "allowed_product_ids")
    @classmethod
    def _normalise_ids(cls, v: list[str]) -> list[str]:
        return [_normalise_id(x) for x in v]


class DevicePolicyUpdate(BaseModel):
    kind: DevicePolicyKind | None = None
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)
    allowed_vendor_ids: list[str] | None = Field(default=None, max_length=256)
    allowed_product_ids: list[str] | None = Field(default=None, max_length=256)
    enabled: bool | None = None

    @field_validator("allowed_vendor_ids", "allowed_product_ids")
    @classmethod
    def _normalise_ids(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return [_normalise_id(x) for x in v]


__all__ = [
    "DevicePolicyCreate",
    "DevicePolicyOut",
    "DevicePolicyUpdate",
]
