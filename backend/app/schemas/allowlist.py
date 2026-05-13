"""Pydantic schemas for the per-host-group application allowlist API
(Phase 2 #2.8).

Shape mirrors :mod:`app.models.allowlist` — the API layer never
mutates the enum stringly, it goes through :class:`AllowlistMode`.
SHA-256 fields are validated to the canonical 64-char lowercase hex
form so the agent doesn't have to be defensive about casing.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.allowlist import AllowlistMode


def _normalize_sha256(value: str) -> str:
    """Lowercase + length-check. Raises ValueError on a bad shape so
    pydantic surfaces a 422 with a clear message."""
    v = value.strip().lower()
    if len(v) != 64:
        raise ValueError("sha256 must be 64 hex chars")
    try:
        bytes.fromhex(v)
    except ValueError as exc:
        raise ValueError("sha256 must be hex") from exc
    return v


class AllowlistModeOut(BaseModel):
    """Current allowlist state for one host group."""

    model_config = ConfigDict(from_attributes=True)

    host_group_id: UUID
    mode: AllowlistMode
    enabled_at: datetime | None
    learn_started_at: datetime | None
    learn_completed_at: datetime | None
    updated_at: datetime
    entry_count: int = 0


class AllowlistModeUpdate(BaseModel):
    """Operator switches the group between off/learn/enforce."""

    mode: AllowlistMode


class AllowlistEntryCreate(BaseModel):
    """Operator-added entry. Distinguished from learner-added entries
    in the DB via the ``manual=True`` flag."""

    sha256: str = Field(min_length=64, max_length=64)
    exec_path: str | None = None
    publisher: str | None = None

    @field_validator("sha256")
    @classmethod
    def _norm(cls, v: str) -> str:
        return _normalize_sha256(v)


class AllowlistEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    host_group_id: UUID
    sha256: str
    exec_path: str | None
    publisher: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    learned: bool
    manual: bool
    created_at: datetime
    updated_at: datetime
