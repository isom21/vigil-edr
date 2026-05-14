"""Pydantic schemas for the detonation API (Phase 4 #4.4)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import DetonationJobStatus, DetonationProviderKind
from app.schemas.common import ORMModel


class DetonationProviderOut(ORMModel):
    """Outbound shape — never echoes ``config_encrypted``."""

    id: UUID
    kind: DetonationProviderKind
    name: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


class DetonationProviderCreate(BaseModel):
    kind: DetonationProviderKind
    name: str = Field(min_length=1, max_length=128)
    # Free-form per-kind config dict. Cuckoo expects ``base_url`` (+ an
    # optional ``api_token``); the stubs ignore the value at submit
    # time but the operator can pre-stage them.
    config: dict[str, Any]
    enabled: bool = True


class DetonationProviderUpdate(BaseModel):
    """Partial update. ``config`` replaces the entire stored blob."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    config: dict[str, Any] | None = None
    enabled: bool | None = None


class DetonationJobOut(ORMModel):
    id: UUID
    provider_id: UUID
    sha256: str
    status: DetonationJobStatus
    verdict_score: float | None
    verdict_label: str | None
    external_id: str | None
    error: str | None
    submitted_at: datetime
    finished_at: datetime | None


class DetonationSubmitRequest(BaseModel):
    sha256: str = Field(min_length=64, max_length=64)
    provider_id: UUID | None = None
    # Optional inline sample bytes (base64). Useful for the test
    # endpoint when the operator hasn't wired the quarantine → MinIO
    # uploader yet; production callers leave this empty and let the
    # submitter pull from object storage.
    sample_b64: str | None = None


__all__ = [
    "DetonationJobOut",
    "DetonationProviderCreate",
    "DetonationProviderOut",
    "DetonationProviderUpdate",
    "DetonationSubmitRequest",
]
