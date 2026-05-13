"""Pydantic schemas for the external case-management API (Phase 3 #3.6)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import CaseDestinationKind, CaseSyncState
from app.schemas.common import ORMModel


class CaseDestinationOut(ORMModel):
    """Outbound shape — the encrypted config NEVER round-trips.

    The UI gets the destination's `kind`, `name`, and `enabled` flag
    plus the create / update timestamps. The credential and base URL
    only ever live in-process at sync time.
    """

    id: UUID
    kind: CaseDestinationKind
    name: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


class CaseDestinationCreate(BaseModel):
    kind: CaseDestinationKind
    name: str = Field(min_length=1, max_length=128)
    # Free-form per-kind config dict. The API surface validates per-kind
    # required fields rather than locking each variant into its own
    # schema; operators can add tracker-specific extras (assignment
    # group, custom field overrides) without a code change.
    config: dict[str, Any]
    enabled: bool = True


class CaseDestinationUpdate(BaseModel):
    """Partial update. `config` replaces the entire stored blob."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    config: dict[str, Any] | None = None
    enabled: bool | None = None


class CaseLinkOut(BaseModel):
    """Per-alert mirror status. Surfaces on the alert detail page."""

    destination_id: UUID
    destination_name: str
    external_id: str
    external_url: str | None
    sync_state: CaseSyncState
    last_synced_at: datetime | None = None
    error: str | None = None


class CaseDestinationTestResult(BaseModel):
    """Outcome of a dry-run create against a registered destination."""

    ok: bool
    external_id: str | None = None
    external_url: str | None = None
    error: str | None = None


__all__ = [
    "CaseDestinationCreate",
    "CaseDestinationOut",
    "CaseDestinationTestResult",
    "CaseDestinationUpdate",
    "CaseLinkOut",
]
