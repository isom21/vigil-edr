"""Threat-intel feed schemas (Phase 1 #1.9)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl

from app.models import IntelFeedKind
from app.schemas.common import ORMModel


class IntelFeedOut(ORMModel):
    id: UUID
    name: str
    kind: IntelFeedKind
    url: str
    # We never send the ciphertext or plaintext over the wire — just
    # whether the row carries auth so the UI can render the right
    # "Edit auth" state.
    has_auth: bool
    interval_s: int
    last_pulled_at: datetime | None
    entry_count: int
    last_error: str | None
    enabled: bool
    managed_rule_id: UUID | None
    created_at: datetime
    updated_at: datetime


class IntelFeedCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    kind: IntelFeedKind
    url: HttpUrl
    # Operator-supplied raw auth string. For TAXII it's `user:password`;
    # for custom_json it's the literal `Authorization` header value
    # (e.g. `Bearer abc123`). Empty / omitted = anonymous pull. We
    # accept it as a write-only field so it never round-trips back out
    # of the API.
    auth: str | None = Field(default=None, max_length=2048)
    # Per-feed pull cadence. 60s floor — anything tighter just burns
    # network without delivering fresher data (most TAXII servers tick
    # at 5–15 minutes anyway). 7-day cap so a typo can't park a feed.
    interval_s: int = Field(default=3600, ge=60, le=7 * 24 * 3600)
    enabled: bool = True


class IntelFeedUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    url: HttpUrl | None = None
    # Sentinel handling: omitting `auth` leaves the existing ciphertext
    # alone; passing an empty string clears it; passing a non-empty
    # string re-encrypts.
    auth: str | None = Field(default=None, max_length=2048)
    interval_s: int | None = Field(default=None, ge=60, le=7 * 24 * 3600)
    enabled: bool | None = None
