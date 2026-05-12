"""API token payloads."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    # Optional. When omitted we apply DEFAULT_TTL_DAYS so a non-expiring
    # token is no longer the default — the pre-fix shape let
    # `ttl_days=None` fall through to `expires_at=None`.
    ttl_days: int | None = Field(default=None, ge=1, le=365 * 5)


DEFAULT_TTL_DAYS = 90


class ApiTokenOut(ORMModel):
    id: UUID
    name: str
    last_used_at: datetime | None
    revoked_at: datetime | None
    expires_at: datetime | None
    created_at: datetime


class ApiTokenCreated(ApiTokenOut):
    """Returned only at creation time — includes the plaintext token."""

    token: str
