"""API token payloads."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    scopes: list[str] = Field(default_factory=list)
    ttl_days: int | None = Field(default=None, ge=1, le=365 * 5)


class ApiTokenOut(ORMModel):
    id: UUID
    name: str
    scopes: list[str]
    last_used_at: datetime | None
    revoked_at: datetime | None
    expires_at: datetime | None
    created_at: datetime


class ApiTokenCreated(ApiTokenOut):
    """Returned only at creation time — includes the plaintext token."""

    token: str
