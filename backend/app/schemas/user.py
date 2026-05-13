"""User payloads."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import UserRole
from app.schemas.common import ORMModel


class UserOut(ORMModel):
    id: UUID
    email: str
    role: UserRole
    disabled: bool
    last_login_at: datetime | None
    created_at: datetime
    totp_enabled: bool = False
    # Phase 3 #3.1: tenant + super-admin bit surface so the frontend
    # tenant switcher knows whether to render and what tenant the
    # session is pinned to.
    tenant_id: UUID
    is_super_admin: bool = False


class UserCreate(BaseModel):
    # Email format is a soft constraint — must contain '@' but otherwise free-form.
    email: str = Field(min_length=3, max_length=255, pattern=r".+@.+")
    password: str = Field(min_length=12, max_length=256)
    role: UserRole = UserRole.ANALYST


class UserUpdate(BaseModel):
    role: UserRole | None = None
    disabled: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)
