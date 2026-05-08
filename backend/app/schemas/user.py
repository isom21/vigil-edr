"""User payloads."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from app.models import UserRole
from app.schemas.common import ORMModel


class UserOut(ORMModel):
    id: UUID
    email: EmailStr
    role: UserRole
    disabled: bool
    last_login_at: datetime | None
    created_at: datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    role: UserRole = UserRole.ANALYST


class UserUpdate(BaseModel):
    role: UserRole | None = None
    disabled: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)
