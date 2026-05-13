"""Tenant payloads (Phase 3 #3.1)."""

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import ORMModel

# Lowercase ascii + digits + dashes, must start with a letter. Same
# shape as a Kubernetes RFC 1123 label so operators have one mental
# model for "what slugs are legal" across the install.
_SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}[a-z0-9]$")


class TenantBase(BaseModel):
    slug: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=1, max_length=255)

    @field_validator("slug")
    @classmethod
    def _check_slug(cls, value: str) -> str:
        value = value.lower().strip()
        if not _SLUG_RE.match(value):
            raise ValueError(
                "slug must be lowercase ascii, dashes/digits allowed, "
                "must start with a letter and end alphanumerically"
            )
        return value


class TenantCreate(TenantBase):
    """Body for ``POST /api/tenants`` (super-admin only)."""


class TenantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    disabled: bool | None = None


class TenantOut(ORMModel):
    id: UUID
    slug: str
    name: str
    disabled: bool
    created_at: datetime
    updated_at: datetime
