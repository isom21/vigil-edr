"""Identity threat detection source schemas (Phase 4 #4.3).

Operator-facing payloads for `/api/identity-sources`. The encrypted
config NEVER round-trips back through the API; the `Out` shape
exposes only metadata (kind, name, enabled, status timestamps), and
`Create` / `Update` take the plaintext config as a write-only field.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import IdentitySourceKind
from app.schemas.common import ORMModel


class IdentitySourceOut(ORMModel):
    """Outbound shape — never includes the config plaintext.

    The UI sees the source's `kind`, `name`, `enabled` flag plus the
    monitor's most recent activity timestamps. The credential and
    domain only ever live in-process at poll time.
    """

    id: UUID
    kind: IdentitySourceKind
    name: str
    enabled: bool
    last_polled_at: datetime | None
    last_event_ts: datetime | None
    created_at: datetime
    updated_at: datetime


class IdentitySourceCreate(BaseModel):
    kind: IdentitySourceKind
    name: str = Field(min_length=1, max_length=128)
    # Free-form per-kind config dict. The API surface validates per-
    # kind required fields rather than locking each variant into its
    # own schema; operators can add provider-specific extras (Okta
    # custom domain, Azure cloud routing) without a code change.
    #
    # Required keys:
    #   * okta: `domain`, `api_token`
    #   * azure_ad: `tenant_id`, `client_id`, `client_secret`
    config: dict[str, Any]
    enabled: bool = True


class IdentitySourceUpdate(BaseModel):
    """Partial update. `config` replaces the entire stored blob."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    config: dict[str, Any] | None = None
    enabled: bool | None = None


__all__ = [
    "IdentitySourceCreate",
    "IdentitySourceOut",
    "IdentitySourceUpdate",
]
