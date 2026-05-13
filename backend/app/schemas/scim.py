"""SCIM 2.0 + admin-side SCIM-token payloads.

The SCIM wire shapes (User Resource, ListResponse, PATCH operation,
ServiceProviderConfig) follow RFC 7643/7644. Pydantic models for the
inbound request bodies catch outright malformed payloads; the helpers
in `app.services.scim` translate between the SCIM shapes and our
internal `User` model.

The admin-side `ScimTokenOut` / `ScimTokenCreated` schemas are kept
small — they're for our own admin console, not the IdP.

SCIM-defined attribute names (`userName`, `externalId`, …) are
mixedCase by RFC, hence the N815 noqa across this module — renaming
them would silently break Okta/Azure compatibility.
"""

# ruff: noqa: N815

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel

# ----------------------------------------------------------------------
# Admin-side: SCIM bearer token CRUD.
# ----------------------------------------------------------------------


class ScimTokenCreate(BaseModel):
    label: str = Field(min_length=1, max_length=128)


class ScimTokenOut(ORMModel):
    id: UUID
    label: str
    last_used_at: datetime | None
    created_at: datetime
    disabled: bool


class ScimTokenCreated(ScimTokenOut):
    """Returned only at creation — includes the raw bearer token."""

    token: str


# ----------------------------------------------------------------------
# SCIM 2.0 wire bodies.
# ----------------------------------------------------------------------


class ScimUserEmail(BaseModel):
    value: str
    primary: bool | None = None
    type: str | None = None


class ScimUserName(BaseModel):
    formatted: str | None = None
    givenName: str | None = None
    familyName: str | None = None


class ScimUserCreate(BaseModel):
    """Inbound POST /Users body.

    Schemas, externalId, userName, emails, displayName, active are the
    ones we actually consume. The model permits extra keys so the IdP's
    Enterprise extension or vendor-specific fields don't 422 the call;
    we just ignore them.
    """

    model_config = {"extra": "allow"}

    schemas: list[str] | None = None
    externalId: str | None = None
    userName: str
    emails: list[ScimUserEmail] | None = None
    name: ScimUserName | None = None
    displayName: str | None = None
    active: bool = True
    # Vigil-specific extension: the IdP can set the role at create time.
    # Defaults to "viewer" when omitted, per service contract.
    role: str | None = None


class ScimUserPut(ScimUserCreate):
    """PUT body — same shape as create. Per RFC the PUT replaces the
    full resource representation."""


class ScimPatchOp(BaseModel):
    """A single op in a PATCH request.

    SCIM PATCH spec (RFC 7644 §3.5.2) allows op values in any case —
    `add`/`Add`/`ADD`. We lowercase before dispatching.
    """

    op: str
    path: str | None = None
    value: Any | None = None


class ScimPatchBody(BaseModel):
    schemas: list[str] | None = None
    Operations: list[ScimPatchOp]
