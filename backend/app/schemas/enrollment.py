"""Enrollment payloads."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import OsFamily
from app.schemas.common import ORMModel


class EnrollmentTokenCreate(BaseModel):
    label: str | None = Field(default=None, max_length=128)
    ttl_hours: int = Field(default=24, ge=1, le=24 * 30)
    # Phase 3 #3.1: super-admins can mint tokens targeting a specific
    # tenant. Defaults to the actor's own tenant; non-super-admins
    # are rejected if they pass a tenant_id that isn't theirs.
    tenant_id: UUID | None = None


class EnrollmentTokenOut(ORMModel):
    id: UUID
    label: str | None
    expires_at: datetime
    used_at: datetime | None
    created_at: datetime
    # Phase 3 #3.1: surface the target tenant on the wire so the UI
    # can show which tenant each token enrolls into.
    tenant_id: UUID


class EnrollmentTokenCreated(EnrollmentTokenOut):
    """Returned only at creation time — includes the plaintext token."""

    token: str


class EnrollRequest(BaseModel):
    enrollment_token: str
    hostname: str = Field(min_length=1, max_length=255)
    os_family: OsFamily
    os_version: str | None = None
    os_platform: str | None = None
    os_arch: str | None = None
    agent_version: str | None = None
    csr_pem: str = Field(description="PKCS#10 CSR in PEM format")


class EnrollResponse(BaseModel):
    host_id: UUID
    client_cert_pem: str
    ca_chain_pem: str
    cert_not_after: datetime
