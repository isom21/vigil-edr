"""Pydantic schemas for the TPM attestation API (Phase 4 #4.10)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class PcrValueOut(BaseModel):
    index: int
    bank: str
    digest_hex: str


class AttestationGoldenOut(ORMModel):
    host_id: UUID
    pcr_values_json: list[dict] = Field(default_factory=list)
    ak_cert_fingerprint: str | None = None
    recorded_at: datetime
    recorded_by_user_id: UUID | None = None


class AttestationEventOut(ORMModel):
    id: UUID
    host_id: UUID
    pcr_values_json: list[dict] = Field(default_factory=list)
    matches_golden: bool
    diverged_pcrs: list[int] = Field(default_factory=list)
    recorded_at: datetime


AttestationStatus = Literal["ok", "diverged", "unverified", "unknown"]


class AttestationBlock(BaseModel):
    """Block embedded in `GET /api/hosts/:id` so the UI can render the
    attestation pane without a separate round-trip."""

    status: AttestationStatus
    latest: AttestationEventOut | None = None
    golden: AttestationGoldenOut | None = None


class RequestAttestationResponse(BaseModel):
    command_id: UUID
    nonce: str


__all__ = [
    "AttestationBlock",
    "AttestationEventOut",
    "AttestationGoldenOut",
    "AttestationStatus",
    "PcrValueOut",
    "RequestAttestationResponse",
]
