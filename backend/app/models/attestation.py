"""TPM-backed boot-state attestation (Phase 4 #4.10).

Two rows here back the entire feature:

  * :class:`AttestationGolden` — one row per host. The promoted PCR
    set and the AK-cert fingerprint that signed the quote when the
    operator promoted. Re-promoting overwrites (PK = host_id).
  * :class:`AttestationEvent` — append-only history of every PCR
    report the manager received. ``matches_golden`` + ``diverged_pcrs``
    are computed at insert time so the host detail endpoint can render
    status from a single row read.

Both tables stamp ``tenant_id`` for Phase 3 #3.1 multi-tenancy scoping.
PCR digests live inside the JSONB blob as lowercase hex strings — the
wire payload sends raw bytes, the service layer hexes them for both
storage (deterministic ordering, easy diffing) and the API.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Integer

from app.models.base import Base, UuidPkMixin, utcnow
from app.models.tenant import DEFAULT_TENANT_ID


class AttestationGolden(Base):
    """Promoted golden baseline for one host. PK = host_id."""

    __tablename__ = "attestation_golden"

    host_id: Mapped[UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
    )
    # List of {"index": int, "bank": "sha256", "digest_hex": str}. Stored
    # as a list (not a dict keyed by index) so the order surfaces a
    # stable diff against a future attestation event.
    pcr_values_json: Mapped[list[dict]] = mapped_column(JSONB, nullable=False, default=list)
    # SHA-256 fingerprint of the AK certificate that signed the quote
    # when the operator promoted. Optional — older agents that haven't
    # provisioned an AK yet still get a baseline, just without a
    # cryptographic identity to pin future quotes against.
    ak_cert_fingerprint: Mapped[str | None] = mapped_column(Text, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    recorded_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class AttestationEvent(UuidPkMixin, Base):
    """One PCR report the manager received from an agent."""

    __tablename__ = "attestation_event"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
    )
    host_id: Mapped[UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
    )
    pcr_values_json: Mapped[list[dict]] = mapped_column(JSONB, nullable=False, default=list)
    matches_golden: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # PCR indices whose digest differed from the golden baseline. Empty
    # on a clean match; the full set when no golden has been promoted
    # yet (status=unverified — divergence is "from nothing").
    diverged_pcrs: Mapped[list[int]] = mapped_column(ARRAY(Integer), nullable=False, default=list)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
