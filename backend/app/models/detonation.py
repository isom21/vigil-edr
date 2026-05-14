"""Network sandbox / detonation providers + jobs (Phase 4 #4.4).

`DetonationProvider` is an operator-registered sandbox instance —
Cuckoo today; VMRay + ANY.RUN stubbed pending paid API access. The
plaintext provider config (base URL + API token) is Fernet-encrypted
via the shared helper in ``app/services/encryption.py``; the runtime
decrypts in-process when it submits or polls.

`DetonationJob` is one submission. Lifecycle:

  queued        — row inserted by ``submitter.submit_for_analysis``
                  before the provider's REST call lands.
  running       — submitter handed the sample off; the poller worker
                  flips this once the external sandbox starts work.
  verdict       — sandbox returned a score; ``verdict_score`` +
                  ``verdict_label`` populated.
  failed        — transport or parse error; ``error`` populated.

On a malicious verdict the poller bootstraps a synthetic per-tenant
``intel_feed`` (the "detonation" feed) and inserts a fresh
``IocEntry(kind=hash_sha256)`` so the regular IOC detector picks the
sample up on subsequent host activity.

Both ``kind`` and ``status`` are stored as TEXT + CHECK rather than a
Postgres enum — adding a fourth provider or a fifth status doesn't
need ALTER TYPE. Same pattern as case_destination.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    LargeBinary,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID


class DetonationProviderKind(str, enum.Enum):
    """Which sandbox services this provider."""

    CUCKOO = "cuckoo"
    VMRAY = "vmray"
    ANYRUN = "anyrun"

    @classmethod
    def coerce(cls, value: object) -> DetonationProviderKind:
        """Coerce a raw DB string (or already-an-enum) into the enum.
        Same shape as ``CaseDestinationKind.coerce`` — TEXT + CHECK is
        read back as a string."""
        return value if isinstance(value, cls) else cls(str(value))


class DetonationJobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    VERDICT = "verdict"
    FAILED = "failed"

    @classmethod
    def coerce(cls, value: object) -> DetonationJobStatus:
        return value if isinstance(value, cls) else cls(str(value))


class DetonationVerdictLabel(str, enum.Enum):
    """Coarse bucket the Cuckoo score maps into. Per the recipe:

    * score >= 5 → malicious
    * score 2-4  → suspicious
    * score < 2  → benign

    Only ``malicious`` triggers the IOC feedback loop.
    """

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class DetonationProvider(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "detonation_provider"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_detonation_provider_tenant_id_name"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )
    kind: Mapped[DetonationProviderKind] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    config_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    jobs: Mapped[list[DetonationJob]] = relationship(
        back_populates="provider",
        cascade="all, delete-orphan",
    )


class DetonationJob(UuidPkMixin, Base):
    __tablename__ = "detonation_job"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )
    provider_id: Mapped[UUID] = mapped_column(
        ForeignKey("detonation_provider.id", ondelete="CASCADE"),
        nullable=False,
    )
    sha256: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    status: Mapped[DetonationJobStatus] = mapped_column(
        Text, nullable=False, default=DetonationJobStatus.QUEUED
    )
    verdict_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    verdict_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Provider-side task id; populated as soon as the submit call returns.
    external_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    provider: Mapped[DetonationProvider] = relationship(back_populates="jobs")
