"""Internal CA singleton row."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, LargeBinary, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID


class CertificateAuthority(UuidPkMixin, Base):
    """Singleton row holding the manager's internal CA.

    The private key is encrypted at rest with the master key from settings
    (Fernet-encrypted bytes stored in `key_encrypted`).
    """

    __tablename__ = "certificate_authority"

    # Phase 3 #3.1: each tenant gets its own internal CA so a tenant
    # admin's CSR signing requests don't depend on (or leak through)
    # a shared root. Defaults to the seeded default tenant.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    key_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(Text, nullable=False)
