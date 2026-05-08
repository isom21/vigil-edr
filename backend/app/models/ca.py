"""Internal CA singleton row."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, LargeBinary, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin


class CertificateAuthority(UuidPkMixin, Base):
    """Singleton row holding the manager's internal CA.

    The private key is encrypted at rest with the master key from settings
    (Fernet-encrypted bytes stored in `key_encrypted`).
    """

    __tablename__ = "certificate_authority"

    cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    key_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fingerprint_sha256: Mapped[str] = mapped_column(Text, nullable=False)
