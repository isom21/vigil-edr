"""Programmatic API tokens (machine-to-manager auth)."""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import ARRAY, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin


class ApiToken(UuidPkMixin, TimestampMixin, Base):
    """A long-lived programmatic token. Plaintext shown once at creation.

    Token wire format: `edr_<token_id_hex>_<secret_hex>`.
    `token_id_hex` is the row's id; `secret_hex` is matched against `secret_hash`.
    """

    __tablename__ = "api_tokens"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # sha256 hex
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
