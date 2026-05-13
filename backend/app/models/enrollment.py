"""Enrollment token (one-time agent install secret)."""

from __future__ import annotations

import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID


class EnrollmentToken(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "enrollment_tokens"

    # Phase 3 #3.1: enrollment tokens carry the tenant their target
    # host will land in. The enrollment endpoint sets the host's
    # ``tenant_id`` from this column so the agent itself stays
    # tenant-blind (the token is what binds it).
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    # SHA-256 of the issued token (the plaintext is shown once at creation time).
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    label: Mapped[str | None] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_by_host_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL")
    )
    created_by: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
