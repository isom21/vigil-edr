"""Audit log entry."""

from __future__ import annotations

import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, LargeBinary, String, text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID


class AuditLog(UuidPkMixin, Base):
    __tablename__ = "audit_log"

    # Phase 3 #3.1: per-tenant audit chain. Each tenant has its own
    # HMAC chain seeded from a tenant-scoped genesis row; the verifier
    # walks per-tenant so a tampered chain in tenant A doesn't taint
    # tenant B's tamper-evidence story.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # M17.c: when the actor was an API token, point at it directly so
    # auditors can distinguish "user X via JWT" from "user X via token T"
    # and (more importantly) follow the chain when token T is later
    # revoked. Nullable since user-JWT actions don't have a token.
    api_token_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("api_tokens.id", ondelete="SET NULL")
    )
    actor_kind: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # "user"|"api_token"|"system"
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), index=True)
    payload: Mapped[dict | None] = mapped_column(JSON)
    ip: Mapped[str | None] = mapped_column(String(64))
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()", index=True
    )
    # M12.f: monotonic sequence + HMAC chain. seq is server-defaulted
    # via the audit_log_seq sequence and uniquely indexed; prev_hmac
    # and row_hmac are populated by the audit service when
    # VIGIL_AUDIT_HMAC_KEY is configured. Nullable for backward compat
    # with rows written before the chain went live.
    seq: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        unique=True,
        index=True,
        server_default=text("nextval('audit_log_seq')"),
    )
    prev_hmac: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    row_hmac: Mapped[bytes | None] = mapped_column(LargeBinary(32))
