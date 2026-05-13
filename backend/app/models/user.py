"""User account model."""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import JSON, DateTime, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        pg_enum(UserRole, name="user_role"), nullable=False, default=UserRole.ANALYST
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Opt-in TOTP 2FA. `totp_enabled` only flips True after the user
    # confirms a fresh code matches the pending secret — so a half-
    # finished setup doesn't lock anyone out. `totp_pending_secret_*`
    # holds the proposed secret between /setup and /verify-setup; it's
    # cleared on success or on a fresh /setup that supersedes it.
    # Recovery codes are bcrypt-hashed and consumed on use; the
    # plaintext is shown to the user exactly once at generation.
    totp_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_pending_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_recovery_codes_hashed: Mapped[list[str] | None] = mapped_column(JSON)

    # Phase 1 #1.6: OIDC SSO. `oidc_subject` is the IdP `sub` claim and
    # is the identity key for subsequent logins; UNIQUE (partial — only
    # non-NULLs) so two OIDC users can't collapse onto the same row.
    # `oidc_issuer` records the issuer URL at provisioning time, and
    # `oidc_email` snapshots whatever email the IdP sent (the local
    # `email` column stays canonical). NULL on password-only users.
    oidc_subject: Mapped[str | None] = mapped_column(String(256))
    oidc_issuer: Mapped[str | None] = mapped_column(String(512))
    oidc_email: Mapped[str | None] = mapped_column(String(256))
