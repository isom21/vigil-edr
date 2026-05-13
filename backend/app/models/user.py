"""User account model."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.tenant import DEFAULT_TENANT_ID


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "users"

    # Phase 3 #3.1: tenant the user belongs to. Defaults to the seeded
    # default tenant so existing fixtures + bootstrap flows that
    # don't know about tenancy keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        pg_enum(UserRole, name="user_role"), nullable=False, default=UserRole.ANALYST
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    # Phase 3 #3.1: super-admin can switch the active tenant and
    # access tenant-management APIs. The active tenant for the
    # session lives in a cookie (`vigil_active_tenant_id`); the JWT
    # still carries the user's home tenant so non-super-admins
    # remain pinned to their `tenant_id` regardless of cookie state.
    is_super_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

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

    # Phase 3 #3.8: SCIM 2.0 external identifier. Whatever the IdP's
    # stable user id is — Okta uses a free-form opaque string, Azure
    # AD uses an objectId GUID, Google Workspace uses the customer-
    # scoped user id. Always paired with `oidc_issuer` via the partial
    # unique index so a single SCIM-provisioned user is addressable
    # idempotently across PUT/PATCH from the IdP. NULL on users that
    # weren't provisioned via SCIM.
    scim_external_id: Mapped[str | None] = mapped_column(String)
