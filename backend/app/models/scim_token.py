"""SCIM bearer token (IdP → manager auth for /scim/v2)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin, utcnow
from app.models.tenant import DEFAULT_TENANT_ID


class ScimToken(UuidPkMixin, Base):
    """Bearer token used by an external IdP (Okta / Azure AD / Google
    Workspace) to authenticate SCIM 2.0 requests.

    Stored as sha256 hex of the raw token. The raw token is returned to
    the operator exactly once at creation; there's no way to recover it
    after that. Compromised tokens are revoked by flipping `disabled`
    to True — we keep the row so audit trails attributing actions to
    that token still resolve to a label.
    """

    __tablename__ = "scim_token"

    # Phase 3 #3.1 (CODE-33): SCIM tokens bind to a tenant. New users
    # created via SCIM inherit this tenant_id, so an IdP provisioned
    # for tenant A can only ever populate tenant A's roster. Migration
    # 20260515_1200_scim_token_tenant_id added the column with a
    # server default of DEFAULT_TENANT_ID so existing rows backfill.
    tenant_id: Mapped[UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        index=True,
    )
    label: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
