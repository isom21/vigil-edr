"""SCIM bearer token (IdP → manager auth for /scim/v2)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin, utcnow


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

    label: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
