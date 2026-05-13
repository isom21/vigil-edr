"""Threat-intel feed model (Phase 1 #1.9).

Each row represents one operator-registered intel source. The
ingest worker pulls each enabled feed on its configured cadence,
parses indicators into the supported `IocKind` subset, and
materialises them under a managed `Rule` of kind=IOC (one rule per
feed). Indicator kinds the schema doesn't model (domain / IP / URL)
are dropped with a warning rather than approximated.

The encrypted_auth column holds either:
  * TAXII: bytes("user:password") encrypted with Fernet, sent as
    HTTP Basic on every pull.
  * custom_json: bytes("Bearer abc...") encrypted with Fernet, sent
    as the literal Authorization header.
  * NULL — anonymous pull (abuse.ch's public urlhaus dump).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.tenant import DEFAULT_TENANT_ID


class IntelFeedKind(str, enum.Enum):
    """Which puller services the feed."""

    TAXII = "taxii"
    ABUSECH_CSV = "abusech_csv"
    CUSTOM_JSON = "custom_json"


class IntelFeed(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "intel_feeds"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    kind: Mapped[IntelFeedKind] = mapped_column(
        pg_enum(IntelFeedKind, name="intel_feed_kind"), nullable=False
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    # Fernet ciphertext bytes; NULL for anonymous feeds.
    encrypted_auth: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Per-feed pull cadence (seconds). The worker's outer loop ticks
    # at VIGIL_INTEL_INGEST_INTERVAL_S; each row's interval_s gates
    # whether this feed is due for THIS tick.
    interval_s: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    last_pulled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # One Rule per feed (kind=ioc, name="intel:<feed_name>"). Created
    # lazily on first successful pull so a feed that never connects
    # doesn't pollute the rules list.
    managed_rule_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("rules.id", ondelete="SET NULL"), nullable=True
    )

    # The managed Rule itself; loaded on demand for the /intel UI's
    # "view managed rule" link.
    managed_rule = relationship("Rule", foreign_keys=[managed_rule_id], uselist=False)
