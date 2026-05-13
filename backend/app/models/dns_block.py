"""DNS block / sinkhole entry (Phase 2 #2.12).

Each row is one operator-registered domain disposition. The agent
receives the effective set for its host as a whole-list resync via
`DnsBlockSyncCmd`; kernel-side hooks (BPF DNS-egress on Linux, WFP
datagram callout on Windows) drop matching outbound DNS queries.

Scoping: `host_group_id` NULL means "every host"; non-NULL scopes
the entry to that group's members. The grouping is intentionally
coarse — per-host DNS-blocking would explode the agent-side map for
no operational benefit. Operators that need a host carve-out create
a host group of one.
"""

from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin, utcnow


class DnsBlockAction(str, enum.Enum):
    BLOCK = "block"
    SINKHOLE = "sinkhole"


class DnsBlockEntry(UuidPkMixin, Base):
    __tablename__ = "dns_block_entry"
    __table_args__ = (
        UniqueConstraint("host_group_id", "domain", name="uq_dns_block_entry_host_group_id_domain"),
        CheckConstraint("action IN ('block', 'sinkhole')", name="ck_dns_block_entry_action"),
        Index("ix_dns_block_entry_domain", "domain"),
    )

    host_group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("host_groups.id", ondelete="CASCADE"), nullable=True
    )
    domain: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
