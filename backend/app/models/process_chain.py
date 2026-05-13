"""Cross-process correlation graph (Phase 2 #2.6).

One row per observed process on an endpoint. The `process_chain_indexer`
worker inserts on `process_started` events and patches `ended_at` when
`process_exited` arrives. `(host_id, pid, started_at)` is unique so
Kafka redeliveries and dual emits from the agent both collapse via
`ON CONFLICT DO NOTHING`.

Queries live in `app.services.process_graph`:
  * ancestors(host_id, pid)        — walk parent_pid back to the root.
  * descendants(host_id, pid)      — walk parent_pid forward.
  * cross_host_lineage(image_sha256) — every observed start of the
    same binary across the fleet, useful for "this hash also ran on
    these hosts" pivots from the alert console.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import CHAR, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin, utcnow
from app.models.tenant import DEFAULT_TENANT_ID


class ProcessChain(UuidPkMixin, Base):
    __tablename__ = "process_chain"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    host_id: Mapped[UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
    )
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    exec_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    image_sha256: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
