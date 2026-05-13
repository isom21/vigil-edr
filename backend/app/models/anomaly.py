"""M11.b anomaly detection — per-host process baseline.

Stores rolling counts of `(host_id, exe, parent_exe)` triples observed
across the fleet. The `app.workers.anomaly` consumer increments the
counter for each process_started event; first-time-seen triples whose
parent is not a known launcher fire an alert.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID


class ProcessBaseline(UuidPkMixin, Base):
    __tablename__ = "process_baseline"
    __table_args__ = (
        UniqueConstraint("host_id", "exe", "parent_exe", name="uq_process_baseline_triple"),
    )

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
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # `exe` and `parent_exe` are full paths capped at 1024 chars.
    exe: Mapped[str] = mapped_column(String(1024), nullable=False)
    parent_exe: Mapped[str] = mapped_column(String(1024), nullable=False, default="")

    # Rolling 7-day count. Trimmed by the worker periodically; on
    # overflow the oldest entries get dropped (M11.b follow-up cron).
    count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
