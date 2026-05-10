"""M11.b anomaly detection — per-host process baseline.

Stores rolling counts of `(host_id, exe, parent_exe)` triples observed
across the fleet. The `app.workers.anomaly` consumer increments the
counter for each process_started event; first-time-seen triples whose
parent is not a known launcher fire an alert.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin


class ProcessBaseline(UuidPkMixin, Base):
    __tablename__ = "process_baseline"
    __table_args__ = (
        UniqueConstraint(
            "host_id", "exe", "parent_exe", name="uq_process_baseline_triple"
        ),
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
