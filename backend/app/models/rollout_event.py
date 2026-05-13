"""Rollout event model (Phase 3 #3.3).

One row per per-host update attempt. The rollout monitor reads this
table on its tick to compute the per-cohort failure rate; the API
surfaces aggregates to the dashboard.

Status lifecycle is:
    pending  → in_flight → success
                       ↘ failed   → (operator decides) rolled_back

Status values are stored as plain text + a CHECK constraint rather
than as a Postgres ENUM so we can extend the set later without an
ALTER TYPE dance.
"""

from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin


class RolloutStatus(str, enum.Enum):
    """Lifecycle for a single per-host update attempt."""

    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class RolloutEvent(UuidPkMixin, Base):
    """One per-host update attempt.

    The (policy_id, status, started_at desc) index supports the
    monitor's failure-window scan; the (host_id, started_at desc)
    index supports the host detail page's recent-rollouts view.
    """

    __tablename__ = "rollout_event"

    host_id: Mapped[UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
    )
    policy_id: Mapped[UUID] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    # Cohort *label* at the time the event was recorded — frozen so
    # later relabeling of cohort buckets doesn't rewrite history.
    cohort: Mapped[str] = mapped_column(Text, nullable=False)
    version_from: Mapped[str | None] = mapped_column(Text)
    version_to: Mapped[str] = mapped_column(Text, nullable=False)
    # Stored as plain text with a CHECK constraint declared in the
    # migration. See :class:`RolloutStatus` for the canonical values.
    status: Mapped[str] = mapped_column(Text, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
