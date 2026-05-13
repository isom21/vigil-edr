"""Archive job model (Phase 3 #3.2 — OpenSearch ILM + S3 cold archive).

One row per freeze (and optional subsequent rehydrate) of an
OpenSearch index. The state machine is intentionally narrow:

    pending -> freezing -> frozen
       frozen -> rehydrating -> rehydrated
    anywhere -> failed

The worker writes the rows on the freeze leg; the API writes the
rehydrate transitions. ``s3_key`` is populated when the freeze
succeeds and is the only thing rehydrate needs to find the data.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin, utcnow


class ArchiveJobStatus(str, enum.Enum):
    PENDING = "pending"
    FREEZING = "freezing"
    FROZEN = "frozen"
    REHYDRATING = "rehydrating"
    REHYDRATED = "rehydrated"
    FAILED = "failed"


class ArchiveJob(UuidPkMixin, Base):
    """Tracks the lifecycle of a single OpenSearch-index freeze.

    Stores status as plain ``Text`` (constrained at the table level)
    rather than a Postgres enum because operators occasionally want to
    repair a stuck row with a SQL UPDATE — bumping a CHECK is cheaper
    than dropping/recreating a pg_enum type.
    """

    __tablename__ = "archive_job"

    index_name: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default=ArchiveJobStatus.PENDING.value
    )
    doc_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    s3_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
