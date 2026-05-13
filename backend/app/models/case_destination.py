"""External case-management destinations + per-alert links (Phase 3 #3.6).

A `CaseDestination` is an operator-registered Jira or ServiceNow instance
that mirrors Vigil alerts into the external tracker. The plaintext
config (base URL + API token / basic auth) is Fernet-encrypted at rest;
the service module decrypts in-process when it needs to call out.

A `CaseLink` is the per-alert receipt: the lifecycle hook inserts one
row when an alert state transitions and the destination accepts a
create-issue call. The poller worker updates `sync_state` on its tick
so the UI can show the close-the-loop status without a fresh API call.
"""

from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, LargeBinary, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UuidPkMixin


class CaseDestinationKind(str, enum.Enum):
    """Which external tracker services the destination."""

    JIRA = "jira"
    SERVICENOW = "servicenow"

    @classmethod
    def coerce(cls, value: object) -> CaseDestinationKind:
        """Normalise a raw DB string (or an existing enum member) into
        the enum. The ``kind`` column is stored as TEXT + CHECK rather
        than a Postgres enum (see the migration's rationale), so
        SQLAlchemy reads it back as a plain string and every caller
        that wants the enum has to coerce."""
        return value if isinstance(value, cls) else cls(str(value))


class CaseSyncState(str, enum.Enum):
    """Mirror of the external issue's lifecycle state.

    The mapping from each tracker's native status set into this small
    enum lives in the per-kind client. ``failed`` is reserved for
    transport errors; the poller doesn't downgrade a previously-good
    link to ``failed`` on a transient network hiccup — it logs and
    re-tries on the next tick.
    """

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FAILED = "failed"


class CaseDestination(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "case_destination"

    # Stored as TEXT + CHECK constraint rather than a Postgres enum so
    # the migration doesn't have to ALTER TYPE when a future tracker
    # (Linear, GitHub Issues) gets added. The CHECK constraint keeps
    # the column safe against typos at INSERT time; the model coerces
    # to the Python enum for ergonomics.
    kind: Mapped[CaseDestinationKind] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    # Fernet ciphertext of the destination's JSON config. Decrypted in
    # process only; never logged, never returned through the API.
    config_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    links: Mapped[list[CaseLink]] = relationship(
        back_populates="destination",
        cascade="all, delete-orphan",
    )


class CaseLink(UuidPkMixin, Base):
    __tablename__ = "case_link"
    __table_args__ = (
        UniqueConstraint(
            "alert_id",
            "destination_id",
            name="uq_case_link_alert_id_destination_id",
        ),
    )

    alert_id: Mapped[UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    destination_id: Mapped[UUID] = mapped_column(
        ForeignKey("case_destination.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Jira issue key (e.g. "SEC-123") or ServiceNow sys_id; whichever
    # the tracker's API returns as the stable handle for fetch-by-id.
    external_id: Mapped[str] = mapped_column(Text, nullable=False)
    external_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sync_state: Mapped[CaseSyncState] = mapped_column(
        Text, nullable=False, default=CaseSyncState.OPEN
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )

    destination: Mapped[CaseDestination] = relationship(back_populates="links")
