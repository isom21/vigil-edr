"""Application allowlist models (Phase 2 #2.8).

The allowlist is scoped per host-group: each group can be ``off``,
``learn`` (the agent ships observed binary SHA-256s, the manager
records them, nothing is blocked), or ``enforce`` (the kernel-side
hook denies any exec whose SHA-256 isn't in the synced set).

Two tables back this:

  * :class:`AllowlistMode` — one row per host group, holding the
    current mode + lifecycle timestamps. The host_group_id doubles
    as the primary key so we don't pay for a surrogate where the
    relationship is 1:1.
  * :class:`AllowlistEntry` — the actual SHA-256 ↔ host-group
    bindings. ``learned`` and ``manual`` distinguish auto-observed
    entries from operator approvals; the synced set is the union.

Storing the digest as ``char(64)`` hex (lowercase) rather than
``bytea`` keeps EXPLAIN / pgAdmin reads operator-friendly; the agent
translates to the raw 32-byte form at sync time.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CHAR,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID


class AllowlistMode(str, enum.Enum):
    """Lifecycle for the per-group allowlist."""

    OFF = "off"
    LEARN = "learn"
    ENFORCE = "enforce"


class AllowlistModeRow(TimestampMixin, Base):
    """Per-host-group allowlist state.

    The CHECK constraint enforcing the mode values lives in the
    migration; we don't re-declare it here so the metadata naming
    convention doesn't double-prefix the name.
    """

    __tablename__ = "allowlist_mode"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    host_group_id: Mapped[UUID] = mapped_column(
        ForeignKey("host_groups.id", ondelete="CASCADE"),
        primary_key=True,
    )
    # Stored as a plain text column rather than a Postgres ENUM —
    # the CHECK constraint above carries the same guarantee without
    # tying us to ENUM's ALTER TYPE quirks.
    mode: Mapped[str] = mapped_column(Text, nullable=False, default=AllowlistMode.OFF.value)
    enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    learn_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    learn_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class AllowlistEntry(UuidPkMixin, TimestampMixin, Base):
    """A single approved binary for one host group."""

    __tablename__ = "allowlist_entry"
    __table_args__ = (
        UniqueConstraint(
            "host_group_id",
            "sha256",
            name="uq_allowlist_entry_host_group_id",
        ),
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

    host_group_id: Mapped[UUID] = mapped_column(
        ForeignKey("host_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    exec_path: Mapped[str | None] = mapped_column(Text)
    publisher: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # True if the learner saw this hash come off an agent in LEARN mode.
    learned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # True if an operator added or pinned this entry from the UI.
    # An entry can be both — the learner observed it, then the
    # operator pinned it so a future learner GC pass won't drop it.
    manual: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
