"""Saved hunt + hunt run models (Phase 2 #2.11).

A `SavedHunt` is an operator-authored OpenSearch query (one of
`lucene`, `kql`, or `sigma`) that can be re-run on demand or on a
cron schedule. When `alert_on_hit` is true, the scheduler emits Alert
rows under a managed `Rule` per hunt — mirroring the threat-intel
feeds pattern.

`HuntRun` rows are append-only history: one per execution, recording
hit count, alert count, and the error message when the run blew up.
The (hunt_id, started_at DESC) index lets the history view paginate
without sorting the whole table.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID


class SavedHunt(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "saved_hunt"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    owner_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # The serialised query body as authored. For `sigma`, this is the
    # raw YAML; the scheduler compiles it to Lucene per-run rather than
    # at save time so a backend update can re-translate old hunts
    # without a migration.
    query_dsl: Mapped[str] = mapped_column(Text, nullable=False)
    query_language: Mapped[str] = mapped_column(Text, nullable=False)
    # Five-field cron string ("m h dom mon dow"). NULL = on-demand only.
    schedule_cron: Mapped[str | None] = mapped_column(Text)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_hit_count: Mapped[int | None] = mapped_column(Integer)
    # When true, scheduled runs that find hits open Alert rows under
    # the hunt's managed Rule. The Rule is created lazily on first hit.
    alert_on_hit: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # Free-text severity ("info" / "low" / "medium" / "high" / "critical").
    # Validated on the API boundary; stored as text so a future severity
    # is a one-line code change rather than a DB migration.
    severity: Mapped[str | None] = mapped_column(Text)
    mitre_techniques: Mapped[list[str] | None] = mapped_column(JSONB)
    # Optional restriction: `{"host_ids": [...]}` keeps hits to a
    # specific list, `{"host_group_id": "..."}` resolves through groups
    # at run time. NULL = no extra restriction (still RBAC-scoped per
    # the runner's actor).
    host_scope_json: Mapped[dict | None] = mapped_column(JSONB)
    managed_rule_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("rules.id", ondelete="SET NULL"), nullable=True
    )


class HuntRun(UuidPkMixin, Base):
    __tablename__ = "hunt_run"

    # Phase 3 #3.1: tenant scoping. Denormalised from the parent hunt
    # so the history-by-tenant query doesn't need a join.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    hunt_id: Mapped[UUID] = mapped_column(
        ForeignKey("saved_hunt.id", ondelete="CASCADE"), nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hit_count: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    alert_count: Mapped[int | None] = mapped_column(Integer)
