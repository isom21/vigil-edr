"""Alert + alert state history."""

from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.rule import RuleAction, Severity


class AlertState(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"


# Allowed transitions. Closed states (FP/TP) are terminal in v1.
ALERT_STATE_TRANSITIONS = {
    AlertState.NEW: {AlertState.INVESTIGATING, AlertState.FALSE_POSITIVE, AlertState.TRUE_POSITIVE},
    AlertState.INVESTIGATING: {AlertState.FALSE_POSITIVE, AlertState.TRUE_POSITIVE, AlertState.NEW},
    AlertState.FALSE_POSITIVE: set(),
    AlertState.TRUE_POSITIVE: set(),
}


class Alert(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "alerts"

    # NULL for synthetic / manager-internal alerts (e.g. audit chain
    # breaks) that don't belong to any specific host. Non-admin RBAC
    # scoping in `apply_host_scope` filters via `host_id IN (visible)`,
    # which SQL evaluates to UNKNOWN for NULL — so analysts won't see
    # these alerts. Admin list/get endpoints LEFT OUTER JOIN hosts so
    # null-host rows still surface.
    host_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    rule_id: Mapped[UUID] = mapped_column(
        ForeignKey("rules.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, name="rule_severity"), nullable=False
    )
    action_taken: Mapped[RuleAction] = mapped_column(
        pg_enum(RuleAction, name="rule_action"),
        default=RuleAction.ALERT,
        nullable=False,
    )
    state: Mapped[AlertState] = mapped_column(
        pg_enum(AlertState, name="alert_state"), default=AlertState.NEW, nullable=False, index=True
    )
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON)

    # Pointer into OpenSearch for the events that triggered this alert.
    telemetry_index: Mapped[str | None] = mapped_column(String(128))
    telemetry_doc_ids: Mapped[list[str] | None] = mapped_column(JSON)

    # Phase 1 #1.8: MITRE ATT&CK technique IDs copied from the rule at
    # fire time. Frozen on the alert row so historical lookups remain
    # accurate even after the rule's tags are updated.
    mitre_techniques: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    assignee_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # Phase 1 #1.11: when the incident_grouper rolls related alerts up,
    # it sets this FK. Nullable so freshly-inserted alerts stay ungrouped
    # until the worker's next pass. ON DELETE SET NULL — removing an
    # incident only ungroups its alerts; it never deletes them.
    incident_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Phase 1 #1.10 alert deduplication. `dedup_key` is sha256-hex of
    # (rule_id, host_id, canonical_event_signal); see
    # `app.services.alert_dedup.dedup_key_for`. Within the sliding
    # window `VIGIL_ALERT_DEDUP_WINDOW_S` (default 300 s) producers
    # bump `occurrence_count` + refresh `last_occurred_at` on the
    # most recent OPEN row sharing this key instead of inserting a
    # duplicate. Closed alerts (false_positive / true_positive) never
    # coalesce — a recurrence after triage gets its own row. NULL key
    # means "this row never participates in dedup" (legacy rows + any
    # producer that lacked enough ECS signal to compute one).
    dedup_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    last_occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()", index=True
    )

    history: Mapped[list[AlertStateHistory]] = relationship(
        back_populates="alert", cascade="all, delete-orphan", order_by="AlertStateHistory.ts"
    )


class AlertStateHistory(UuidPkMixin, Base):
    __tablename__ = "alert_state_history"

    alert_id: Mapped[UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    from_state: Mapped[AlertState | None] = mapped_column(pg_enum(AlertState, name="alert_state"))
    to_state: Mapped[AlertState] = mapped_column(
        pg_enum(AlertState, name="alert_state"), nullable=False
    )
    by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    comment: Mapped[str | None] = mapped_column(Text)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )

    alert: Mapped[Alert] = relationship(back_populates="history")
