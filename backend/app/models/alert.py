"""Alert + alert state history."""

from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
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

    host_id: Mapped[UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True
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

    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    assignee_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

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
