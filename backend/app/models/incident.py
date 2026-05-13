"""Incident — alert grouping (Phase 1 #1.11).

An Incident is a triage container that groups related alerts. Grouping
rule v1: same `host_id`, alerts inside a sliding `VIGIL_INCIDENT_WINDOW_S`
window. See `app.services.incident_grouping.regroup_recent` for the
periodic batch implementation.

The incident's severity is the max severity of its grouped alerts at
the moment the incident is created/regrouped; status flows
open → investigating → (resolved | closed) and analysts can move it
between these via POST /api/incidents/{id}/state.

Host scoping inherits from the underlying alerts: a non-admin sees an
incident only if its `host_id` lives in one of their host groups.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.rule import Severity
from app.models.tenant import DEFAULT_TENANT_ID


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentGroupingReason(str, enum.Enum):
    """Why a set of alerts ended up under one incident.

    Stored as text + CHECK at the DB level so adding a new reason is a
    constraint swap rather than an `ALTER TYPE`. See Phase 2 #2.13.
    """

    WINDOW = "window"
    PROCESS_TREE = "process_tree"
    RULE_CLUSTER = "rule_cluster"


# Allowed transitions. RESOLVED can be reopened to INVESTIGATING in
# case an analyst flips a verdict; CLOSED is terminal (operator
# explicitly closes for archival). Matches the alert-state shape.
INCIDENT_STATUS_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.OPEN: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
        IncidentStatus.OPEN,
    },
    IncidentStatus.RESOLVED: {IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED},
    IncidentStatus.CLOSED: set(),
}


class Incident(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "incidents"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    # Nullable so future multi-host / synthetic incidents don't need a
    # migration; v1 always writes a real host_id.
    host_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, name="rule_severity"), nullable=False
    )
    status: Mapped[IncidentStatus] = mapped_column(
        pg_enum(IncidentStatus, name="incident_status"),
        default=IncidentStatus.OPEN,
        nullable=False,
        index=True,
    )
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()", index=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    assignee_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # Stored as text + CHECK at the DB level (see migration
    # d8b9c0d1e2f3) so adding a new reason later is a constraint swap
    # rather than an ALTER TYPE. `native_enum=False` keeps SQLAlchemy
    # from emitting `::incident_grouping_reason` casts that would
    # require a matching PG ENUM type.
    grouping_reason: Mapped[IncidentGroupingReason] = mapped_column(
        Enum(
            IncidentGroupingReason,
            name="incident_grouping_reason",
            native_enum=False,
            length=32,
            values_callable=lambda c: [m.value for m in c],
        ),
        default=IncidentGroupingReason.WINDOW,
        nullable=False,
        server_default=IncidentGroupingReason.WINDOW.value,
    )
