"""Incident payloads (Phase 1 #1.11)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import IncidentGroupingReason, IncidentStatus, Severity
from app.schemas.alert import AlertOut
from app.schemas.common import ORMModel


class IncidentOut(ORMModel):
    id: UUID
    host_id: UUID | None
    title: str
    summary: str | None
    severity: Severity
    status: IncidentStatus
    opened_at: datetime
    closed_at: datetime | None
    assignee_id: UUID | None
    created_at: datetime
    updated_at: datetime
    # Phase 2 #2.13 — why the alerts ended up in this incident.
    grouping_reason: IncidentGroupingReason = IncidentGroupingReason.WINDOW
    # M7.6+ list/detail denormalisation — same pattern Alerts use.
    host_hostname: str | None = None
    # Pre-computed for the list page so it doesn't N+1 on alerts.
    alert_count: int = 0


class IncidentDetail(IncidentOut):
    alerts: list[AlertOut] = Field(default_factory=list)


class IncidentStateChange(BaseModel):
    to_state: IncidentStatus
    comment: str | None = None


class IncidentAssign(BaseModel):
    assignee_id: UUID | None
