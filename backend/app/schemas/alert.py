"""Alert payloads."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import AlertState, RuleAction, Severity
from app.schemas.common import ORMModel


class AlertHistoryOut(ORMModel):
    id: UUID
    from_state: AlertState | None
    to_state: AlertState
    by_user_id: UUID | None
    comment: str | None
    ts: datetime


class AlertOut(ORMModel):
    id: UUID
    host_id: UUID
    rule_id: UUID
    severity: Severity
    action_taken: RuleAction
    state: AlertState
    summary: str
    details: dict[str, Any] | None
    telemetry_index: str | None
    telemetry_doc_ids: list[str] | None
    opened_at: datetime
    closed_at: datetime | None
    assignee_id: UUID | None
    created_at: datetime
    updated_at: datetime


class AlertDetail(AlertOut):
    history: list[AlertHistoryOut] = Field(default_factory=list)


class AlertStateChange(BaseModel):
    to_state: AlertState
    comment: str | None = None


class AlertAssign(BaseModel):
    assignee_id: UUID | None
