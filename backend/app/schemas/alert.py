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
    # M7.6+ UI denormalisation: list endpoint joins these so the table
    # can show a hostname/rule name without a second round-trip.
    host_hostname: str | None = None
    rule_name: str | None = None


class AlertDetail(AlertOut):
    history: list[AlertHistoryOut] = Field(default_factory=list)


class AlertStateChange(BaseModel):
    to_state: AlertState
    comment: str | None = None


class AlertAssign(BaseModel):
    assignee_id: UUID | None


# ----- M20.d alert investigation context -----


class ProcessChainNode(BaseModel):
    """One process in the ancestry chain of an alert's triggering event."""

    pid: int
    parent_pid: int | None = None
    name: str | None = None
    executable: str | None = None
    command_line: str | None = None
    sha256: str | None = None
    user_name: str | None = None
    integrity_level: str | None = None
    working_directory: str | None = None
    started_at: datetime | None = None
    event_id: str | None = None
    # True when we couldn't find a process_started doc for this pid in
    # OpenSearch (process predates lookback or was never observed) —
    # the UI greys it out and shows "no telemetry recorded".
    inferred: bool = False


class TimelineEvent(BaseModel):
    """A single telemetry row rendered on the alert investigation page."""

    event_id: str
    timestamp: datetime
    category: list[str] = Field(default_factory=list)
    action: str | None = None
    outcome: str | None = None
    pid: int | None = None
    executable: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    is_trigger: bool = False


class AlertContext(BaseModel):
    """Payload for the alert investigation page (M20.d).

    Two backing tabs:
      * `chain` — the process ancestry that led to the alert
      * `events` — every telemetry doc for the host inside the window
    """

    alert_id: UUID
    host_id: UUID
    host_hostname: str | None = None
    rule_id: UUID
    rule_name: str | None = None
    opened_at: datetime
    window_start: datetime
    window_end: datetime
    trigger_event_ids: list[str] = Field(default_factory=list)
    chain: list[ProcessChainNode] = Field(default_factory=list)
    events: list[TimelineEvent] = Field(default_factory=list)
    events_truncated: bool = False
