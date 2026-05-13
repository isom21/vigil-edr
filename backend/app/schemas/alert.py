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
    # Null for synthetic / manager-internal alerts (e.g. audit chain
    # break). The UI renders these as host="System".
    host_id: UUID | None
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
    # Phase 1 #1.10 alert deduplication. `occurrence_count` is the
    # number of distinct detections folded onto this row (1 for a
    # never-deduped alert); `last_occurred_at` is the timestamp of
    # the most recent detection. Together they let the UI render an
    # "x N · last seen HH:MM" badge without a second endpoint.
    occurrence_count: int = 1
    last_occurred_at: datetime
    # Phase 1 #1.8: MITRE ATT&CK technique IDs copied from the rule at
    # fire time so historical queries stay stable.
    mitre_techniques: list[str] | None = None
    # M7.6+ UI denormalisation: list endpoint joins these so the table
    # can show a hostname/rule name without a second round-trip.
    host_hostname: str | None = None
    rule_name: str | None = None


class ContainerInfo(BaseModel):
    """Phase 2 #2.9: container attribution from the triggering
    process_started event. Populated on AlertDetail when the agent
    enriched the process with cgroup-derived container.* fields.
    """

    id: str
    image: str | None = None
    runtime: str | None = None


class AlertDetail(AlertOut):
    history: list[AlertHistoryOut] = Field(default_factory=list)
    # Phase 2 #2.9: container attribution lifted from the triggering
    # process_started doc, when available. Null on hosts not running
    # the container_v1-capable agent build, or on alerts whose
    # triggering process is bare-metal.
    container: ContainerInfo | None = None


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
    # M22.c: other children spawned by this node's parent that aren't
    # on the alert path. Only populated one level deep — the UI keeps
    # the tree to "ancestors + their siblings", not full subtrees.
    siblings: list[ProcessChainNode] = Field(default_factory=list)
    # Direct children spawned by THIS process. Populated only for the
    # leaf node in the chain (the alert-triggering process) so analysts
    # can see what the suspect process went on to do without diving
    # into the timeline.
    children: list[ProcessChainNode] = Field(default_factory=list)


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


# ----- M20.i selected-process detail panel -----


class ProcessFileEvent(BaseModel):
    timestamp: datetime
    action: str | None = None
    path: str | None = None
    target_path: str | None = None
    sha256: str | None = None
    size: int | None = None


class ProcessImageLoad(BaseModel):
    timestamp: datetime
    path: str | None = None
    sha256: str | None = None
    signed: bool | None = None
    signer: str | None = None


class ProcessNetworkEvent(BaseModel):
    timestamp: datetime
    action: str | None = None
    transport: str | None = None
    direction: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    source_ip: str | None = None
    source_port: int | None = None


class ProcessOtherEvent(BaseModel):
    timestamp: datetime
    category: list[str] = Field(default_factory=list)
    action: str | None = None
    outcome: str | None = None


class ProcessDetail(BaseModel):
    """What a single pid did during the alert window."""

    alert_id: UUID
    host_id: UUID
    pid: int
    window_start: datetime
    window_end: datetime
    process: ProcessChainNode | None = None
    image_loads: list[ProcessImageLoad] = Field(default_factory=list)
    files: list[ProcessFileEvent] = Field(default_factory=list)
    network: list[ProcessNetworkEvent] = Field(default_factory=list)
    other: list[ProcessOtherEvent] = Field(default_factory=list)
    truncated: bool = False
