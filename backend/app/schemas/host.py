"""Host payloads."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import HostStatus, OsFamily
from app.schemas.common import ORMModel


class HostOut(ORMModel):
    id: UUID
    hostname: str
    os_family: OsFamily
    os_version: str | None
    os_platform: str | None
    os_arch: str | None
    agent_version: str | None
    status: HostStatus
    enrolled_at: datetime | None
    last_seen_at: datetime | None
    policy_id: UUID | None


class HostDetail(HostOut):
    """Phase 2 #2.9: host detail extends HostOut with derived
    aggregations the detail page needs but the list view doesn't.

    `container_runtimes_seen` is a 24h-rolling list of container
    runtimes that emitted process events on this host (e.g. one host
    might surface both `docker` and `containerd` if it runs hybrid
    workloads). Sorted by count desc, capped at 5 — the UI shows
    badges, not a full distribution. Empty list when the host hasn't
    reported any container telemetry.
    """

    container_runtimes_seen: list[str] = Field(default_factory=list)


class HostUpdate(BaseModel):
    policy_id: UUID | None = None
    status: HostStatus | None = None


class HostListFilter(BaseModel):
    status: HostStatus | None = None
    os_family: OsFamily | None = None
    q: str | None = Field(default=None, description="hostname substring")
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


# ----- M20.j live telemetry tab -----


class LiveTelemetryEvent(BaseModel):
    """One ECS document flattened for the live host telemetry table.

    Carries enough per-category detail (process parent, user, file size,
    source/destination tuple, signed module status, DNS question, event
    provider/code) that the UI can run dedicated tabs without a second
    round-trip per row.
    """

    event_id: str
    timestamp: datetime
    category: list[str] = Field(default_factory=list)
    action: str | None = None
    outcome: str | None = None

    # process.* (covers exec, child spawn, terminate)
    pid: int | None = None
    parent_pid: int | None = None
    executable: str | None = None
    command_line: str | None = None
    working_directory: str | None = None
    user_name: str | None = None

    # file.*
    file_path: str | None = None
    file_action: str | None = None
    file_size: int | None = None

    # network.* + source/destination tuple
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    destination_domain: str | None = None
    transport: str | None = None
    direction: str | None = None

    # dns.* (Linux DNS observation, Windows ETW DNS)
    dns_question_name: str | None = None

    # library/module load — signed/signer pulled from file.code_signature
    module_path: str | None = None
    module_signed: bool | None = None
    module_signer: str | None = None

    # event.* and rule.* metadata (provider helps narrow tabs; code is
    # useful when the agent didn't normalize action).
    event_provider: str | None = None
    event_code: str | None = None
    rule_name: str | None = None
    sha256: str | None = None


class LiveTelemetryPage(BaseModel):
    """A polling window of telemetry — newest doc on the right.

    Callers pass `since` (the most recent @timestamp they've seen) and
    walk forward. `latest_timestamp` is the @timestamp of the last
    event returned; clients pass that back as `since` next tick.
    """

    host_id: UUID
    events: list[LiveTelemetryEvent] = Field(default_factory=list)
    latest_timestamp: datetime | None = None
    truncated: bool = False
