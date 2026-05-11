"""Pydantic schemas for response-action commands.

M17 hardened the input shape: `CommandIn` now validates the
kind-specific payload at parse time via a Pydantic `model_validator`,
so bad inputs return 422 rather than reaching the router's hand-rolled
`_validate_payload` helper. The router still calls `_validate_payload`
defensively in case a future caller path bypasses Pydantic (e.g. a
gRPC trigger).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.models import CommandKind, CommandStatus
from app.schemas.common import ORMModel


class CommandIn(BaseModel):
    kind: CommandKind
    payload: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_payload(self) -> CommandIn:
        if self.kind == CommandKind.KILL_PROCESS:
            pid = self.payload.get("pid")
            if not isinstance(pid, int) or pid <= 0:
                raise ValueError("kill_process payload requires integer pid > 0")
        elif self.kind in (
            CommandKind.BLOCK_PROCESS,
            CommandKind.BLOCK_FILE,
            CommandKind.UNBLOCK_PROCESS,
            CommandKind.UNBLOCK_FILE,
        ):
            pattern = self.payload.get("pattern")
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError(f"{self.kind.value} payload requires non-empty 'pattern' string")
            if len(pattern.encode("utf-16-le")) > 512:
                raise ValueError("pattern is longer than the driver's 512-byte UTF-16 limit")
        elif self.kind == CommandKind.ISOLATE:
            allowlist = self.payload.get("allowlist_ips", [])
            if not isinstance(allowlist, list):
                raise ValueError("isolate payload requires allowlist_ips as a list")
        elif self.kind == CommandKind.QUARANTINE_FILE:
            path = self.payload.get("path")
            if not isinstance(path, str) or not path.strip():
                raise ValueError("quarantine_file payload requires non-empty 'path' string")
        return self


class CommandOut(ORMModel):
    id: UUID
    host_id: UUID
    # Joined denormalisation so the cross-host commands page can show
    # which agent the command targets without N+1 host lookups.
    host_hostname: str | None = None
    kind: CommandKind
    status: CommandStatus
    payload: dict[str, Any]
    triggered_by_alert_id: UUID | None
    triggered_by_rule_id: UUID | None
    issued_by_user_id: UUID | None
    dispatched_at: datetime | None
    completed_at: datetime | None
    error: str | None
    created_at: datetime
    updated_at: datetime
