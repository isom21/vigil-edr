"""Process-chain payloads (Phase 2 #2.6)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class ProcessChainNodePG(ORMModel):
    """One node from the Postgres process_chain table. Distinct from
    `app.schemas.alert.ProcessChainNode` (which is OpenSearch-shaped
    and carries siblings/children for the alert investigation tree)
    — this one is the durable graph-store record."""

    id: UUID
    host_id: UUID
    pid: int
    parent_pid: int | None = None
    exec_path: str | None = None
    image_sha256: str | None = None
    command_line: str | None = None
    started_at: datetime
    ended_at: datetime | None = None


class ProcessChainResponse(BaseModel):
    """Ancestors + descendants of a pid on one host. Both lists are
    ordered root → leaf so the UI can walk them top-down."""

    host_id: UUID
    pid: int
    ancestors: list[ProcessChainNodePG] = Field(default_factory=list)
    descendants: list[ProcessChainNodePG] = Field(default_factory=list)


class CrossHostLineageEntry(ORMModel):
    """One process_chain row + the host that owns it. The cross-host
    lineage view groups by image_sha256 so the same binary running on
    different hosts shows up as one set of starts."""

    host_id: UUID
    pid: int
    exec_path: str | None = None
    image_sha256: str | None = None
    command_line: str | None = None
    started_at: datetime
    ended_at: datetime | None = None
