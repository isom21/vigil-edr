"""Threat-hunting workbench schemas (Phase 2 #2.11)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel

QueryLanguage = Literal["lucene", "kql", "sigma"]
HuntSeverity = Literal["info", "low", "medium", "high", "critical"]


class HuntResultHit(BaseModel):
    """One row from a hunt run, projected from a telemetry-* document."""

    timestamp: str | None = None
    host_id: str | None = None
    event_id: str | None = None
    source: dict[str, Any]


class HuntRunOut(ORMModel):
    id: UUID
    hunt_id: UUID
    started_at: datetime
    finished_at: datetime | None
    hit_count: int | None
    error: str | None
    alert_count: int | None


class HuntRunResult(BaseModel):
    """In-band response shape for both ad-hoc and saved-hunt runs.

    Carries the projected hits when the caller wants to inspect them
    (ad-hoc / manual run) plus a persisted `HuntRunOut` row when the
    run was tied to a saved hunt.
    """

    query_dsl: str
    total: int
    hits: list[HuntResultHit]
    truncated: bool
    run: HuntRunOut | None = None


class HuntAdhocRequest(BaseModel):
    query: str = Field(min_length=1, max_length=64 * 1024)
    language: QueryLanguage
    lookback_hours: int = Field(default=24, ge=1, le=90 * 24)
    size: int = Field(default=100, ge=1, le=10_000)


class SavedHuntOut(ORMModel):
    id: UUID
    owner_user_id: UUID
    name: str
    description: str | None
    query_dsl: str
    query_language: QueryLanguage
    schedule_cron: str | None
    last_run_at: datetime | None
    last_run_hit_count: int | None
    alert_on_hit: bool
    severity: HuntSeverity | None
    mitre_techniques: list[str] | None
    host_scope_json: dict[str, Any] | None
    managed_rule_id: UUID | None
    created_at: datetime
    updated_at: datetime


class SavedHuntCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    query_dsl: str = Field(min_length=1, max_length=64 * 1024)
    query_language: QueryLanguage
    schedule_cron: str | None = Field(default=None, max_length=255)
    alert_on_hit: bool = False
    severity: HuntSeverity | None = None
    mitre_techniques: list[str] | None = None
    host_scope_json: dict[str, Any] | None = None


class SavedHuntUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    query_dsl: str | None = Field(default=None, min_length=1, max_length=64 * 1024)
    query_language: QueryLanguage | None = None
    schedule_cron: str | None = Field(default=None, max_length=255)
    alert_on_hit: bool | None = None
    severity: HuntSeverity | None = None
    mitre_techniques: list[str] | None = None
    host_scope_json: dict[str, Any] | None = None
