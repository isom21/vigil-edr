"""Playbook API payloads (Phase 3 #3.5)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel

PlaybookRunStatusLit = Literal["pending", "running", "succeeded", "failed", "partial"]
TriggerSeverityLit = Literal["low", "medium", "high", "critical"]


class PlaybookOut(ORMModel):
    id: UUID
    name: str
    description: str | None
    yaml_body: str
    enabled: bool
    trigger_rule_id: UUID | None
    trigger_severity: TriggerSeverityLit | None
    trigger_mitre_techniques: list[str] | None
    created_at: datetime
    updated_at: datetime


class PlaybookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    yaml_body: str = Field(min_length=1)
    enabled: bool = True
    trigger_rule_id: UUID | None = None
    trigger_severity: TriggerSeverityLit | None = None
    trigger_mitre_techniques: list[str] | None = None


class PlaybookUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    yaml_body: str | None = Field(default=None, min_length=1)
    enabled: bool | None = None
    trigger_rule_id: UUID | None = None
    trigger_severity: TriggerSeverityLit | None = None
    trigger_mitre_techniques: list[str] | None = None


class PlaybookRunOut(ORMModel):
    id: UUID
    playbook_id: UUID
    alert_id: UUID | None
    started_at: datetime
    finished_at: datetime | None
    status: PlaybookRunStatusLit
    steps_executed_json: list[dict]
    error: str | None
