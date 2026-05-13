"""Sequence rule API payloads (Phase 2 #2.3)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import Severity
from app.schemas.common import ORMModel


class SequenceRuleOut(ORMModel):
    id: UUID
    name: str
    description: str | None
    yaml_body: str
    window_s: int
    enabled: bool
    severity: Severity
    mitre_techniques: list[str] | None = None
    hit_count: int
    last_hit_at: datetime | None
    managed_rule_id: UUID | None
    created_at: datetime
    updated_at: datetime


class SequenceRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    yaml_body: str = Field(min_length=1)
    # Floor 1s prevents pathological state from getting wedged in
    # memory; cap 1h matches "this is behavioural, not historical
    # correlation". Beyond an hour, push the rule onto sigma_scheduler
    # instead.
    window_s: int = Field(default=60, ge=1, le=3600)
    enabled: bool = True
    severity: Severity = Severity.MEDIUM
    mitre_techniques: list[str] | None = None


class SequenceRuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    yaml_body: str | None = Field(default=None, min_length=1)
    window_s: int | None = Field(default=None, ge=1, le=3600)
    enabled: bool | None = None
    severity: Severity | None = None
    mitre_techniques: list[str] | None = None
