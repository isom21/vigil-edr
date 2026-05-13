"""Pydantic schemas for the routing-rules API (Phase 1 #1.7)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.rule import RuleKind, Severity


class RoutingRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    min_severity: Severity = Severity.MEDIUM
    rule_kind: RuleKind | None = None
    host_group_id: UUID | None = None
    channel_ids: list[UUID] = Field(default_factory=list)
    enabled: bool = True


class RoutingRuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    min_severity: Severity | None = None
    rule_kind: RuleKind | None = None
    host_group_id: UUID | None = None
    channel_ids: list[UUID] | None = None
    enabled: bool | None = None


class RoutingRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    min_severity: Severity
    rule_kind: RuleKind | None
    host_group_id: UUID | None
    channel_ids: list[UUID]
    enabled: bool
    created_at: datetime
    updated_at: datetime
