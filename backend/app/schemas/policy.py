"""Policy payloads."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import RuleAction
from app.schemas.common import ORMModel


class PolicyRuleEntryIn(BaseModel):
    rule_id: UUID
    action_override: RuleAction | None = None
    enabled_override: bool | None = None


class PolicyRuleEntryOut(ORMModel):
    rule_id: UUID
    action_override: RuleAction | None
    enabled_override: bool | None


class PolicyOut(ORMModel):
    id: UUID
    name: str
    description: str | None
    version: int
    sweep_interval_hours: int
    sweep_categories: list[str]
    created_at: datetime
    updated_at: datetime
    rules: list[PolicyRuleEntryOut] = Field(default_factory=list)


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    sweep_interval_hours: int = Field(default=4, ge=0, le=24 * 30)
    sweep_categories: list[str] | None = None
    rules: list[PolicyRuleEntryIn] = Field(default_factory=list)


class PolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    sweep_interval_hours: int | None = Field(default=None, ge=0, le=24 * 30)
    sweep_categories: list[str] | None = None
    rules: list[PolicyRuleEntryIn] | None = None
