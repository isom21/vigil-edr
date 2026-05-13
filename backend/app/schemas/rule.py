"""Rule + IOC payloads."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.models import IocKind, RuleAction, RuleKind, Severity
from app.schemas.common import ORMModel


class IocEntryIn(BaseModel):
    kind: IocKind
    value: str = Field(min_length=1, max_length=1024)


class IocEntryOut(ORMModel):
    id: UUID
    kind: IocKind
    value: str


class RuleOut(ORMModel):
    id: UUID
    kind: RuleKind
    name: str
    description: str | None
    severity: Severity
    action: RuleAction
    enabled: bool
    body: str | None
    revision: int
    group_id: UUID | None = None
    created_at: datetime
    updated_at: datetime
    iocs: list[IocEntryOut] = Field(default_factory=list)
    # Phase 1 #1.8: MITRE ATT&CK technique IDs (e.g. ["T1059.001"]).
    mitre_techniques: list[str] | None = None
    # Phase 2 #2.1: auto-queue a MEMORY_YARA_SCAN job when an alert
    # from this rule carries a process.pid.
    auto_memory_scan: bool = False


class RuleCreate(BaseModel):
    kind: RuleKind
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    severity: Severity = Severity.MEDIUM
    action: RuleAction = RuleAction.ALERT
    enabled: bool = True
    body: str | None = None
    group_id: UUID | None = None
    iocs: list[IocEntryIn] | None = None
    mitre_techniques: list[str] | None = None
    auto_memory_scan: bool = False

    @model_validator(mode="after")
    def _validate_kind_payload(self) -> RuleCreate:
        if self.kind in (RuleKind.YARA, RuleKind.SIGMA):
            if not self.body:
                raise ValueError(f"{self.kind.value} rules require a body")
            if self.iocs:
                raise ValueError("iocs are only valid for kind=ioc")
        elif self.kind is RuleKind.IOC:
            if not self.iocs:
                raise ValueError("ioc rules require at least one ioc entry")
            if self.body:
                raise ValueError("body is not used for kind=ioc")
        return self


class RuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    severity: Severity | None = None
    action: RuleAction | None = None
    enabled: bool | None = None
    body: str | None = None
    group_id: UUID | None = None
    iocs: list[IocEntryIn] | None = None
    mitre_techniques: list[str] | None = None
    auto_memory_scan: bool | None = None


class RuleGroupOut(ORMModel):
    id: UUID
    kind: RuleKind
    name: str
    description: str | None
    max_action: RuleAction
    created_at: datetime
    updated_at: datetime
    rule_count: int = 0


class RuleGroupCreate(BaseModel):
    kind: RuleKind
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    max_action: RuleAction = RuleAction.ALERT


class RuleGroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    max_action: RuleAction | None = None
