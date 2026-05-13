"""Rollout cohort + event payloads (Phase 3 #3.3)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class CohortCounts(BaseModel):
    """Success / failure aggregates for a single cohort label."""

    cohort: str
    success: int = 0
    failed: int = 0
    in_flight: int = 0


class RolloutEventOut(ORMModel):
    id: UUID
    host_id: UUID
    policy_id: UUID
    cohort: str
    version_from: str | None
    version_to: str
    status: str
    error: str | None
    started_at: datetime
    finished_at: datetime | None


class PolicyRolloutOut(BaseModel):
    """Aggregated rollout status for a single policy."""

    policy_id: UUID
    policy_name: str
    rollout_cohort: str | None
    cohort_target_version: str | None
    cohort_rolled_out_pct: int = Field(ge=0, le=100)
    cohorts: list[CohortCounts]
    recent: list[RolloutEventOut]


class RolloutAdvanceIn(BaseModel):
    to_pct: int = Field(ge=0, le=100)
