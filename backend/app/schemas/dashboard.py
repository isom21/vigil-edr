"""Dashboard schemas (Phase 3 #3.4).

The widget catalogue is a typed discriminated union: each widget kind
carries its own option shape, and the dispatcher in
`app.services.dashboard.resolve_widget` switches on `type` to fetch
the underlying data. New widget kinds are a Pydantic-only change.

Position is the react-grid-layout cell tuple `(x, y, w, h)` — the
editor on the frontend persists this verbatim. Validation only
enforces non-negative-x/y and w/h >= 1; the visual grid is 12 columns
by convention but the editor lets operators choose any reasonable
size, so we don't bound w on the API side.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import ORMModel

KpiQuery = Literal[
    "alerts_open",
    "alerts_today",
    "hosts_online",
    "hosts_total",
    "jobs_failed_24h",
    "avg_mttr_hours",
]


class WidgetPosition(BaseModel):
    """react-grid-layout cell position. (x, y) is the top-left of the
    widget in the 12-column grid; (w, h) is its size in grid units."""

    x: int = Field(ge=0)
    y: int = Field(ge=0)
    w: int = Field(ge=1)
    h: int = Field(ge=1)


class _WidgetBase(BaseModel):
    """Shared shape: a typed discriminator + a position + a free-form
    options bag for per-kind tunables that aren't part of the typed
    discriminator (e.g. an analyst-chosen colour palette)."""

    model_config = ConfigDict(extra="forbid")
    position: WidgetPosition
    options: dict[str, Any] | None = None


class KpiWidget(_WidgetBase):
    type: Literal["kpi"] = "kpi"
    title: str = Field(min_length=1, max_length=120)
    query: KpiQuery


class SeverityDonutWidget(_WidgetBase):
    type: Literal["severity_donut"] = "severity_donut"


class StateDonutWidget(_WidgetBase):
    type: Literal["state_donut"] = "state_donut"


class HostStatusDonutWidget(_WidgetBase):
    type: Literal["host_status_donut"] = "host_status_donut"


class TopRulesWidget(_WidgetBase):
    type: Literal["top_rules"] = "top_rules"
    # The hosts/alerts stats endpoints already cap at 10; default
    # matches and the API rejects anything above so the underlying
    # `apply_host_scope`-flavoured query stays cheap.
    limit: int = Field(default=10, ge=1, le=50)


class Timeline24hWidget(_WidgetBase):
    type: Literal["timeline_24h"] = "timeline_24h"


class HostsTableWidget(_WidgetBase):
    type: Literal["hosts_table"] = "hosts_table"
    limit: int = Field(default=10, ge=1, le=100)


class IncidentsTableWidget(_WidgetBase):
    type: Literal["incidents_table"] = "incidents_table"
    limit: int = Field(default=10, ge=1, le=100)


Widget = Annotated[
    KpiWidget
    | SeverityDonutWidget
    | StateDonutWidget
    | HostStatusDonutWidget
    | TopRulesWidget
    | Timeline24hWidget
    | HostsTableWidget
    | IncidentsTableWidget,
    Field(discriminator="type"),
]


class DashboardOut(ORMModel):
    id: UUID
    owner_user_id: UUID
    name: str
    description: str | None
    shared: bool
    is_default: bool
    widgets_json: list[Widget]
    created_at: datetime
    updated_at: datetime


class DashboardCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    shared: bool = False
    widgets_json: list[Widget] = Field(default_factory=list)


class DashboardUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    shared: bool | None = None
    is_default: bool | None = None
    widgets_json: list[Widget] | None = None


class WidgetData(BaseModel):
    """One resolved widget payload. `type` mirrors the originating
    widget's discriminator so the renderer can dispatch off the same
    union. `data` is whatever the resolver returned — the renderer
    knows what shape to expect per type."""

    type: str
    data: Any
    error: str | None = None
