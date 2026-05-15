"""Dashboard model (Phase 3 #3.4).

A `Dashboard` is an operator-authored grid layout of widgets. The
`widgets_json` column carries the entire layout — widget type +
position + per-widget options — as a JSONB array so adding a new
widget kind is a schema (Pydantic) change rather than a migration.

`is_default` is per-owner unique (partial UNIQUE index in the
migration). The default dashboard is what `/api/dashboards/default`
returns on every page load; on first call for a user the API creates
one populated with the historical hardcoded layout so the page never
renders an empty grid.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID


class Dashboard(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "dashboard"

    # Phase 3 #3.1 (CODE-20): dashboards live per-tenant. Migration
    # 20260515_1100_dashboard_tenant_id adds the column with a server
    # default of DEFAULT_TENANT_ID so existing rows land on the seed
    # tenant; new rows are stamped by the router.
    tenant_id: Mapped[UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
        index=True,
    )
    owner_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # When true, any analyst+ can list / read / clone the dashboard.
    # Edit / delete still require ownership (or admin).
    shared: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # The grid layout. Validated against `app.schemas.dashboard.Widget`
    # on the API boundary; stored as raw JSONB so future widget kinds
    # don't require a migration.
    widgets_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    # Per-owner default. Enforced unique via a partial UNIQUE index on
    # `(owner_user_id) WHERE is_default = true` in the migration.
    is_default: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
