"""Routing rules (Phase 1 #1.7 — alert routing).

A `RoutingRule` is a declarative filter ("alerts matching X go to
these channels"). Match predicates are conjunctive — the rule fires
when *all* of (severity >= min_severity, rule_kind matches or NULL,
host belongs to host_group_id or NULL) hold.

`channel_ids` is a UUID[] rather than a join table. Worst-case match
fan-out is bounded by the number of channels on the rule (typically
1–3); promoting to a separate table is the future refactor when per-
channel retry state or large reuse demands it.
"""

from __future__ import annotations

import uuid
from uuid import UUID

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.rule import RuleKind, Severity
from app.models.tenant import DEFAULT_TENANT_ID


class RoutingRule(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "routing_rules"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    min_severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, name="rule_severity"),
        default=Severity.MEDIUM,
        nullable=False,
    )
    # NULL means match any rule kind.
    rule_kind: Mapped[RuleKind | None] = mapped_column(
        pg_enum(RuleKind, name="rule_kind"), nullable=True
    )
    # NULL means match alerts on any host. When non-null, an alert
    # whose host is *not* a member of this group is skipped. Synthetic
    # alerts (`host_id IS NULL`) only match rules where host_group_id
    # is also NULL.
    host_group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("host_groups.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Ordered list of NotificationChannel ids to fire. Order is
    # preserved on update so operators can express priority (the
    # dispatcher fans out concurrently but logs in this order).
    channel_ids: Mapped[list[UUID]] = mapped_column(PG_ARRAY(Uuid()), default=list, nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
