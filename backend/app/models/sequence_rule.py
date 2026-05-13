"""Sequence / behavioral rule model (Phase 2 #2.3).

A SequenceRule encodes a multi-step detection: an initial trigger
event followed by one or more chained events within a sliding window.
The evaluator (`app.services.sequence`) holds per-host in-memory
state with TTL, advances it on every event, and emits an alert when
the full sequence completes.

The managed-Rule pattern (mirroring `IntelFeed.managed_rule_id`) is
used so the resulting `Alert.rule_id` FK is satisfied without
introducing a parallel rules table — when the worker first sees a
SequenceRule it lazily creates a `Rule` of kind=sigma (the closest
existing bucket — there's no kind=sequence today) and points
`managed_rule_id` at it. The alert UI's rule lookup keeps working.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.rule import Severity
from app.models.tenant import DEFAULT_TENANT_ID


class SequenceRule(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "sequence_rules"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    # Full YAML source. The evaluator parses this on each rule load and
    # caches the parsed form keyed by `(id, updated_at)`.
    yaml_body: Mapped[str] = mapped_column(Text, nullable=False)
    # Sliding-window cap for the full sequence. Individual `followed_by`
    # legs carry their own `within` (the parser defaults a leg to this
    # value when omitted).
    window_s: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, name="rule_severity"),
        nullable=False,
        default=Severity.MEDIUM,
    )
    # Phase 1 #1.8: copied onto every Alert row this rule fires.
    mitre_techniques: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    # Lifetime counters surfaced in the UI's status column.
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Audit trail. Nullable because rule-pack-loaded sequence rules in
    # the future may have no user attribution; ON DELETE SET NULL keeps
    # the rule when the operator who created it leaves.
    created_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # The lazily-created managed `Rule` row. Created on first run by the
    # sequence_detector worker so emitted alerts have a valid rule_id
    # FK target (Alert.rule_id is ondelete=RESTRICT). Nullable so an
    # enabled rule that has never fired (or whose worker has never run)
    # doesn't carry a stub Rule with no body.
    managed_rule_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("rules.id", ondelete="SET NULL"), nullable=True
    )

    managed_rule = relationship("Rule", foreign_keys=[managed_rule_id], uselist=False)
