"""Rule and IOC entry models."""

from __future__ import annotations

import enum
from uuid import UUID

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum


class RuleKind(str, enum.Enum):
    YARA = "yara"
    SIGMA = "sigma"
    IOC = "ioc"


class RuleAction(str, enum.Enum):
    """Three-level escalation. Each level implicitly includes the levels
    below it: `block` also alerts; `quarantine` also alerts and blocks.

    * `alert` — log + UI alert only (was `detect`).
    * `block` — alert + prevent the action (deny exec / file open) and
      kill any running matching process (was `kill` + `block`).
    * `quarantine` — alert + block + move offending file to the
      agent's quarantine directory.
    """

    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"


# Ordering for the rule-group ceiling: rule fires at min(rule.action,
# group.max_action). Lower index = less invasive.
ACTION_ORDER: dict[RuleAction, int] = {
    RuleAction.ALERT: 0,
    RuleAction.BLOCK: 1,
    RuleAction.QUARANTINE: 2,
}


def clamp_action(rule_action: RuleAction, ceiling: RuleAction | None) -> RuleAction:
    """Apply a rule-group ceiling. Returns the lesser of the two."""
    if ceiling is None:
        return rule_action
    return rule_action if ACTION_ORDER[rule_action] <= ACTION_ORDER[ceiling] else ceiling


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IocKind(str, enum.Enum):
    HASH_SHA256 = "hash_sha256"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    FILENAME = "filename"
    FILEPATH = "filepath"


class RuleGroup(UuidPkMixin, TimestampMixin, Base):
    """A named bucket of rules that share a kind. The group carries a
    ceiling action — when one of its rules fires, the effective action
    is min(rule.action, group.max_action). Lets an operator dial down
    a whole class of rules to alert-only during tuning, then promote
    the whole group to block / quarantine when confident.
    """

    __tablename__ = "rule_groups"

    kind: Mapped[RuleKind] = mapped_column(pg_enum(RuleKind, name="rule_kind"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    max_action: Mapped[RuleAction] = mapped_column(
        pg_enum(RuleAction, name="rule_action"), default=RuleAction.ALERT, nullable=False
    )


class Rule(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "rules"

    kind: Mapped[RuleKind] = mapped_column(pg_enum(RuleKind, name="rule_kind"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, name="rule_severity"), default=Severity.MEDIUM, nullable=False
    )
    action: Mapped[RuleAction] = mapped_column(
        pg_enum(RuleAction, name="rule_action"), default=RuleAction.ALERT, nullable=False
    )
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)

    # M20.b: optional grouping. The group's max_action clamps this
    # rule's effective action at fire time. Nullable so ungrouped
    # rules keep working.
    group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("rule_groups.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # YARA: source text. Sigma: yaml source. IOC: not used (entries in IocEntry).
    body: Mapped[str | None] = mapped_column(Text)
    # Sigma compiled output (Flink SQL, OpenSearch DSL, etc.) cached here.
    sigma_compiled: Mapped[str | None] = mapped_column(Text)
    # Monotonic per-rule version; bumped on every body change. Sent to agent for cache invalidation.
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Phase 1 #1.8: MITRE ATT&CK technique IDs (e.g. ["T1059.001"]).
    # When this rule fires, the worker copies this list onto the
    # resulting Alert row so historical queries stay stable when the
    # rule's tags change later.
    mitre_techniques: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    # Phase 2 #2.1: when true, an alert from this rule whose ECS event
    # carries `process.pid` auto-queues a MEMORY_YARA_SCAN job against
    # that pid on the originating host. Lets analysts get a memory
    # ruleset hit without pivoting through the Jobs UI.
    auto_memory_scan: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    iocs: Mapped[list[IocEntry]] = relationship(back_populates="rule", cascade="all, delete-orphan")


class IocEntry(UuidPkMixin, Base):
    __tablename__ = "ioc_entries"

    rule_id: Mapped[UUID] = mapped_column(
        ForeignKey("rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[IocKind] = mapped_column(pg_enum(IocKind, name="ioc_kind"), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    # Lower-cased / normalized form for matching (filenames lowered, paths backslash-normalized).
    value_normalized: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)

    # Phase 1 #1.9: NULL = operator-created; non-NULL = materialised
    # from a threat-intel feed. The worker diffs old-vs-new entries
    # under a feed's managed Rule by filtering on this FK.
    source_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("intel_feeds.id", ondelete="SET NULL"), nullable=True, index=True
    )

    rule: Mapped[Rule] = relationship(back_populates="iocs")
