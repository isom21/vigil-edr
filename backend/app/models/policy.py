"""Policy + policy-rule association."""

from __future__ import annotations

import uuid
from uuid import UUID

from sqlalchemy import Boolean, ForeignKey, Integer, SmallInteger, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.rule import Rule, RuleAction
from app.models.tenant import DEFAULT_TENANT_ID

# Default categories the sweep scheduler enables when a policy is
# created. Listed in jobs_handlers / jobs_acquire / jobs_hunt registry
# order so adding/removing one here matches what the agent can do.
DEFAULT_SWEEP_CATEGORIES: list[str] = [
    "process_snapshot",
    "network_snapshot",
    "account_audit",
    "installed_software",
    "persistence_audit",
    "service_audit",
]


class Policy(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "policies"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Bumped on any structural change (rule add/remove or override edit).
    # Agents sync when their cached version < this.
    version: Mapped[int] = mapped_column(default=1, nullable=False)

    # M23.h: how often the sweep scheduler fires a HOST_SWEEP job for
    # hosts assigned to this policy. 0 disables sweeps for the policy.
    sweep_interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    # JSON list of survey job kinds to include in each sweep. Empty list
    # also disables; analysts can shrink the set if a category is too
    # noisy on a given host group.
    sweep_categories: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=lambda: list(DEFAULT_SWEEP_CATEGORIES)
    )

    # Phase 3 #3.3: rollout cohort gating. The cohort *label* is purely
    # cosmetic — the gate is the percentage. ``cohort_target_version``
    # is the version operators want hosts under this policy to converge
    # toward; the response layer compares it to ``host.agent_version``
    # before queuing a ``JobKind.UPDATE``. When the rollout monitor sees
    # too many failures in the configured window it slams the percentage
    # to 0; operators inspect ``rollout_event`` rows + reissue once the
    # root cause is fixed.
    rollout_cohort: Mapped[str | None] = mapped_column(Text)
    cohort_target_version: Mapped[str | None] = mapped_column(Text)
    cohort_rolled_out_pct: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)

    rule_links: Mapped[list[PolicyRule]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )


class PolicyRule(Base):
    """Many-to-many between policies and rules with optional per-link overrides."""

    __tablename__ = "policy_rules"

    policy_id: Mapped[UUID] = mapped_column(
        ForeignKey("policies.id", ondelete="CASCADE"), primary_key=True
    )
    rule_id: Mapped[UUID] = mapped_column(
        ForeignKey("rules.id", ondelete="CASCADE"), primary_key=True
    )
    # null => use the rule's own action / enabled flag.
    action_override: Mapped[RuleAction | None] = mapped_column(
        pg_enum(RuleAction, name="rule_action")
    )
    enabled_override: Mapped[bool | None] = mapped_column(Boolean)

    policy: Mapped[Policy] = relationship(back_populates="rule_links")
    rule: Mapped[Rule] = relationship()
