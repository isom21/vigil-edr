"""Policy + policy-rule association."""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import Boolean, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UuidPkMixin
from app.models.rule import Rule, RuleAction


class Policy(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "policies"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Bumped on any structural change (rule add/remove or override edit).
    # Agents sync when their cached version < this.
    version: Mapped[int] = mapped_column(default=1, nullable=False)

    rule_links: Mapped[list["PolicyRule"]] = relationship(
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
        Enum(RuleAction, name="rule_action", create_type=False)
    )
    enabled_override: Mapped[bool | None] = mapped_column(Boolean)

    policy: Mapped[Policy] = relationship(back_populates="rule_links")
    rule: Mapped[Rule] = relationship()
