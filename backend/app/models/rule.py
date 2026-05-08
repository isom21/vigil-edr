"""Rule and IOC entry models."""
from __future__ import annotations

import enum
from uuid import UUID

from sqlalchemy import Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UuidPkMixin


class RuleKind(str, enum.Enum):
    YARA = "yara"
    SIGMA = "sigma"
    IOC = "ioc"


class RuleAction(str, enum.Enum):
    DETECT = "detect"
    KILL = "kill"
    BLOCK = "block"


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


class Rule(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "rules"

    kind: Mapped[RuleKind] = mapped_column(Enum(RuleKind, name="rule_kind"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="rule_severity"), default=Severity.MEDIUM, nullable=False
    )
    action: Mapped[RuleAction] = mapped_column(
        Enum(RuleAction, name="rule_action"), default=RuleAction.DETECT, nullable=False
    )
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)

    # YARA: source text. Sigma: yaml source. IOC: not used (entries in IocEntry).
    body: Mapped[str | None] = mapped_column(Text)
    # Sigma compiled output (Flink SQL, OpenSearch DSL, etc.) cached here.
    sigma_compiled: Mapped[str | None] = mapped_column(Text)
    # Monotonic per-rule version; bumped on every body change. Sent to agent for cache invalidation.
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    iocs: Mapped[list["IocEntry"]] = relationship(
        back_populates="rule", cascade="all, delete-orphan"
    )


class IocEntry(UuidPkMixin, Base):
    __tablename__ = "ioc_entries"

    rule_id: Mapped[UUID] = mapped_column(
        ForeignKey("rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[IocKind] = mapped_column(Enum(IocKind, name="ioc_kind"), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    # Lower-cased / normalized form for matching (filenames lowered, paths backslash-normalized).
    value_normalized: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)

    rule: Mapped[Rule] = relationship(back_populates="iocs")
