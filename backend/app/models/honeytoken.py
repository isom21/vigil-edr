"""Honeytoken decoys + hit log (Phase 4 #4.5).

Operators register decoys (fake creds, fake docs, fake registry keys)
that the agent plants on every targeted host. Each row is one decoy
spec; the agent stamps a token-id tag onto the artifact (xattr on
Linux files, NTFS ADS on Windows, registry value name on Windows
regkeys). Whenever the artifact is touched, the agent emits a
`HoneytokenHit` on the existing gRPC stream and the manager raises a
critical-severity alert via the synthetic
`HONEYTOKEN_HIT_RULE_ID`.

Scoping mirrors device_policy: `host_group_id` NULL means "every host
in the tenant"; non-NULL scopes the decoy to that group's members.
Unique `(tenant_id, name)` so a tenant can't double-register a name —
the agent uses the name as a human-readable correlation handle in
alerts.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin, utcnow
from app.models.tenant import DEFAULT_TENANT_ID


class HoneytokenKind(str, enum.Enum):
    CREDS_IN_LSASS = "creds_in_lsass"
    FAKE_FILE = "fake_file"
    FAKE_REGKEY = "fake_regkey"


class Honeytoken(UuidPkMixin, Base):
    __tablename__ = "honeytoken"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_honeytoken_tenant_id_name"),
        CheckConstraint(
            "kind IN ('creds_in_lsass', 'fake_file', 'fake_regkey')",
            name="ck_honeytoken_kind",
        ),
        Index("ix_honeytoken_tenant_id", "tenant_id"),
        Index("ix_honeytoken_host_group_id", "host_group_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
    )
    host_group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("host_groups.id", ondelete="CASCADE"), nullable=True
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    # JSONB so the operator can stash anything kind-specific
    # (e.g. {"username": "svc_backup", "password": "decoy-..."}).
    # The agent gets the canonical wire-format `payload` bytes derived
    # from this — see `services.honeytoken._payload_bytes`.
    payload_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Optional. For `fake_file` the agent writes the payload here; for
    # `fake_regkey` the operator passes the registry path (e.g.
    # `HKLM\SOFTWARE\AcmeBackup\Credentials`). For `creds_in_lsass` we
    # ignore it.
    target_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    deployed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class HoneytokenHit(UuidPkMixin, Base):
    __tablename__ = "honeytoken_hit"
    __table_args__ = (
        Index(
            "ix_honeytoken_hit_honeytoken_id_hit_at",
            "honeytoken_id",
            "hit_at",
        ),
        Index(
            "ix_honeytoken_hit_host_id_hit_at",
            "host_id",
            "hit_at",
        ),
        Index("ix_honeytoken_hit_tenant_id", "tenant_id"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        default=DEFAULT_TENANT_ID,
    )
    honeytoken_id: Mapped[UUID] = mapped_column(
        ForeignKey("honeytoken.id", ondelete="CASCADE"), nullable=False
    )
    host_id: Mapped[UUID] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
    )
    hit_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    process_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_executable: Mapped[str | None] = mapped_column(Text, nullable=True)
    alert_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
