"""Device control policy (Phase 3 #3.10).

Each row is one operator-registered USB device policy. The agent
applies the effective policy for its host (globals + the union of every
group the host belongs to) via `DEVICE_CONTROL_SYNC` — Linux pushes a
udev rule into `/run/udev/rules.d/`, Windows flips
`HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions`.

Scoping: `host_group_id` NULL means the policy applies to every host.
A non-NULL group scopes the policy to its members. Unique
`(host_group_id, name)` so the same group can't list two policies under
the same operator-visible name; cross-scope name collisions are fine
because Postgres uniqueness treats NULL as distinct.
"""

from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin, utcnow


class DevicePolicyKind(str, enum.Enum):
    USB_BLOCK = "usb_block"
    USB_READ_ONLY = "usb_read_only"
    USB_ALLOW_ONLY = "usb_allow_only"


class DevicePolicy(UuidPkMixin, Base):
    __tablename__ = "device_policy"
    __table_args__ = (
        UniqueConstraint("host_group_id", "name", name="uq_device_policy_host_group_id_name"),
        CheckConstraint(
            "kind IN ('usb_block', 'usb_read_only', 'usb_allow_only')",
            name="ck_device_policy_kind",
        ),
        Index("ix_device_policy_host_group_id", "host_group_id"),
    )

    host_group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("host_groups.id", ondelete="CASCADE"), nullable=True
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    # JSONB list of 4-hex-digit lowercase VIDs / PIDs. Same-index pair
    # forms an exception (allowed_vids[i], allowed_pids[i]); the agent
    # zips them when materialising the udev rule / registry value.
    allowed_vendor_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    allowed_product_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
