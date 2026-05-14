"""Cloud telemetry source + IAM anomaly baseline (Phase 4 #4.2).

A ``CloudSource`` is one operator-registered AWS CloudTrail bucket. The
plaintext config (bucket, prefix, AWS access key/secret, region) is
Fernet-encrypted at rest via ``app.services.encryption.encrypt_config``;
the cloudtrail service decrypts in-process when it needs to call out.

A ``CloudBaseline`` is the per-(source, principal_arn) observation
record the IAM anomaly detector keeps. It records the set of actions
and regions ever seen for that principal so subsequent events outside
those sets can fire a synthetic alert.
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
    LargeBinary,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID


class CloudSourceKind(str, enum.Enum):
    """Which cloud telemetry provider services the source. Only AWS
    CloudTrail in the MVP; Azure/GCP equivalents would land here."""

    AWS_CLOUDTRAIL = "aws_cloudtrail"


class CloudSource(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "cloud_source"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_cloud_source_tenant_id_name"),
        CheckConstraint("kind IN ('aws_cloudtrail')", name="ck_cloud_source_kind"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    # Fernet ciphertext of the source's JSON config (bucket, prefix,
    # aws_access_key_id, aws_secret_access_key, region). Decrypted only
    # in-process by the cloudtrail poller; never returned through the API.
    config_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Wall-clock of the last poll attempt (success or failure). Lets the
    # UI render a "last seen N minutes ago" health badge without scanning
    # the worker log.
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # The newest CloudTrail event timestamp observed across all objects
    # processed so far. The worker only fetches objects whose
    # last-modified is newer than this watermark, so on warm restart we
    # don't re-replay history.
    last_event_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CloudBaseline(UuidPkMixin, Base):
    __tablename__ = "cloud_baseline"
    __table_args__ = (
        UniqueConstraint(
            "source_id", "principal_arn", name="uq_cloud_baseline_source_id_principal_arn"
        ),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )
    source_id: Mapped[UUID] = mapped_column(
        ForeignKey("cloud_source.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    principal_arn: Mapped[str] = mapped_column(Text, nullable=False)
    # JSONB list of (event_source, event_name) action keys ever observed
    # for this principal. JSONB instead of text[] so the detector can
    # store the canonical "s3.amazonaws.com:GetObject" form without
    # worrying about Postgres array-of-text quoting.
    observed_actions: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    observed_regions: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
