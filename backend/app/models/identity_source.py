"""Identity threat detection source (Phase 4 #4.3).

An `IdentitySource` is an operator-registered Okta or Azure AD
integration. The monitor worker (`app.workers.identity_monitor`)
walks every enabled row on its configured tick, pulls the upstream
event stream (Okta System Log v1 for Okta; Microsoft Graph
`/auditLogs/signIns` for Azure AD), normalises events to a common
`{ts, actor_email, action, src_ip, src_geo, success}` shape, and
runs the detector functions in `app.services.identity.detectors`.

The plaintext config (Okta domain + API token, or Azure tenant_id +
client_id + client_secret) is Fernet-encrypted under the shared
notification key — see `app.services.encryption`. Plaintext only
exists in-process at poll time; the API surface returns metadata
only.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, LargeBinary, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID


class IdentitySourceKind(str, enum.Enum):
    """Which upstream identity provider the source pulls from."""

    OKTA = "okta"
    AZURE_AD = "azure_ad"

    @classmethod
    def coerce(cls, value: object) -> IdentitySourceKind:
        """Normalise a raw DB string (or an existing enum member) into
        the enum. The `kind` column is stored as TEXT + CHECK rather
        than a Postgres enum so adding a third provider later (Google
        Workspace, JumpCloud) doesn't require an ALTER TYPE migration."""
        return value if isinstance(value, cls) else cls(str(value))


class IdentitySource(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "identity_source"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "name",
            name="uq_identity_source_tenant_id_name",
        ),
    )

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    # Stored as TEXT + CHECK constraint rather than a Postgres enum
    # so the migration doesn't have to ALTER TYPE when a future
    # provider (Google Workspace, JumpCloud) gets added.
    kind: Mapped[IdentitySourceKind] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    # Fernet ciphertext of the source's JSON config. Decrypted in
    # process only; never logged, never returned through the API.
    config_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # When the monitor worker last attempted a pull. Drives the
    # cadence gate. Nullable for "never polled" rows.
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # High-water mark of the latest event ts we ingested. The next
    # poll uses this as the `?since=…` cursor so we don't re-fetch
    # the world on every tick. Nullable for "never polled" rows.
    last_event_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
