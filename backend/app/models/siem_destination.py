"""SIEM forwarder destinations (Phase 1 — 1.5).

A `SiemDestination` is an operator-registered sink that receives a
copy of every event consumed from `telemetry.normalized` + `alerts.raw`,
formatted per destination kind:

  * `syslog_cef`    — RFC 5424 framed CEF over TCP / UDP / TLS
  * `splunk_hec`    — HTTPS POST to /services/collector/event
  * `sentinel_hub`  — Azure Event Hub send (REST API)

`encrypted_config` is Fernet-ciphertext of a JSON blob holding the
destination-specific connection params and secrets (HEC token,
Sentinel SAS key, syslog host/port/tls). Plaintext never lives on
disk and never round-trips through audit-log payloads.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum
from app.models.tenant import DEFAULT_TENANT_ID


class SiemKind(str, enum.Enum):
    SYSLOG_CEF = "syslog_cef"
    SPLUNK_HEC = "splunk_hec"
    SENTINEL_HUB = "sentinel_hub"


class SiemDestination(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "siem_destinations"

    # Phase 3 #3.1: tenant scoping. Defaults to the seeded default
    # tenant so existing fixtures + bootstrap flows that don't pass
    # tenant_id keep working unchanged.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    kind: Mapped[SiemKind] = mapped_column(pg_enum(SiemKind, name="siem_kind"), nullable=False)
    # Fernet-ciphertext (urlsafe-base64) of the destination's JSON config.
    # Decrypted in-process only, never logged, never echoed back through
    # GET responses. Caller passes plaintext config on create/update;
    # service module encrypts before persist.
    encrypted_config: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Last successful send timestamp. NULL until the worker has
    # delivered at least one event to this destination.
    last_send_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Approximate per-destination lag — seconds between the event's
    # original timestamp and when we successfully delivered it. The
    # worker updates this on every send so the gauge in
    # `app.core.metrics` can be derived from a SELECT without scanning
    # Kafka offsets. Stored as float (Postgres double precision).
    lag_seconds: Mapped[float] = mapped_column(nullable=False, default=0.0)
    # Cumulative error count since process start of this row. Reset to
    # zero on every successful delivery. Useful for the "is this
    # destination wedged?" view in the UI without needing to hit
    # Prometheus.
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
