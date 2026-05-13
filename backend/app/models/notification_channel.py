"""Notification channels (Phase 1 #1.7 — alert routing).

A `NotificationChannel` is a credentialed destination the routing
worker can fire when an alert matches a routing rule. Three kinds are
shipped in Phase 1:

  * `slack`     — incoming-webhook URL stored under key "webhook_url".
  * `pagerduty` — Events v2 integration key stored under
                  "integration_key" (a.k.a. routing_key).
  * `email`     — SMTP destination. Stored keys: "smtp_host",
                  "smtp_port", "smtp_user" (optional), "smtp_password"
                  (optional), "use_tls" (bool), "from_addr", "to_addr",
                  "subject_template" (optional, with {alert.summary} etc.).

The `encrypted_config` blob is Fernet-encrypted under
`VIGIL_NOTIFICATION_ENCRYPTION_KEY`. Decryption + access conventions
live in `app/services/routing.py` so the model stays a thin row.
"""

from __future__ import annotations

import enum

from sqlalchemy import LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin, pg_enum


class NotificationChannelKind(str, enum.Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


class NotificationChannel(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "notification_channels"

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    kind: Mapped[NotificationChannelKind] = mapped_column(
        pg_enum(NotificationChannelKind, name="notification_channel_kind"),
        nullable=False,
    )
    # Fernet ciphertext of a JSON-serialised dict whose schema depends
    # on `kind` (see module docstring). Never expose plaintext via API
    # or audit log — the audit payload stores a fingerprint of the
    # secret values, not the values themselves.
    encrypted_config: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
