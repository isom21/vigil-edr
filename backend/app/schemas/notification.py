"""Pydantic schemas for the notification-channel API (Phase 1 #1.7).

Notification channels are credentialed destinations the routing
worker fires when an alert matches a routing rule. The `config` blob
is shape-validated per `kind` at the service layer (we keep the wire
schema loose so the same endpoint covers slack / pagerduty / email
without union gymnastics in the OpenAPI surface). The persisted
form is Fernet-encrypted; the response model NEVER includes the
plaintext credentials.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.notification_channel import NotificationChannelKind


class NotificationChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: NotificationChannelKind
    # The shape of this dict depends on kind. Validated in the service
    # before encryption — see app/services/routing.py::validate_config.
    config: dict[str, Any]
    enabled: bool = True


class NotificationChannelUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    # Replace the whole config blob. Partial-update would mean handing
    # decrypted credentials back to the caller (or storing nulls in
    # the encrypted JSON), both worse than a full re-send.
    config: dict[str, Any] | None = None
    enabled: bool | None = None


class NotificationChannelOut(BaseModel):
    """Public projection — never includes plaintext credentials."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    kind: NotificationChannelKind
    enabled: bool
    created_at: datetime
    updated_at: datetime
    # Short fingerprint of the encrypted secret values for ops to
    # confirm "did this rotate?" without leaking the secret. Computed
    # by the service from the decrypted plaintext (sha256 first 8 hex
    # chars over a stable subset of fields, e.g. webhook_url or
    # integration_key). NULL when the channel has no secret fields
    # (shouldn't happen in Phase 1).
    secret_fingerprint: str | None = None


class NotificationChannelTestResult(BaseModel):
    """Optional sandbox endpoint — fire a synthetic alert through one
    channel without persisting anything. Used by the Integrations UI's
    'Test' button."""

    ok: bool
    detail: str
