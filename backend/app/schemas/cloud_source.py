"""Cloud telemetry source schemas (Phase 4 #4.2)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import CloudSourceKind
from app.schemas.common import ORMModel


class CloudSourceOut(ORMModel):
    id: UUID
    name: str
    kind: CloudSourceKind
    enabled: bool
    bucket: str
    prefix: str
    region: str
    # Mask the secret entirely. The plaintext access key id is fine to
    # show — operators need to identify which AWS account a source maps
    # to — but the secret only round-trips back as a boolean.
    aws_access_key_id: str
    has_credentials: bool
    last_polled_at: datetime | None
    last_event_ts: datetime | None
    created_at: datetime
    updated_at: datetime


class CloudSourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    kind: CloudSourceKind = CloudSourceKind.AWS_CLOUDTRAIL
    bucket: str = Field(min_length=1, max_length=255)
    prefix: str = Field(default="", max_length=1024)
    region: str = Field(default="us-east-1", min_length=1, max_length=64)
    aws_access_key_id: str = Field(min_length=1, max_length=128)
    aws_secret_access_key: str = Field(min_length=1, max_length=256)
    enabled: bool = True


class CloudSourceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    bucket: str | None = Field(default=None, min_length=1, max_length=255)
    prefix: str | None = Field(default=None, max_length=1024)
    region: str | None = Field(default=None, min_length=1, max_length=64)
    # Sentinel handling: omitting these leaves the existing values
    # alone; passing a non-empty value rotates them. Pass both together
    # to rotate the credential pair.
    aws_access_key_id: str | None = Field(default=None, max_length=128)
    aws_secret_access_key: str | None = Field(default=None, max_length=256)
    enabled: bool | None = None
