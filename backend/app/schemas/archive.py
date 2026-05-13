"""Phase 3 #3.2 archive schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from app.schemas.common import ORMModel


class ArchiveJobOut(ORMModel):
    id: UUID
    index_name: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    doc_count: int | None
    s3_key: str | None
    error: str | None
    created_at: datetime
