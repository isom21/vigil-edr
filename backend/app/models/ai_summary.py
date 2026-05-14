"""AI-generated alert summary (Phase 4 #4.1).

Sidecar to ``alerts``: at most one canonical LLM rendering per alert
(UNIQUE alert_id). Re-summarisation deletes the prior row and inserts
a fresh one in the same transaction so analysts always see the
current model's output, not an interleaved history.

``cached_input_tokens`` records the cache-read input tokens reported
by the Anthropic response so an operator can audit prompt-cache hit
rate over time. The rule-pack catalogue we ship in the system prompt
is the only thing in the prompt we expect to cache; other inputs
(the alert envelope, the rule body) are per-call.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Integer, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UuidPkMixin
from app.models.tenant import DEFAULT_TENANT_ID


class AlertSummary(UuidPkMixin, Base):
    __tablename__ = "alert_summary"

    alert_id: Mapped[UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenant.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        default=DEFAULT_TENANT_ID,
    )

    summary: Mapped[str] = mapped_column(Text, nullable=False)
    # Free-form JSON: a list of suggested response actions.
    # Each entry has shape `{kind: str, label: str, rationale?: str}`.
    # Pinning this in the schema would make every prompt-tuning round
    # a schema migration; leaving it loose keeps the API stable while
    # the prompt evolves. The widget renders entries it knows and
    # ignores the rest.
    suggested_response_json: Mapped[list[dict] | None] = mapped_column(JSONB, nullable=True)

    # Model id frozen from `settings.ai_model_id` at write time. The
    # presence of this column means analysts comparing two summaries
    # know which model produced each, even if `ai_model_id` was
    # rotated between the two writes.
    model_id: Mapped[str] = mapped_column(Text, nullable=False)
    cached_input_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    output_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("now()"),
        nullable=False,
    )


__all__ = ["AlertSummary"]
