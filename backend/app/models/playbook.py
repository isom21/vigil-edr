"""Playbook + playbook run models (Phase 3 #3.5).

A `Playbook` is a YAML-defined response chain. The trigger keys
(`trigger_rule_id`, `trigger_severity`, `trigger_mitre_techniques`)
combine in OR-fashion: a playbook matches an alert if any of the
non-NULL triggers match. A `Playbook` with all-NULL triggers is
dormant — the executor never matches it.

A `PlaybookRun` is one execution. The engine inserts a row in
`pending` state, flips it to `running` when work begins, and
finalises it as `succeeded`, `failed`, or `partial`. Each step's
outcome lands in `steps_executed_json` so the UI can render a
per-run timeline without inventing a side-table.

Playbook RUNS aren't audited (high volume); the API audits the
`playbook.{create,update,delete}` operations on the `Playbook` row.
"""

from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UuidPkMixin


class PlaybookRunStatus(str, enum.Enum):
    """Lifecycle states for a playbook run.

    * `pending`   — row inserted, executor hasn't picked it up.
    * `running`   — executor has started processing steps.
    * `succeeded` — all steps reported success.
    * `failed`    — the engine couldn't proceed at all.
    * `partial`   — some steps succeeded, some failed — the engine
                    finished walking the body but at least one step
                    returned a non-OK outcome.
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"


class Playbook(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "playbook"

    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    # Full YAML source. The engine parses on each trigger; the parsed
    # form isn't cached because playbook fires are rare relative to
    # rule edits.
    yaml_body: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    # Triggers. All three are optional; the executor matches an alert
    # against any non-NULL one (OR semantics). A playbook with all
    # three NULL is dormant.
    trigger_rule_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("rules.id", ondelete="SET NULL"), nullable=True
    )
    trigger_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    trigger_mitre_techniques: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)


class PlaybookRun(UuidPkMixin, Base):
    __tablename__ = "playbook_run"

    playbook_id: Mapped[UUID] = mapped_column(
        ForeignKey("playbook.id", ondelete="CASCADE"), nullable=False
    )
    # Nullable so a run survives deletion of the originating alert (the
    # FK is SET NULL on alert delete). Operators still see the run
    # history attached to the playbook itself.
    alert_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    # One element per executed step, each an object with keys
    # `{kind, status, started_at, finished_at, outcome, error?}`.
    # JSON not a side-table because a run is bounded (~10 steps) and
    # the UI always reads them in order.
    steps_executed_json: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    error: Mapped[str | None] = mapped_column(Text)
