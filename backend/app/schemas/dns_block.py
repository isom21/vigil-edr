"""Pydantic schemas for the DNS block / sinkhole API (Phase 2 #2.12)."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.models import DnsBlockAction
from app.schemas.common import ORMModel


def _normalise_domain(value: str) -> str:
    """Normalise a domain to the canonical key form used kernel-side.

    Lowercased, stripped of leading/trailing whitespace and trailing
    dot. We do this once at the schema boundary so:

      * The UNIQUE (host_group_id, domain) constraint actually fires
        for `Foo.Bar.` vs `foo.bar`.
      * Audit-log payloads + agent-bound resyncs stay byte-identical
        regardless of operator casing.
    """
    return value.strip().lower().rstrip(".")


class DnsBlockEntryOut(ORMModel):
    id: UUID
    host_group_id: UUID | None
    domain: str
    action: DnsBlockAction
    created_by_user_id: UUID | None
    created_at: datetime
    expires_at: datetime | None
    hits: int
    last_hit_at: datetime | None


class DnsBlockEntryCreate(BaseModel):
    host_group_id: UUID | None = None
    domain: str = Field(min_length=1, max_length=253)
    action: DnsBlockAction = DnsBlockAction.BLOCK
    expires_at: datetime | None = None

    @field_validator("domain")
    @classmethod
    def _normalise(cls, v: str) -> str:
        out = _normalise_domain(v)
        if not out:
            raise ValueError("domain is empty after normalisation")
        # Domain labels: alnum + hyphen + dot. We reject anything with
        # whitespace or path-shaped junk here; the kernel side hashes
        # the whole 256-byte key and would silently miss "evil.com/path".
        for ch in out:
            if not (ch.isalnum() or ch in "-._"):
                raise ValueError(f"invalid character in domain: {ch!r}")
        return out


class DnsBlockBulkImport(BaseModel):
    """Bulk add — one POST replaces nothing, only inserts. Existing
    `(host_group_id, domain)` pairs are skipped (counted as
    `skipped`), not errored. Keeps the import idempotent so an
    operator can re-run a feed without an explicit dedupe step."""

    host_group_id: UUID | None = None
    action: DnsBlockAction = DnsBlockAction.BLOCK
    # Newline-separated list is the operator-friendly shape; the API
    # accepts a plain list of strings.
    domains: list[str] = Field(min_length=1, max_length=10_000)

    @field_validator("domains")
    @classmethod
    def _normalise_each(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for raw in v:
            d = _normalise_domain(raw)
            if not d:
                continue
            if d in seen:
                continue
            seen.add(d)
            out.append(d)
        if not out:
            raise ValueError("no valid domains after normalisation")
        return out


class DnsBlockBulkImportResult(BaseModel):
    inserted: int
    skipped: int


__all__ = [
    "DnsBlockBulkImport",
    "DnsBlockBulkImportResult",
    "DnsBlockEntryCreate",
    "DnsBlockEntryOut",
]
