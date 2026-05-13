"""Async NVD 2.0 REST client (Phase 2 #2.7).

Pulls the `cves/2.0` endpoint with `lastModStartDate` /
`lastModEndDate` for incremental sync. The worker passes the last
successful pull's timestamp as `lastModStartDate` and "now" as
`lastModEndDate`; the response gives us only CVEs whose `modified_at`
moved inside that window.

Rate limit
----------
NVD publishes a soft rate limit of 5 requests / 30 s without an API
key, 50 requests / 30 s with one. The conservative per-request floor
we enforce client-side is 6 s without a key, 0.6 s with one. This
matches NVD's published "best practices" guidance and keeps us well
inside the 429 ceiling.

Schema notes
------------
NVD's payload is deeply nested. We unpack:

  * `cve.id`                      → cve_id
  * `cve.descriptions[en].value`  → summary
  * `cve.metrics.cvssMetricV3{1,0}[0].cvssData.baseSeverity` → severity
  * `cve.metrics.cvssMetricV3{1,0}[0].cvssData.baseScore`    → cvss_v3_score
  * `cve.references[].url`        → references_json (URLs only)
  * `cve.configurations[].nodes[].cpeMatch[].criteria`       → affected_cpe_json
  * `cve.published`               → published_at
  * `cve.lastModified`            → modified_at

Older entries that don't carry a v3 score keep severity / score NULL.
The matcher ignores those for now — we surface them in the UI but
they can't match a host's installed CPE without an affected_cpe entry.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import httpx
import structlog

from app.core.config import settings

log = structlog.get_logger()


@dataclass(frozen=True)
class NvdVulnerability:
    """One CVE flattened out of NVD's nested envelope."""

    cve_id: str
    severity: str | None
    cvss_v3_score: Decimal | None
    summary: str | None
    references: list[str]
    affected_cpes: list[str]
    published_at: datetime | None
    modified_at: datetime | None


def _parse_iso(value: str | None) -> datetime | None:
    """NVD timestamps are ISO 8601 but without `Z` or `+00:00`. Treat
    naive responses as UTC so the comparator with our timezone-aware
    rows in Postgres doesn't drift by the local-tz offset."""
    if not value:
        return None
    try:
        # NVD returns "2024-01-02T03:04:05.123"; fromisoformat handles
        # the fractional seconds. Force UTC on naive results.
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (TypeError, ValueError):
        return None


def _pick_v3(metrics: dict[str, Any]) -> tuple[str | None, Decimal | None]:
    """Prefer cvssMetricV31; fall back to V30 if the older record only
    publishes the legacy submetric. Returns (severity, base_score)."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = (entries[0] or {}).get("cvssData") or {}
        sev = data.get("baseSeverity")
        score = data.get("baseScore")
        sev_norm = sev.lower() if isinstance(sev, str) else None
        try:
            score_dec = Decimal(str(score)) if score is not None else None
        except (TypeError, ValueError):
            score_dec = None
        return sev_norm, score_dec
    return None, None


def _flatten_cpe(configurations: list[dict[str, Any]]) -> list[str]:
    """Extract every `criteria` string from the NVD configuration tree.
    The vulnerability matcher does a substring check against the
    installed CPE's part/vendor/product, so the version range from
    `versionStartIncluding`/`versionEndExcluding` is intentionally
    dropped — we only need the product locator to figure out which
    package on a host is implicated."""
    out: list[str] = []
    for cfg in configurations or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                crit = m.get("criteria")
                if isinstance(crit, str) and crit:
                    out.append(crit)
    return out


def _parse_entry(entry: dict[str, Any]) -> NvdVulnerability | None:
    cve = entry.get("cve") or {}
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not cve_id:
        return None
    descs = cve.get("descriptions") or []
    summary: str | None = None
    for d in descs:
        if (d or {}).get("lang") == "en":
            summary = d.get("value")
            break
    severity, score = _pick_v3(cve.get("metrics") or {})
    refs_raw = cve.get("references") or []
    refs = [r["url"] for r in refs_raw if isinstance(r, dict) and isinstance(r.get("url"), str)]
    cpes = _flatten_cpe(cve.get("configurations") or [])
    return NvdVulnerability(
        cve_id=cve_id,
        severity=severity,
        cvss_v3_score=score,
        summary=summary,
        references=refs,
        affected_cpes=cpes,
        published_at=_parse_iso(cve.get("published")),
        modified_at=_parse_iso(cve.get("lastModified")),
    )


@dataclass
class NvdClient:
    """Thin async wrapper around the NVD 2.0 endpoint.

    The worker holds one client across a scan pass; per-request rate
    limiting is enforced inside `fetch_modified`. The base URL +
    api-key live on the dataclass so tests can override them at
    construction time without touching settings.
    """

    base_url: str = field(default_factory=lambda: settings.nvd_base_url)
    api_key: str = field(default_factory=lambda: settings.nvd_api_key)
    timeout: float = 30.0
    # Public ceiling: NVD's rate-limit docs say 5 requests / 30 s
    # without a key, 50 with. The 6.0 / 0.6 defaults stay inside that
    # ceiling with margin.
    page_size: int = 2000

    def _rate_limit_seconds(self) -> float:
        return 0.6 if self.api_key else 6.0

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if self.api_key:
            h["apiKey"] = self.api_key
        return h

    async def fetch_modified(
        self,
        *,
        last_mod_start: datetime,
        last_mod_end: datetime,
        client: httpx.AsyncClient | None = None,
    ) -> list[NvdVulnerability]:
        """Return every CVE whose `lastModified` falls in
        [last_mod_start, last_mod_end]. Pages until totalResults is
        exhausted; sleeps `_rate_limit_seconds()` between pages."""
        owned = client is None
        cli = client or httpx.AsyncClient(timeout=self.timeout)
        try:
            return await self._paginate(cli, last_mod_start, last_mod_end)
        finally:
            if owned:
                await cli.aclose()

    async def _paginate(
        self,
        cli: httpx.AsyncClient,
        start: datetime,
        end: datetime,
    ) -> list[NvdVulnerability]:
        url = f"{self.base_url.rstrip('/')}/cves/2.0"
        results: list[NvdVulnerability] = []
        offset = 0
        sleep_s = self._rate_limit_seconds()
        first = True
        while True:
            params = {
                "lastModStartDate": _to_nvd_iso(start),
                "lastModEndDate": _to_nvd_iso(end),
                "startIndex": offset,
                "resultsPerPage": self.page_size,
            }
            if not first:
                await asyncio.sleep(sleep_s)
            first = False
            resp = await cli.get(url, params=params, headers=self._headers())
            resp.raise_for_status()
            data = resp.json() or {}
            entries = data.get("vulnerabilities") or []
            for raw in entries:
                parsed = _parse_entry(raw)
                if parsed is not None:
                    results.append(parsed)
            total = int(data.get("totalResults") or 0)
            offset += len(entries)
            if offset >= total or not entries:
                break
        log.info("vuln.nvd.fetch_modified.ok", count=len(results))
        return results


def _to_nvd_iso(dt: datetime) -> str:
    """NVD wants `YYYY-MM-DDTHH:MM:SS.sss` with no offset, treated as
    UTC. Drop the timezone after normalising to UTC so the wire
    format matches what their parser accepts."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    # Trim microseconds to milliseconds to match NVD's accepted shape.
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


__all__ = (
    "NvdClient",
    "NvdVulnerability",
    "_parse_entry",
    "_to_nvd_iso",
)
