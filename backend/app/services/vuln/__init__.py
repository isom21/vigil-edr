"""Vulnerability-assessment services (Phase 2 #2.7).

Splits into:

  * `nvd`: async client over the NVD 2.0 REST API. Honours the
    documented 6s public / 0.6s with-API-key rate limit. Returns
    structured `NvdVulnerability` dataclasses; the caller decides what
    to materialise.
  * `cpe`: CPE 2.3 URI parsing + the "is this installed package
    affected by this advisory?" predicate.

The worker (`app.workers.vuln_scanner`) wires them together: pull the
NVD delta into `vulnerability`, walk `INSTALLED_SOFTWARE` job
artifacts into `host_software`, then run the CPE matcher to UPSERT
into `host_vulnerability`.
"""

from __future__ import annotations

from app.services.vuln.cpe import CpeMatch, match, parse_cpe
from app.services.vuln.nvd import NvdClient, NvdVulnerability

__all__ = (
    "CpeMatch",
    "NvdClient",
    "NvdVulnerability",
    "match",
    "parse_cpe",
)
