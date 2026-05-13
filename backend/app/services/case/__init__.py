"""External case management clients (Phase 3 #3.6).

Per-tracker thin async clients live in sibling modules (`jira`,
`servicenow`). They share the contract:

  * `create_issue(config, alert) -> (external_id, external_url)` —
    open a new case mirroring the alert. Raises CaseSyncError on
    transient + permanent failure; the caller distinguishes by the
    `transient` attribute on the exception.
  * `fetch_status(config, external_id) -> CaseSyncState` — poll the
    tracker for the case's current state, mapped into Vigil's small
    sync-state enum. Raises CaseSyncError when the tracker is
    unreachable; the poller worker logs + carries on without
    downgrading the link's stored state.

Both clients use httpx (matches the rest of the codebase: routing,
SIEM, intel pullers, OIDC). The spec mentioned `aiohttp` but the test
recipe pins on `respx` which targets httpx.
"""

from __future__ import annotations


class CaseSyncError(Exception):
    """Raised by the per-tracker clients on a failed API call.

    `transient=True` means a retry is worth attempting (5xx, network
    error, timeout). `transient=False` means the call won't succeed
    no matter how many times we retry (4xx malformed request, auth
    rejected, project missing) — the caller records the error on the
    link's `error` column and stops re-firing for this destination
    until the operator intervenes.
    """

    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


__all__ = ["CaseSyncError"]
