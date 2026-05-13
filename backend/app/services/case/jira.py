"""Jira REST v3 client for the case-management mirror.

Destination config shape:

    {
      "base_url":   "https://acme.atlassian.net",
      "email":      "soc@acme.example",
      "api_token":  "<atlassian API token>",
      "project_key": "SEC",
      "issue_type": "Task"        # optional; defaults to "Task"
    }

Auth is HTTP Basic with the operator's email + API token, which is
Atlassian's recommended pattern for personal/integration tokens. The
issue body uses ADF (Atlassian Document Format) so Jira renders the
description with structure rather than a single-paragraph blob.

Status-mapping note: Jira's status field is per-project configurable,
so we map by the workflow category (`statusCategory.key`) rather than
the human-readable status name. The categories are stable:
`new` / `indeterminate` / `done`. Anything else lands as `open`.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.models import Alert, CaseSyncState
from app.services.case import CaseSyncError

log = structlog.get_logger()

DEFAULT_ISSUE_TYPE = "Task"
CREATE_PATH = "/rest/api/3/issue"
FETCH_PATH = "/rest/api/3/issue/{key}"


def _required(config: dict[str, Any]) -> tuple[str, str, str, str, str]:
    """Pull the five required config fields or raise CaseSyncError.

    Returns (base_url, email, api_token, project_key, issue_type).
    """
    missing = [k for k in ("base_url", "email", "api_token", "project_key") if not config.get(k)]
    if missing:
        raise CaseSyncError(
            f"jira destination missing config fields: {','.join(missing)}",
            transient=False,
        )
    return (
        str(config["base_url"]).rstrip("/"),
        str(config["email"]),
        str(config["api_token"]),
        str(config["project_key"]),
        str(config.get("issue_type") or DEFAULT_ISSUE_TYPE),
    )


def _alert_to_description(alert: Alert) -> dict[str, Any]:
    """Render the alert summary + details as an ADF document.

    Keep this conservative — Jira rejects ADF with unknown node types
    outright. We use only `paragraph` + `text` nodes so it works
    against every Jira Cloud instance regardless of plugin set.
    """
    lines = [
        f"Vigil alert {alert.id}",
        f"Severity: {alert.severity.value}",
        f"State: {alert.state.value}",
        f"Opened: {alert.opened_at.isoformat()}",
    ]
    if alert.summary:
        lines.append("")
        lines.append(alert.summary)
    content: list[dict[str, Any]] = []
    for line in lines:
        if line:
            content.append(
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": line}],
                }
            )
        else:
            content.append({"type": "paragraph", "content": []})
    return {"type": "doc", "version": 1, "content": content}


async def create_issue(config: dict[str, Any], alert: Alert) -> tuple[str, str]:
    """Open a new Jira issue mirroring `alert`.

    Returns (issue_key, issue_url). Raises CaseSyncError on failure.
    """
    base_url, email, api_token, project_key, issue_type = _required(config)
    summary = (alert.summary or f"Vigil alert {alert.id}")[:255]
    body = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "issuetype": {"name": issue_type},
            "description": _alert_to_description(alert),
        }
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                base_url + CREATE_PATH,
                auth=(email, api_token),
                json=body,
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise CaseSyncError(f"jira create request failed: {exc}", transient=True) from exc

    if resp.status_code >= 500 or resp.status_code == 429:
        raise CaseSyncError(
            f"jira create transient error {resp.status_code}: {resp.text[:200]}",
            transient=True,
        )
    if resp.status_code >= 400:
        raise CaseSyncError(
            f"jira create rejected {resp.status_code}: {resp.text[:200]}",
            transient=False,
        )

    data = resp.json()
    key = data.get("key")
    if not isinstance(key, str) or not key:
        raise CaseSyncError("jira create returned no issue key", transient=False)
    url = f"{base_url}/browse/{key}"
    return key, url


async def fetch_status(config: dict[str, Any], external_id: str) -> CaseSyncState:
    """Look up the issue's current status and map to a CaseSyncState."""
    base_url, email, api_token, _project_key, _issue_type = _required(config)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                base_url + FETCH_PATH.format(key=external_id),
                auth=(email, api_token),
                headers={"Accept": "application/json"},
                params={"fields": "status"},
            )
    except httpx.HTTPError as exc:
        raise CaseSyncError(f"jira fetch request failed: {exc}", transient=True) from exc

    if resp.status_code == 404:
        # Issue was deleted on the Jira side. Treat as closed so the
        # link drops out of the "live" filter; operator can re-fire
        # by re-transitioning the alert if they want a new mirror.
        return CaseSyncState.CLOSED
    if resp.status_code >= 500 or resp.status_code == 429:
        raise CaseSyncError(
            f"jira fetch transient error {resp.status_code}: {resp.text[:200]}",
            transient=True,
        )
    if resp.status_code >= 400:
        raise CaseSyncError(
            f"jira fetch rejected {resp.status_code}: {resp.text[:200]}",
            transient=False,
        )

    fields = (resp.json() or {}).get("fields") or {}
    status = fields.get("status") or {}
    category = (status.get("statusCategory") or {}).get("key")
    return _map_category(category)


def _map_category(category: object) -> CaseSyncState:
    """Map a Jira statusCategory.key into the small Vigil sync-state enum.

    Jira's three stable categories:
      * `new`           — issue created, not picked up.
      * `indeterminate` — work in progress.
      * `done`          — resolved/closed.

    Anything else (custom category) falls back to OPEN so we don't
    accidentally show a stale "closed" badge for a live issue.
    """
    if category == "done":
        return CaseSyncState.CLOSED
    if category == "indeterminate":
        return CaseSyncState.IN_PROGRESS
    return CaseSyncState.OPEN


__all__ = ["create_issue", "fetch_status"]
