"""ServiceNow incident-table client for the case-management mirror.

Destination config shape:

    {
      "instance_url": "https://acme.service-now.com",
      "username":     "vigil_integration",
      "password":     "<sn password / api token>",
      "caller_id":    "<sys_id of the SOC user>",   # optional
      "assignment_group": "<sys_id of the SOC group>"  # optional
    }

The ServiceNow Table API uses HTTP Basic auth. We round-trip
`sys_id` as the external handle since `number` (INC0001234) can be
reformatted by the instance's numbering rules, but `sys_id` is
guaranteed-stable for the row's lifetime. The browser URL is built
from the instance URL + `sys_id`.

State mapping: the `incident` table's `state` column is an integer
choice with stable codes; we map by code value rather than the
display label so the mapping survives instance localisation. The
defaults (1=new, 2=in progress, 6=resolved, 7=closed, 8=canceled)
are the ServiceNow OOTB values.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.models import Alert, CaseSyncState
from app.services.case import CaseSyncError

log = structlog.get_logger()

CREATE_PATH = "/api/now/table/incident"
FETCH_PATH = "/api/now/table/incident/{sys_id}"

# ECS-like severity → ServiceNow incident impact (1 high / 2 med / 3 low).
_IMPACT_BY_SEVERITY: dict[str, int] = {
    "critical": 1,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 3,
}
# Vigil-side sync states keyed by ServiceNow's state column integer
# codes. Anything not listed defaults to OPEN — covers custom states
# instances sometimes add. 8 (canceled) collapses to CLOSED because
# Vigil's enum doesn't distinguish "operator closed it" from "issue
# was canceled" — the link is no longer live either way.
_STATE_BY_CODE: dict[str, CaseSyncState] = {
    "1": CaseSyncState.OPEN,
    "2": CaseSyncState.IN_PROGRESS,
    "3": CaseSyncState.IN_PROGRESS,
    "4": CaseSyncState.IN_PROGRESS,
    "5": CaseSyncState.IN_PROGRESS,
    "6": CaseSyncState.RESOLVED,
    "7": CaseSyncState.CLOSED,
    "8": CaseSyncState.CLOSED,
}


def _required(config: dict[str, Any]) -> tuple[str, str, str]:
    """Pull the three required config fields or raise CaseSyncError.

    Returns (instance_url, username, password).
    """
    missing = [k for k in ("instance_url", "username", "password") if not config.get(k)]
    if missing:
        raise CaseSyncError(
            f"servicenow destination missing config fields: {','.join(missing)}",
            transient=False,
        )
    return (
        str(config["instance_url"]).rstrip("/"),
        str(config["username"]),
        str(config["password"]),
    )


def _build_body(alert: Alert, config: dict[str, Any]) -> dict[str, Any]:
    """Render an alert as a ServiceNow incident-create payload."""
    short_description = (alert.summary or f"Vigil alert {alert.id}")[:160]
    description_lines = [
        f"Vigil alert {alert.id}",
        f"Severity: {alert.severity.value}",
        f"State:    {alert.state.value}",
        f"Opened:   {alert.opened_at.isoformat()}",
    ]
    if alert.summary:
        description_lines.append("")
        description_lines.append(alert.summary)
    body: dict[str, Any] = {
        "short_description": short_description,
        "description": "\n".join(description_lines),
        # impact + urgency together drive ServiceNow's priority matrix.
        "impact": _IMPACT_BY_SEVERITY.get(alert.severity.value, 3),
        "urgency": _IMPACT_BY_SEVERITY.get(alert.severity.value, 3),
    }
    if config.get("caller_id"):
        body["caller_id"] = config["caller_id"]
    if config.get("assignment_group"):
        body["assignment_group"] = config["assignment_group"]
    return body


async def create_issue(config: dict[str, Any], alert: Alert) -> tuple[str, str]:
    """Open a new ServiceNow incident mirroring `alert`.

    Returns (sys_id, browser_url). Raises CaseSyncError on failure.
    """
    instance_url, username, password = _required(config)
    body = _build_body(alert, config)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                instance_url + CREATE_PATH,
                auth=(username, password),
                json=body,
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise CaseSyncError(f"servicenow create request failed: {exc}", transient=True) from exc

    if resp.status_code >= 500 or resp.status_code == 429:
        raise CaseSyncError(
            f"servicenow create transient error {resp.status_code}: {resp.text[:200]}",
            transient=True,
        )
    if resp.status_code >= 400:
        raise CaseSyncError(
            f"servicenow create rejected {resp.status_code}: {resp.text[:200]}",
            transient=False,
        )

    result = (resp.json() or {}).get("result") or {}
    sys_id = result.get("sys_id")
    if not isinstance(sys_id, str) or not sys_id:
        raise CaseSyncError("servicenow create returned no sys_id", transient=False)
    # The incident sys_id is enough for the browser URL — the deep link
    # uses the incident form view keyed by sys_id.
    url = f"{instance_url}/nav_to.do?uri=incident.do?sys_id={sys_id}"
    return sys_id, url


async def fetch_status(config: dict[str, Any], external_id: str) -> CaseSyncState:
    """Look up the incident's current state and map to a CaseSyncState."""
    instance_url, username, password = _required(config)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                instance_url + FETCH_PATH.format(sys_id=external_id),
                auth=(username, password),
                headers={"Accept": "application/json"},
                params={"sysparm_fields": "state,sys_id"},
            )
    except httpx.HTTPError as exc:
        raise CaseSyncError(f"servicenow fetch request failed: {exc}", transient=True) from exc

    if resp.status_code == 404:
        # Incident deleted on the SN side. Treat as closed (same shape
        # as the Jira client).
        return CaseSyncState.CLOSED
    if resp.status_code >= 500 or resp.status_code == 429:
        raise CaseSyncError(
            f"servicenow fetch transient error {resp.status_code}: {resp.text[:200]}",
            transient=True,
        )
    if resp.status_code >= 400:
        raise CaseSyncError(
            f"servicenow fetch rejected {resp.status_code}: {resp.text[:200]}",
            transient=False,
        )

    result = (resp.json() or {}).get("result") or {}
    state_raw = result.get("state")
    # Table API returns the state as a string (display value when
    # sysparm_display_value=true; raw integer otherwise). We pass no
    # display flag, so the response is the integer code as a string.
    return _STATE_BY_CODE.get(str(state_raw), CaseSyncState.OPEN)


__all__ = ["create_issue", "fetch_status"]
