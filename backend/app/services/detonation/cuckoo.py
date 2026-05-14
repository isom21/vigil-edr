"""Cuckoo Sandbox REST client (Phase 4 #4.4).

Cuckoo's REST API is the historical reference for open-source sandbox
detonation. Endpoints used:

  * ``POST /tasks/create/file`` — multipart form upload returning
    ``{"task_id": <int>}``.
  * ``GET /tasks/view/<task_id>`` — returns ``{"task": {"status": "..."},
    ...}``. We map Cuckoo's lifecycle ("pending", "running", "completed",
    "reported", "failed_*") onto our coarser status set.
  * ``GET /tasks/report/<task_id>`` — full report. We only read
    ``info.score`` and the optional ``signatures`` list.

Auth is via the optional ``api_token`` field in the provider config,
sent as the ``Authorization: Bearer <token>`` header. Cuckoo deploys
that don't enable auth ignore the header.

httpx is the codebase's standard HTTP client (case_management, intel
pullers, OIDC) so respx-driven tests work uniformly. The recipe
mentions ``aiohttp`` but consistency with the rest of the manager wins.
"""

from __future__ import annotations

from typing import Any

import httpx


class CuckooError(RuntimeError):
    """Transport / parse error talking to Cuckoo. The caller turns this
    into a ``DetonationJob`` row with ``status="failed"``."""


_TIMEOUT_S = 30.0


def _base_url(config: dict[str, Any]) -> str:
    raw = config.get("base_url")
    if not isinstance(raw, str) or not raw:
        raise CuckooError("cuckoo config missing 'base_url'")
    return raw.rstrip("/")


def _headers(config: dict[str, Any]) -> dict[str, str]:
    token = config.get("api_token")
    if isinstance(token, str) and token:
        return {"Authorization": f"Bearer {token}"}
    return {}


async def submit(
    config: dict[str, Any],
    sample_bytes: bytes,
    sample_name: str,
) -> str:
    """Upload a sample and return the Cuckoo task id (as a string).

    Cuckoo returns ``task_id`` as a JSON number; we stringify so the
    per-provider contract carries one type for the external id.
    """
    url = f"{_base_url(config)}/tasks/create/file"
    files = {"file": (sample_name, sample_bytes, "application/octet-stream")}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            resp = await client.post(url, headers=_headers(config), files=files)
    except httpx.HTTPError as exc:
        raise CuckooError(f"cuckoo submit transport error: {exc}") from exc
    if resp.status_code >= 400:
        raise CuckooError(f"cuckoo submit returned {resp.status_code}: {resp.text[:200]}")
    try:
        body = resp.json()
    except ValueError as exc:
        raise CuckooError(f"cuckoo submit returned non-JSON body: {exc}") from exc
    task_id = body.get("task_id")
    if task_id is None:
        raise CuckooError(f"cuckoo submit response missing 'task_id': {body!r}")
    return str(task_id)


# Cuckoo's task.status values: pending, running, completed, reported,
# failed_analysis, failed_processing, failed_reporting. Anything with
# a "reported" or "completed" status is finished and ready for a report
# fetch; "failed_*" maps to our failed bucket.
_RUNNING_STATUSES = frozenset({"pending", "running", "processing"})
_FINISHED_STATUSES = frozenset({"reported", "completed"})


async def poll(config: dict[str, Any], task_id: str) -> dict[str, Any]:
    """Fetch the current status of a task and the report when ready.

    Returns a dict with keys ``status`` (always present), ``score``
    (verdict only), and ``signatures`` (verdict only). The caller maps
    the score onto a ``DetonationVerdictLabel`` via
    ``app.services.detonation.label_for_score``.
    """
    base = _base_url(config)
    headers = _headers(config)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
            view = await client.get(f"{base}/tasks/view/{task_id}", headers=headers)
            if view.status_code >= 500:
                raise CuckooError(f"cuckoo view returned {view.status_code}")
            if view.status_code >= 400:
                raise CuckooError(f"cuckoo view returned {view.status_code}: {view.text[:200]}")
            try:
                view_body = view.json()
            except ValueError as exc:
                raise CuckooError(f"cuckoo view non-JSON: {exc}") from exc
            task = view_body.get("task") or {}
            status = str(task.get("status") or "").lower()

            if status in _RUNNING_STATUSES:
                return {"status": "running"}
            if status.startswith("failed"):
                return {
                    "status": "failed",
                    "error": f"cuckoo task status={status}",
                }
            if status not in _FINISHED_STATUSES:
                # Unknown status — treat as still in flight so the
                # operator doesn't lose the job to an upstream rename.
                return {"status": "running"}

            report = await client.get(f"{base}/tasks/report/{task_id}", headers=headers)
            if report.status_code >= 400:
                raise CuckooError(
                    f"cuckoo report returned {report.status_code}: {report.text[:200]}"
                )
            try:
                report_body = report.json()
            except ValueError as exc:
                raise CuckooError(f"cuckoo report non-JSON: {exc}") from exc
    except httpx.HTTPError as exc:
        raise CuckooError(f"cuckoo poll transport error: {exc}") from exc

    info = report_body.get("info") or {}
    score = info.get("score")
    if isinstance(score, int):
        score = float(score)
    elif not isinstance(score, float):
        score = None
    sig_names: list[str] = []
    for sig in report_body.get("signatures") or []:
        if isinstance(sig, dict):
            name = sig.get("name")
            if isinstance(name, str):
                sig_names.append(name)
    return {
        "status": "verdict",
        "score": score,
        "signatures": sig_names,
    }
