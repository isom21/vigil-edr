"""Generic JSON puller (Phase 1 #1.9).

For sources that don't speak TAXII and don't dump abuse.ch-style
CSV, operators can register a custom JSON URL that returns one of:

  * `{"indicators": [{"kind": "...", "value": "..."}, …]}` — explicit
    Vigil-native shape.
  * `[{"kind": "...", "value": "..."}, …]` — bare list, same per-item
    shape.

`kind` strings are matched case-insensitively against `IocKind`
member values. Anything we can't lower (domain / ip / url / unknown
strings) is dropped with a warning so the operator sees the partial
match in the worker logs.

`auth` is passed straight through as the Authorization header value
(after Fernet decrypt). Operators who need Basic should encode the
header value themselves — keeps this puller's surface area minimal.
"""

from __future__ import annotations

import httpx
import structlog

from app.models import IntelFeed, IntelFeedKind, IocKind
from app.services.intel import ParsedIndicator, register

log = structlog.get_logger()


def _parse_kind(raw: object) -> IocKind | None:
    if not isinstance(raw, str):
        return None
    key = raw.strip().lower()
    for k in IocKind:
        if k.value == key:
            return k
    return None


def parse_indicators(body: object) -> list[ParsedIndicator]:
    """Lower a parsed JSON body into indicators.

    Public for the test suite; the puller calls this on the response
    body. Accepts the two shapes documented in the module docstring;
    rejects anything else with a warning + empty list (the worker
    treats this as "0 indicators pulled" and surfaces last_error if
    nothing landed).
    """
    items: object = body.get("indicators", []) if isinstance(body, dict) else body
    if not isinstance(items, list):
        log.warning("intel.custom_json.unexpected_top_level", got=type(items).__name__)
        return []
    out: list[ParsedIndicator] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        kind = _parse_kind(item.get("kind"))
        value = item.get("value")
        if kind is None or not isinstance(value, str):
            log.debug(
                "intel.custom_json.skipped_indicator",
                kind=item.get("kind"),
                has_value=isinstance(value, str),
            )
            continue
        v = value.strip()
        if not v:
            continue
        out.append(ParsedIndicator(kind=kind, value=v))
    return out


async def pull(feed: IntelFeed, auth: str | None) -> list[ParsedIndicator]:
    """Pull a custom JSON URL. `auth`, if present, is used as the literal
    `Authorization` header value (no rewriting)."""
    headers: dict[str, str] = {"Accept": "application/json"}
    if auth:
        headers["Authorization"] = auth
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        resp = await client.get(feed.url, headers=headers)
        resp.raise_for_status()
        body = resp.json()
    return parse_indicators(body)


register(IntelFeedKind.CUSTOM_JSON, pull)


__all__ = ["parse_indicators", "pull"]
