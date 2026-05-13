"""TAXII 2.1 puller (Phase 1 #1.9).

Fetches the configured collection's STIX 2.1 bundle and walks the
indicator objects for pattern matches we can lower into `IocEntry`
rows. Only the kinds the existing `IocKind` enum models are emitted;
everything else is dropped at parse time (with a debug log line so
operators can spot why an indicator they expected didn't land).

STIX indicator patterns are STIX-Patterning syntax — a small grammar
that supports comparisons over object properties. We implement the
narrow subset that's the only practical shape for free-form intel
feeds, which is:

    [file:hashes.'SHA-256' = '...']
    [file:hashes.MD5 = '...']
    [file:hashes.'SHA-1' = '...']
    [file:name = '...']

…with optional OR-chains (`[…] OR [...]`) and case-insensitive hash
algorithm names. Anything more exotic (regex matchers, contains,
matches, multi-property bundles) is skipped — those are vanishingly
rare in practice in TAXII collections.

The HTTP path uses the documented TAXII 2.1 media types and the
`accept: application/taxii+json;version=2.1` header so servers that
multiplex multiple TAXII versions on the same URL hand us back the
right shape.
"""

from __future__ import annotations

import re

import httpx
import structlog

from app.models import IntelFeed, IntelFeedKind, IocKind
from app.services.intel import ParsedIndicator, register

log = structlog.get_logger()


# TAXII 2.1 media type. The server may also accept the older
# `application/vnd.oasis.taxii+json` — the 2.1 spec asks
# implementations to honour it too — but we only send the 2.1 form;
# servers stuck on the older type get a 406 here, which surfaces to
# the operator as `last_error` rather than silently mis-parsing.
_ACCEPT = "application/taxii+json;version=2.1"

# STIX-Patterning matcher.
#
# We're intentionally narrow: a top-level [path = 'value'] match, with
# the value a single-quoted string. Real-world TAXII feeds tend to ship
# patterns shaped like this for file IOCs:
#   [file:hashes.'SHA-256' = '...']
#   [file:hashes.MD5 = '...']
#   [file:name = 'evil.exe']
#
# OR-chains between multiple bracket groups get split by `_iter_atoms`
# before we apply this regex; nested AND / NOT / FOLLOWED_BY etc.
# inside one bracket group is treated as "too complex, skip".
_ATOM_RE = re.compile(
    r"""
    ^\s*\[\s*                   # opening bracket
    (?P<path>[A-Za-z0-9:._'-]+) # property path (allow quoted dotted segments)
    \s*=\s*
    '(?P<value>[^']+)'          # value (single-quoted)
    \s*\]\s*$
    """,
    re.VERBOSE,
)


def _iter_atoms(pattern: str) -> list[str]:
    """Split a STIX pattern into individual `[…]` atoms separated by
    top-level `OR`. Returns the bracketed substrings (including the
    brackets). Doesn't try to be a real parser — anything with
    parenthesised grouping or nested expressions falls out as one
    blob that `_ATOM_RE` will reject."""
    atoms: list[str] = []
    depth = 0
    start = -1
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "[":
            if depth == 0:
                start = i
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0 and start >= 0:
                atoms.append(pattern[start : i + 1])
                start = -1
        i += 1
    return atoms


def _path_to_kind(path: str) -> IocKind | None:
    """Map a STIX property path to an `IocKind`. Returns None for
    paths the schema doesn't model (domain-name:value, url:value,
    ipv4-addr:value, etc.) so the caller can drop with a warning."""
    p = path.replace("'", "").lower()
    if p == "file:hashes.sha-256" or p == "file:hashes.sha256":
        return IocKind.HASH_SHA256
    if p == "file:hashes.md5":
        return IocKind.HASH_MD5
    if p == "file:hashes.sha-1" or p == "file:hashes.sha1":
        return IocKind.HASH_SHA1
    if p == "file:name":
        return IocKind.FILENAME
    return None


def parse_indicator(pattern: str) -> list[ParsedIndicator]:
    """Lower a STIX pattern string into zero or more indicators.

    Public for the test suite; the puller calls this for every
    indicator object the TAXII server hands back.
    """
    out: list[ParsedIndicator] = []
    for atom in _iter_atoms(pattern):
        m = _ATOM_RE.match(atom)
        if not m:
            continue
        kind = _path_to_kind(m.group("path"))
        if kind is None:
            log.debug("intel.taxii.unsupported_pattern_path", path=m.group("path"))
            continue
        value = m.group("value").strip()
        if not value:
            continue
        out.append(ParsedIndicator(kind=kind, value=value))
    return out


async def pull(feed: IntelFeed, auth: str | None) -> list[ParsedIndicator]:
    """Pull one TAXII 2.1 collection. `auth` is the decrypted basic-auth
    string in `user:password` form, or None for anonymous access.

    Returns the list of parsed indicators; raises any HTTP / parse
    error to the worker, which records it on the feed row.
    """
    headers = {"Accept": _ACCEPT}
    basic: httpx.BasicAuth | None = None
    if auth:
        if ":" in auth:
            user, _, password = auth.partition(":")
            basic = httpx.BasicAuth(user, password)
        else:
            # Single-string auth = bearer / API key. The TAXII 2.1 spec
            # leaves the auth method open, so just pass through as-is.
            headers["Authorization"] = auth

    indicators: list[ParsedIndicator] = []
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        resp = await client.get(feed.url, headers=headers, auth=basic)
        resp.raise_for_status()
        body = resp.json()

    # TAXII 2.1 returns either an Envelope object ({"objects": [...]})
    # or a bare STIX bundle. Be defensive about either shape.
    raw_objects = body.get("objects") if isinstance(body, dict) else None
    if not isinstance(raw_objects, list):
        log.warning(
            "intel.taxii.unexpected_response_shape",
            feed_id=str(feed.id),
            top_keys=list(body.keys()) if isinstance(body, dict) else [],
        )
        return []

    for obj in raw_objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern")
        if not isinstance(pattern, str):
            continue
        # `pattern_type` defaults to "stix" in 2.1. Anything else
        # (snort, yara, eql) is a different language we don't speak —
        # skip rather than guess.
        pt = obj.get("pattern_type", "stix")
        if pt != "stix":
            log.debug(
                "intel.taxii.skipping_non_stix_pattern",
                feed_id=str(feed.id),
                pattern_type=pt,
            )
            continue
        indicators.extend(parse_indicator(pattern))

    return indicators


register(IntelFeedKind.TAXII, pull)


__all__ = ["parse_indicator", "pull"]
