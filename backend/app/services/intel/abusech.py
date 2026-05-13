"""abuse.ch CSV puller (Phase 1 #1.9).

Handles the canonical abuse.ch dump formats:

  * urlhaus.abuse.ch  payload_delivery / url IOCs (column 7 = sha256)
  * malwarebazaar     hash-based listings (sha256 / md5 / sha1 columns)
  * threatfox         comment-headered CSVs with `# Hash` / `# Filename`

The parser is intentionally flexible: it inspects the header row (the
last comment line starting with `#` before the data rows in the
abuse.ch dumps) to map columns to `IocKind`. Rows without any
supported indicator are skipped. Domain / IP / URL columns are
recognised but dropped — the schema doesn't model those kinds yet
(Phase 1 scope).

For feeds that don't include a header row, we sniff the first data
row: a 64-char hex string is sha256, 40-char hex is sha1, 32-char hex
is md5, anything else with a `.exe` / `.dll` / `.scr` extension is
filename.
"""

from __future__ import annotations

import csv
import io
import re

import httpx
import structlog

from app.models import IntelFeed, IntelFeedKind, IocKind
from app.services.intel import ParsedIndicator, register

log = structlog.get_logger()


# Column-name → IocKind. Lower-cased lookup; the keys here cover the
# names abuse.ch uses across urlhaus / threatfox / malwarebazaar.
_COLUMN_TO_KIND: dict[str, IocKind] = {
    "sha256": IocKind.HASH_SHA256,
    "sha256_hash": IocKind.HASH_SHA256,
    "sha-256": IocKind.HASH_SHA256,
    "sha1": IocKind.HASH_SHA1,
    "sha1_hash": IocKind.HASH_SHA1,
    "sha-1": IocKind.HASH_SHA1,
    "md5": IocKind.HASH_MD5,
    "md5_hash": IocKind.HASH_MD5,
    "filename": IocKind.FILENAME,
    "file_name": IocKind.FILENAME,
}


def _normalise_header(name: str) -> str:
    return name.strip().lstrip("#").strip().lower().replace(" ", "_")


_HEX64 = re.compile(r"^[a-fA-F0-9]{64}$")
_HEX40 = re.compile(r"^[a-fA-F0-9]{40}$")
_HEX32 = re.compile(r"^[a-fA-F0-9]{32}$")


def _sniff_value_kind(value: str) -> IocKind | None:
    """Last-ditch type sniff for a bare value when no usable header is
    present. Used for feeds that ship a single column of hashes with no
    column label."""
    v = value.strip().strip('"').strip("'")
    if _HEX64.match(v):
        return IocKind.HASH_SHA256
    if _HEX40.match(v):
        return IocKind.HASH_SHA1
    if _HEX32.match(v):
        return IocKind.HASH_MD5
    return None


def parse_csv(text: str) -> list[ParsedIndicator]:
    """Lower a CSV body into indicators.

    Public for the test suite; the puller calls this on the response
    body. Comment lines (`# …`) are inspected for a header row; data
    rows are split with the stdlib csv module so quoting works.
    """
    lines = text.splitlines()
    header: list[str] | None = None
    # abuse.ch dumps put the column header inside the trailing `#` comment.
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            candidate = [_normalise_header(c) for c in s.lstrip("#").split(",")]
            # Only treat as header if at least one cell matches our
            # column map — otherwise it's just a comment line.
            if any(c in _COLUMN_TO_KIND for c in candidate):
                header = candidate
            continue
        # First non-comment / non-blank line wins as "where data starts".
        break

    indicators: list[ParsedIndicator] = []
    data_text = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
    reader = csv.reader(io.StringIO(data_text))
    for row in reader:
        if not row or all(not c.strip() for c in row):
            continue
        if header is not None and len(row) >= 1:
            for idx, cell in enumerate(row):
                if idx >= len(header):
                    break
                kind = _COLUMN_TO_KIND.get(header[idx])
                if kind is None:
                    continue
                value = cell.strip().strip('"').strip("'")
                if not value:
                    continue
                indicators.append(ParsedIndicator(kind=kind, value=value))
        else:
            # No usable header — fall back to per-cell value sniffing.
            # Keeps headerless single-column dumps working.
            for cell in row:
                value = cell.strip().strip('"').strip("'")
                if not value:
                    continue
                kind = _sniff_value_kind(value)
                if kind is not None:
                    indicators.append(ParsedIndicator(kind=kind, value=value))
    return indicators


async def pull(feed: IntelFeed, auth: str | None) -> list[ParsedIndicator]:
    """Pull a static abuse.ch-style CSV. `auth` is ignored — these
    dumps are public — but accepted for puller-signature uniformity
    so the worker can call any registered puller the same way."""
    _ = auth
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        resp = await client.get(feed.url)
        resp.raise_for_status()
        text = resp.text
    indicators = parse_csv(text)
    log.debug(
        "intel.abusech.parsed",
        feed_id=str(feed.id),
        n=len(indicators),
        size_bytes=len(text),
    )
    return indicators


register(IntelFeedKind.ABUSECH_CSV, pull)


__all__ = ["parse_csv", "pull"]
