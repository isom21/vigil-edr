"""CPE 2.3 parsing + the installed-package vs. advisory match
predicate (Phase 2 #2.7).

The NIST spec for CPE 2.3 URI: `cpe:2.3:<part>:<vendor>:<product>:
<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:
<target_hw>:<other>`. We only need the first five components for the
matcher; the rest stay on the parsed dataclass for completeness so a
future caller (e.g. CPE-version-range-aware match) doesn't have to
re-parse the URI.

Matching is "part + vendor + product are equal, and either the
advisory has wildcard version OR versions match by string". The
version range NVD encodes as `versionStartIncluding` /
`versionEndExcluding` lives outside the URI itself and would require a
parallel data path — out of scope for the first cut. Operators get
the over-match (we'll flag a CVE on a package whose installed version
is actually patched) rather than the false negative.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CpeMatch:
    """Parsed CPE 2.3 URI. The matcher only uses part/vendor/product/
    version; the rest is preserved verbatim."""

    raw: str
    part: str
    vendor: str
    product: str
    version: str
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"


def parse_cpe(uri: str | None) -> CpeMatch | None:
    """Parse a CPE 2.3 formatted URI. Returns None on anything that
    doesn't start with `cpe:2.3:` or is missing required fields.

    Per the spec, components are colon-separated; a literal colon
    inside a component would be backslash-escaped. We use a simple
    split because no real-world CPE we ingest carries an escaped
    colon in the first five slots."""
    if not uri or not isinstance(uri, str):
        return None
    if not uri.startswith("cpe:2.3:"):
        return None
    body = uri[len("cpe:2.3:") :]
    parts = body.split(":")
    if len(parts) < 5:
        return None
    # Pad to 11 trailing fields with the wildcard so we never IndexError.
    while len(parts) < 11:
        parts.append("*")
    return CpeMatch(
        raw=uri,
        part=parts[0].lower(),
        vendor=parts[1].lower(),
        product=parts[2].lower(),
        version=parts[3].lower(),
        update=parts[4].lower(),
        edition=parts[5].lower(),
        language=parts[6].lower(),
        sw_edition=parts[7].lower(),
        target_sw=parts[8].lower(),
        target_hw=parts[9].lower(),
        other=parts[10].lower(),
    )


def _eq_or_wildcard(installed: str, advisory: str) -> bool:
    """A spec-compliant wildcard match: `*` on either side matches
    anything. Otherwise the values must be equal."""
    return advisory == "*" or installed == "*" or installed == advisory


def match(installed: str | CpeMatch | None, advisory_cpes: list[str]) -> str | None:
    """Return the first advisory CPE whose part/vendor/product align
    with the installed package, or None if nothing matches.

    The returned string is the matching advisory CPE — the scanner
    stores it on `host_vulnerability.cpe` so the UI can show "this
    host's <package> is implicated as <CPE>".
    """
    if installed is None:
        return None
    inst = installed if isinstance(installed, CpeMatch) else parse_cpe(installed)
    if inst is None:
        return None
    for raw in advisory_cpes:
        adv = parse_cpe(raw)
        if adv is None:
            continue
        if inst.part != adv.part:
            continue
        if not _eq_or_wildcard(inst.vendor, adv.vendor):
            continue
        if not _eq_or_wildcard(inst.product, adv.product):
            continue
        if not _eq_or_wildcard(inst.version, adv.version):
            continue
        return raw
    return None


__all__ = ("CpeMatch", "match", "parse_cpe")
