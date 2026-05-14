"""AWS CloudTrail S3 ingest helpers (Phase 4 #4.2).

We sign S3 requests inline with SigV4 + ``httpx`` rather than pull a
full boto3/aiobotocore dependency for two endpoints. The signing is the
canonical AWS algorithm (HMAC-SHA256 over the canonical request, then
HMAC-SHA256 chain through date / region / service / signing key); see
the AWS docs "Signing AWS API requests" for the exact byte layout we
mirror.

Three entry points:

  * :func:`list_objects` — paginate ``ListObjectsV2`` against the bucket
    under ``prefix``, optionally filtering server-side by
    ``after_ts`` (we still re-filter client-side because S3 returns
    ``LastModified`` rather than the event timestamp inside the
    gzipped record).
  * :func:`fetch_object` — fetch + gunzip + JSON-parse one object.
  * :func:`parse_events` — pull the CloudTrail ``Records`` envelope
    apart into the uniform dict shape the detector consumes.

Tests patch the underlying HTTP via ``respx`` (which intercepts httpx
transports). The signing code path is exercised but the receiver
doesn't verify the signature.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import io
import json
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

import httpx

# S3 wraps every response in this XML namespace; ElementTree's parser
# requires the brace-prefixed form to match the tags.
_S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _endpoint(bucket: str, region: str) -> str:
    """S3 virtual-hosted-style endpoint. us-east-1 historically used the
    bare ``s3.amazonaws.com`` form; every other region requires the
    region prefix."""
    if region == "us-east-1":
        return f"https://{bucket}.s3.amazonaws.com"
    return f"https://{bucket}.s3.{region}.amazonaws.com"


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


def _sigv4_headers(
    *,
    method: str,
    host: str,
    path: str,
    query: dict[str, str],
    access_key: str,
    secret_key: str,
    region: str,
    now: datetime | None = None,
) -> dict[str, str]:
    """Build the headers a GET request needs to satisfy SigV4 against S3."""
    now = now or _utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    service = "s3"

    payload_hash = hashlib.sha256(b"").hexdigest()

    canonical_qs = "&".join(
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
        for k, v in sorted(query.items())
    )
    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = "\n".join(
        [method, path, canonical_qs, canonical_headers, signed_headers, payload_hash]
    )

    cr_hash = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, cr_hash])

    signature = hmac.new(
        _signing_key(secret_key, date_stamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope},"
        f" SignedHeaders={signed_headers}, Signature={signature}"
    )
    return {
        "Authorization": authorization,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }


async def _signed_get(
    config: dict[str, Any],
    *,
    path: str,
    query: dict[str, str],
) -> bytes:
    bucket = config["bucket"]
    region = config.get("region", "us-east-1")
    base = _endpoint(bucket, region)
    host = urllib.parse.urlparse(base).hostname or ""
    headers = _sigv4_headers(
        method="GET",
        host=host,
        path=path,
        query=query,
        access_key=config["aws_access_key_id"],
        secret_key=config["aws_secret_access_key"],
        region=region,
    )
    url = f"{base}{path}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, headers=headers, params=query)
        if resp.status_code >= 400:
            snippet = resp.text[:256]
            raise RuntimeError(f"S3 GET {path} returned {resp.status_code}: {snippet}")
        return resp.content


def _ns(tag: str) -> str:
    return f"{{{_S3_NS}}}{tag}"


def _parse_iso8601(value: str) -> datetime | None:
    """Tolerate the ``Z`` suffix S3 ships."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


async def list_objects(
    config: dict[str, Any],
    *,
    prefix: str = "",
    after_ts: datetime | None = None,
) -> list[dict[str, Any]]:
    """List objects in the configured bucket / prefix.

    Returns a list of ``{"key": str, "last_modified": datetime|None}``.
    Pagination is handled here so callers see one flat list. Objects
    whose ``LastModified`` is older than ``after_ts`` are dropped client-
    side; S3's ``ListObjectsV2`` doesn't accept a date filter.
    """
    prefix = (prefix or "").lstrip("/")
    continuation: str | None = None
    out: list[dict[str, Any]] = []

    while True:
        query: dict[str, str] = {"list-type": "2"}
        if prefix:
            query["prefix"] = prefix
        if continuation is not None:
            query["continuation-token"] = continuation
        body = await _signed_get(config, path="/", query=query)
        root = ET.fromstring(body)
        for content in root.findall(_ns("Contents")):
            key_el = content.find(_ns("Key"))
            lm_el = content.find(_ns("LastModified"))
            if key_el is None or key_el.text is None:
                continue
            last_modified: datetime | None = None
            if lm_el is not None and lm_el.text:
                last_modified = _parse_iso8601(lm_el.text)
            if after_ts is not None and last_modified is not None and last_modified <= after_ts:
                continue
            out.append({"key": key_el.text, "last_modified": last_modified})
        truncated = root.find(_ns("IsTruncated"))
        if truncated is None or (truncated.text or "").lower() != "true":
            break
        token_el = root.find(_ns("NextContinuationToken"))
        if token_el is None or not token_el.text:
            break
        continuation = token_el.text

    return out


async def fetch_object(config: dict[str, Any], key: str) -> dict[str, Any]:
    """Fetch one object, decompress if gzipped, parse JSON."""
    path = "/" + urllib.parse.quote(key.lstrip("/"), safe="/-_.~")
    body = await _signed_get(config, path=path, query={})
    if key.endswith(".gz") or body[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
            body = gz.read()
    return json.loads(body.decode("utf-8"))


def parse_events(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalise CloudTrail's ``{"Records": [...]}`` envelope into the
    detector's uniform shape.

    Output fields per event: ``ts``, ``principal_arn``, ``region``,
    ``event_source``, ``event_name``, ``source_ip``, ``error_code``,
    ``user_type``.
    """
    records: Iterable[dict[str, Any]] = raw.get("Records") or []
    out: list[dict[str, Any]] = []
    for rec in records:
        identity = rec.get("userIdentity") or {}
        arn = identity.get("arn") or identity.get("principalId") or ""
        ts: datetime | None = None
        ev_time = rec.get("eventTime")
        if isinstance(ev_time, str):
            ts = _parse_iso8601(ev_time)
        out.append(
            {
                "ts": ts,
                "principal_arn": arn,
                "region": rec.get("awsRegion") or "",
                "event_source": rec.get("eventSource") or "",
                "event_name": rec.get("eventName") or "",
                "source_ip": rec.get("sourceIPAddress"),
                "error_code": rec.get("errorCode"),
                "user_type": identity.get("type"),
            }
        )
    return out


__all__ = ["fetch_object", "list_objects", "parse_events"]
