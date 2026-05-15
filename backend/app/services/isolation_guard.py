"""Defense-in-depth helper for IsolateHostCmd payloads.

An operator who issues an isolate command without including the
manager's IP in `allowlist_ips` accidentally severs the manager's
control channel to the agent — the matching `isolate=false` recovery
command then can't land. The agent-side fix is the load-bearing one
(`apply_network_isolation` resolves its own configured manager URLs
and forces them into the allowlist on every apply, regardless of the
operator's input). This module adds the same injection on the
manager side so older agents that don't carry the agent-side fix also
get the safety net.

We resolve `settings.manager_public_url`'s hostname plus any explicit
entries from `settings.grpc_san_extras` to IPs via `socket.getaddrinfo`,
deduplicate against any IPs the operator already supplied, and append
the result to `payload["allowlist_ips"]`. Failure to resolve is logged
but not fatal — the agent-side injection will still catch the case.
"""

from __future__ import annotations

import socket
from typing import Any

import structlog

from app.core.config import settings

log = structlog.get_logger()


def _extract_host(url_or_host: str) -> str | None:
    """Pull the bare host out of a "scheme://host:port/..." URL or a
    bare "host:port" / "host" string. IPv6 literals in brackets are
    unwrapped. Returns None on parse failure."""
    s = url_or_host.strip()
    if not s:
        return None
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            return None
        return s[1:end]
    if ":" in s:
        # bare "host:port" — only split if the part after the last `:`
        # is a port (digits). Avoids breaking IPv6 literals that
        # somehow slipped through without brackets.
        host, _, port = s.rpartition(":")
        if port.isdigit():
            return host
    return s


def _resolve_to_ips(host: str) -> list[str]:
    """Resolve a hostname to all v4 + v6 addresses. Returns an empty
    list on any failure; the caller treats that as "couldn't help"
    rather than fatal."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as e:
        log.warning("isolation_guard.resolve_failed", host=host, error=str(e))
        return []
    out: list[str] = []
    seen: set[str] = set()
    for family, _socktype, _proto, _canon, sa in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        # sa is (host, port) for v4 and (host, port, flowinfo, scope_id)
        # for v6; first element is always the address string.
        ip = str(sa[0])
        if ip and ip not in seen:
            out.append(ip)
            seen.add(ip)
    return out


def ensure_manager_in_allowlist(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of `payload` with the manager's resolved IPs
    appended to `payload["allowlist_ips"]`. Idempotent — re-running on
    an already-augmented payload is a no-op.

    Sources resolved:
      * the hostname in `VIGIL_MANAGER_PUBLIC_URL`
      * every entry in `VIGIL_GRPC_SAN_EXTRAS` (the SAN list the agent
        certificate already validates against)

    If neither resolves to a single IP, returns `payload` unchanged
    with a warning — the agent-side
    `command_worker::apply_network_isolation` will refuse the isolate
    if the agent's own resolution also comes back empty, which is the
    real safety check.
    """
    out = dict(payload)
    existing_raw = out.get("allowlist_ips", []) or []
    if not isinstance(existing_raw, list):
        return out
    existing: list[str] = [str(x).strip() for x in existing_raw if str(x).strip()]
    existing_set = set(existing)

    candidates: list[str] = []
    if pub := _extract_host(settings.manager_public_url):
        candidates.append(pub)
    for extra in settings.grpc_san_extras.split(","):
        extra = extra.strip()
        if not extra:
            continue
        if host := _extract_host(extra):
            candidates.append(host)

    injected: list[str] = []
    for host in candidates:
        for ip in _resolve_to_ips(host):
            if ip not in existing_set:
                injected.append(ip)
                existing_set.add(ip)

    if not injected:
        log.warning(
            "isolation_guard.no_manager_ip_injected",
            manager_public_url=settings.manager_public_url,
            grpc_san_extras=settings.grpc_san_extras,
            existing=len(existing),
        )
        return out

    out["allowlist_ips"] = existing + injected
    log.info(
        "isolation_guard.injected",
        operator_count=len(existing),
        injected_count=len(injected),
        injected=injected,
    )
    return out
