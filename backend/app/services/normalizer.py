"""Convert protobuf EndpointEvent -> ECS-shaped dict ready for OpenSearch.

Only the payloads we care about for M2 are populated; others pass through
with their oneof name as `event.action` so we can still index them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from google.protobuf.timestamp_pb2 import Timestamp

from app.proto_gen.edr.v1 import common_pb2, events_pb2

_EVENT_KIND_BY_NUM = {
    events_pb2.EVENT_KIND_UNSPECIFIED: "unspecified",
    events_pb2.EVENT_KIND_EVENT: "event",
    events_pb2.EVENT_KIND_ALERT: "alert",
    events_pb2.EVENT_KIND_STATE: "state",
}
_CATEGORY_BY_NUM = {
    events_pb2.EVENT_CATEGORY_UNSPECIFIED: "unspecified",
    events_pb2.EVENT_CATEGORY_PROCESS: "process",
    events_pb2.EVENT_CATEGORY_FILE: "file",
    events_pb2.EVENT_CATEGORY_NETWORK: "network",
    events_pb2.EVENT_CATEGORY_REGISTRY: "registry",
    events_pb2.EVENT_CATEGORY_AUTHENTICATION: "authentication",
    events_pb2.EVENT_CATEGORY_INTRUSION_DETECTION: "intrusion_detection",
}
_INTEGRITY_BY_NUM = {
    events_pb2.INTEGRITY_LEVEL_UNTRUSTED: "untrusted",
    events_pb2.INTEGRITY_LEVEL_LOW: "low",
    events_pb2.INTEGRITY_LEVEL_MEDIUM: "medium",
    events_pb2.INTEGRITY_LEVEL_HIGH: "high",
    events_pb2.INTEGRITY_LEVEL_SYSTEM: "system",
    events_pb2.INTEGRITY_LEVEL_PROTECTED: "protected",
}

# Phase 2 #2.9: container runtime → ECS-aligned token. Omitted for
# CONTAINER_RUNTIME_UNKNOWN so the normalizer skips emitting a runtime
# field for containers the agent couldn't classify.
_CONTAINER_RUNTIME_BY_NUM = {
    events_pb2.CONTAINER_RUNTIME_DOCKER: "docker",
    events_pb2.CONTAINER_RUNTIME_CONTAINERD: "containerd",
    events_pb2.CONTAINER_RUNTIME_CRI_O: "cri_o",
    events_pb2.CONTAINER_RUNTIME_PODMAN: "podman",
}

# Phase 2 #2.4: auth event enum mappings.
_AUTH_KIND_BY_NUM = {
    events_pb2.AUTH_KIND_UNSPECIFIED: "auth",
    events_pb2.AUTH_KIND_LOGON: "logon",
    events_pb2.AUTH_KIND_LOGOFF: "logoff",
    events_pb2.AUTH_KIND_KERBEROS_TGT: "kerberos_tgt",
    events_pb2.AUTH_KIND_KERBEROS_TGS: "kerberos_tgs",
    events_pb2.AUTH_KIND_NT_LOGON: "nt_logon",
}
_AUTH_RESULT_BY_NUM = {
    events_pb2.AUTH_RESULT_UNSPECIFIED: "unknown",
    events_pb2.AUTH_RESULT_SUCCESS: "success",
    events_pb2.AUTH_RESULT_FAILURE: "failure",
    events_pb2.AUTH_RESULT_UNKNOWN: "unknown",
}


def _ts_to_iso(ts: Timestamp | None) -> str | None:
    if ts is None or (ts.seconds == 0 and ts.nanos == 0):
        return None
    dt = datetime.fromtimestamp(ts.seconds + ts.nanos / 1e9, tz=UTC)
    return dt.isoformat()


def _hash_dict(h: common_pb2.Hash) -> dict[str, str]:
    out: dict[str, str] = {}
    if h.sha256:
        out["sha256"] = h.sha256.lower()
    if h.sha1:
        out["sha1"] = h.sha1.lower()
    if h.md5:
        out["md5"] = h.md5.lower()
    return out


def to_ecs(ev: events_pb2.EndpointEvent) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "@timestamp": _ts_to_iso(ev.event_observed)
        or _ts_to_iso(ev.event_created)
        or datetime.now(UTC).isoformat(),
        "event": {
            "id": ev.event_id,
            "kind": _EVENT_KIND_BY_NUM.get(ev.kind, "event"),
            "category": [_CATEGORY_BY_NUM.get(c, "unspecified") for c in ev.category],
            "action": ev.action or None,
            "outcome": ev.outcome or None,
            "created": _ts_to_iso(ev.event_created),
        },
        "host": {"id": ev.host_id},
        "agent": {"id": ev.agent_id, "version": ev.agent_version},
        "labels": dict(ev.labels) if ev.labels else None,
    }

    payload = ev.WhichOneof("payload")
    if payload == "process":
        p = ev.process
        proc: dict[str, Any] = {
            "pid": p.process.pid,
            "name": p.name or None,
            "executable": p.executable or None,
            "command_line": p.command_line or None,
        }
        h = _hash_dict(p.hash)
        if h:
            proc["hash"] = h
        if p.parent.pid:
            proc["parent"] = {
                "pid": p.parent.pid,
                "executable": None,
            }
        # M20.d: surface process_started details needed by the alert
        # investigation page. The percolator template doesn't pin these
        # fields, but dynamic mapping picks them up as keyword.
        if p.user.name or p.user.id:
            proc["user"] = {
                "name": p.user.name or None,
                "id": p.user.id or None,
            }
        integrity = _INTEGRITY_BY_NUM.get(p.integrity)
        if integrity:
            proc["integrity_level"] = integrity
        if p.working_directory:
            proc["working_directory"] = p.working_directory
        start_iso = _ts_to_iso(p.start)
        if start_iso:
            proc["start"] = start_iso
        doc["process"] = proc
        # Phase 2 #2.9: container.* ECS fields when the Linux agent
        # resolved a cgroup → runtime mapping. Image is best-effort
        # (empty when the runtime socket isn't reachable); runtime is
        # omitted (rather than indexed as "unknown") when the agent
        # saw a container id it couldn't classify.
        if p.container_id:
            container_doc: dict[str, Any] = {"id": p.container_id}
            if p.container_image:
                container_doc["image"] = {"name": p.container_image}
            runtime = _CONTAINER_RUNTIME_BY_NUM.get(p.container_runtime)
            if runtime:
                container_doc["runtime"] = runtime
            doc["container"] = container_doc
    elif payload == "file":
        f = ev.file
        fdoc: dict[str, Any] = {
            "path": f.path or None,
            "name": f.name or None,
            "size": f.size or None,
        }
        h = _hash_dict(f.hash)
        if h:
            fdoc["hash"] = h
        doc["file"] = fdoc
        # Mirror the actor pid up to top-level `process.pid` so file events
        # join with process events by pid (matches the network branch).
        if f.process.pid:
            doc["process"] = {"pid": f.process.pid}
    elif payload == "image_load":
        il = ev.image_load
        file_doc: dict[str, Any] = {"path": il.path or None}
        h = _hash_dict(il.hash)
        if h:
            file_doc["hash"] = h
        doc["file"] = file_doc
        # Mirror loader pid up to top-level for joins (matches file branch).
        if il.process.pid:
            doc["process"] = {"pid": il.process.pid}
    elif payload == "network":
        n = ev.network
        # ECS network shape: source.* + destination.* at top level,
        # network.transport / direction / type. Process attribution under
        # `process` so a downstream join with process events is by pid.
        direction_map = {
            events_pb2.NETWORK_DIRECTION_INBOUND: "inbound",
            events_pb2.NETWORK_DIRECTION_OUTBOUND: "outbound",
        }
        action_map = {
            events_pb2.NETWORK_ACTION_CONNECT: "connection_started",
            events_pb2.NETWORK_ACTION_ACCEPT: "connection_accepted",
            events_pb2.NETWORK_ACTION_DISCONNECT: "connection_closed",
            events_pb2.NETWORK_ACTION_BLOCKED: "connection_blocked",
        }
        doc["network"] = {
            "transport": n.transport or None,
            "direction": direction_map.get(n.direction),
            "type": "ipv6" if n.source_ip and ":" in n.source_ip else "ipv4",
        }
        doc["source"] = {
            "ip": n.source_ip or None,
            "port": n.source_port or None,
        }
        doc["destination"] = {
            "ip": n.destination_ip or None,
            "port": n.destination_port or None,
        }
        if n.process.pid:
            doc["process"] = {"pid": n.process.pid}
        # Refine event.action with the network-specific verb.
        if n.action in action_map:
            doc["event"]["type"] = [action_map[n.action]]
    elif payload == "scan":
        s = ev.scan
        doc["rule"] = {"id": s.rule_id, "name": s.rule_name}
    elif payload == "agent_tamper":
        # M12: agent self-protection tamper alert. Always rendered as an
        # alert-class doc — the agent already set kind=ALERT, but we
        # surface the tamper specifics under `agent.tamper.*` so the
        # SOC can pivot on hash drift without parsing the message body.
        t = ev.agent_tamper
        kind_map = {
            events_pb2.TAMPER_KIND_BINARY_MISMATCH: "binary_mismatch",
            events_pb2.TAMPER_KIND_CONFIG_MISMATCH: "config_mismatch",
            events_pb2.TAMPER_KIND_BPF_DETACHED: "bpf_detached",
            events_pb2.TAMPER_KIND_BPF_MAP_MISSING: "bpf_map_missing",
        }
        doc["agent"]["tamper"] = {
            "kind": kind_map.get(t.kind, "unspecified"),
            "target_path": t.target_path or None,
            "expected_hash": t.expected_hash or None,
            "actual_hash": t.actual_hash or None,
            "detail": t.detail or None,
        }
        if t.target_path:
            doc["file"] = {"path": t.target_path}
    elif payload == "auth":
        # Phase 2 #2.4: Windows ETW 4624/4625/4768/4769 and Linux
        # auditd USER_LOGIN / USER_AUTH (sshd fallback) all land here.
        # ECS shape: event.category=["authentication"], event.action
        # mirrors the AuthKind verb, event.outcome mirrors the
        # AuthResult, with the principal under `user.*` and the
        # network origin under `source.ip`. Kerberos-specific bits
        # land under `kerberos.*` so dashboards can pivot on TGT vs
        # TGS without parsing event.action.
        a = ev.auth
        kind = _AUTH_KIND_BY_NUM.get(a.auth_kind, "auth")
        result = _AUTH_RESULT_BY_NUM.get(a.result, "unknown")
        doc["event"]["category"] = ["authentication"]
        doc["event"]["action"] = kind
        doc["event"]["outcome"] = result
        if a.user or a.user_domain:
            user_doc: dict[str, Any] = {
                "name": a.user or None,
                "domain": a.user_domain or None,
            }
            if a.target_user:
                user_doc["target"] = {"name": a.target_user}
            doc["user"] = user_doc
        elif a.target_user:
            doc["user"] = {"target": {"name": a.target_user}}
        if a.source_ip:
            doc["source"] = {"ip": a.source_ip}
        if a.target_host:
            # Don't blow away the existing host.id mapping above.
            doc["host"]["name"] = a.target_host
        if a.logon_type or a.event_id_raw:
            winlog: dict[str, Any] = {}
            if a.logon_type:
                winlog["logon"] = {"type": int(a.logon_type)}
            if a.event_id_raw:
                winlog["event_id"] = int(a.event_id_raw)
            doc["winlog"] = winlog
        if a.ticket_kind:
            doc["kerberos"] = {"ticket": {"kind": a.ticket_kind}}
        if a.service_name:
            doc["service"] = {"name": a.service_name}
        if a.failure_reason:
            doc["event"]["reason"] = a.failure_reason
    elif payload == "quarantine_completed":
        # M20.c: agent's report after a quarantine / release action.
        # Land under `agent.quarantine.*` so the quarantine worker can
        # filter on `agent.quarantine.outcome` and update the
        # quarantined_files row.
        q = ev.quarantine_completed
        outcome_map = {
            events_pb2.QUARANTINE_OUTCOME_QUARANTINED: "quarantined",
            events_pb2.QUARANTINE_OUTCOME_RELEASED: "released",
            events_pb2.QUARANTINE_OUTCOME_FAILED: "failed",
        }
        doc["agent"]["quarantine"] = {
            "outcome": outcome_map.get(q.outcome, "unspecified"),
            "sha256": q.sha256 or None,
            "path": q.path or None,
            "size_bytes": int(q.size_bytes) if q.size_bytes else None,
            "deleted_original": bool(q.deleted_original),
        }
        if q.path:
            doc["file"] = {"path": q.path, "hash": {"sha256": q.sha256} if q.sha256 else None}

    # Strip None values so OpenSearch doesn't store them.
    return _prune_none(doc)


def _prune_none(d: Any) -> Any:
    if isinstance(d, dict):
        return {k: _prune_none(v) for k, v in d.items() if v not in (None, {}, [])}
    if isinstance(d, list):
        return [_prune_none(x) for x in d]
    return d
