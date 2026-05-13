"""OpenSearch client wrapper + index helpers.

Indices are date-rolled:
  telemetry-YYYYMMDD  - one ECS document per ingested EndpointEvent
  alerts-YYYYMMDD     - one document per generated alert (mirrors the alerts table)

Plus a single non-date index used by the realtime Sigma engine:
  sigma-rules         - one doc per registered Sigma rule, with the rule's
                        compiled Lucene query stored in a `query` field of
                        type percolator. Telemetry events are percolated
                        against this index for sub-second Sigma matching.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from opensearchpy._async.client import AsyncOpenSearch

from app.core.config import settings


def _client() -> AsyncOpenSearch:
    return AsyncOpenSearch(
        hosts=[settings.opensearch_url],
        verify_certs=False,
        ssl_show_warn=False,
    )


SIGMA_RULES_INDEX = "sigma-rules"
_TEMPLATE_NAME = "edr-telemetry"

# Phase 3 #3.2: OpenSearch ILM policy. Newly-rolled telemetry-* and
# alerts-* indices inherit this via the `vigil_telemetry` index
# template (linked through `index.plugins.index_state_management.policy_id`).
# The four tiers are env-tunable via VIGIL_ILM_*_DAYS (see config.py);
# the policy itself is idempotent — re-PUTting it under the same name
# is a no-op for indices already attached.
_ILM_POLICY_NAME = "vigil_telemetry_ilm"
_ILM_TEMPLATE_NAME = "vigil_telemetry"


# Field shapes that telemetry-* and sigma-rules share. Sigma rules' Lucene
# queries reference these fields; mappings must match for percolator to find
# matches against incoming ECS docs.
_SHARED_PROPERTIES: dict[str, Any] = {
    "@timestamp": {"type": "date"},
    "event": {
        "properties": {
            "id": {"type": "keyword"},
            "kind": {"type": "keyword"},
            "category": {"type": "keyword"},
            "action": {"type": "keyword"},
            "outcome": {"type": "keyword"},
            "created": {"type": "date"},
        }
    },
    "host": {
        "properties": {
            "id": {"type": "keyword"},
            "name": {"type": "keyword"},
        }
    },
    "agent": {
        "properties": {
            "id": {"type": "keyword"},
            "version": {"type": "keyword"},
        }
    },
    "process": {
        "properties": {
            "pid": {"type": "long"},
            "name": {"type": "keyword"},
            "executable": {"type": "keyword"},
            "command_line": {
                "type": "text",
                "fields": {"raw": {"type": "keyword", "ignore_above": 4096}},
            },
            "hash": {
                "properties": {
                    "sha256": {"type": "keyword"},
                    "sha1": {"type": "keyword"},
                    "md5": {"type": "keyword"},
                }
            },
            "parent": {
                "properties": {
                    "pid": {"type": "long"},
                    "executable": {"type": "keyword"},
                }
            },
        }
    },
    "file": {
        "properties": {
            "path": {"type": "keyword"},
            "name": {"type": "keyword"},
            "size": {"type": "long"},
            "hash": {
                "properties": {
                    "sha256": {"type": "keyword"},
                    "sha1": {"type": "keyword"},
                    "md5": {"type": "keyword"},
                }
            },
        }
    },
    "labels": {"type": "object", "dynamic": True},
    "rule": {
        "properties": {
            "id": {"type": "keyword"},
            "name": {"type": "keyword"},
        }
    },
    # Phase 2 #2.9: container telemetry on process_started docs.
    # Sigma rules pivot on `container.runtime` (e.g. detect drift from
    # "containerd" to "docker" on a k8s node) and on `container.image.name`
    # (alert when sensitive workloads launch unexpected images), so we
    # pin these as keyword rather than relying on dynamic mapping.
    "container": {
        "properties": {
            "id": {"type": "keyword"},
            "runtime": {"type": "keyword"},
            "image": {
                "properties": {
                    "name": {"type": "keyword"},
                }
            },
        }
    },
}


_TEMPLATE_BODY: dict[str, Any] = {
    "index_patterns": ["telemetry-*", "alerts-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "5s",
        },
        "mappings": {
            "dynamic_templates": [
                {
                    "strings_as_keyword": {
                        "match_mapping_type": "string",
                        "mapping": {"type": "keyword", "ignore_above": 1024},
                    }
                }
            ],
            "properties": _SHARED_PROPERTIES,
        },
    },
}


# sigma-rules is created explicitly (not from the shared template) because:
# - it needs the percolator-typed `query` field
# - dynamic=strict prevents accidental field drift between rule registrations
# - tighter refresh_interval so a freshly-saved rule starts matching within ~1s
_SIGMA_INDEX_BODY: dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "1s",
    },
    "mappings": {
        "dynamic": "strict",
        "properties": {
            **_SHARED_PROPERTIES,
            "query": {"type": "percolator"},
            "rule_id": {"type": "keyword"},
            "rule_name": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "enabled": {"type": "boolean"},
            "registered_at": {"type": "date"},
        },
    },
}


async def ensure_template(client: AsyncOpenSearch) -> None:
    if not await client.indices.exists_index_template(name=_TEMPLATE_NAME):
        await client.indices.put_index_template(name=_TEMPLATE_NAME, body=_TEMPLATE_BODY)
    # Phase 3 #3.2: install/refresh the ILM policy + linking index
    # template. Best-effort — older OpenSearch builds without the ISM
    # plugin will reject the policy PUT; we swallow that so a missing
    # plugin doesn't block ingest.
    try:
        await ensure_ilm_policy(client)
    except Exception:  # pragma: no cover — degrades on plugin-less OS
        pass


def _ilm_policy_body() -> dict[str, Any]:
    """Build the ISM policy body from the configured tier days.

    Days are interpreted as `min_index_age` per state transition; the
    last state (`delete`) actually drops the index. The ISM plugin
    expects total ages (not deltas), so each transition is the
    cumulative wall-clock age, not the time since the previous state.
    """
    hot_d = settings.ilm_hot_days
    warm_d = settings.ilm_warm_days
    # `cold_days` is consumed by the archive worker (freeze threshold);
    # the ISM policy only needs warm + delete boundaries.
    del_d = settings.ilm_delete_days
    return {
        "policy": {
            "description": (
                "Vigil telemetry/alerts retention: hot -> warm -> cold -> delete. "
                "Tier ages are days since rollover."
            ),
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [],
                    "transitions": [
                        {"state_name": "warm", "conditions": {"min_index_age": f"{hot_d}d"}}
                    ],
                },
                {
                    "name": "warm",
                    "actions": [{"replica_count": {"number_of_replicas": 0}}],
                    "transitions": [
                        {"state_name": "cold", "conditions": {"min_index_age": f"{warm_d}d"}}
                    ],
                },
                # `cold_d` (VIGIL_ILM_COLD_DAYS) isn't a transition
                # trigger inside the ISM policy — it's the threshold
                # the standalone archive worker uses when picking
                # freeze candidates. ISM only owns hot→warm→cold and
                # the eventual delete; the read-only flip on cold gives
                # OpenSearch heap back well before the worker ships the
                # blob out.
                {
                    "name": "cold",
                    "actions": [{"read_only": {}}],
                    "transitions": [
                        {"state_name": "delete", "conditions": {"min_index_age": f"{del_d}d"}}
                    ],
                },
                {
                    "name": "delete",
                    "actions": [{"delete": {}}],
                    "transitions": [],
                },
            ],
            "ism_template": [{"index_patterns": ["telemetry-*", "alerts-*"]}],
        }
    }


async def ensure_ilm_policy(client: AsyncOpenSearch) -> None:
    """Install/refresh the Vigil telemetry ILM policy and link it via
    the `vigil_telemetry` index template.

    Idempotent: re-running re-PUTs the policy + template under the same
    name. Newly-rolled `telemetry-*` / `alerts-*` indices pick the
    policy up automatically through the template's
    `index.plugins.index_state_management.policy_id` setting.
    """
    # PUT _plugins/_ism/policies/<name> creates or replaces. The plugin
    # ignores re-PUTs that match the existing policy.
    body = _ilm_policy_body()
    await client.transport.perform_request(
        "PUT",
        f"/_plugins/_ism/policies/{_ILM_POLICY_NAME}",
        body=body,
    )
    # The linking index template uses `_index_template` so it composes
    # with the existing `edr-telemetry` template — settings from both
    # are merged, with this one supplying the ISM policy id.
    link_body = {
        "index_patterns": ["telemetry-*", "alerts-*"],
        "template": {
            "settings": {
                "plugins.index_state_management.policy_id": _ILM_POLICY_NAME,
            },
        },
        # Lower priority than the field-mapping template so a conflict
        # falls through to the mapping side.
        "priority": 1,
    }
    await client.indices.put_index_template(name=_ILM_TEMPLATE_NAME, body=link_body)


async def ensure_sigma_index(client: AsyncOpenSearch) -> None:
    if not await client.indices.exists(index=SIGMA_RULES_INDEX):
        await client.indices.create(index=SIGMA_RULES_INDEX, body=_SIGMA_INDEX_BODY)


def telemetry_index_for(ts: datetime) -> str:
    return f"telemetry-{ts.astimezone(UTC):%Y%m%d}"


def alerts_index_for(ts: datetime) -> str:
    return f"alerts-{ts.astimezone(UTC):%Y%m%d}"


# ----- Sigma percolator helpers -----


async def register_sigma_rule(
    client: AsyncOpenSearch,
    *,
    rule_id: UUID,
    rule_name: str,
    severity: str,
    lucene_query: str,
) -> None:
    """Index/refresh the percolator doc for a Sigma rule.

    Doc id = rule's PG UUID, so re-registering after an edit overwrites in
    place. We wrap the rule's Lucene string in a query_string query — same
    shape pySigma's OpenSearch backend produces.
    """
    body = {
        "query": {"query_string": {"query": lucene_query}},
        "rule_id": str(rule_id),
        "rule_name": rule_name,
        "severity": severity,
        "enabled": True,
        "registered_at": datetime.now(UTC).isoformat(),
    }
    # `refresh`/`request_timeout` are opensearch-py runtime kwargs that
    # forward into the URL params; the type stubs in opensearch-py 2.x
    # don't list them. The kwarg is real at runtime, so we suppress
    # the per-kwarg call-issue with the inline pyright pragma.
    await client.index(
        index=SIGMA_RULES_INDEX,
        id=str(rule_id),
        body=body,
        refresh="wait_for",  # pyright: ignore[reportCallIssue]
    )


async def unregister_sigma_rule(client: AsyncOpenSearch, rule_id: UUID) -> None:
    """Remove a rule's percolator doc. Idempotent — 404 is swallowed."""
    try:
        await client.delete(
            index=SIGMA_RULES_INDEX,
            id=str(rule_id),
            refresh="wait_for",  # pyright: ignore[reportCallIssue]
        )
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        if status not in (404, "404"):
            raise


# ----- M20.d alert investigation context -----


async def fetch_events_by_ids(
    client: AsyncOpenSearch, event_ids: list[str]
) -> list[dict[str, Any]]:
    """Look up a small set of telemetry docs by their `event.id` (ULID).
    Used to resolve the triggers an alert recorded into telemetry_doc_ids.
    """
    if not event_ids:
        return []
    resp = await client.search(
        index="telemetry-*",
        body={
            "size": len(event_ids),
            "query": {"terms": {"event.id": event_ids}},
            "sort": [{"@timestamp": {"order": "asc"}}],
        },
        request_timeout=10,  # pyright: ignore[reportCallIssue]
    )
    return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]


async def fetch_process_started(
    client: AsyncOpenSearch,
    *,
    host_id: str,
    pid: int,
    before: datetime,
    lookback_hours: int = 24,
) -> dict[str, Any] | None:
    """Find the most recent process_started event for (host, pid) at or
    before `before`. Returns the doc's _source or None when not in
    OpenSearch (process predates the lookback window or never recorded).
    """
    lower = before - timedelta(hours=lookback_hours)
    resp = await client.search(
        index="telemetry-*",
        body={
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"host.id": host_id}},
                        {"term": {"process.pid": pid}},
                        {"term": {"event.action": "process_started"}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": lower.isoformat(),
                                    "lte": before.isoformat(),
                                }
                            }
                        },
                    ]
                }
            },
        },
        request_timeout=10,  # pyright: ignore[reportCallIssue]
    )
    hits = resp.get("hits", {}).get("hits", [])
    return hits[0]["_source"] if hits else None


async def fetch_host_window(
    client: AsyncOpenSearch,
    *,
    host_id: str,
    start: datetime,
    end: datetime,
    size: int = 500,
) -> list[dict[str, Any]]:
    """Return all telemetry docs for a host in [start, end], ordered by
    @timestamp asc. Capped at `size` documents to keep the payload
    bounded; the UI shows a hint when truncation occurs.
    """
    resp = await client.search(
        index="telemetry-*",
        body={
            "size": size,
            "track_total_hits": True,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"host.id": host_id}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start.isoformat(),
                                    "lte": end.isoformat(),
                                }
                            }
                        },
                    ]
                }
            },
        },
        request_timeout=15,  # pyright: ignore[reportCallIssue]
    )
    return resp.get("hits", {}).get("hits", [])


async def fetch_host_since(
    client: AsyncOpenSearch,
    *,
    host_id: str,
    since: datetime | None,
    fallback_window: timedelta = timedelta(minutes=5),
    size: int = 200,
) -> list[dict[str, Any]]:
    """Polling helper for the live host telemetry tab.

    Returns docs with @timestamp > since, ordered asc. When `since` is
    None (first poll), returns up to `fallback_window` of recent
    history so the tab has something to render immediately rather than
    waiting for the next event.
    """
    if since is None:
        lower = datetime.now(UTC) - fallback_window
        lower_op = "gte"
    else:
        lower = since
        lower_op = "gt"
    resp = await client.search(
        index="telemetry-*",
        body={
            "size": size,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"host.id": host_id}},
                        {"range": {"@timestamp": {lower_op: lower.isoformat()}}},
                    ]
                }
            },
        },
        request_timeout=10,  # pyright: ignore[reportCallIssue]
    )
    return resp.get("hits", {}).get("hits", [])


async def fetch_process_children(
    client: AsyncOpenSearch,
    *,
    host_id: str,
    parent_pid: int,
    before: datetime,
    after: datetime | None = None,
    exclude_pids: set[int] | None = None,
    lookback_hours: int = 24,
    size: int = 12,
) -> list[dict[str, Any]]:
    """Find process_started events for processes spawned by `parent_pid`.

    Used by M22.c (chain siblings — children of an *ancestor*, capped at
    `before`) and by the chain builder's leaf-children pass which wants
    events both before AND after the alert. When `after` is provided the
    upper bound is `after` rather than `before`; the lower bound stays
    `before - lookback_hours` so older spawns still surface.
    """
    lower = before - timedelta(hours=lookback_hours)
    upper = after if after is not None else before
    resp = await client.search(
        index="telemetry-*",
        body={
            "size": size,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"host.id": host_id}},
                        {"term": {"process.parent.pid": parent_pid}},
                        {"term": {"event.action": "process_started"}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": lower.isoformat(),
                                    "lte": upper.isoformat(),
                                }
                            }
                        },
                    ]
                }
            },
        },
        request_timeout=10,  # pyright: ignore[reportCallIssue]
    )
    hits = resp.get("hits", {}).get("hits", [])
    out = []
    for h in hits:
        pid = (h.get("_source") or {}).get("process", {}).get("pid")
        if exclude_pids and pid in exclude_pids:
            continue
        out.append(h["_source"])
    return out


async def fetch_pid_window(
    client: AsyncOpenSearch,
    *,
    host_id: str,
    pid: int,
    start: datetime,
    end: datetime,
    size: int = 1000,
) -> list[dict[str, Any]]:
    """Return telemetry docs attributed to a specific (host, pid) in the
    window. Used by the selected-process detail panel to show what the
    process did during the alert — image_loads, file ops, network etc.
    """
    resp = await client.search(
        index="telemetry-*",
        body={
            "size": size,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"host.id": host_id}},
                        {"term": {"process.pid": pid}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start.isoformat(),
                                    "lte": end.isoformat(),
                                }
                            }
                        },
                    ]
                }
            },
        },
        request_timeout=15,  # pyright: ignore[reportCallIssue]
    )
    return resp.get("hits", {}).get("hits", [])


async def percolate(client: AsyncOpenSearch, ecs_doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Run an ECS event against every registered Sigma rule. Returns the
    matching docs' _source (rule_id, rule_name, severity).
    """
    body = {
        "size": 100,
        "_source": ["rule_id", "rule_name", "severity"],
        "query": {
            "percolate": {
                "field": "query",
                "document": ecs_doc,
            }
        },
    }
    resp = await client.search(
        index=SIGMA_RULES_INDEX,
        body=body,
        request_timeout=10,  # pyright: ignore[reportCallIssue]
    )
    return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]
