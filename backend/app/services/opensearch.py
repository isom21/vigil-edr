"""OpenSearch client wrapper + index helpers.

Indices are date-rolled:
  telemetry-YYYYMMDD  - one ECS document per ingested EndpointEvent
  alerts-YYYYMMDD     - one document per generated alert (mirrors the alerts table)

Both share an index template installed on first use.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from opensearchpy._async.client import AsyncOpenSearch

from app.core.config import settings


def _client() -> AsyncOpenSearch:
    return AsyncOpenSearch(
        hosts=[settings.opensearch_url],
        verify_certs=False,
        ssl_show_warn=False,
    )


_TEMPLATE_NAME = "edr-telemetry"
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
            "properties": {
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
                        "command_line": {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 4096}}},
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
            },
        },
    },
}


async def ensure_template(client: AsyncOpenSearch) -> None:
    if not await client.indices.exists_index_template(name=_TEMPLATE_NAME):
        await client.indices.put_index_template(name=_TEMPLATE_NAME, body=_TEMPLATE_BODY)


def telemetry_index_for(ts: datetime) -> str:
    return f"telemetry-{ts.astimezone(timezone.utc):%Y%m%d}"


def alerts_index_for(ts: datetime) -> str:
    return f"alerts-{ts.astimezone(timezone.utc):%Y%m%d}"
