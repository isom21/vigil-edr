"""Prometheus metrics for the manager (M14.a).

Exposes Counter / Histogram / Gauge singletons that the request
middleware + the gRPC service + the Kafka producer wrapper update.
The `/metrics` route in `app.api.metrics` serves the registry in
prometheus text format.

We use the global `prometheus_client.REGISTRY` so any metric
registered anywhere in the app appears at `/metrics` automatically.
That means a contributor adding a new counter doesn't need to touch
this file beyond importing.
"""

from __future__ import annotations

from typing import Final

from prometheus_client import Counter, Gauge, Histogram

# HTTP request metrics, populated by RequestMetricsMiddleware.
requests_total: Final[Counter] = Counter(
    "edr_manager_requests_total",
    "Total HTTP requests handled by the manager.",
    labelnames=("method", "route", "status"),
)
request_latency_seconds: Final[Histogram] = Histogram(
    "edr_manager_request_latency_seconds",
    "Latency of HTTP requests handled by the manager (seconds).",
    labelnames=("method", "route"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# gRPC stream metrics, populated by AgentService.HostStream.
grpc_active_streams: Final[Gauge] = Gauge(
    "edr_manager_grpc_active_streams",
    "Number of currently-open agent HostStream sessions.",
)

# Pipeline counters.
kafka_produce_total: Final[Counter] = Counter(
    "edr_manager_kafka_produce_total",
    "Kafka records produced by the manager (telemetry.raw + alerts.raw).",
    labelnames=("topic",),
)
opensearch_index_total: Final[Counter] = Counter(
    "edr_manager_opensearch_index_total",
    "Documents indexed into OpenSearch by the indexer worker.",
    labelnames=("index_pattern",),
)

# Alert + command lifecycle.
alerts_opened_total: Final[Counter] = Counter(
    "edr_manager_alerts_opened_total",
    "Alerts opened by the detector + sigma_realtime workers.",
    labelnames=("severity", "rule_kind"),
)
commands_queued_total: Final[Counter] = Counter(
    "edr_manager_commands_queued_total",
    "Commands queued via /api/hosts/{id}/commands or auto-action.",
    labelnames=("kind",),
)

# Audit-chain integrity (M-audit-and-auth #6). The background
# verifier worker updates these on every pass; the values flatline at
# 0 / 1 if a break is ever detected, which is what alerting should
# care about. Last-success timestamp is the trip-wire for "the
# verifier itself has stopped running" (gauge stale -> alarm).
audit_chain_breaks: Final[Gauge] = Gauge(
    "edr_manager_audit_chain_breaks",
    "Number of HMAC-chain breaks observed in the most recent audit-log scan.",
)
audit_chain_rows_examined: Final[Gauge] = Gauge(
    "edr_manager_audit_chain_rows_examined",
    "Rows scanned in the most recent audit-log integrity pass.",
)
audit_chain_last_run_timestamp: Final[Gauge] = Gauge(
    "edr_manager_audit_chain_last_run_timestamp",
    "Unix timestamp of the most recent audit-log integrity pass.",
)

# LOW #6: heartbeat-gap surface. The Linux agent's self-protection
# takeover takes <1 s during restart; that's too short for the
# silence worker (10-min threshold). Operators who want to detect
# unexpected gaps in the seconds-range alert on a percentile of this
# histogram (e.g. p99 > 5 s = suspicious). Unlabelled to avoid the
# host-id cardinality explosion on a multi-thousand-host fleet —
# operators who need per-host can pivot on `last_seen_at` directly.
agent_heartbeat_lag_seconds: Final[Histogram] = Histogram(
    "edr_manager_agent_heartbeat_lag_seconds",
    "Seconds between consecutive agent heartbeats (across all hosts).",
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600),
)

# Sigma realtime worker: number of telemetry messages whose alert-doc
# index failed and were left uncommitted in Kafka for retry. A non-
# zero rate here means OpenSearch is unhealthy or the alerts index
# template is wrong — Kafka lag will pile up until it's fixed.
sigma_realtime_index_failures_total: Final[Counter] = Counter(
    "edr_manager_sigma_realtime_index_failures_total",
    "Sigma realtime alert-doc OpenSearch indexing failures (Kafka offset NOT committed).",
)

# CODE-27: the indexer worker's async_bulk → OpenSearch flush failed
# silently pre-PR (log + drop + commit). Now the offset stays put on
# failure and the flushed batch is retained for retry. A non-zero
# rate here means OpenSearch is unhealthy; Kafka lag on
# `telemetry.normalized` is the SLO indicator paired with this
# counter.
indexer_flush_failures_total: Final[Counter] = Counter(
    "edr_manager_indexer_flush_failures_total",
    "telemetry.normalized → OpenSearch bulk-flush failures (Kafka offset NOT committed).",
)

# CODE-28: per-message playbook-executor handler failures. A non-zero
# rate means the DB is unhealthy (or a playbook YAML is shaped in a
# way that crashes the executor); the offending alert stays on the
# Kafka topic for retry. Pair with `alerts.opened` consumer lag.
playbook_executor_handle_failures_total: Final[Counter] = Counter(
    "edr_manager_playbook_executor_handle_failures_total",
    "Playbook-executor handle_message failures (Kafka offset NOT committed).",
)

# CODE-29: per-event webhook-dispatcher failures. Pre-PR the consumer
# ran with enable_auto_commit=True so failed deliveries lost the
# event. Now the dispatcher commits manually only on success; a
# spike here means a subscriber's URL / HMAC secret is broken.
webhook_dispatcher_handle_failures_total: Final[Counter] = Counter(
    "edr_manager_webhook_dispatcher_handle_failures_total",
    "Webhook-dispatcher dispatch_event failures (Kafka offset NOT committed).",
)

# Phase 1 #1.5 — SIEM forwarders. Per-destination lag gauge + error
# counter so operators can wire `edr_manager_siem_forwarder_lag_seconds`
# alerts up to whichever Sentinel/Splunk/etc. their on-call cares
# about. The label is the destination's UUID — cardinality is bounded
# by the operator (single-digit destinations in practice), so the
# label doesn't cause Prometheus storage to blow up. The worker emits
# lag = (now - event.@timestamp) on each successful send.
siem_forwarder_lag_seconds: Final[Gauge] = Gauge(
    "edr_manager_siem_forwarder_lag_seconds",
    "Seconds between an event's @timestamp and successful delivery to a SIEM destination.",
    labelnames=("destination",),
)
siem_forwarder_send_errors_total: Final[Counter] = Counter(
    "edr_manager_siem_forwarder_send_errors_total",
    "Errors raised by SIEM destination senders (offset replay path).",
    labelnames=("destination",),
)
siem_forwarder_sends_total: Final[Counter] = Counter(
    "edr_manager_siem_forwarder_sends_total",
    "Successful SIEM destination sends.",
    labelnames=("destination",),
)


# Top-20 #17: dispatch watchdog. Commands flip to DISPATCHED when the
# gRPC dispatcher hands them to the bidi stream; a healthy agent then
# reports back with SUCCEEDED / FAILED. Commands stuck in DISPATCHED
# beyond `VIGIL_DISPATCH_WATCHDOG_TIMEOUT_S` (default 600 s) are
# marked FAILED with `error="dispatch watchdog: no result before
# {ts}"` so the alert console reflects reality instead of pretending
# the action is still in flight. The counter is monotonic across the
# process lifetime; an absolute rate > 0 is the trip-wire.
dispatch_watchdog_expired_total: Final[Counter] = Counter(
    "edr_manager_dispatch_watchdog_expired_total",
    "Commands moved from DISPATCHED -> FAILED by the dispatch watchdog "
    "(agent never reported a result).",
)
dispatch_watchdog_last_run_timestamp: Final[Gauge] = Gauge(
    "edr_manager_dispatch_watchdog_last_run_timestamp",
    "Unix timestamp of the most recent dispatch-watchdog pass "
    "(stale -> the watchdog itself is dead).",
)
