# ADR 0004 — Sigma evaluation: scheduled OpenSearch correlation, not Flink streaming

- **Status:** Superseded by [ADR 0005](0005-sigma-realtime-percolator.md). The reasoning here for not using Flink remains valid; the *choice* of scheduled-correlation as the evaluation engine was replaced by an OpenSearch percolator the same week.
- **Date:** 2026-05-08

## Context

ADR 0001 committed to evaluating Sigma rules in Apache Flink — a Sigma rule would be compiled to streaming queries, the Flink job would consume `telemetry.normalized` from Kafka, and matches would land on `alerts.raw`. ADR 0001 also explicitly recorded the fallback if Flink slipped: a "Python streaming consumer."

Two things became evident during M3:

1. **pySigma has no Flink backend.** It targets log-search systems (OpenSearch, Elasticsearch, Splunk, Sentinel) and a few SIEM-specific languages. There is no first-class compilation path to Flink Table API or Flink SQL. Building one would mean writing a Sigma → Flink-SQL backend from scratch — non-trivial and tangential to the EDR product itself.
2. **A pure-Python streaming Sigma evaluator is also a real project.** Sigma's grammar (selections, modifiers, condition expressions, count-of, near-of, aggregations) doesn't have a maintained in-process matcher in the Python ecosystem. We'd be writing an evaluator alongside the EDR.

Meanwhile pySigma's **OpenSearch backend is mature**: it converts the same rule we already store into a Lucene query string in milliseconds. We're already indexing all telemetry into OpenSearch in M2.

## Decision

Sigma rules are evaluated by a periodic worker (`app/workers/sigma_scheduler.py`) that translates each enabled Sigma rule to an OpenSearch Lucene query and runs it in a sliding window over the live `telemetry-*` indices.

Concretely:

- Default cadence: **30s tick**, querying the window `(last_run, now - 30s]`. The 30s lag absorbs ingest latency between agent → Kafka → indexer → OpenSearch.
- Rule compilation is cached per `(rule_id, revision)`. A rule edit bumps revision in PG and the next scheduler tick recompiles.
- Each hit emits one Alert row in PG (engine=sigma, action_taken=detect, state=new) plus a parallel doc in `alerts-YYYYMMDD`. The hit's `event.id` is recorded in `alert.details` for cross-referencing with the source telemetry event.
- The scheduler advances `last_run` only on a successful OpenSearch query, so a transient failure causes the next tick to replay rather than skip.

Kafka's `telemetry.normalized` topic still exists and is still consumed by:
- `indexer` (writes to OpenSearch)
- `detector` (IOC matching — emits alerts directly without going through OpenSearch)

So the streaming pipeline remains intact for the cheap match types (IOC). Sigma is the one engine that uses OpenSearch as its evaluation store rather than Kafka as its evaluation stream.

## Rationale

- **Time-to-working-Sigma**: pySigma's OpenSearch backend works today. Total integration effort: one wrapper module + one scheduler worker + a 30s tick. Streaming would have been weeks.
- **Reuse of existing infrastructure**: the OpenSearch index exists for hunting/search and the UI's telemetry views; querying it for Sigma costs little.
- **Adequate latency for a PoC**: detection latency is bounded at `INTERVAL + LAG ≈ 60s`. This is fine for the first product, and can be tightened if customers demand it (drop `INTERVAL` to 5s; accept higher OpenSearch query load).
- **Correctness over throughput**: scheduled correlation doesn't drop events under back-pressure — it just slides the window forward. The streaming alternative would have required careful handling of Kafka offsets per Sigma rule.
- **Composable later**: if/when we need real-time Sigma, we can add a parallel Flink (or Python) streaming engine for a *subset* of rules (those with `condition: selection`, no aggregations). The scheduled engine remains the path for aggregations and count-of/near-of rules anyway, since OpenSearch handles those natively.

## Trade-offs

- **Detection latency** of up to ~60s by default. For a kill/block agent action chain this would be too slow; M5 will keep IOC matching (which already runs in the streaming detector) for fast actions, and reserve Sigma for detect-mode alerts.
- **OpenSearch query load**: N rules × every 30s. With current rule counts (≤100) this is trivial. We should add a circuit breaker when rule count grows past, say, 1000.
- **Sigma rule limitations**: pySigma's OpenSearch backend supports the standard rule grammar but some advanced features (aggregations across long time windows) need OpenSearch's transforms or rollup jobs to be efficient. Out of scope for the PoC.
- **Field-mapping**: rules must currently use ECS field names (e.g. `process.command_line`). Real Sigma rule libraries use Sysmon or Windows-EVT fields. M4/M5 should add a sysmon→ECS pipeline to pysigma so we can ingest community rule sets unchanged.

## Alternatives considered

- **Stream via Flink with a custom backend** — rejected. Backend authoring + Flink ops cost is multiples of the chosen path, and the rule grammar overlap with OpenSearch's Lucene is high anyway.
- **Stream via Python consumer with an in-process evaluator** — rejected. Writing a faithful Sigma evaluator is its own project; Sigma's full grammar is not trivial, and partial implementations bite later when community rules use unsupported features.
- **Schedule via Flink** — rejected. We already need OpenSearch as the search index for the UI; Flink would be a second copy of compute infrastructure for no win.
- **Push Sigma evaluation down to the agent** — rejected for now. Constraint: cross-host correlation (e.g. "5 failed logons within 1 minute on N hosts") needs a server-side view. We may add a hybrid in M7 where simple per-event Sigma rules run on the agent for low-latency response actions.

## Consequences

- ADR 0001's "Sigma engine" decision is superseded by this ADR (later
  superseded again by [ADR 0005](0005-sigma-realtime-percolator.md));
  ADR 0001's stack table cell already reflects the final percolator
  shape.
- Kafka topic `alerts.raw` (planned in M0 for streaming Sigma output) is currently unused. Keep the topic provisioned; if a future engine needs it, the wiring is ready.
- ADR 0001's listed top risk #2 ("Flink + pySigma integration") is closed by removing Flink from the Sigma path. Flink's container in `docker-compose.yml` remains for now — useful for ad-hoc analytics jobs the team may want — but is no longer load-bearing for any milestone.
