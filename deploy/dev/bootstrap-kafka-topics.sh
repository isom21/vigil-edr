#!/usr/bin/env bash
# Create the Kafka topics used by the EDR backend.
# Run once after `docker compose up -d`.
set -euo pipefail

BROKER="${BROKER:-localhost:19092}"

create_topic() {
  local name="$1"
  local partitions="${2:-4}"
  local retention_ms="${3:-604800000}"  # 7d default
  echo "creating topic ${name} (partitions=${partitions}, retention=${retention_ms}ms)"
  docker exec edr-redpanda rpk topic create "$name" \
    --partitions "$partitions" \
    --replicas 1 \
    --topic-config "retention.ms=${retention_ms}" || true
}

create_topic telemetry.raw         8 86400000     # 1d raw events
create_topic telemetry.normalized  8 604800000    # 7d ECS-normalized
create_topic alerts.raw            4 2592000000   # 30d alerts
create_topic agent.commands        4 86400000     # 1d (compacted alternative TBD)
create_topic agent.heartbeats      2 86400000

echo "done."
