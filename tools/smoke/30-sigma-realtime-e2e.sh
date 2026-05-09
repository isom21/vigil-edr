#!/usr/bin/env bash
# End-to-end test for the realtime (percolator-based) Sigma engine.
#   1. Login + create a NEW Sigma rule (verifies the api/rules.py hook
#      registers it in the percolator index on save).
#   2. Issue enrollment token, start agent.
#   3. Spawn /tmp/sliver.exe (matches the new rule).
#   4. Poll alerts every 200ms; report wall-clock latency from spawn to
#      alert-visible-in-PG.
#
# Expectation: alert lands in single-digit seconds (vs ~30-60s for the
# scheduled engine). Latency is dominated by the agent's 1s /proc poll.
#
# Pre-requisites: full pipeline + sigma-realtime running:
#   make backend-dev backend-grpc backend-normalizer backend-indexer
#   make backend-detector backend-sigma   # backend-sigma is the realtime worker

set -euo pipefail

EMAIL="${EMAIL:-admin@example.local}"
PASSWORD="${PASSWORD:-change-me-please-12chars}"
BASE="${BASE:-http://127.0.0.1:8000}"
OS_URL="${OS_URL:-http://localhost:9200}"
AGENT_BIN="${AGENT_BIN:-$(git rev-parse --show-toplevel 2>/dev/null || echo .)/target/release/edr-agent}"
STATE_DIR=$(mktemp -d /tmp/edr-agent-state.XXXXXX)
LOG=/tmp/edr-sigma-realtime.log

cleanup() {
  if [ -n "${AGENT_PID:-}" ]; then kill "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "${MIM_PID:-}" ]; then kill "$MIM_PID" 2>/dev/null || true; fi
  rm -f /tmp/sliver.exe
}
trap cleanup EXIT

echo "[1] login"
TOKENS=$(curl -fsS -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
ACCESS=$(printf '%s' "$TOKENS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')

echo "[2] create sigma rule"
SIGMA_YAML='title: Suspicious sliver-like process
id: 22222222-3333-4444-5555-666666666666
status: experimental
description: Detects processes whose name contains the string sliver.
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        process.name|contains: sliver
    condition: selection
'
RULE=$(curl -fsS -X POST $BASE/api/rules -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d "$(python3 -c "
import json, sys
body = sys.stdin.read()
print(json.dumps({
    'kind': 'sigma',
    'name': 'sigma_sliver_realtime',
    'severity': 'critical',
    'action': 'detect',
    'enabled': True,
    'body': body,
}))" <<<"$SIGMA_YAML")")
RULE_ID=$(printf '%s' "$RULE" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
echo "    rule_id=$RULE_ID"

echo "[3] verify rule is in percolator index"
sleep 1.0
PERC=$(curl -fsS "$OS_URL/sigma-rules/_count?q=rule_id:$RULE_ID" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["count"])')
if [ "$PERC" != "1" ]; then
  echo "    FAIL: percolator does not have the rule (count=$PERC)"
  exit 1
fi
echo "    ok (count=1)"

echo "[4] mint enrollment token"
ENR=$(curl -fsS -X POST $BASE/api/enrollment/tokens -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"label":"sigma-realtime","ttl_hours":1}')
TOKEN=$(printf '%s' "$ENR" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')

echo "[5] start agent"
EDR_MANAGER_ENDPOINT='https://localhost:50051' \
EDR_MANAGER_REST=$BASE \
EDR_ENROLLMENT_TOKEN="$TOKEN" \
EDR_STATE_DIR="$STATE_DIR" \
EDR_HOSTNAME=sigma-realtime-host \
RUST_LOG=info \
"$AGENT_BIN" >"$LOG" 2>&1 &
AGENT_PID=$!

for i in $(seq 1 30); do
  if grep -q "rule_sync.received" "$LOG" 2>/dev/null; then break; fi
  sleep 1
done

BEFORE=$(curl -fsS -H "Authorization: Bearer $ACCESS" \
  "$BASE/api/alerts?rule_id=$RULE_ID&limit=1" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["total"])')
echo "[6] alerts (rule) before: $BEFORE"

echo "[7] spawn /tmp/sliver.exe"
cp /usr/bin/sleep /tmp/sliver.exe
SPAWN_TS=$(date +%s.%3N)
/tmp/sliver.exe 60 &
MIM_PID=$!

echo "[8] poll alerts every 200ms (max 15s)"
ELAPSED_MS=""
for i in $(seq 1 75); do
  AFTER=$(curl -fsS -H "Authorization: Bearer $ACCESS" \
    "$BASE/api/alerts?rule_id=$RULE_ID&limit=1" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["total"])')
  if [ "$AFTER" -gt "$BEFORE" ]; then
    NOW=$(date +%s.%3N)
    ELAPSED_MS=$(python3 -c "print(int(($NOW - $SPAWN_TS) * 1000))")
    break
  fi
  python3 -c "import time;time.sleep(0.2)"
done

if [ -n "$ELAPSED_MS" ]; then
  echo "[9] sigma realtime alert latency: ${ELAPSED_MS}ms"
  curl -fsS -H "Authorization: Bearer $ACCESS" "$BASE/api/alerts?rule_id=$RULE_ID&limit=1" \
    | python3 -c '
import json, sys
d = json.load(sys.stdin)
a = d["items"][0]
for k in ("id", "state", "severity", "summary"):
    print("  {:9} = {}".format(k, a[k]))
det = a.get("details") or {}
print("  engine    = {}".format(det.get("engine")))
print("  mode      = {}".format(det.get("mode")))
'
  echo "[10] PASS"
  exit 0
fi

echo "[10] FAIL — no alert within 15s"
echo "--- agent log ---"; tail -30 "$LOG"
exit 1
