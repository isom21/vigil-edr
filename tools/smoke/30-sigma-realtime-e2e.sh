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
AGENT_BIN="${AGENT_BIN:-$(git rev-parse --show-toplevel 2>/dev/null || echo .)/target/release/vigil-agent}"
STATE_DIR=$(mktemp -d /tmp/vigil-agent-state.XXXXXX)
LOG=/tmp/vigil-sigma-realtime.log

cleanup() {
  if [ -n "${AGENT_PID:-}" ]; then kill "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "${MIM_PID:-}" ]; then kill "$MIM_PID" 2>/dev/null || true; fi
  if [ -n "${TRIPPER_PID:-}" ]; then kill "$TRIPPER_PID" 2>/dev/null || true; fi
  rm -f /tmp/sliver.exe /tmp/sliver-block.exe /tmp/sigma-reexec.err
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
    'action': 'alert',
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
VIGIL_MANAGER_ENDPOINT='https://localhost:50051' \
VIGIL_MANAGER_REST=$BASE \
VIGIL_ENROLLMENT_TOKEN="$TOKEN" \
VIGIL_STATE_DIR="$STATE_DIR" \
VIGIL_HOSTNAME=sigma-realtime-host \
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

if [ -z "$ELAPSED_MS" ]; then
  echo "[10] FAIL — no alert within 15s"
  echo "--- agent log ---"; tail -30 "$LOG"
  exit 1
fi

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

# [10] auto-block follow-up — pin H7's full-path block fix. Create a
# second rule with action=block, fire a matching exec, then re-exec
# the same path and assert it returns Permission denied (EPERM from
# the BPF block list). Pre-fix, the manager queued a basename and
# the kernel's full-path lookup missed; the re-exec succeeded.
echo "[10] auto-block follow-up: create action=block rule"
BLOCK_YAML='title: Block sliver-block on full path
id: 33333333-4444-5555-6666-777777777777
status: experimental
description: Auto-blocks /tmp/sliver-block.exe by full path.
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        process.name|contains: sliver-block
    condition: selection
'
BLOCK_RULE=$(curl -fsS -X POST $BASE/api/rules -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d "$(python3 -c "
import json, sys
body = sys.stdin.read()
print(json.dumps({
    'kind': 'sigma',
    'name': 'sigma_sliver_block_realtime',
    'severity': 'critical',
    'action': 'block',
    'enabled': True,
    'body': body,
}))" <<<"$BLOCK_YAML")")
BLOCK_RULE_ID=$(printf '%s' "$BLOCK_RULE" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
echo "    rule_id=$BLOCK_RULE_ID"
sleep 1.0

echo "[11] spawn /tmp/sliver-block.exe to trip the block rule"
cp /usr/bin/sleep /tmp/sliver-block.exe
/tmp/sliver-block.exe 5 &
TRIPPER_PID=$!
# Wait for the auto-block command to dispatch + the agent to push it
# into the kernel block map. 10s upper bound is generous (sigma
# realtime is sub-second; block dispatch + IOCTL is a few hundred ms).
sleep 10
wait "$TRIPPER_PID" 2>/dev/null || true

echo "[12] re-exec /tmp/sliver-block.exe — expect Permission denied"
if /tmp/sliver-block.exe 0 2>/tmp/sigma-reexec.err; then
  echo "    FAIL: re-exec succeeded; preventive block missed."
  echo "    This is the basename-vs-full-path regression from H7."
  echo "--- agent log tail ---"; tail -30 "$LOG"
  rm -f /tmp/sliver-block.exe /tmp/sigma-reexec.err
  exit 1
elif grep -qi -E 'permission denied|operation not permitted' /tmp/sigma-reexec.err; then
  echo "    ok — re-exec blocked by EPERM"
else
  echo "    FAIL: re-exec failed but not with EPERM:"
  cat /tmp/sigma-reexec.err
  rm -f /tmp/sliver-block.exe /tmp/sigma-reexec.err
  exit 1
fi
rm -f /tmp/sliver-block.exe /tmp/sigma-reexec.err

echo "[13] PASS"
exit 0
