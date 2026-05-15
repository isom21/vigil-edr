#!/usr/bin/env bash
# End-to-end test for the LEGACY scheduled Sigma engine (~30-60s latency).
# Useful when validating aggregation rules or comparing engines.
#
# Pre-requisites: backend + grpc + normalizer + indexer + sigma-scheduled:
#   make backend-dev backend-grpc backend-normalizer backend-indexer backend-detector
#   make backend-sigma-scheduled   # NOT backend-sigma (that's the realtime one)

set -euo pipefail

EMAIL="${EMAIL:-admin@example.local}"
PASSWORD="${PASSWORD:-change-me-please-12chars}"
BASE="${BASE:-http://127.0.0.1:8000}"
AGENT_BIN="${AGENT_BIN:-$(git rev-parse --show-toplevel 2>/dev/null || echo .)/target/release/vigil-agent}"
STATE_DIR=$(mktemp -d /tmp/vigil-agent-state.XXXXXX)
LOG=/tmp/vigil-sigma-scheduled.log

cleanup() {
  if [ -n "${AGENT_PID:-}" ]; then kill "$AGENT_PID" 2>/dev/null || true; fi
  if [ -n "${MIM_PID:-}" ]; then kill "$MIM_PID" 2>/dev/null || true; fi
  rm -f /tmp/mimikatz.exe
}
trap cleanup EXIT

echo "[1] login"
TOKENS=$(curl -fsS -X POST $BASE/api/auth/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
ACCESS=$(printf '%s' "$TOKENS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')

echo "[2] create sigma rule"
SIGMA_YAML='title: Suspicious mimikatz-like process
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Detects processes whose name contains the string mimikatz.
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        process.name|contains: mimikatz
    condition: selection
'
RULE=$(curl -fsS -X POST $BASE/api/rules -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' \
  -d "$(python3 -c "
import json, sys
body = sys.stdin.read()
print(json.dumps({
    'kind': 'sigma',
    'name': 'sigma_mimikatz_e2e',
    'severity': 'high',
    'action': 'alert',
    'enabled': True,
    'body': body,
}))" <<<"$SIGMA_YAML")")
RULE_ID=$(printf '%s' "$RULE" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')

echo "[3] mint enrollment token + start agent"
ENR=$(curl -fsS -X POST $BASE/api/enrollment/tokens -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"label":"sigma-e2e","ttl_hours":1}')
TOKEN=$(printf '%s' "$ENR" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
VIGIL_MANAGER_ENDPOINT='https://localhost:50051' \
VIGIL_MANAGER_REST=$BASE \
VIGIL_ENROLLMENT_TOKEN="$TOKEN" \
VIGIL_STATE_DIR="$STATE_DIR" \
VIGIL_HOSTNAME=sigma-scheduled-host \
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

echo "[4] spawn /tmp/mimikatz.exe (sleep 90s so the /proc poller catches it)"
cp /usr/bin/sleep /tmp/mimikatz.exe
/tmp/mimikatz.exe 90 &
MIM_PID=$!

echo "[5] wait for sigma scheduler tick (up to 75s)"
for i in $(seq 1 75); do
  AFTER=$(curl -fsS -H "Authorization: Bearer $ACCESS" \
    "$BASE/api/alerts?rule_id=$RULE_ID&limit=1" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["total"])')
  if [ "$AFTER" -gt "$BEFORE" ]; then
    echo "    alert at t+${i}s"
    break
  fi
  sleep 1
done

if [ "${AFTER:-0}" -gt "${BEFORE:-0}" ]; then
  echo "PASS"
else
  echo "FAIL"; tail -30 "$LOG"
  exit 1
fi
