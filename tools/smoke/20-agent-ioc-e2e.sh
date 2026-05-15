#!/usr/bin/env bash
# End-to-end IOC test:
#   1. Issue enrollment token via REST.
#   2. Start the Linux agent with that token.
#   3. Wait for it to enroll + receive RuleSync.
#   4. Spawn /tmp/mimikatz.exe (basename matches the smoke_iocs IOC rule
#      created by 00-backend-smoke.sh).
#   5. Verify a new alert lands in Postgres.
#
# Pre-requisites: full pipeline running:
#   make backend-dev backend-grpc backend-normalizer backend-indexer backend-detector
# And the agent built:
#   cargo build -p agent-linux --release
# And smoke_iocs rule created (run 00-backend-smoke.sh first or create manually).

set -euo pipefail

EMAIL="${EMAIL:-admin@example.local}"
PASSWORD="${PASSWORD:-change-me-please-12chars}"
BASE="${BASE:-http://127.0.0.1:8000}"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
AGENT_BIN="${AGENT_BIN:-$REPO_ROOT/target/release/vigil-agent}"
STATE_DIR=$(mktemp -d /tmp/vigil-agent-state.XXXXXX)
LOG=/tmp/vigil-agent-e2e.log

# LIVE-8: a fresh checkout has no compiled agent binary. Build it on
# demand; cargo caches across runs so this is a no-op after the first
# build. Set AGENT_BIN explicitly to bypass.
if [ ! -x "$AGENT_BIN" ]; then
  echo "[0] building agent binary (target/release/vigil-agent)"
  ( cd "$REPO_ROOT" && cargo build -p agent-linux --release )
fi

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

echo "[2] mint enrollment token"
ENR=$(curl -fsS -X POST $BASE/api/enrollment/tokens -H "Authorization: Bearer $ACCESS" \
  -H 'Content-Type: application/json' -d '{"label":"e2e","ttl_hours":1}')
TOKEN=$(printf '%s' "$ENR" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')

echo "[3] start agent ($AGENT_BIN)"
VIGIL_MANAGER_ENDPOINT='https://localhost:50051' \
VIGIL_MANAGER_REST=$BASE \
VIGIL_ENROLLMENT_TOKEN="$TOKEN" \
VIGIL_STATE_DIR="$STATE_DIR" \
VIGIL_HOSTNAME=e2e-host-01 \
RUST_LOG=info \
"$AGENT_BIN" >"$LOG" 2>&1 &
AGENT_PID=$!

echo "[4] wait for enrollment + RuleSync"
for i in $(seq 1 30); do
  if grep -q "rule_sync.received" "$LOG" 2>/dev/null; then echo "    ok"; break; fi
  sleep 1
done

BEFORE=$(curl -fsS -H "Authorization: Bearer $ACCESS" "$BASE/api/alerts?limit=1" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["total"])')
echo "[5] alerts before: $BEFORE"

echo "[6] spawn /tmp/mimikatz.exe"
cp /usr/bin/sleep /tmp/mimikatz.exe
/tmp/mimikatz.exe 30 &
MIM_PID=$!

echo "[7] wait for alert"
for i in $(seq 1 30); do
  AFTER=$(curl -fsS -H "Authorization: Bearer $ACCESS" "$BASE/api/alerts?limit=1" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["total"])')
  if [ "$AFTER" -gt "$BEFORE" ]; then
    echo "    alerts after: $AFTER (+$((AFTER - BEFORE))) at t+${i}s"
    break
  fi
  sleep 1
done

if [ "${AFTER:-0}" -gt "${BEFORE:-0}" ]; then
  echo "[8] PASS"
  exit 0
fi
echo "[8] FAIL"
echo "--- agent log ---"; tail -30 "$LOG"
exit 1
