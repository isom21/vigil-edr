#!/usr/bin/env bash
# 50-rbac-e2e.sh - exercises M7.5 host-group scoping end-to-end against a
# running backend.
#
# Builds: 1 admin, 1 viewer, 2 hosts (or reuses existing), 2 host groups.
# Puts host A in group "alpha" and host B in group "beta", assigns the
# viewer to "alpha" only, then verifies:
#
#   - admin sees both hosts in GET /api/hosts
#   - viewer sees only host A
#   - viewer GET /api/hosts/<host_B> -> 403
#   - viewer POST /api/hosts/<host_B>/commands -> 403
#   - viewer POST /api/hosts/<host_A>/commands -> 201 (when permitted) or
#     403 (current implementation requires admin/analyst — this verifies
#     the scoping is at host visibility, not role).
#
# Cleans up the created users/groups at the end.

set -euo pipefail

BASE="${BASE:-http://localhost:8000}"
ADMIN_EMAIL="${EMAIL:-admin@example.local}"
ADMIN_PASS="${PASSWORD:-change-me-please-12chars}"

note() { printf '\033[36m[smoke]\033[0m %s\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m   - %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m - %s\n' "$*"; FAILS=$((FAILS+1)); }

FAILS=0

note "log in as admin"
ADMIN_TOK=$(curl -fsS -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASS\"}" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')

# Need at least 2 hosts. Use existing hosts; if fewer, this smoke is best-effort.
HOSTS_JSON=$(curl -fsS "$BASE/api/hosts" -H "Authorization: Bearer $ADMIN_TOK")
HOST_COUNT=$(echo "$HOSTS_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["total"])')
if [ "$HOST_COUNT" -lt 2 ]; then
    note "fewer than 2 hosts ($HOST_COUNT) — smoke needs >=2 enrolled hosts; skipping"
    exit 0
fi
HOST_A=$(echo "$HOSTS_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["items"][0]["id"])')
HOST_B=$(echo "$HOSTS_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["items"][1]["id"])')
note "host_A=$HOST_A  host_B=$HOST_B"

# Create the viewer.
VIEWER_EMAIL="rbac-smoke-viewer-$$@example.local"
VIEWER_PASS="rbac-smoke-viewer-pass-$$"
VIEWER_ID=$(curl -fsS -X POST "$BASE/api/users" -H "Authorization: Bearer $ADMIN_TOK" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$VIEWER_EMAIL\",\"password\":\"$VIEWER_PASS\",\"role\":\"analyst\"}" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
note "created analyst user $VIEWER_ID"

# Create two host groups.
ALPHA_ID=$(curl -fsS -X POST "$BASE/api/host-groups" -H "Authorization: Bearer $ADMIN_TOK" \
    -H 'Content-Type: application/json' -d "{\"name\":\"smoke-alpha-$$\"}" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
BETA_ID=$(curl -fsS -X POST "$BASE/api/host-groups" -H "Authorization: Bearer $ADMIN_TOK" \
    -H 'Content-Type: application/json' -d "{\"name\":\"smoke-beta-$$\"}" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
note "created groups alpha=$ALPHA_ID beta=$BETA_ID"

# host_A -> alpha; host_B -> beta; user -> alpha.
curl -fsS -X POST "$BASE/api/host-groups/$ALPHA_ID/members" \
    -H "Authorization: Bearer $ADMIN_TOK" -H 'Content-Type: application/json' \
    -d "{\"host_ids\":[\"$HOST_A\"],\"user_ids\":[\"$VIEWER_ID\"]}" > /dev/null
curl -fsS -X POST "$BASE/api/host-groups/$BETA_ID/members" \
    -H "Authorization: Bearer $ADMIN_TOK" -H 'Content-Type: application/json' \
    -d "{\"host_ids\":[\"$HOST_B\"],\"user_ids\":[]}" > /dev/null
note "membership applied"

# Log in as the analyst.
ANALYST_TOK=$(curl -fsS -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$VIEWER_EMAIL\",\"password\":\"$VIEWER_PASS\"}" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')

# 1. admin sees both.
A_TOTAL=$(curl -fsS "$BASE/api/hosts" -H "Authorization: Bearer $ADMIN_TOK" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["total"])')
if [ "$A_TOTAL" -ge 2 ]; then ok "admin sees >=2 hosts ($A_TOTAL)"; else fail "admin sees only $A_TOTAL"; fi

# 2. analyst sees host_A but not host_B.
LISTED=$(curl -fsS "$BASE/api/hosts" -H "Authorization: Bearer $ANALYST_TOK" \
    | python3 -c 'import json,sys;d=json.load(sys.stdin);ids=[i["id"] for i in d["items"]];print(",".join(ids))')
if [[ "$LISTED" == *"$HOST_A"* ]]; then ok "analyst's host list contains host_A"; else fail "host_A missing from analyst list ($LISTED)"; fi
if [[ "$LISTED" != *"$HOST_B"* ]]; then ok "analyst's host list does NOT contain host_B"; else fail "host_B leaked into analyst list ($LISTED)"; fi

# 3. analyst GET /api/hosts/<host_B> -> 403
GETB_HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/hosts/$HOST_B" -H "Authorization: Bearer $ANALYST_TOK")
if [ "$GETB_HTTP" = "403" ]; then ok "analyst GET host_B -> 403"; else fail "analyst GET host_B -> $GETB_HTTP (expected 403)"; fi

# 4. analyst POST commands on host_A -> 201 or 200 (allowed by group)
CMDA_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/hosts/$HOST_A/commands" \
    -H "Authorization: Bearer $ANALYST_TOK" -H 'Content-Type: application/json' \
    -d '{"kind":"block_process","payload":{"pattern":"smoke.exe"}}')
if [ "$CMDA_HTTP" = "201" ] || [ "$CMDA_HTTP" = "200" ]; then ok "analyst POST commands on host_A -> $CMDA_HTTP"; else fail "analyst POST commands on host_A -> $CMDA_HTTP (expected 201)"; fi

# 5. analyst POST commands on host_B -> 403
CMDB_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/hosts/$HOST_B/commands" \
    -H "Authorization: Bearer $ANALYST_TOK" -H 'Content-Type: application/json' \
    -d '{"kind":"block_process","payload":{"pattern":"smoke.exe"}}')
if [ "$CMDB_HTTP" = "403" ]; then ok "analyst POST commands on host_B -> 403"; else fail "analyst POST commands on host_B -> $CMDB_HTTP (expected 403)"; fi

# Cleanup.
curl -fsS -X DELETE "$BASE/api/host-groups/$ALPHA_ID" -H "Authorization: Bearer $ADMIN_TOK" > /dev/null
curl -fsS -X DELETE "$BASE/api/host-groups/$BETA_ID" -H "Authorization: Bearer $ADMIN_TOK" > /dev/null
curl -fsS -X DELETE "$BASE/api/users/$VIEWER_ID" -H "Authorization: Bearer $ADMIN_TOK" > /dev/null

if [ "$FAILS" -eq 0 ]; then echo "PASS - all RBAC scoping checks behaved as expected"; exit 0; fi
echo "FAIL - $FAILS check(s) failed"; exit 1
