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
#   - viewer GET /api/hosts/<host_B> -> 404
#   - viewer POST /api/hosts/<host_B>/commands -> 404
#   - viewer POST /api/hosts/<host_A>/commands -> 201 (when permitted) or
#     403 (current implementation requires admin/analyst — this verifies
#     the scoping is at host visibility, not role).
#
# Note: out-of-scope returns 404 (not 403) so the wire response
# doesn't distinguish "exists-but-hidden" from "does-not-exist".
# See MEDIUM #7 in the review.
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

# Need at least 2 hosts. Use existing hosts; if fewer, give the
# operator the exact bootstrap commands and exit non-zero so the
# smoke counts as failed (LIVE-9 — pre-PR this exited 0, silently
# masking that the test never actually ran).
HOSTS_JSON=$(curl -fsS "$BASE/api/hosts" -H "Authorization: Bearer $ADMIN_TOK")
HOST_COUNT=$(echo "$HOSTS_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["total"])')
if [ "$HOST_COUNT" -lt 2 ]; then
    note "[smoke 50-rbac-e2e] precondition failed: only $HOST_COUNT enrolled host(s); need >=2"
    note ""
    note "  Quickest path (build agent + enrol two synthetic hosts):"
    note "    cargo build -p agent-linux --release"
    note "    bash tools/smoke/20-agent-ioc-e2e.sh   # one host"
    note "    VIGIL_HOSTNAME=e2e-host-02 \\"
    note "      bash tools/smoke/20-agent-ioc-e2e.sh   # second host"
    note ""
    note "  Or run 50 again once you have any 2 hosts visible to the admin."
    exit 1
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

# 3. analyst GET /api/hosts/<host_B> -> 404 (M-audit-and-auth #7:
#    out-of-scope is indistinguishable from non-existent on the wire,
#    so a bug-bounty hunter pasting alert / host UUIDs around can't
#    use 403-vs-404 to confirm a UUID is real).
GETB_HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/hosts/$HOST_B" -H "Authorization: Bearer $ANALYST_TOK")
if [ "$GETB_HTTP" = "404" ]; then ok "analyst GET host_B -> 404"; else fail "analyst GET host_B -> $GETB_HTTP (expected 404)"; fi

# 4. analyst POST commands on host_A -> 201 or 200 (allowed by group)
CMDA_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/hosts/$HOST_A/commands" \
    -H "Authorization: Bearer $ANALYST_TOK" -H 'Content-Type: application/json' \
    -d '{"kind":"block_process","payload":{"pattern":"smoke.exe"}}')
if [ "$CMDA_HTTP" = "201" ] || [ "$CMDA_HTTP" = "200" ]; then ok "analyst POST commands on host_A -> $CMDA_HTTP"; else fail "analyst POST commands on host_A -> $CMDA_HTTP (expected 201)"; fi

# 5. analyst POST commands on host_B -> 404 (was 403; see #3 above)
CMDB_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/hosts/$HOST_B/commands" \
    -H "Authorization: Bearer $ANALYST_TOK" -H 'Content-Type: application/json' \
    -d '{"kind":"block_process","payload":{"pattern":"smoke.exe"}}')
if [ "$CMDB_HTTP" = "404" ]; then ok "analyst POST commands on host_B -> 404"; else fail "analyst POST commands on host_B -> $CMDB_HTTP (expected 404)"; fi

# Cleanup.
curl -fsS -X DELETE "$BASE/api/host-groups/$ALPHA_ID" -H "Authorization: Bearer $ADMIN_TOK" > /dev/null
curl -fsS -X DELETE "$BASE/api/host-groups/$BETA_ID" -H "Authorization: Bearer $ADMIN_TOK" > /dev/null
curl -fsS -X DELETE "$BASE/api/users/$VIEWER_ID" -H "Authorization: Bearer $ADMIN_TOK" > /dev/null

if [ "$FAILS" -eq 0 ]; then echo "PASS - all RBAC scoping checks behaved as expected"; exit 0; fi
echo "FAIL - $FAILS check(s) failed"; exit 1
