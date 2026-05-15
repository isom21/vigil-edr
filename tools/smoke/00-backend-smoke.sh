#!/usr/bin/env bash
# Backend REST API smoke test. Verifies health, login, /me, rule CRUD,
# enrollment token issuance, hosts list, policy CRUD.
#
# Pre-requisites: backend running on localhost:8000 with an admin user.
#   make backend-dev          # in another shell
#   python -m scripts.create_admin --email admin@example.local --password 'change-me-please-12chars'
#
# Override EMAIL / PASSWORD / URL via env if your admin differs.

set -e

EMAIL="${EMAIL:-admin@example.local}"
PASSWORD="${PASSWORD:-change-me-please-12chars}"
URL="${URL:-http://127.0.0.1:8000}"

echo "=== /api/health ==="
curl -fsS $URL/api/health
echo
echo "=== /api/version ==="
curl -fsS $URL/api/version
echo

echo
echo "=== login ==="
TOKENS=$(curl -fsS -X POST $URL/api/auth/login -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
ACCESS=$(printf '%s' "$TOKENS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')
echo "access token len=${#ACCESS}"

AUTH="Authorization: Bearer $ACCESS"

echo
echo "=== /api/me ==="
curl -fsS -H "$AUTH" $URL/api/me

echo
echo
echo "=== POST /api/rules (yara) ==="
# LIVE-6: M20.a simplified the action enum to alert/block/quarantine
# (was detect/kill/block/quarantine). detect→alert, kill→block.
RULE_YARA=$(curl -fsS -X POST $URL/api/rules -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "kind":"yara",
  "name":"smoke_yara",
  "severity":"medium",
  "action":"alert",
  "body":"rule t { strings: $a = \"bad\" condition: $a }"
}')
echo "$RULE_YARA" | python3 -m json.tool | head -10

echo
echo "=== POST /api/rules (ioc) ==="
RULE_IOC=$(curl -fsS -X POST $URL/api/rules -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "kind":"ioc",
  "name":"smoke_iocs",
  "severity":"high",
  "action":"block",
  "iocs":[
    {"kind":"hash_sha256","value":"AABBCCDDEEFF1122334455667788991122334455667788991122334455667788"},
    {"kind":"filename","value":"mimikatz.exe"}
  ]
}')
echo "$RULE_IOC" | python3 -m json.tool | head -20

echo
echo "=== GET /api/rules ==="
curl -fsS -H "$AUTH" "$URL/api/rules?limit=10" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("total =", d["total"])
for r in d["items"]:
    print("  -", r["kind"].ljust(5), r["name"].ljust(20), r["severity"].ljust(8), r["action"])
'

echo
echo "=== POST /api/enrollment/tokens ==="
TOK=$(curl -fsS -X POST $URL/api/enrollment/tokens -H "$AUTH" -H 'Content-Type: application/json' -d '{"label":"smoke","ttl_hours":1}')
echo "$TOK" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("id =", d["id"])
print("token (prefix) =", d["token"][:16] + "...")
print("expires_at =", d["expires_at"])
'

echo
echo "=== GET /api/hosts ==="
curl -fsS -H "$AUTH" "$URL/api/hosts" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("total =", d["total"])
'

echo
echo "=== POST /api/policies ==="
POL=$(curl -fsS -X POST $URL/api/policies -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "name":"smoke_default",
  "description":"smoke test policy",
  "rules":[]
}')
echo "$POL" | python3 -m json.tool | head -8

echo
echo "=== smoke OK ==="
