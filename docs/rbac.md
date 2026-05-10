# RBAC — roles, host groups, audit log

Companion to `operator-guide.md` and `threat-model.md`. Describes the
manager's authorization model, how to scope users to host groups,
and how to use API tokens for service accounts.

## Roles

The manager has three roles, stored as `users.role` (PG enum
`user_role`):

| Role | Scope | Typical use |
|---|---|---|
| `viewer` | Read-only on alerts, hosts, rules. Cannot queue commands. | SOC junior / read-only stakeholder. |
| `analyst` | Read on hosts, alerts, rules. Queue response commands. Move alert states. | SOC operator / on-call. |
| `admin` | Everything: user CRUD, host group CRUD, rule CRUD, enrollment, decommission, API token management. | Detection engineering / platform team. |

Role gates are enforced at the FastAPI router level via the
`RequireAdmin` / `RequireAnalyst` typed dependencies in
`app/core/deps.py`. There's no per-route override; if you need a finer
gate, add a new typed dependency rather than runtime branching inside
the handler.

## Host groups (M7.5)

A `HostGroup` is a labelled bucket of hosts. Two many-to-many tables
back it:

- `user_host_group` — which users see which groups.
- `host_in_group` — which hosts are in which groups.

A non-admin user sees a host iff at least one of their groups also
contains that host. Admins are pass-through (see all).

The same predicate scopes:

- `GET /api/hosts` — list.
- `GET /api/hosts/{id}` — detail.
- `POST /api/hosts/{id}/commands` — queue.
- `GET /api/hosts/{id}/commands` — list per host.
- `GET /api/commands` — cross-host list (M7.6).
- `GET /api/alerts`, `GET /api/alerts/{id}` — alert visibility.

Implementation: `app/services/scoping.py::apply_host_scope()` for
list queries and `host_visible_to()` for single-resource gates.

### Creating a host group

```bash
ADMIN_TOK=...
curl -s "$MANAGER_REST/api/host-groups" -X POST \
  -H "Authorization: Bearer $ADMIN_TOK" \
  -H 'Content-Type: application/json' \
  -d '{"name":"prod-web","description":"Production web tier"}'
```

### Adding hosts + users to a group

```bash
# Atomic replace. Pass the full lists you want this group to contain.
curl -s "$MANAGER_REST/api/host-groups/$GROUP_ID/members" -X POST \
  -H "Authorization: Bearer $ADMIN_TOK" \
  -H 'Content-Type: application/json' \
  -d '{"host_ids":["<uuid>","<uuid>"],"user_ids":["<uuid>"]}'
```

### Recommended host-group patterns

- One per production tier (`prod-web`, `prod-app`, `prod-db`).
- One per environment (`production`, `staging`, `dev`).
- One per customer / tenant (single-tenant for now; PoC schema is
  not multi-tenant — plan group naming accordingly so a future
  `Tenant` model maps cleanly).

A host can belong to multiple groups (e.g. `prod-web` AND
`production`). A user can belong to multiple groups (e.g.
`prod-web-on-call` AND `prod-app-on-call`).

## API tokens (machine accounts)

For automation that shouldn't use a human's JWT, mint an API token:

```bash
curl -s "$MANAGER_REST/api/tokens" -X POST \
  -H "Authorization: Bearer $ADMIN_TOK" \
  -H 'Content-Type: application/json' \
  -d '{"name":"detection-rule-pipeline","expires_in_days":90}'
```

Returns `{"token": "edr_…"}` — record once; it's not retrievable later.
Revoke via `DELETE /api/tokens/{id}`.

API tokens authenticate by `Authorization: Bearer edr_…`; the gateway
detects the prefix and routes to the API-token resolver in
`app/core/deps.py`. They inherit the role of the user who created them
and respect the same host-group scoping.

## Audit log

Every state-changing route call writes one row to `audit_log` via
`app/services/audit.py::record()`. Schema:

```
audit_log
├── id           uuid
├── user_id      uuid | NULL  (NULL for system actions)
├── actor_kind   "user" | "api_token" | "system"
├── action       str          (indexed; e.g. "host.update", "command.queue")
├── resource_type str | NULL  (e.g. "host", "host_group")
├── resource_id  str | NULL
├── payload      jsonb | NULL (caller-supplied detail)
├── ip           str | NULL
└── ts           timestamptz  (indexed)
```

Today the log is append-only at the model level — there's no API to
prune it, and the indexer doesn't archive it. Operators with growing
volume should periodically `DELETE FROM audit_log WHERE ts < now() -
interval '90 days'` themselves; archive to S3 + WORM bucket if
compliance demands.

What's logged today:

| Action | Source |
|---|---|
| `user.create`, `user.update`, `user.delete` | `/api/users` |
| `host.update`, `host.delete` | `/api/hosts` |
| `host_group.create`, `host_group.update`, `host_group.delete`, `host_group.members.replace` | `/api/host-groups` |
| `rule.*` | `/api/rules` |
| `enrollment_token.create`, `enrollment_token.revoke` | `/api/enrollment` |
| `api_token.create`, `api_token.revoke` | `/api/tokens` |
| `alert.state_change`, `alert.assign` | `/api/alerts` |
| `command.queue` | `/api/hosts/{id}/commands` |

Reads are NOT logged; if you need that, add a FastAPI middleware that
wraps every successful 2xx response.

## Query examples

### Recent admin actions

```sql
SELECT ts, action, resource_type, resource_id, payload
FROM audit_log
WHERE actor_kind = 'user'
  AND ts > now() - interval '24 hours'
ORDER BY ts DESC
LIMIT 50;
```

### Who queued kill commands?

```sql
SELECT a.ts, u.email, a.payload
FROM audit_log a JOIN users u ON u.id = a.user_id
WHERE a.action = 'command.queue'
  AND a.payload ->> 'kind' = 'kill_process'
ORDER BY a.ts DESC;
```

### Hosts visible to a non-admin user

```sql
SELECT h.id, h.hostname
FROM hosts h
JOIN host_in_group hig ON hig.host_id = h.id
JOIN user_host_group uhg ON uhg.host_group_id = hig.host_group_id
WHERE uhg.user_id = '<user_uuid>';
```

## What's NOT enforced (yet)

- **Group-aware enrollment tokens** — the operator who mints a token
  cannot pre-assign the future host to a specific group. Workaround:
  enroll the host, then run `POST /api/host-groups/<group>/members`
  with the new host_id.
- **Rule scoping by group** — Sigma + IOC rules apply to all hosts;
  there's no concept of "this rule only fires on prod-web hosts".
  Workaround: create separate rule sets and toggle via policy
  assignment per host.
- **Per-host policy still admin-managed** — the analyst role can
  queue commands but cannot edit the policy a host runs under.
- **OIDC / SSO** — only password + future TOTP; no enterprise SSO
  integration yet. Tracked as a future polish item.

These gaps are documented in `threat-model.md` "What changes the
calculus" and are slated for a future M7.x extension or M8.
