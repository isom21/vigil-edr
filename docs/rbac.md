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

Role gates are enforced at the FastAPI router level via three typed
dependencies in `app/core/deps.py`:

  * `RequireAdmin`    — admin only (user CRUD, rule CRUD, host PATCH /
    DELETE, enrollment-token CRUD, API-token CRUD, audit log).
  * `RequireAnalyst`  — admin + analyst (POST /alerts/<id>/state,
    POST /alerts/<id>/assign, POST /hosts/<id>/commands, all the
    write-side mutations short of full admin).
  * `RequireViewer`   — admin + analyst + viewer (GET /alerts,
    /alerts/<id>, /alerts/<id>/context, /alerts/<id>/process/<pid>,
    /alerts/stats; GET /hosts, /hosts/<id>, /hosts/<id>/telemetry,
    /hosts/stats; GET /rules, /rules/<id>, /rules/stats). Host-group
    scoping still applies, so a viewer only sees their groups'
    resources.

There's no per-route override; if you need a finer gate, add a new
typed dependency rather than runtime branching inside the handler.

Up to MEDIUM #9 (in the 2026-05 review) all read endpoints were gated
on `RequireAnalyst` and a viewer login returned 403 on every page. The
docs above were aspirational rather than enforced; they're now real.

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
- One per customer / tenant (the schema is single-tenant today;
  plan group naming accordingly so a future `Tenant` model maps
  cleanly).

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

Today the log is append-only at the **DB role level**. Two independent
defenses:

1. **Role split.** `audit_log` is owned by `vigil_audit_writer`. The
   manager's runtime user `vigil_manager` is non-superuser and has
   only `SELECT, INSERT` on the table and `USAGE, SELECT` on
   `audit_log_seq`. `UPDATE`, `DELETE`, `TRUNCATE` from the runtime
   pool raise `InsufficientPrivilege` (PG SQLSTATE 42501). See
   `deploy/postgres-init.sql` (which provisions `vigil_manager` as
   non-superuser) and migration `c41d5b7e9f02` (which moves
   ownership). Operators who built dev environments before this fix
   need to `docker compose down -v` and re-run `install.sh`.
2. **HMAC chain.** Every row carries `prev_hmac` + `row_hmac`,
   computed under `VIGIL_AUDIT_HMAC_KEY`. The verifier
   (`app/services/audit_verifier.py`, also reachable via
   `python -m app.services.audit_verifier`) walks the chain and
   reports any UPDATE / DELETE / re-key that slipped past the role
   split — i.e. the second leg is the trip-wire if the first ever
   breaks.

Pruning is intentionally not exposed to the manager. Operators with
growing volume connect as `vigil_audit_writer` and run their own
retention sweep (`DELETE FROM audit_log WHERE ts < now() - interval
'90 days'`); archive to S3 + WORM bucket if compliance demands. A
pruning worker (M16.b) will live behind the same DSN.

The HMAC key co-located with the manager means a manager-host
compromise can rewrite history *and* recompute the chain. Externalize
`VIGIL_AUDIT_HMAC_KEY` (HSM / KMS / vault) for deployments where the
threat model includes a manager-host attacker.

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
