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

What's logged today (regenerated from the `audit.record(`
call sites in `backend/app/api/`):

| Action family | Source |
|---|---|
| `user.create`, `user.update`, `user.delete`, `user.groups.replace`, `user.provision`, `user.oidc_link` | `/api/users` + OIDC callback |
| `user.login`, `user.login.failed`, `user.login.throttled`, `user.login.password_ok_mfa_required`, `user.login.oidc_ok_mfa_required`, `user.login.2fa_failed` | `/api/auth/login`, `/login/2fa`, `/oidc/callback` |
| `user.2fa.setup_started`, `user.2fa.enabled`, `user.2fa.disabled`, `user.2fa.admin_disabled`, `user.2fa.recovery_used` | `/api/auth/totp/*`, `/api/users/{id}/2fa/disable` |
| `host.update`, `host.delete`, `host.enroll` | `/api/hosts` + enrollment |
| `host_group.create / .update / .delete / .members.replace` | `/api/host-groups` |
| `rule.create / .update / .delete` | `/api/rules` |
| `rule_group.create / .update / .delete` | `/api/rule-groups` |
| `sequence_rule.create / .update / .delete` | `/api/sequence-rules` |
| `playbook.create / .update / .delete` | `/api/playbooks` |
| `tenant.create / .update / .delete` | `/api/tenants` (super-admin) |
| `policy.create / .update / .delete` | `/api/policies` |
| `command.queue`, `host.terminal.open / .io / .close` | `/api/hosts/{id}/commands`, `/api/hosts/{id}/terminal` |
| `alert.state_change`, `alert.assign` | `/api/alerts` |
| `incident.state_change`, `incident.assign` | `/api/incidents` |
| `notification_channel.create / .update / .delete` | `/api/notifications/channels` |
| `routing_rule.create / .update / .delete` | `/api/notifications/rules` |
| `intel_feed.create / .update / .delete / .pull_triggered` | `/api/intel/feeds` |
| `allowlist.mode.set`, `allowlist.entry.create / .delete` | `/api/host-groups/{id}/allowlist` |
| `dns_block.create / .delete / .import` | `/api/dns-blocks` |
| `device_policy.create / .update / .delete` | `/api/device-policies` |
| `quarantine.release / .delete` | `/api/quarantine` |
| `job.create / .cancel`, `artifact.download` | `/api/jobs` |
| `hunt.create / .update / .delete / .run_adhoc / .run_saved` | `/api/hunt/*` |
| `webhook.create / .update / .delete / .rotate / .test` | `/api/webhooks` |
| `case_destination.create / .update / .delete / .test` | `/api/cases/destinations` |
| `cloud_source.create / .update / .delete` | `/api/cloud-sources` |
| `identity_source.create / .update / .delete` | `/api/identity-sources` |
| `detonation_provider.create / .update / .delete`, `detonation.submit` | `/api/detonation/*` |
| `honeytoken.create / .update / .delete` | `/api/honeytokens` |
| `siem_destination.create / .update / .delete` | `/api/siem-forwarders` |
| `attestation.promote`, `attestation.request` | `/api/attestation` |
| `dashboard.create / .update / .delete` | `/api/dashboards` |
| `archive.rehydrate` | `/api/archive` |
| `rollout.advance` | `/api/rollouts` |
| `api_token.create / .revoke` | `/api/tokens` |
| `enrollment_token.create / .revoke` | `/api/enrollment` |
| `scim.user.create / .update / .delete` | `/scim/v2/Users` (SCIM IdP-driven) |

Reads are NOT logged; if you need that, add a FastAPI middleware
that wraps every successful 2xx response. Per-tenant chains: a
tenant-A admin's `GET /api/audit` only returns rows where
`audit_log.tenant_id == actor.tenant_id` (super-admins switch
tenants via the active-tenant cookie).

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

## Tenancy (Phase 3 #3.1)

Multi-tenancy shipped in PR #64 and was fully wired through every
operator-managed resource in PRs 4 / 5a-5l. Every row in the
following tables carries a `tenant_id` FK to `tenant.id`:
`users`, `host_groups`, `hosts`, `policies`, `api_tokens`,
`rules`, `rule_groups`, `sequence_rule`, `playbook`, `playbook_run`,
`intel_feed`, `notification_channel`, `routing_rule`, `dns_block_entry`,
`allowlist_entry`, `allowlist_mode_row`, `host_vulnerability`,
`host_software`, `quarantined_file`, `job`, `job_run`, `job_artifact`,
`saved_hunt`, `hunt_run`, `dashboard`, `scim_token`, `tenant_audit_log`,
`alerts`, `incident`, `audit_log`.

Practical implications for RBAC:

- **Cross-tenant resource access is invisible**. An admin in tenant A
  cannot enumerate, read, mutate, or delete a row in tenant B by id —
  the router returns 404 on cross-tenant id (project convention is to
  never leak existence cross-tenant).
- **Super-admins** are the only role that can cross tenant boundaries.
  They flip the active tenant via the `vigil_active_tenant_id`
  cookie; non-super-admins are pinned to their JWT's `tenant_id`
  claim and the cookie is ignored for them.
- **Per-tenant uniqueness**: name uniqueness on tenant-scoped tables
  is now `(tenant_id, name)`. Tenant A and tenant B can each have a
  `linux-prod` host group, `lsass-credential-dump-response` playbook,
  `abuse.ch-urlhaus` intel feed, etc.
- **Per-tenant audit chain**: the HMAC chain in `audit_log` is per-
  tenant. The audit-verifier walks each tenant's chain independently;
  a break inside tenant A cannot cascade into tenant B's chain.
- **Per-tenant alert routing**: a tenant-A routing rule cannot
  reference a tenant-B channel or host_group — the validator returns
  400 `unknown` on cross-tenant ids.
- **Per-tenant SCIM**: bearer tokens bind to a tenant, so an IdP
  connection provisioned for tenant A only ever populates tenant A's
  roster.

## Enterprise SSO via OIDC

Phase 1 #1.6 shipped OIDC authorization-code flow with PKCE. Enable
via `./install.sh --with-oidc` or by setting the four
`VIGIL_OIDC_*` env vars on the manager process. See
[`install.md → OIDC SSO`](install.md#oidc-sso) for the full
configuration.

The OIDC sign-in path **does not bypass TOTP** (PR #97 / CODE-30
fix). If a user has `totp_enabled=true`, the OIDC callback redirects
to `/login/mfa?token=<mfa-pending-jwt>` after IdP verification; the
SPA finishes the login by posting the TOTP code to
`/api/auth/login/2fa`. The audit row reflects the half-completed
login (`user.login.oidc_ok_mfa_required`); the full `user.login`
row only writes after the TOTP step succeeds.

## SCIM 2.0 (Phase 3 #3.8)

`POST /scim/v2/Users` (and the `Schemas`, `ServiceProviderConfig`,
`ResourceTypes`, list, get, put, patch, delete relatives) provide
IdP-side bulk user provisioning. Authenticated by a bearer token
minted from `/api/scim-tokens` (admin-only); tokens bind to the
admin's tenant. Newly-provisioned users inherit the token's
`tenant_id`, so an Okta connection scoped to tenant A only ever
populates tenant A's roster.

SCIM-created users carry `password_hash=""` and an `oidc_issuer`
matching the deployment's IdP — they sign in via OIDC, never via a
local password.

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

## Two-factor authentication (TOTP)

Per-user opt-in via the `/api/auth/2fa/*` endpoints. Not enforced —
the project targets solo-developer / small-team operations and a
hard mandate at the auth layer would lock out anyone whose
authenticator drifts before recovery codes are saved.

- Enrollment: `POST /api/auth/2fa/setup` → render the returned
  `provisioning_uri` as a QR code → `POST /api/auth/2fa/verify-setup
  { code }` to confirm. Server returns ten one-shot recovery codes
  at this step; they're shown once.
- Login on a 2FA-enabled account: `/api/auth/login` returns
  `{ mfa_required: true, mfa_token }` instead of a token pair.
  Client exchanges at `/api/auth/login/2fa { mfa_token, code }`
  with either a current TOTP or one of the recovery codes.
- Disable: `POST /api/auth/2fa/disable { code }`. Self-service
  only, but requires a valid code so a stolen session can't
  silently turn it off.
- Admin recovery: if a user loses both their authenticator and
  recovery codes, an admin can clear all 2FA state via
  `POST /api/users/{id}/2fa/disable`. Audited as
  `user.2fa.admin_disabled`.

API tokens are out of scope — they're opaque machine credentials
and the 2FA endpoints reject them explicitly.

Secrets are stored Fernet-encrypted with `VIGIL_TOTP_ENCRYPTION_KEY`,
kept separate from `jwt_secret` and `upload_token_key` so a leak
in one auth path doesn't cross-contaminate the others. Recovery
codes live as bcrypt hashes; only the one-shot plaintext leaves
the server, only at enrollment.

These gaps are documented in `threat-model.md` "What changes the
calculus" and are slated for a future M7.x extension or M8.
