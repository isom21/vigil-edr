# Identity + RBAC depth (M13)

> **Status:** scaffolded. M13 ships a per-token API rate limiter
> (M13.a, fully wired) + the roadmap for the rest. Each remaining
> substage (OIDC, SCIM, WebAuthn, service mesh mTLS, SoftHSM-backed
> CA, JIT admin, CRL/OCSP) is independent and can be picked up by
> any future session.

## What M1 + M5.3 + M7.5 already give us

- Password + JWT auth (`/api/auth/login`, `/api/auth/refresh`).
- Three roles (admin, analyst, viewer) with per-route gates.
- Named API tokens (`/api/tokens`) for service accounts.
- Per-host scoping via host groups (M7.5).
- Append-only audit log (`audit_log` table) covering state-changing
  routes.
- Internal CA + per-host enrollment certs (`agent_core::enroll`).

## Substages

| Substage | What |
|---|---|
| **M13.a (this commit)** | Per-token / per-IP API rate limiting middleware |
| M13.b | OIDC integration (tested against self-hosted Keycloak) |
| M13.c | SCIM 2.0 server for user provisioning |
| M13.d | WebAuthn / FIDO2 (optional 2FA on top of TOTP) |
| M13.e | Service mesh mTLS via Linkerd (manager↔normalizer↔indexer) |
| M13.f | SoftHSM-backed manager CA via PKCS11 |
| M13.g | Just-in-time admin elevation workflow |
| M13.h | CRL + OCSP responder for cert revocation |
| M13.i | API token rotation tooling |

## M13.a — Rate limiting (this commit)

**Goal**: cap each authenticated identity (user or API token) to N
requests per minute, returning HTTP 429 with `Retry-After` on
overflow. Prevents one stuck script from exhausting backend resources
+ provides per-token observability for abuse.

**Storage**: in-memory sliding window per identity. Redis-backed
variant is M15 follow-up (when we go multi-instance manager). For a
single FastAPI process, a `dict[identity_id, deque[timestamp]]` with
periodic GC is enough.

**Limits** (defaults; configurable):

| Identity | Limit |
|---|---|
| `admin` user JWT | 600 / minute |
| `analyst` user JWT | 300 / minute |
| `viewer` user JWT | 120 / minute |
| API token (per-token) | 600 / minute |
| Anonymous (`/api/enrollment/enroll`) | 10 / minute / IP |

429 responses include:

```
Retry-After: <seconds-until-window-rolls>
X-RateLimit-Limit: <quota>
X-RateLimit-Remaining: 0
X-RateLimit-Reset: <unix-time>
```

**Bypass**: `/api/health` and `/api/openapi.json` are always allowed
(monitoring + ops tooling).

## Why these later substages and not now

- **OIDC** is operator-side work primarily — the Keycloak deployment
  itself is on the operator's side; the manager-side change is a single
  router + a `redirect_uri` config knob. We can ship it whenever a
  customer asks for it.
- **SCIM** requires real customer integration to test meaningfully.
  Spec'ing it now without a target is overengineering.
- **WebAuthn** is paired with hardware-key purchase decisions; the
  TOTP path stays default per the project memory.
- **Service mesh mTLS** depends on multi-instance manager, which is
  M15 territory.
- **SoftHSM** is a 1-day swap when we have a real production CA. Today
  the CA key is a fine-grained hot path; refactoring it to PKCS11 with
  no operational pressure to do so risks regressions.
- **JIT admin / CRL / OCSP** all benefit from compliance pressure —
  they ship when M16 forces the hand.

## Integration with the audit log

Every 429 response is logged to `audit_log` with
`action="rate_limit.exceeded"` and `payload={limit, identity, ip}`.
Operators can SQL-query the log to find abusive identities.
