# Operator guide

Day-to-day operations runbook: provisioning hosts, triaging alerts,
queueing response actions, upgrading, decommissioning. For the
first-time install (manager + agents), see `install.md`.

Companion docs:

- `install.md` — first-time bring-up of manager + agents.
- `threat-model.md` — what the agent defends against and explicit gaps.
- `rbac.md` — roles, host groups, audit log, API tokens.

## Glossary

| Term | Meaning |
|---|---|
| Manager | The FastAPI backend + UI + workers running centrally. |
| Agent | The endpoint binary (`vigil-agent`) running on each protected host. |
| Driver | Windows-only kernel component (`vigil.sys`) the agent talks to via IOCTL. |
| Host | A single endpoint enrolled with the manager (one row in PG `hosts`). |
| Host group | A label-bucket of hosts used for RBAC scoping (M7.5). |
| Enrollment token | One-time secret minted by an admin, consumed by the agent on first run. |
| Pin path | bpffs directory (`/sys/fs/bpf/vigil/`) where the Linux agent's BPF programs/links/maps are kept alive across crashes. |

## Provisioning a new endpoint

See [`install.md`](install.md) §2 (enrollment token) and §3–§5
(Linux / Windows install + verification). This guide picks up
afterwards, once the host is enrolled and visible in the UI.

## Operating

### Reading telemetry

OpenSearch dashboard: the `telemetry-*` index pattern. As of M7.7,
each doc carries `host.id`, `host.hostname`, and `host.os.family`,
so analysts can search by hostname.

Quick checks:

```bash
# Recent process_started on a host:
curl -s "$OS_URL/telemetry-*/_search?q=event.kind:process_started+AND+host.hostname:<name>&size=20"

# Outbound connects from a binary:
curl -s "$OS_URL/telemetry-*/_search?q=event.kind:network_connect+AND+process.name:curl"
```

### Triaging an alert

UI: Alerts → click the row → Alert Detail.

Move state with the buttons at the top: `new` → `investigating` →
`true_positive` (or `false_positive`). Optional comment goes in the
state-history.

Queue a response action:

- "Block process by path…" — drops every future exec of that binary.
- "Block file…" — denies open() on that path.
- "Kill PID…" — terminates a specific running pid.

Status lands on `/commands` once the agent confirms.

### Queueing commands without the UI

```bash
curl -s "$MANAGER_REST/api/hosts/$HOST_ID/commands" -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"block_process","payload":{"pattern":"/usr/local/bin/evil"}}' \
  | jq .
```

`kind` values supported by `backend/app/models/command.py`:

| Kind | Payload | Use |
|---|---|---|
| `kill_process` | `{"pid": <int>}` | Terminate a specific running pid. |
| `block_process` | `{"pattern": "<path>"}` | Deny future exec of the binary. |
| `block_file` | `{"pattern": "<path>"}` | Deny `open()` on that path. |
| `unblock_process` | `{"pattern": "<path>"}` | Remove a previous block. |
| `unblock_file` | `{"pattern": "<path>"}` | Remove a previous file block. |
| `isolate` | `{}` | Cut the host off the network except for the manager / DNS / NTP allowlist. |
| `unisolate` | `{}` | Restore normal network. |
| `quarantine_file` | `{"path": "...", "alert_id": "..."}` | Move the file to the host's quarantine vault; record in `quarantined_files`. |
| `release_quarantine` | `{"quarantine_id": "..."}` | Restore a quarantined file. |
| `run_job` | `{"job_id": "..."}` | Launch a triage job (process_snapshot, file_acquire, etc.) on the host. |
| `allowlist_sync` | `{}` | Push the latest allowlist for the host's groups (M2.8). |
| `dns_block_sync` | `{}` | Push the latest DNS sinkhole list to the host (#2.12). |
| `device_control_sync` | `{}` | Push USB device-control policy (#3.10). |
| `request_attestation` | `{"nonce": "..."}` | Ask the agent for a TPM quote (Linux active, Windows pending). |
| `deploy_honeytoken` | `{"honeytoken_id": "..."}` | Plant a decoy file / regkey / cred. |

The UI surfaces a context-appropriate subset of these on the alert
detail and host detail pages; the REST API accepts the full set
gated by RBAC.

### Auto-block fallback {#auto-block-fallback}

When a Sigma / IOC rule with `action=block` matches, the manager
queues both a kill-by-pid (if the event has a live pid) and a
preventive block-by-path. The block pattern is the resolved full
executable / file path from the matched event (`process.executable`
or `file.path` in ECS). The agent pushes that exact string into the
kernel-side block map, which is keyed by the full path the kernel
sees on exec / file_open. So the pattern and the lookup key match
and future invocations of the same binary return EPERM.

If the matched event only carries a basename (`process.name` /
`file.name`) — older events, or normalizers that drop the path — the
manager falls back to queueing the basename. The kernel will not
match it on future invocations (`"mimikatz.exe"` vs
`"/usr/local/bin/mimikatz.exe"`); the kill-by-pid limb is the only
effective response. The UI surfaces this as a normal "block queued"
status because the IOCTL succeeded — the kernel map row was added,
just keyed by a string that the resolver will never produce. If you
need a preventive block against a basename-only event, re-queue the
block manually with the path you actually want denied.

## Upgrading

### Linux

```bash
# Build the new deb, copy to endpoint:
make agent-linux-deb
scp target/debian/vigil-agent_*.deb endpoint:/tmp/

# On endpoint:
apt-get install -y /tmp/vigil-agent_*.deb     # postinst handles daemon-reload
systemctl restart vigil-agent
journalctl -u vigil-agent -f                  # watch takeover + reload
```

Takeover protocol (post-M7.1.b): on agent exit the
`sched_process_exit` tracepoint zeroes `agent_self[0]` from kernel
context, so the new agent finds `self_tgid() == 0` and claims via
the standard initial-load path. The "old agent's tgid written by
the new agent" trick is gone — that route was the
`bpftool map update`-based hijack the M7.1.b fix closes. If the
exit auto-clear ever fails to fire (kernel quirk), the new agent
logs `self_protection.takeover.stale_self_observed`, unlinks the
old pins, and proceeds with a fresh load. Brief (<1s) protection
gap during restart; documented in `threat-model.md`.

### Windows

```powershell
.\vigil-windows-1.0.0\install-vigil.ps1   # idempotent; reuses identity material
Stop-Service vigil; Start-Service vigil   # post-M9.1 SCM service name
```

The driver may need a reboot if the `.sys` is in use; the installer
will print a warning if `Copy-Item` fails on `system32\drivers\`.

## Decommissioning

### Stop the host (preserve identity for re-enrollment)

```bash
# Linux:
systemctl stop vigil-agent
systemctl disable vigil-agent

# Windows:
Stop-Service vigil
```

### Full uninstall

```bash
# Linux:
apt-get remove -y vigil-agent      # keeps state
apt-get purge -y vigil-agent       # removes /var/lib/vigil + /etc/vigil

# Windows:
.\vigil-windows-1.0.0\uninstall-vigil.ps1            # keeps state + cert
.\vigil-windows-1.0.0\uninstall-vigil.ps1 -Purge -RemoveCert
```

### Mark the host as decommissioned in the manager

```bash
curl -s "$MANAGER_REST/api/hosts/$HOST_ID" -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"status":"decommissioned"}'
```

This flips `Host.status` to `DECOMMISSIONED` and the manager's gRPC
service rejects every future `HostStream` open from that host id with
`UNAUTHENTICATED: host decommissioned` — verified at the
`_check_host_admission` gate in `backend/app/grpc/services.py`. The
heartbeat tick on an already-open stream catches the same flip within
~30s and aborts mid-stream. The mTLS cert itself stays
cryptographically valid until its 90-day expiry (we don't operate a
CRL), so the decommission is enforced by the manager, not by the TLS
layer. If you need the cert to stop validating outright before its
expiry — say, for a stolen-laptop scenario — rotate the internal CA
and re-issue every other agent's cert.

Cert-pinning sits at the same gate: the SHA-256 of the presented PEM
is compared against `Host.cert_fingerprint`, so a second host that
somehow ended up with the same CN can't take over the slot.

## Troubleshooting

### Linux

| Symptom | Likely cause | Fix |
|---|---|---|
| `systemctl status vigil-agent` fails with "agent.identity.using_existing" missing | Identity dir wiped; need new token | Mint enrollment token, set `VIGIL_ENROLLMENT_TOKEN` in `/etc/vigil/agent.env`, restart. |
| `self_protection.takeover.failed` on startup | Old pins exist but agent_self map name changed across versions | `vigil-agent --unpin` then start. |
| `ebpf load failed; falling back to /proc poller` | `CONFIG_BPF_LSM=y` not enabled, kernel <5.7, missing CAP_BPF | Confirm `cat /sys/kernel/security/lsm` contains `bpf`; ensure systemd unit's `AmbientCapabilities` line has `CAP_BPF`. |
| File-open events stop flowing under load | Backpressure (pre-M7.7) | Confirm normalizer is current; `make backend-normalizer` should pick up M7.7 batched-send. |
| `kill -9` from root succeeds | `VIGIL_DISABLE_SELF_PROTECTION=1` set, or `lsm/task_kill` failed to attach | Inspect journal for `lsm_task_kill.skipped`. |

### Windows

| Symptom | Likely cause | Fix |
|---|---|---|
| Driver fails to load with "signature invalid" | testsigning off or cert not in TrustedPublisher | `bcdedit /set testsigning on` + reboot; verify `certutil -store -enterprise Root` shows the cert. |
| `VigilKernelSession AlreadyExist` | Stale ETW session from a previous crash (pre-M7.7) | Upgrade to current; `ControlTraceA(STOP)` runs on startup. |
| Agent task starts but exits immediately | Bad `agent.env` format | Check `C:\Windows\Temp\vigil-agent.err.log`. |
| `taskkill /F` succeeds against agent | Driver not loaded, or `g_ProtectedPid == 0` | `sc.exe query vigil` (RUNNING) and verify the agent logged `driver.self_protection.registered`. |
| Defender races and wins our kill IOCTL | Built-in signature on the target name (e.g. `mimikatz.exe`) | Lab-only: `Set-MpPreference -DisableRealtimeMonitoring $true`. Block-path is unaffected. |

### Sigma / detection pipeline

| Symptom | Likely cause | Fix |
|---|---|---|
| Same alert opens twice (or N times) after a sigma worker restart | The realtime Sigma engine doesn't dedup across Kafka offset replays. ADR 0005 acknowledges this — when the percolator worker restarts, it re-consumes the last batch of events and re-fires any matches. Expected, not a bug. | Close the duplicates manually; if a worker bounces repeatedly, fix the underlying crash rather than try to suppress the duplicates. The percolator + auto-action path is idempotent on commands (the IOC dedup map in `agent_commands` keys by `(host_id, command_kind, payload)`), so the kernel block list ends up correct even if N alerts opened. |

## Smoke tests

`tools/smoke/` — bash + PowerShell scripts that verify the running
stack from the operator's perspective. Reference:

| Script | Verifies |
|---|---|
| `00-backend-smoke.sh` | REST API surface (login, /me, rule CRUD, enrollment, hosts, policies). |
| `10-grpc-smoke.py` | gRPC ingest path end-to-end. |
| `20-agent-ioc-e2e.sh` | IOC detector → alert in PG. |
| `30-sigma-realtime-e2e.sh` | Realtime Sigma engine wall-clock latency. |
| `40-sigma-scheduled-e2e.sh` | Legacy scheduled Sigma (kept for aggregation). |
| `45-self-protection-linux.sh` | M7.1 BPF LSM hooks all reject same-box-root attacks. |
| `46-self-protection-windows.ps1` | M7.2 driver ObCallback strips dangerous handle access. |
| `50-rbac-e2e.sh` | M7.5 host-group scoping for hosts / alerts / commands. |

Recommended run order after a fresh dev-stack bring-up: 00 → 10 → 20 →
30 → 45 → 50 → (Windows lab) 46.

## Detection workflow

The detection pipeline went from "Sigma on every event" (M-series)
to the Phase 1 alert lifecycle below. The order matters because an
alert can be folded into an incident, deduped by a sliding window,
filed against a saved hunt's `alert_on_hit`, or routed to Slack
before any human ever sees it.

### Alert dedup (Phase 1 #1.10)

Open alerts inside a configurable window (`VIGIL_ALERT_DEDUP_WINDOW_S`,
default 300 s) that share a `dedup_key` of `(rule_id, host_id,
canonical-event-id)` coalesce: the second + Nth matches bump
`occurrence_count` + `last_occurred_at` instead of inserting a new
row. The Alert state machine never auto-closes, so once an operator
marks the alert `true_positive` or `false_positive` the dedup latch
releases — a fresh recurrence after triage opens a new row, which
is what you want.

### Incidents (Phase 1 #1.11, process-tree expanded in #1.12)

The incident grouper folds alerts from the same host inside a
configurable window (`VIGIL_INCIDENT_GROUP_WINDOW_S`, default 1800 s)
into a single `Incident`. Process-tree-aware grouping (#1.12) also
walks `process.ancestor_pids` so a Sigma alert on the parent and an
IOC hit on a child collapse into one incident even when they were
emitted by different engines.

Incidents are the UI's primary "did this matter?" view. The
detection workflow is:

1. Telemetry events land in `telemetry-*`.
2. Sigma percolator / IOC detector / sequence detector emit Alerts.
3. The dedup pre-check (above) folds matches inside the window.
4. The grouper attaches each fresh Alert to an existing or new
   Incident.
5. Routing rules fan the alert out to channels (next section).

The UI lives at `/incidents`. Triage on an incident updates every
attached alert at once.

### Alert routing → Slack / PagerDuty / SMTP (#1.7) {#notifications}

Two surfaces:

- **Channels** (`/api/notifications/channels`): credentialed
  destinations. Slack incoming webhook, PagerDuty Events v2
  integration key, SMTP. Secrets are Fernet-encrypted at rest under
  `VIGIL_NOTIFICATION_ENCRYPTION_KEY` and never returned to the UI —
  the UI surfaces a short fingerprint so operators can confirm a
  rotation took effect.
- **Routing rules** (`/api/notifications/rules`): predicates that
  pick alerts and pick channels. `min_severity` + optional
  `rule_kind` + optional `host_group_id`; `channel_ids` lists which
  channels fire. All same-tenant.

A rule with no channels never fires. A channel with no rules is
dormant. The dispatcher worker drains `kafka.alerts.opened` and
fans the alert out at-most-once per (alert × channel).

### Saved hunts + hunt workbench (#2.11)

`/api/hunt/run` is the ad-hoc query path; `/api/hunt/saved/*` is
CRUD on stored hunts. Admins can wire `alert_on_hit` or
`schedule_cron` on a saved hunt so the scheduler fires the same
query on a cron + raises a Sigma-equivalent Alert when hits land.

### Process graph (#1.12)

The `/api/graph/...` endpoints expose the parent/child walk that
the grouper uses. UI: alert detail → "Process tree" tab.

### Live terminal (#1.4)

Status note: the bidi TerminalStream RPC + xterm.js UI shipped, but
the agent half is not currently wired (CODE-204 — the `terminal_v1`
capability is stripped on both targets). The UI surfaces a
"Terminal" tab on the host detail page but the open-session button
is gated on the host advertising `terminal_v1`. When the agent-side
PTY proxy lands the strip reverts.

## Network containment

### Isolate / unisolate (#1.x)

Cuts a host off the network except for a static allowlist
(manager + DNS + NTP). Linux: BPF cgroup_skb hook + nftables fallback.
Windows: WFP filter.

```bash
curl -s "$MANAGER_REST/api/hosts/$HOST_ID/commands" -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"isolate"}'
```

`unisolate` restores normal traffic. UI: host detail → "Isolate"
button (single-click; analyst+).

**Recovery invariant — you can't accidentally lock yourself out.**
On every isolate-apply the agent resolves its own configured
`VIGIL_MANAGER_ENDPOINT` + `VIGIL_MANAGER_REST` URLs and forces those
IPs into the BPF + nft allowlist, regardless of what the operator
passed in. The manager's API does the same on the queue side using
`VIGIL_MANAGER_PUBLIC_URL` + `VIGIL_GRPC_SAN_EXTRAS` — two layers of
the same check, so older agents without the agent-side fix still get
covered. If the agent can't resolve the manager hostname at apply
time (DNS broken, network already down), the agent refuses the
isolate with `isolation.refused: could not resolve manager
endpoints` — the operator sees a failed command status and the host
keeps its current network state. The unisolate path is always
`POST /api/hosts/<id>/commands` with `kind=isolate, isolate=false`;
no local CLI escape hatch is needed because the manager-driven path
is structurally guaranteed reachable.

If you ever need to bypass isolation by hand (e.g. the host is on a
network the manager can't reach at all), the BPF state lives in
`/sys/fs/bpf/vigil/maps/{isolation_state,manager_ip_allowlist}` and
the nft table is `inet edr-isolation`. Wiping them requires
`vigil-agent --unpin` followed by an agent restart; see
[`docs/threat-model.md`](threat-model.md) for the audit consequences
of doing this without going through the manager.

### Quarantine file + release (#M11.f / #M20.c)

Moves a file to the agent's quarantine vault (Linux: `/var/lib/vigil/quarantine/`;
Windows: `%ProgramData%\Vigil\quarantine\`) with a manifest. The
manager ledger lives in `quarantined_files`. UI: alert detail →
"Quarantine file…" (admin); restore via "Release" in the
`/quarantine` tab.

The Windows path is not currently implemented (CODE-228); the UI is
gated on the host's OS family for now.

### DNS block list (#2.12) {#dns-block-list}

Per-host-group sinkhole list. Bulk-import accepts a flat domain list
(one per line; CSV header optional) from feeds like
`urlhaus.abuse.ch` and dedupes on (`tenant_id`, `host_group_id`,
`domain`). Manager pushes a `DNS_BLOCK_SYNC` command per affected host
on every CRUD so the agent's kernel-side map converges within
seconds.

### USB device control (#3.10)

Per-host-group device-policy push. Allow / deny rules on
vendor:product ids. The agent applies via WMI / udev rules on the
respective platforms.

## Multi-tenancy {#multi-tenancy}

Phase 3 #3.1 made every operator-managed resource tenant-scoped.
Practical implications:

- An admin in tenant A cannot see, mutate, or delete tenant B's
  users / host groups / rules / playbooks / hunts / channels /
  routing rules / intel feeds / dashboards / SCIM tokens.
- Tenant-A and tenant-B can each have a `linux-prod` host group or
  `lsass-credential-dump-response` playbook — name uniqueness is
  per (tenant, name).
- Cross-tenant ids surface as 404, not 403, per the project
  convention — existence stays opaque.
- The cookie `vigil_active_tenant_id` switches a super-admin's
  active tenant without re-logging-in. Non-super-admins are pinned
  to their home tenant by the JWT claim; the cookie is ignored for
  them.
- The audit log is tenant-scoped per request (see [`rbac.md`](rbac.md)).
- Alerts, incidents, and OpenSearch telemetry docs all carry
  `tenant.id` (PR 4: workers stamp it from the host's tenant; the
  hunt / sigma test endpoints pin the OpenSearch filter to
  `actor.tenant_id` for non-super-admins).

The grpc enrollment endpoint stamps `tenant_id` from the enrollment
token's tenant. A token minted by tenant A's admin only ever
provisions tenant-A hosts.

## Phase 3 / 4 features {#phase-3-4}

### Dashboards (#3.4)

Operator-authored widget grids at `/dashboards`. Per-owner default
auto-created on first call. `shared=true` makes a layout visible to
every analyst+ in the same tenant.

### Playbooks (#3.5) {#playbooks}

YAML response chains. Triggers: `trigger_rule_id`, `trigger_severity`,
`trigger_mitre_techniques` (any matches; all-NULL is dormant).
Executor consumes `kafka.alerts.opened`, parses the YAML, runs each
step. Currently supported step kinds:

- `isolate` / `unisolate` — fan a `Command` out to the alert's host.
- `quarantine_file` — needs `path`.
- `memory_yara` — runs a rule against the live process memory.
- `notify_slack` — bypasses the routing rule and fires a channel
  directly.

UI: `/playbooks` (list + edit) + `/playbooks/:id/runs` (timeline).

### Case sync — Jira / ServiceNow (#3.6)

Per-incident bidirectional sync. Outbound creates a ticket on
incident open; inbound polls for state changes and reflects them
back as `incident.state_changed` audit rows.

### Webhooks (#3.7)

HMAC-signed outbound deliveries to subscriber URLs. Each subscription
picks an event-type set (`alert.opened`, `incident.opened`, …); the
dispatcher fans the event to every matching subscription with a
detached `X-Vigil-Signature` header (`sha256=<hex>`). Failed deliveries
keep the Kafka offset (CODE-29 fix) so a stuck subscriber doesn't
drop events.

### SCIM 2.0 (#3.8)

IdP-side bulk user provisioning at `/scim/v2/Users` (and friends).
Authenticated via SCIM bearer token; the token now binds to a
tenant (PR 5l), so an Okta connection provisioned for tenant A
only ever populates tenant A's roster.

### AI summary + NL2query (#4.1)

Two surfaces, both gated behind `VIGIL_AI_ENABLED=true`:

- **Alert summary**: on alert open, a worker sends the alert's
  evidence to the configured LLM and persists a 3-line summary
  ("what triggered, why it matters, suggested next step"). The
  summary appears at the top of the alert detail page.
- **NL → hunt**: the hunt workbench's "Ask in natural language…"
  box translates English into the Lucene / KQL query language the
  hunt engine compiles. The translation is non-binding — operators
  see the compiled query before running.

Default backend is Ollama (`ollama serve` on the manager). Provider
+ model are env-configured.

### Identity sources (#4.3)

Okta + Azure AD integrations under `/api/identity-sources`. Polls
the IdP for sign-in events and synthesises Alerts for impossible-
travel, MFA fatigue, and stale-session anomalies. Tenant-scoped.

### Cloud IAM CloudTrail anomaly (#4.2)

AWS-only for now. The IAM-anomaly worker pulls CloudTrail, baselines
each role's "normal" event set, and alerts on a role-event combo
that's never been observed before in the last 30 days.

### Honeytoken decoys (#4.5)

Operator plants a decoy under `/honeytokens`. The agent writes the
sentinel onto the host (NTFS ADS marker on Windows; xattr on Linux
ext4/xfs/btrfs). Linux reads the marker back via a BPF kprobe on
`do_filp_open` and fires `HoneytokenHit`; Windows hit emission is
not currently wired (CODE-205 — the capability is stripped on
Windows until the registry-write ETW path lands).

### Cuckoo sandbox detonation (#4.4)

Submit a sample by SHA-256 + provider; the worker polls the sandbox
and folds the resulting verdict + extracted IOCs into the IOC list,
so a single detonation seeds future Sigma matches across the fleet.

### TPM-backed boot-state attestation (#4.10)

Status: Linux active, Windows pending Tbsi. The capability is
currently stripped on both targets (CODE-201/202 — see PR 8a).
When re-advertised: the agent reports PCRs alongside Hello; the
manager promotes a "golden" set on operator command; future quotes
that diverge from the golden raise a divergence alert.

## Production deployment

The default `make up` path is for development on a single box. A
production fleet usually wants:

- **Externally-managed Postgres** (RDS / Cloud SQL / on-prem patroni).
  Set `VIGIL_PG_DSN` to the runtime role (`vigil_manager`) and
  `VIGIL_PG_DSN_AUDIT` to the audit-writer role (`vigil_audit_writer`).
  Run `deploy/postgres-init.sql` once against the cluster to create
  both roles; the migrations are owned by the audit-writer.
- **Externally-managed OpenSearch** (AWS OpenSearch Service /
  self-hosted cluster). The manager talks to it over HTTPS with
  basic-auth; ILM is configured by the bootstrap job.
- **Externally-managed Kafka** (Redpanda Cloud / MSK / self-hosted).
  The manager workers join consumer groups; partition count + RF
  are operator-tuned.
- **HA manager** — run two FastAPI replicas behind a TLS-terminating
  reverse proxy; the gRPC ingest service is stateless and replicates
  cleanly. Redis is the alert broker + login-throttle backend; set
  `VIGIL_REDIS_URL` on every replica so all of them see the same
  fan-out.
- **Real CA** — the dev-time `dev-only-` CA master key is
  refuse-to-boot-checked. Provision a real intermediate CA cert + key
  and set `VIGIL_CA_DIR` to its location.
- **Real OIDC / IdP** — set the four `VIGIL_OIDC_*` env vars and
  point the IdP at `/api/auth/oidc/callback`. Pair with TOTP for
  defense-in-depth.

The exact runbook is operator-shaped (compose / k8s / nomad / VM);
this section enumerates the moving parts rather than prescribing one
layout.
