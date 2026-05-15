# Threat model

This document scopes what Vigil defends against, what it does
*not* defend against, and where the explicit gaps are. Companion to
`operator-guide.md` and `rbac.md`. Audience: anyone deploying or
operating the agent + manager.

The product is a **defensive-monitoring + response-action tool** that
trades depth for breadth: we cover process / file / network / module
load on both Linux (eBPF LSM) and Windows (KMDF + minifilter), with
explicit kill / block-process / block-file / quarantine-file response
actions and self-protection on both sides. We are **not** an EDR-bypass
research platform, a kernel-rootkit detector, or a NIDS.

## In scope

### Telemetry collection (M2 / M4 / M6 + Phase 1-4 expansions)

We collect a high-confidence subset of endpoint activity:

- Process create + exit (image path, command line, parent pid).
- Image / kernel module load.
- File open + create + write (path, hash on demand).
- Outbound network connect, IPv4 + IPv6, 5-tuple + process attribution
  (kernel-side only — see "out of scope" below for plaintext-after-TLS).
- Registry create / set / delete (Windows only).
- **DNS queries + responses** (Phase 2 #2.12) — both for sinkhole
  enforcement and for upstream Sigma `dns.name` rules.
- **Authentication events** (Phase 2 #2.5) — successful + failed
  logins, sudo invocations, su, ssh accept, RDP logon, UAC elevation.
  Linux: auditd + sshd journal; Windows: Security ETW provider.
- **Container metadata enrichment** (Phase 2 #2.13) — every process /
  file / network event gets the originating container id + image +
  pod name when one is detected (cgroup walk + containerd / docker
  introspection).
- **Cloud telemetry — AWS CloudTrail** (Phase 4 #4.2) — pulled from
  the configured trail, baselined per IAM role, anomalies surface
  as Alerts.
- **Identity-source events** (Phase 4 #4.3) — Okta + Azure AD
  sign-ins via the IdP's reporting API. Anomaly detectors flag
  impossible-travel, MFA fatigue, stale-session reuse.

Collection survives:

- An attacker without root / Administrator privileges (DAC + capability
  set rejects access to driver / agent state).
- A user-mode adversary who knows the agent's pid (kernel-enforced
  self-protection — see below).
- An agent crash within 1–2 seconds (systemd Restart=always on Linux,
  scheduled-task RestartOnFailure on Windows).

### Self-protection

The agent process and its on-disk state survive a same-box
root / Administrator attacker who tries to:

| Attack | Linux defense | Windows defense |
|---|---|---|
| `kill -9` / `taskkill /F` against agent pid | `lsm/task_kill` returns EPERM (init carve-out for `systemctl stop`) | `ObRegisterCallbacks` strips `PROCESS_TERMINATE` from non-self handles |
| `gdb -p` / `Stop-Process -Force` | Same as above (signals route through `task_kill`) / Same as above |
| `ptrace(PTRACE_ATTACH)` / `ReadProcessMemory` | `lsm/ptrace_access_check` + `prctl(PR_SET_DUMPABLE,0)` | `ObRegisterCallbacks` strips `PROCESS_VM_READ`/`VM_WRITE` |
| `bpftool prog detach` / `bpftool link detach` | `lsm/bpf` rejects DETACH from non-self callers | (N/A on Windows) |
| `bpftool map update id <agent_self>` | `lsm/bpf` rejects `BPF_MAP_UPDATE_ELEM` / `BPF_MAP_DELETE_ELEM` from non-self callers when an agent has claimed the slot | (N/A on Windows) |
| `rm /sys/fs/bpf/vigil/links/*` | `lsm/inode_unlink` rejects unlinks under protected dirs | (N/A on Windows) |
| `rm /var/lib/vigil/*` (state, identity material) | `lsm/inode_unlink` rejects unlinks under state dir | ProgramData ACL: SYSTEM + Administrators only |

Crash survivability on Linux: BPF programs and links are pinned to
`/sys/fs/bpf/vigil/`, so the LSM hooks keep enforcing even if the agent
process is killed.

Takeover protocol (Linux): the older "next agent writes its tgid into
the old `agent_self` map" path is gone — that was the bypass the
reviewer flagged in M7.1.b, since a non-self caller could write any
tgid into the map and redirect every LSM hook's protection target to
a process of their choosing. Instead:

  * `lsm/bpf` rejects `BPF_MAP_UPDATE_ELEM` / `BPF_MAP_DELETE_ELEM`
    from any non-self caller when `self_tgid() != 0`. The
    `bpftool map update` path no longer reaches the slot at all.
  * The `tracepoint/sched/sched_process_exit` program watches for the
    agent's tgid exiting (crash or graceful) and zeroes
    `agent_self[0]` from kernel context — kernel-side BPF map writes
    are not subject to `lsm/bpf`, so this fires reliably.
  * The next agent's `cleanup_or_takeover` reads `agent_self[0]`. If
    it's `0`, claim via the normal initial-load path
    (`self_tgid() == 0` is the documented carve-out that lets a fresh
    agent write its own tgid). If it's a live tgid, refuse to start
    — another vigil-agent is running. If it's a dead tgid (kernel
    quirk where the exit tracepoint didn't fire), log loudly and
    continue; the old pinned map gets unlinked on the way to a fresh
    load.

Crash survivability on Windows: scheduled-task RestartOnFailure brings
the agent back within a minute. Driver-side `ObCallbacks` clear their
protected pid via `PsCreateProcessNotifyRoutineEx` exit branch when
the agent exits, so a future process inheriting the pid doesn't get
spuriously protected.

### RBAC

- Per-host visibility: non-admin users see only hosts in their
  assigned `HostGroup`s. Applies to host list, alerts, and command
  queue.
- Three roles (`admin`, `analyst`, `viewer`) with role-gated routes.
- Append-only audit log for every state-changing action — enforced
  at the DB role level (`audit_log` is owned by `vigil_audit_writer`;
  the manager's runtime user has only `SELECT, INSERT`; `UPDATE` /
  `DELETE` / `TRUNCATE` raise `InsufficientPrivilege`) **and**
  tamper-evident via an HMAC chain (`VIGIL_AUDIT_HMAC_KEY`). The
  chain is the trip-wire if the role split is ever bypassed (e.g.
  someone restores the volume to a snapshot with a less-restrictive
  schema). Co-locating the HMAC key with the manager means a
  manager-host compromise can rewrite history *and* recompute the
  chain — externalize the key (HSM / KMS / vault) when the threat
  model includes a manager-host attacker.
- API tokens (machine accounts) inherit a fixed role + are
  individually revocable.

### Phase 3 / 4 surface additions

Each of the items below expanded the manager + agent surface
post-M7. The threat-model entries here are intentionally narrow —
"what's new in the trust boundary" — rather than re-deriving each
feature. See [`operator-guide.md → Phase 3 / 4 features`](operator-guide.md#phase-3-4)
for the operator-facing side.

| Feature | Trust-boundary expansion | Mitigation |
|---|---|---|
| **TPM-backed boot-state attestation** (Phase 4 #4.10) | Manager promotes a "golden" PCR set per host; subsequent quotes that diverge raise an alert. The quote is signed by the host's TPM Attestation Key — the manager must store the AK cert fingerprint and refuse quotes signed by unknown AKs. Linux path active; Windows path pending Tbsi (capability currently stripped, CODE-201/202). | AK cert pinning, refuse quote on AK rotation without operator opt-in. |
| **Honeytoken decoys** (Phase 4 #4.5) | Operator-authored decoy paths + regkeys + creds are stored in `honeytokens` table. A read leak would tell an attacker which decoys to avoid. | RBAC: only admins see the full token surface; analysts see hits but not the underlying sentinel paths. |
| **Cuckoo sandbox detonation** (Phase 4 #4.4) | The manager submits samples to an external sandbox + ingests the verdict back as IOCs. A poisoned sandbox can seed false-positive IOCs across the fleet. | Operator pins the sandbox URL + API key in `detonation_provider` config; sandbox results are gated through the operator-approved provider list. |
| **Agent rollout** (Phase 3 #3.3) | A bad rollout cohort can ship a broken agent build to N hosts. The auto-rollback monitor watches the breaker rule and halts the rollout when failures exceed the configured threshold. | Cohort sizing + breaker. Operator-side: stage rollouts through a small canary group first. |
| **Outbound webhooks** (Phase 3 #3.7) | The manager makes HTTPS POSTs to operator-configured URLs. A misconfigured subscriber URL leaks alert metadata; a malicious one phishes the recipient. | HMAC-signed payloads (`X-Vigil-Signature`); secret rotation via `POST /api/webhooks/:id/rotate`. Per-tenant; never receives credentials. |
| **Playbooks** (Phase 3 #3.5) | YAML response chains that fan `Command` rows out to hosts automatically. A malicious playbook author with admin can craft a chain that, e.g., isolates every host. | Admin-only authoring + audit on every playbook write. Per-tenant scope (PR 5e). The list of supported step kinds is intentionally narrow. |
| **AI summary + NL→query** (Phase 4 #4.1) | Each alert open hits an LLM; user-typed natural language flows into the hunt engine via the LLM. A compromised LLM provider can read alert evidence + return adversarial output that tricks operators. | LLM gated behind `VIGIL_AI_ENABLED=true`; the translated query is shown before execution; provider URL pinned in config. Default backend is local Ollama. See ADR 0009. |

### External-feed trust (STIX / ATT&CK / abuse.ch / NVD)

STIX/TAXII intel feeds (Phase 1 #1.9) ingest IOCs from external
sources. A poisoned upstream feed can seed bogus IOC matches that
fire `block` actions across the fleet.

Mitigation:

- Feed credentials are Fernet-encrypted at rest under
  `VIGIL_INTEL_ENCRYPTION_KEY`; rotating a leaked feed credential
  is supported.
- Feeds are tenant-scoped (PR 5g / CODE-10): a poisoned feed in
  tenant A cannot inject into tenant B.
- Operators can pin the feed kind, URL, and pull cadence; review
  the curated abuse.ch + ATT&CK packs as the reference shape.
- The IOC list a feed materialises is editable post-pull — analysts
  can mark a feed-injected IOC as suppressed without disabling the
  whole feed.
- We have no signature verification on upstream IOC content; if
  an upstream is compromised, the next pull will pull the bad data.
  Operator-side: disable the feed promptly when an upstream incident
  is known.

## Out of scope

The product explicitly **does not** defend against:

### Kernel-mode adversary

If the attacker can:
- Load their own kernel module / `.sys`, or
- Replace the agent binary on disk before the agent starts, or
- Disable BPF LSM in `/sys/kernel/security/lsm` and reboot, or
- (Windows) Disable `bcdedit /set testsigning` and reboot, or
- Patch the kernel's Object Manager, lsm hook table, or syscall table,

…then they can defeat self-protection. This is the standard
"tampering with the trusted computing base" gap.

Mitigations the operator can layer on top:

- Linux: lockdown LSM in integrity mode, `chattr +i /usr/bin/vigil-agent`,
  Secure Boot with shim-validated kernel modules.
- Windows: HVCI / Memory Integrity, Secure Boot, attestation-signed
  Vigil driver via Microsoft (requires WHQL + cross-signed cert; see
  README "What's not included").

### Plaintext-before-TLS network visibility

The kernel WFP callouts on Windows and `lsm/socket_connect` on Linux
fire **before** TLS encryption is layered on. We get the 5-tuple +
process attribution, but the *bytes* are still pre-TCP-stack. Capturing
plaintext-after-TLS requires user-mode SChannel hooks (DLL injection)
or a system-wide TLS-MITM proxy with a trusted root CA. Both are
out of scope for this codebase.

### Privileged operator turning the agent off

`systemctl stop vigil-agent` (Linux) or `Stop-ScheduledTask` (Windows)
both succeed for an Administrator. This is intentional — the operator
must be able to stop the agent for maintenance. Detection: alert when
the agent disconnects gracefully (heartbeat gap), which the manager
already infers from `last_seen_at`.

Mitigations: SCM ACL hardening (deny `SC_MANAGER_STOP` to non-admins
even in the Administrators group via custom service DACL); systemd
unit `RefuseManualStop=true` plus a separate `vigil-agent-watchdog.service`
that re-enables. Tracked as future polish.

### Disk forensics on a powered-down endpoint

Identity material and the blocklist live unencrypted under
`/var/lib/vigil` and `C:\ProgramData\Vigil`. An attacker with full disk
access (cold boot, stolen laptop without FDE) can read keys + replay
mTLS to impersonate the host, until the operator revokes the cert via
`/api/hosts/{id}` PATCH.

Mitigation: full-disk encryption at the OS level (LUKS, BitLocker).
The agent doesn't ship its own at-rest encryption.

### Supply-chain attacks on dependencies

`cargo deny` + `cargo audit` are wired into CI and gate the dep
graph against the RustSec advisory database, with a small set of
deliberate ignores documented in `deny.toml` and `.cargo/audit.toml`
(each tied to an upstream-bump path). `pip-audit` covers the Python
side. We don't currently produce reproducible builds and we don't
sign packages — see README "What's not included".

### Anti-malware bypass against the response actions

On Windows, Defender's behavioral signatures fire faster than our
`IOCTL_VIGIL_KILL_PROCESS` against well-known names like
`mimikatz.exe`. In a lab where you want to confirm Vigil's kill path
specifically, disable Defender's real-time protection with
`Set-MpPreference -DisableRealtimeMonitoring $true`. In production
Defender racing us is a feature, not a bug. The block path
(`STATUS_ACCESS_DENIED` at `PsCreateProcessNotifyRoutineEx`) runs
before any AV signature scan and is unaffected.

On Linux, no equivalent racing security tool by default; SELinux
in enforcing mode would interact, but the BPF LSM stacking model
means our `-EPERM` returns are visible alongside SELinux's.

## Assumptions

- The host kernel is not actively malicious. We trust that
  `BPF_PROG_TYPE_LSM` returns are honored by `security_*` dispatchers,
  that `ObRegisterCallbacks` pre-op return values are honored by
  `ObOpenObjectByPointer`, and that bpffs / Object Manager don't lie
  to us. A deeper attacker can subvert these — see "Kernel-mode
  adversary" above.
- The manager-side TLS PKI is trusted: the CA's private key on the
  manager is not exfiltrated. Compromising it lets an attacker mint
  certs for any host_id. Operator-side mitigation: rotate the CA
  on a periodic schedule and consider a hardware-backed signing key
  (pkcs11) for the manager.
- The dev-host that builds packages is trusted. Compiled binaries are
  signed only by a self-signed test cert by default; production
  needs WHQL / Microsoft attestation signing for the Windows driver
  and a real Authenticode codesigning cert for the agent binaries
  (see README "What's not included").
- Operators don't share API tokens, don't enable
  `VIGIL_DISABLE_SELF_PROTECTION=1` in production, and rotate
  enrollment tokens via the manager.

## What changes the calculus

Conditions under which the threat model needs revisiting:

- Adding the user-mode SChannel hook for plaintext-after-TLS visibility
  (separate future project): expands attack surface considerably; the
  injected DLL becomes another high-value target.
- Adding kernel-side hash-allowlisting for "known-good" processes:
  expands the trusted-computing-base to include the hash list, which
  must then be signed and rotated.
- Adding peer-to-peer agent communication (e.g. for distributed
  detection): expands attack surface to inter-agent comms.
- **Multi-tenant deployments**: per-tenant isolation shipped in
  Phase 3 #3.1 + PR 5a-5l. Every operator-managed resource is now
  tenant-scoped; cross-tenant access surfaces as 404 (existence
  stays opaque). See [`rbac.md → Tenancy`](rbac.md#tenancy-phase-3-31)
  for the full table of scoped resources. Threat-model items
  specific to tenancy: a super-admin compromise still grants
  cross-tenant access; rotate super-admin credentials separately
  from per-tenant admin credentials.
