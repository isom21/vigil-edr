# Threat model — EDR PoC

This document scopes what the EDR PoC defends against, what it does
*not* defend against, and where the explicit gaps are. It is the
companion to `operator-guide.md` and `rbac.md`. Audience: anyone
deploying or operating the agent + manager.

The PoC is a **defensive-monitoring + response-action tool** that
trades depth for breadth: we cover process / file / network / module
load on both Linux (eBPF LSM) and Windows (KMDF + minifilter), with
explicit kill / block-process / block-file response actions and
self-protection on both sides. We are **not** an EDR-bypass research
platform, a kernel-rootkit detector, or a NIDS.

## In scope

### Telemetry collection (M2 / M4 / M6)

We collect a high-confidence subset of endpoint activity:

- Process create + exit (image path, command line, parent pid).
- Image / kernel module load.
- File open + create + write (path, hash on demand).
- Outbound network connect, IPv4 + IPv6, 5-tuple + process attribution
  (kernel-side only — see "out of scope" below for plaintext-after-TLS).
- Registry create / set / delete (Windows only).

Collection survives:

- An attacker without root / Administrator privileges (DAC + capability
  set rejects access to driver / agent state).
- A user-mode adversary who knows the agent's pid (M7.1 / M7.2
  self-protection — see below).
- An agent crash within 1–2 seconds (systemd Restart=always on Linux,
  scheduled-task RestartOnFailure on Windows).

### Self-protection (M7.1 Linux / M7.2 Windows)

The agent process and its on-disk state survive a same-box
root / Administrator attacker who tries to:

| Attack | Linux defense | Windows defense |
|---|---|---|
| `kill -9` / `taskkill /F` against agent pid | `lsm/task_kill` returns EPERM (init carve-out for `systemctl stop`) | `ObRegisterCallbacks` strips `PROCESS_TERMINATE` from non-self handles |
| `gdb -p` / `Stop-Process -Force` | Same as above (signals route through `task_kill`) / Same as above |
| `ptrace(PTRACE_ATTACH)` / `ReadProcessMemory` | `lsm/ptrace_access_check` + `prctl(PR_SET_DUMPABLE,0)` | `ObRegisterCallbacks` strips `PROCESS_VM_READ`/`VM_WRITE` |
| `bpftool prog detach` / `bpftool link detach` | `lsm/bpf` rejects DETACH from non-self callers | (N/A on Windows) |
| `rm /sys/fs/bpf/edr/links/*` | `lsm/inode_unlink` rejects unlinks under protected dirs | (N/A on Windows) |
| `rm /var/lib/edr/*` (state, identity material) | `lsm/inode_unlink` rejects unlinks under state dir | ProgramData ACL: SYSTEM + Administrators only |

Crash survivability on Linux: BPF programs and links are pinned to
`/sys/fs/bpf/edr/`, so the LSM hooks keep enforcing even if the agent
process is killed. On agent restart, a takeover protocol claims the
old pinned `agent_self` map and unpins cleanly before reloading.

Crash survivability on Windows: scheduled-task RestartOnFailure brings
the agent back within a minute. Driver-side `ObCallbacks` clear their
protected pid via `PsCreateProcessNotifyRoutineEx` exit branch when
the agent exits, so a future process inheriting the pid doesn't get
spuriously protected.

### RBAC (M7.5)

- Per-host visibility: non-admin users see only hosts in their
  assigned `HostGroup`s. Applies to host list, alerts, and command
  queue.
- Three roles (`admin`, `analyst`, `viewer`) with role-gated routes.
- Append-only audit log for every state-changing action.
- API tokens (machine accounts) inherit a fixed role + are
  individually revocable.

## Out of scope

The PoC explicitly **does not** defend against:

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

- Linux: lockdown LSM in integrity mode, `chattr +i /usr/bin/edr-agent`,
  Secure Boot with shim-validated kernel modules.
- Windows: HVCI / Memory Integrity, Secure Boot, attestation-signed
  EDR driver via Microsoft (post-PoC requires WHQL + cross-signed cert).

### Plaintext-before-TLS network visibility

The kernel WFP callouts on Windows and `lsm/socket_connect` on Linux
fire **before** TLS encryption is layered on. We get the 5-tuple +
process attribution, but the *bytes* are still pre-TCP-stack. Capturing
plaintext-after-TLS requires user-mode SChannel hooks (DLL injection)
or a system-wide TLS-MITM proxy with a trusted root CA, both of which
are tracked as a separate future project (see SESSION_HANDOFF §1).

### Privileged operator turning the agent off

`systemctl stop edr-agent` (Linux) or `Stop-ScheduledTask` (Windows)
both succeed for an Administrator. This is intentional — the operator
must be able to stop the agent for maintenance. Detection: alert when
the agent disconnects gracefully (heartbeat gap), which the manager
already infers from `last_seen_at`.

Mitigations: SCM ACL hardening (deny `SC_MANAGER_STOP` to non-admins
even in the Administrators group via custom service DACL); systemd
unit `RefuseManualStop=true` plus a separate `edr-agent-watchdog.service`
that re-enables. Tracked as future polish.

### Disk forensics on a powered-down endpoint

Identity material and the blocklist live unencrypted under
`/var/lib/edr` and `C:\ProgramData\EDR`. An attacker with full disk
access (cold boot, stolen laptop without FDE) can read keys + replay
mTLS to impersonate the host, until the operator revokes the cert via
`/api/hosts/{id}` PATCH.

Mitigation: full-disk encryption at the OS level (LUKS, BitLocker).
The PoC doesn't ship its own at-rest encryption.

### Supply-chain attacks on dependencies

We don't pin transitive deps via `cargo deny` audits; we don't reproduce
builds; we don't sign packages. Tracked as future polish for the M7.3
deb/rpm and M7.4 Windows installer.

### Anti-malware bypass against the response actions

On Windows, Defender's behavioral signatures fire faster than our
`IOCTL_EDR_KILL_PROCESS` against well-known names like `mimikatz.exe`.
This is documented in the feedback memory `disable Defender for EDR
tests`; in production it's a feature, not a bug. The block path
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
  certs for any host_id. M7.8 follow-up: rotate the CA, support a
  hardware-backed signing key (pkcs11) for the manager.
- The dev-host that builds packages is trusted. Compiled binaries are
  signed only by a self-signed test cert in the PoC; production
  needs WHQL / Microsoft attestation signing for the Windows driver
  and a real codesigning cert for the agent binaries.
- Operators don't share API tokens, don't enable
  `EDR_DISABLE_SELF_PROTECTION=1` in production, and rotate
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
- Multi-tenant deployments (post-M7.5 RBAC): need per-tenant data
  isolation guarantees; currently the manager's PG schema is single-tenant.
