# Self-protection depth (M12)

> **Status:** scaffolded. M12 ships the binary-integrity check on
> agent startup (Linux + Windows) and an `lsm/inode_setattr` hook
> that prevents `chattr -i` from non-self callers. The remaining
> depth items (WDAC policy, Threat Intelligence rules, image-load
> veto, lsm/bpf altitude protection, SCM service ACL hardening,
> systemd RefuseManualStop pairing) sequence as M12.b through M12.g.

## What M7.1 + M7.2 already give us

The baseline is good:

- Linux: lsm/task_kill + lsm/ptrace_access_check + lsm/bpf +
  lsm/inode_unlink/rmdir/rename + program/link pinning. Defends the
  running agent + state dir against same-box root.
- Windows: ObRegisterCallbacks pre-op handlers strip dangerous access
  bits from non-self handles to the agent / threads. Tight ProgramData
  ACL on state.

What's missing:

| Surface | Gap | Substage |
|---|---|---|
| Binary-on-disk integrity | M7.2 covers process-side; binary at rest is unchecked | **M12.a (this commit)** |
| Linux `chattr -i` defense | postinst sets `+i` but rm of the binary file path can be undone via `chattr -i` from root | **M12.a (this commit, lsm/inode_setattr)** |
| Windows WDAC policy snippet | Manifest pinning agent + driver hashes | M12.b |
| Microsoft-Windows-Threat-Intelligence ETW rules | Subscribed in M10 telemetry; no detection rules consume the events yet | M12.c |
| Image-load veto for agent process | Linux `lsm/file_mprotect` + Windows ObCallbacks for handle-to-section | M12.d |
| `lsm/bpf` altitude defense | Reject `BPF_PROG_LOAD` of LSM programs at altitudes near ours that always-return-0 | M12.e |
| SCM service ACL hardening | Deny SC_MANAGER_STOP from non-admin Administrators | M12.f |
| systemd `RefuseManualStop` + watchdog unit | Pair with auto-restart unit so even an admin's `systemctl stop` is detected and reverted | M12.g |
| ELAM cert / true PPL on Windows | Requires Microsoft Virus Initiative membership | **M19 paid** |

## M12.a — Binary integrity + chattr defense (this commit)

**Goal**: agent refuses to start if its own binary on disk doesn't
match the manifest hash, AND root can't undo the immutable flag we
set in the deb/rpm postinst.

### Binary-hash check

The deb/rpm postinst writes the binary's SHA-256 to
`/etc/edr/agent.sha256` after install. On startup, the agent re-hashes
its `/proc/self/exe` and refuses to start if the hash mismatches.

This catches an attacker who has overwritten the binary on disk while
the agent was stopped (the M7.1 / M7.2 self-protection only protects
the running process; nothing covers cold-on-disk integrity).

The manifest hash is also reported to the manager as part of
`AgentMetrics.binary_sha256` (M9.4 follow-up field; populated here as
zero-default until the next proto bump). Manager logs a warning if
the value drifts across heartbeats from the same host.

### Linux `chattr -i` defense

New BPF LSM hook `lsm/inode_setattr` rejects attempts to clear the
immutable flag (FS_IMMUTABLE_FL) on inodes the agent has marked as
protected. The postinst calls a new IOCTL (M12.a continuation) to
register `/usr/bin/edr-agent` and `/usr/sbin/edr.sys`-equivalents.
The hook applies the same caller-tgid check used by lsm/task_kill —
only the agent itself can clear the flag.

The simpler version landing in this commit: the LSM hook unconditionally
rejects *any* `chattr -i` against the protected inode list (which is
populated at agent startup from the M7.1 `protected_inodes` map's twin).
Future M12.a-b refines to allow operator-driven `--unfreeze` flow.

### Test

After install, run as root:

    chattr -i /usr/bin/edr-agent

Expected: `Operation not permitted`. The flag stays set.

After agent stop + on-disk tamper:

    sudo systemctl stop edr-agent
    sudo cp /tmp/evil-replacement /usr/bin/edr-agent
    sudo systemctl start edr-agent

Expected: agent refuses to start. journal shows
`agent.binary_integrity.mismatch expected=<hex> actual=<hex>`.

## M12.b – M12.g — Sequenced

Same shape as M11's roadmap: each substage one focused commit, all
slotting into existing infrastructure (proto schema, BPF C, ObCallbacks).

The hardest of these is **M12.f SCM service ACL hardening** — Windows
service DACLs don't expose a clean "deny stop from a specific group"
primitive; we work around via `sc.exe sdset` with a manually-crafted
SDDL. Documented in M12.f's commit message when it lands.
