//! Command worker (M6.6) — Linux response actions.
//!
//! Mirrors `agent-windows/src/driver.rs::run_command_worker`. Receives
//! [`p::Command`] messages from the gRPC client, dispatches them to the
//! right OS primitive, and ships back a [`p::CommandResult`].
//!
//! - Kill: `kill(pid, SIGKILL)` via libc.
//! - BlockProcess / UnblockProcess: insert/remove a path into the
//!   `process_block` BPF hash map. The kernel's `lsm/bprm_check_security`
//!   then returns -EPERM on exec for matching paths.
//! - BlockFile / UnblockFile: same against the `file_block` map; kernel
//!   denies in `lsm/file_open`.
//!
//! Block lists persist to `{state_dir}/blocklist.json` and reload on
//! startup, mirroring the Windows REG_MULTI_SZ persistence.

#![cfg(target_os = "linux")]

use crate::ebpf::BlockListHandle;
use agent_core::event as ev;
use agent_core::jobs::JobDispatcher;
use agent_core::jobs_runtime::{build_context, Channel};
use agent_core::proto as p;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Identity carried into the command worker so it can author
/// EndpointEvents (e.g. quarantine_completed) on its own.
#[derive(Clone, Debug)]
pub struct WorkerIdentity {
    pub host_id: String,
    pub agent_id: String,
    pub agent_version: String,
}

/// Per-quarantine outcome captured by `quarantine_file` so we can
/// surface it as a QuarantineCompletedEvent without re-hashing the
/// file from the dispatch site.
#[derive(Clone, Debug)]
struct QuarantineOutcomeRecord {
    sha256: String,
    path: String,
    size_bytes: u64,
    deleted_original: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PersistedBlockLists {
    #[serde(default)]
    pub processes: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
}

/// Load block lists from `{state_dir}/blocklist.json` (if present), push
/// every entry into the kernel maps, and return the in-memory state for
/// future updates.
pub fn restore(state_dir: &Path, blocks: &BlockListHandle) -> Result<PersistedBlockLists> {
    let path = state_dir.join("blocklist.json");
    let state: PersistedBlockLists = if path.exists() {
        let s =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&s).with_context(|| format!("parse {}", path.display()))?
    } else {
        PersistedBlockLists::default()
    };
    for proc in &state.processes {
        if let Err(e) = blocks.block_process(proc) {
            tracing::warn!(path = %proc, error = %e, "blocklist.restore.process_failed");
        }
    }
    for f in &state.files {
        if let Err(e) = blocks.block_file(f) {
            tracing::warn!(path = %f, error = %e, "blocklist.restore.file_failed");
        }
    }
    tracing::info!(
        processes = state.processes.len(),
        files = state.files.len(),
        "blocklist.restored"
    );
    Ok(state)
}

fn persist(state_dir: &Path, state: &PersistedBlockLists) -> Result<()> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("mkdir -p {}", state_dir.display()))?;
    let path = state_dir.join("blocklist.json");
    let tmp = state_dir.join("blocklist.json.tmp");
    let s = serde_json::to_string_pretty(state)?;
    std::fs::write(&tmp, s).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    state_dir: PathBuf,
    blocks: BlockListHandle,
    dns_blocks: Option<crate::ebpf::DnsBlockHandle>,
    mut state: PersistedBlockLists,
    identity: WorkerIdentity,
    mut rx: mpsc::Receiver<p::Command>,
    send_tx: mpsc::Sender<p::ClientMessage>,
    job_dispatcher: Arc<JobDispatcher>,
    control_channel: Channel,
) {
    tracing::info!(
        kinds = ?job_dispatcher.supported_kinds(),
        "command_worker.jobs_dispatcher_ready"
    );
    while let Some(cmd) = rx.recv().await {
        let result = dispatch(
            &cmd,
            &state_dir,
            &blocks,
            dns_blocks.as_ref(),
            &mut state,
            &identity,
            &send_tx,
            &job_dispatcher,
            &control_channel,
        )
        .await;
        let (success, error) = match &result {
            Ok(()) => (true, String::new()),
            Err(e) => (false, format!("{e:#}")),
        };
        if !success {
            tracing::warn!(command_id = %cmd.command_id, error = %error, "command.failed");
        } else {
            tracing::info!(command_id = %cmd.command_id, "command.succeeded");
        }
        let cr = p::CommandResult {
            command_id: cmd.command_id.clone(),
            success,
            error,
            payload: Vec::new(),
        };
        let msg = p::ClientMessage {
            payload: Some(p::client_message::Payload::CommandResult(cr)),
        };
        let _ = send_tx.send(msg).await;
    }
}

async fn emit_quarantine_event(
    send_tx: &mpsc::Sender<p::ClientMessage>,
    identity: &WorkerIdentity,
    outcome: p::QuarantineOutcome,
    sha256: &str,
    path: &str,
    size_bytes: u64,
    deleted_original: bool,
) {
    let event = ev::quarantine_completed(
        &identity.host_id,
        &identity.agent_id,
        &identity.agent_version,
        outcome,
        sha256,
        path,
        size_bytes,
        deleted_original,
    );
    let batch = p::EventBatch {
        events: vec![event],
        batch_id: ulid::Ulid::new().to_string(),
        first_seq: 0,
        last_seq: 0,
    };
    let msg = p::ClientMessage {
        payload: Some(p::client_message::Payload::Events(batch)),
    };
    let _ = send_tx.send(msg).await;
}

#[allow(clippy::too_many_arguments)]
async fn dispatch(
    cmd: &p::Command,
    state_dir: &Path,
    blocks: &BlockListHandle,
    dns_blocks: Option<&crate::ebpf::DnsBlockHandle>,
    state: &mut PersistedBlockLists,
    identity: &WorkerIdentity,
    send_tx: &mpsc::Sender<p::ClientMessage>,
    job_dispatcher: &Arc<JobDispatcher>,
    control_channel: &Channel,
) -> Result<()> {
    use p::command::Body;
    let body = cmd
        .body
        .as_ref()
        .ok_or_else(|| anyhow!("command.body missing"))?;
    match body {
        Body::Kill(k) => {
            let pid = k.target.as_ref().map(|t| t.pid).unwrap_or(0);
            if pid == 0 {
                anyhow::bail!("kill.target.pid must be > 0");
            }
            kill_pid(pid)?;
        }
        Body::BlockProcess(b) => {
            let pat = b.pattern.clone();
            blocks.block_process(&pat)?;
            if !state.processes.iter().any(|p| p == &pat) {
                state.processes.push(pat);
                persist(state_dir, state)?;
            }
        }
        Body::BlockFile(b) => {
            let pat = b.pattern.clone();
            blocks.block_file(&pat)?;
            if !state.files.iter().any(|p| p == &pat) {
                state.files.push(pat);
                persist(state_dir, state)?;
            }
        }
        Body::UnblockProcess(b) => {
            let pat = b.pattern.clone();
            // Best-effort: remove from kernel even if not in our
            // persisted list; the user may be cleaning up.
            let _ = blocks.unblock_process(&pat);
            let before = state.processes.len();
            state.processes.retain(|p| p != &pat);
            if state.processes.len() != before {
                persist(state_dir, state)?;
            }
        }
        Body::UnblockFile(b) => {
            let pat = b.pattern.clone();
            let _ = blocks.unblock_file(&pat);
            let before = state.files.len();
            state.files.retain(|p| p != &pat);
            if state.files.len() != before {
                persist(state_dir, state)?;
            }
        }
        Body::Isolate(req) => {
            apply_network_isolation(state_dir, blocks, req.isolate, &req.allowlist_ips)?;
        }
        Body::QuarantineFile(req) => {
            match quarantine_file(state_dir, &req.path, req.delete_original) {
                Ok(Some(rec)) => {
                    emit_quarantine_event(
                        send_tx,
                        identity,
                        p::QuarantineOutcome::Quarantined,
                        &rec.sha256,
                        &rec.path,
                        rec.size_bytes,
                        rec.deleted_original,
                    )
                    .await;
                }
                Ok(None) => {
                    // Source already gone — idempotent no-op. Don't
                    // emit an event; manager has nothing to track.
                }
                Err(e) => {
                    emit_quarantine_event(
                        send_tx,
                        identity,
                        p::QuarantineOutcome::Failed,
                        "",
                        &req.path,
                        0,
                        false,
                    )
                    .await;
                    return Err(e);
                }
            }
        }
        Body::ReleaseQuarantine(req) => {
            match release_quarantine(state_dir, &req.sha256, &req.target_path) {
                Ok(rec) => {
                    emit_quarantine_event(
                        send_tx,
                        identity,
                        p::QuarantineOutcome::Released,
                        &rec.sha256,
                        &rec.path,
                        rec.size_bytes,
                        false,
                    )
                    .await;
                }
                Err(e) => {
                    emit_quarantine_event(
                        send_tx,
                        identity,
                        p::QuarantineOutcome::Failed,
                        &req.sha256,
                        &req.target_path,
                        0,
                        false,
                    )
                    .await;
                    return Err(e);
                }
            }
        }
        Body::ScanFile(_) | Body::ScanMemory(_) | Body::Update(_) => {
            anyhow::bail!("command kind not implemented on linux yet");
        }
        Body::DnsBlockSync(cmd) => match dns_blocks {
            Some(handle) => {
                let entries = cmd
                    .block_domains
                    .iter()
                    .map(|d| (d.clone(), crate::ebpf::DnsBlockAction::Block))
                    .chain(
                        cmd.sinkhole_domains
                            .iter()
                            .map(|d| (d.clone(), crate::ebpf::DnsBlockAction::Sinkhole)),
                    );
                handle.replace_all(entries)?;
                tracing::info!(
                    block_count = cmd.block_domains.len(),
                    sinkhole_count = cmd.sinkhole_domains.len(),
                    map_entries = handle.len().unwrap_or(0),
                    "dns_block.synced"
                );
            }
            None => {
                tracing::warn!("dns_block.handle_unavailable; agent built without DNS map support");
            }
        },
        Body::RunJob(cmd) => {
            if !job_dispatcher.supports(&cmd.job_kind) {
                anyhow::bail!(
                    "run_job: no handler for kind '{}' on linux (run_id={})",
                    cmd.job_kind,
                    cmd.run_id
                );
            }
            let params: serde_json::Value = if cmd.parameters_json.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_str(&cmd.parameters_json)
                    .with_context(|| format!("parse parameters_json for kind={}", cmd.job_kind))?
            };
            let ctx = build_context(
                cmd.run_id.clone(),
                cmd.job_kind.clone(),
                send_tx.clone(),
                control_channel.clone(),
            );
            job_dispatcher.dispatch(ctx, params).await?;
        }
    }
    Ok(())
}

fn kill_pid(pid: u32) -> Result<()> {
    // libc::kill returns 0 on success, -1 on error with errno set.
    let r = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("kill({pid}, SIGKILL): {err}");
    }
    Ok(())
}

/// M11.f: quarantine the file at `src` by moving it (or copying then
/// deleting) into `{state_dir}/quarantine/<sha256>.bin` with mode 0600
/// and SYSTEM ownership. Logs the SHA-256 + original path so the
/// operator can correlate via the audit log.
///
/// Returns Ok(()) even if the source file is already gone (idempotent
/// on operator double-clicks) but bails on any other I/O error.
fn quarantine_file(
    state_dir: &Path,
    src: &str,
    delete_original: bool,
) -> Result<Option<QuarantineOutcomeRecord>> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let src_path = std::path::Path::new(src);
    if !src_path.exists() {
        tracing::info!(path = src, "quarantine.skip_already_gone");
        return Ok(None);
    }
    if !src_path.is_file() {
        anyhow::bail!("quarantine: {src} is not a regular file");
    }

    // Hash the file content once so we can use the digest as the
    // quarantine basename. Avoids collisions when multiple variants of
    // the same file appear; identical bytes share a quarantine entry.
    let mut hasher = Sha256::new();
    let mut f = std::fs::File::open(src_path).with_context(|| format!("open {src}"))?;
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf).with_context(|| format!("read {src}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    drop(f);
    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    let qdir = state_dir.join("quarantine");
    std::fs::create_dir_all(&qdir).with_context(|| format!("mkdir -p {}", qdir.display()))?;
    let qpath = qdir.join(format!("{hex}.bin"));

    // Copy then optionally delete. If we're keeping the original we
    // still copy (so quarantine has a snapshot), but we don't error
    // on already-existing quarantine entry — re-copying the same
    // content is safe.
    if !qpath.exists() {
        std::fs::copy(src_path, &qpath)
            .with_context(|| format!("copy {src} -> {}", qpath.display()))?;
        // Tighten the mode after copy. The agent already runs as root,
        // so mode 0600 with default ownership is enough (no other user
        // can read).
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&qpath, std::fs::Permissions::from_mode(0o600)).ok();
    }

    if delete_original {
        std::fs::remove_file(src_path).with_context(|| format!("remove {src}"))?;
    }

    tracing::info!(
        path = src,
        sha256 = %&hex[..16],
        deleted = delete_original,
        quarantine = %qpath.display(),
        "quarantine.complete"
    );
    Ok(Some(QuarantineOutcomeRecord {
        sha256: hex,
        path: src.to_string(),
        size_bytes: total,
        deleted_original: delete_original,
    }))
}

/// M20.c: restore a quarantined file by copying
/// `{state_dir}/quarantine/<sha256>.bin` back to `target_path` and
/// removing the quarantine copy. Returns the restored size so we can
/// stamp the QuarantineCompletedEvent. Bails if the quarantine copy
/// is missing (operator already swept it) or target_path is empty.
fn release_quarantine(
    state_dir: &Path,
    sha256: &str,
    target_path: &str,
) -> Result<QuarantineOutcomeRecord> {
    if sha256.is_empty() {
        anyhow::bail!("release_quarantine: sha256 missing");
    }
    if target_path.is_empty() {
        anyhow::bail!("release_quarantine: target_path missing");
    }
    let qpath = state_dir.join("quarantine").join(format!("{sha256}.bin"));
    if !qpath.exists() {
        anyhow::bail!("release_quarantine: {} not in quarantine", qpath.display());
    }
    let dst = std::path::Path::new(target_path);
    if let Some(parent) = dst.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir -p {}", parent.display()))?;
        }
    }
    let size = std::fs::copy(&qpath, dst)
        .with_context(|| format!("copy {} -> {target_path}", qpath.display()))?;
    // Remove the quarantine copy now that the original is restored.
    // Errors here are non-fatal — the file is back on disk, the audit
    // log will note the leftover quarantine blob.
    if let Err(e) = std::fs::remove_file(&qpath) {
        tracing::warn!(
            error = %e,
            quarantine = %qpath.display(),
            "release_quarantine.cleanup_failed"
        );
    }
    tracing::info!(
        target = target_path,
        sha256 = %&sha256[..sha256.len().min(16)],
        size = size,
        "quarantine.release_complete"
    );
    Ok(QuarantineOutcomeRecord {
        sha256: sha256.to_string(),
        path: target_path.to_string(),
        size_bytes: size,
        deleted_original: false,
    })
}

/// M11.a + Phase 1 #1.3: enforce network isolation through two
/// independent layers.
///
///   1. **BPF LSM hook**: the kernel-side `lsm/socket_connect` hook
///      reads `isolation_state[0]` and the `manager_ip_allowlist` HASH
///      map and returns -EPERM for any outbound TCP/UDP connect whose
///      destination IP isn't in the allowlist. This is the
///      authoritative deny path: it fires before the network stack
///      ever sees the connect, can't be bypassed by reconfiguring
///      nftables, and survives nft daemon crashes.
///
///   2. **nftables**: defense-in-depth — drops anything that gets past
///      the BPF hook (e.g. if BPF LSM isn't enabled in the kernel) and
///      gives operators a familiar surface to inspect with `nft list
///      ruleset`. Also covers connectionless flows the LSM hook
///      doesn't catch.
///
/// Restore (`isolate=false`) clears both layers. Sentinel file at
/// `{state_dir}/isolated` lets us reapply on agent restart.
///
/// Requires CAP_NET_ADMIN — already in the systemd unit's
/// AmbientCapabilities. nftables is best-effort: if `nft` is absent
/// the BPF hook still enforces, but we log a warning so the operator
/// can spot the half-armed state.
fn apply_network_isolation(
    state_dir: &Path,
    blocks: &BlockListHandle,
    isolate: bool,
    allowlist_ips: &[String],
) -> Result<()> {
    use std::io::Write as _;
    use std::net::IpAddr;
    use std::process::{Command as Proc, Stdio};

    let sentinel = state_dir.join("isolated");

    if !isolate {
        // Restore: BPF first (so future connects pass even if nft
        // cleanup fails), then nft.
        if let Err(e) = blocks.set_isolation(false) {
            tracing::warn!(error = %e, "isolation.bpf_off_failed");
        }
        if let Err(e) = blocks.clear_allowlist() {
            tracing::warn!(error = %e, "isolation.bpf_clear_allowlist_failed");
        }
        let status = Proc::new("nft")
            .args(["delete", "table", "inet", "edr-isolation"])
            .stderr(Stdio::null())
            .status();
        if let Ok(s) = status {
            tracing::info!(exit = ?s.code(), "isolation.removed");
        }
        let _ = std::fs::remove_file(&sentinel);
        return Ok(());
    }

    // Parse + push the allowlist to BPF *first* so the LSM hook is
    // ready before we flip the state flag. Without that ordering, a
    // connect that lands between `set_isolation(true)` and the first
    // `allow_ip` would be denied even if the operator listed its
    // destination.
    let parsed: Vec<IpAddr> = allowlist_ips
        .iter()
        .filter_map(|s| {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                match t.parse::<IpAddr>() {
                    Ok(ip) => Some(ip),
                    Err(_) => {
                        tracing::warn!(ip = %t, "isolation.allowlist.parse_failed");
                        None
                    }
                }
            }
        })
        .collect();

    // Reset BPF allowlist before re-populating so a repeated isolate
    // with a smaller allowlist doesn't leave stale entries reachable.
    if let Err(e) = blocks.clear_allowlist() {
        tracing::warn!(error = %e, "isolation.bpf_clear_allowlist_failed");
    }
    for ip in &parsed {
        if let Err(e) = blocks.allow_ip(*ip) {
            tracing::warn!(ip = %ip, error = %e, "isolation.bpf_allow_ip_failed");
        }
    }
    if let Err(e) = blocks.set_isolation(true) {
        tracing::error!(error = %e, "isolation.bpf_on_failed");
        // BPF enforcement failed — don't try to fall back to nft alone;
        // surface so the manager records the failure and the operator
        // can investigate (likely an out-of-date kernel without BPF LSM).
        return Err(anyhow::anyhow!("set_isolation(true): {e}"));
    }

    let mut ruleset = String::from(
        "table inet edr-isolation {\n  chain output {\n    type filter hook output priority 0; policy accept;\n",
    );
    // Always allow loopback + DNS + NTP + DHCP renewals.
    ruleset.push_str("    oifname \"lo\" accept\n");
    ruleset.push_str("    udp dport 53 accept\n");
    ruleset.push_str("    udp dport 123 accept\n");
    ruleset.push_str("    udp dport 67 accept\n");
    ruleset.push_str("    udp dport 68 accept\n");
    // Operator-supplied allowlist: each IP must be valid; we render
    // both v4 and v6 lines so the chain is `inet`-family safe.
    for ip in allowlist_ips {
        let ip = ip.trim();
        if ip.is_empty() {
            continue;
        }
        if ip.contains(':') {
            ruleset.push_str(&format!("    ip6 daddr {ip} accept\n"));
        } else {
            ruleset.push_str(&format!("    ip daddr {ip} accept\n"));
        }
    }
    // Default deny.
    ruleset.push_str("    counter drop\n  }\n}\n");

    let nft_result = (|| -> Result<()> {
        let mut child = Proc::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| "spawn nft (is nftables installed?)")?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(ruleset.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            anyhow::bail!("nft -f failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(())
    })();
    if let Err(e) = nft_result {
        // BPF is already armed; nft is best-effort defense-in-depth.
        // Log the failure but don't unwind isolation.
        tracing::warn!(error = %e, "isolation.nft_apply_failed (BPF still enforcing)");
    }
    std::fs::create_dir_all(state_dir).ok();
    std::fs::write(&sentinel, &ruleset).ok();
    tracing::info!(
        allowlist = allowlist_ips.len(),
        parsed = parsed.len(),
        "isolation.applied"
    );
    Ok(())
}
