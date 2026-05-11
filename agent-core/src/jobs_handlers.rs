//! Cross-platform [`JobHandler`] implementations.
//!
//! These run on both Linux and Windows. Platform-specific handlers
//! (Windows registry_query, USB history, etc.) live in `agent-windows`
//! and `agent-linux`. The handlers here are intentionally restricted
//! to read-only, non-privileged operations so analysts can run them
//! against any host without elevation prompts on the agent side.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sysinfo::{Networks, ProcessesToUpdate, System, Users};

use crate::jobs::{ArtifactKind, ArtifactSpec, JobContext, JobHandler};

// ---------------- process_snapshot ----------------

#[derive(Serialize)]
struct ProcessRow {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    executable: Option<String>,
    command_line: Vec<String>,
    user: Option<String>,
    start_time_unix: u64,
    cpu_pct: f32,
    rss_bytes: u64,
}

#[derive(Serialize)]
struct ProcessSnapshot {
    hostname: Option<String>,
    os_name: Option<String>,
    kernel: Option<String>,
    collected_at_unix: u64,
    process_count: usize,
    processes: Vec<ProcessRow>,
}

pub struct ProcessSnapshotHandler;

#[async_trait]
impl JobHandler for ProcessSnapshotHandler {
    fn kind(&self) -> &'static str {
        "process_snapshot"
    }

    async fn run(&self, ctx: &JobContext, _params: JsonValue) -> Result<()> {
        ctx.reporter
            .progress(5, Some("enumerating processes".into()))
            .await;

        // sysinfo refresh is sync + CPU-bound — run it on a blocking thread.
        let snapshot = tokio::task::spawn_blocking(collect_process_snapshot)
            .await
            .map_err(|e| anyhow!("join: {e}"))??;

        ctx.reporter
            .progress(
                70,
                Some(format!("collected {} processes", snapshot.process_count)),
            )
            .await;

        let body = serde_json::to_vec_pretty(&snapshot).context("serialize snapshot")?;
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::Json,
                    original_filename: "process_snapshot.json".into(),
                    metadata: serde_json::json!({
                        "process_count": snapshot.process_count,
                    }),
                },
                body,
            )
            .await?;
        ctx.reporter.progress(100, None).await;
        Ok(())
    }
}

fn collect_process_snapshot() -> Result<ProcessSnapshot> {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let users = Users::new_with_refreshed_list();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut rows: Vec<ProcessRow> = sys
        .processes()
        .iter()
        .map(|(pid, p)| ProcessRow {
            pid: pid.as_u32(),
            parent_pid: p.parent().map(|pp| pp.as_u32()),
            name: p.name().to_string_lossy().to_string(),
            executable: p.exe().map(|e| e.display().to_string()),
            command_line: p
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect(),
            user: p
                .user_id()
                .and_then(|uid| users.get_user_by_id(uid))
                .map(|u| u.name().to_string()),
            start_time_unix: p.start_time(),
            cpu_pct: p.cpu_usage(),
            rss_bytes: p.memory(),
        })
        .collect();
    rows.sort_unstable_by_key(|r| r.pid);

    Ok(ProcessSnapshot {
        hostname: System::host_name(),
        os_name: System::name(),
        kernel: System::kernel_version(),
        collected_at_unix: now,
        process_count: rows.len(),
        processes: rows,
    })
}

// ---------------- network_snapshot ----------------

#[derive(Serialize)]
struct NetworkInterface {
    name: String,
    mac: String,
    received_bytes: u64,
    transmitted_bytes: u64,
    received_packets: u64,
    transmitted_packets: u64,
    errors_in: u64,
    errors_out: u64,
}

#[derive(Serialize)]
struct NetworkSnapshot {
    hostname: Option<String>,
    collected_at_unix: u64,
    interfaces: Vec<NetworkInterface>,
}

pub struct NetworkSnapshotHandler;

#[async_trait]
impl JobHandler for NetworkSnapshotHandler {
    fn kind(&self) -> &'static str {
        "network_snapshot"
    }
    async fn run(&self, ctx: &JobContext, _params: JsonValue) -> Result<()> {
        ctx.reporter
            .progress(10, Some("enumerating interfaces".into()))
            .await;
        let snap = tokio::task::spawn_blocking(collect_network_snapshot)
            .await
            .map_err(|e| anyhow!("join: {e}"))??;
        ctx.reporter
            .progress(80, Some(format!("{} interfaces", snap.interfaces.len())))
            .await;
        let body = serde_json::to_vec_pretty(&snap).context("serialize")?;
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::Json,
                    original_filename: "network_snapshot.json".into(),
                    metadata: serde_json::json!({
                        "interface_count": snap.interfaces.len(),
                    }),
                },
                body,
            )
            .await?;
        ctx.reporter.progress(100, None).await;
        Ok(())
    }
}

fn collect_network_snapshot() -> Result<NetworkSnapshot> {
    let networks = Networks::new_with_refreshed_list();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let interfaces: Vec<NetworkInterface> = networks
        .iter()
        .map(|(name, n)| NetworkInterface {
            name: name.to_string(),
            mac: n.mac_address().to_string(),
            received_bytes: n.total_received(),
            transmitted_bytes: n.total_transmitted(),
            received_packets: n.total_packets_received(),
            transmitted_packets: n.total_packets_transmitted(),
            errors_in: n.total_errors_on_received(),
            errors_out: n.total_errors_on_transmitted(),
        })
        .collect();
    Ok(NetworkSnapshot {
        hostname: System::host_name(),
        collected_at_unix: now,
        interfaces,
    })
}

// ---------------- account_audit ----------------

#[derive(Serialize)]
struct AccountRow {
    uid: String,
    name: String,
    groups: Vec<String>,
}

#[derive(Serialize)]
struct AccountAudit {
    collected_at_unix: u64,
    hostname: Option<String>,
    users: Vec<AccountRow>,
}

pub struct AccountAuditHandler;

#[async_trait]
impl JobHandler for AccountAuditHandler {
    fn kind(&self) -> &'static str {
        "account_audit"
    }
    async fn run(&self, ctx: &JobContext, _params: JsonValue) -> Result<()> {
        ctx.reporter.progress(20, None).await;
        let audit = tokio::task::spawn_blocking(collect_account_audit)
            .await
            .map_err(|e| anyhow!("join: {e}"))??;
        let body = serde_json::to_vec_pretty(&audit).context("serialize")?;
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::Json,
                    original_filename: "account_audit.json".into(),
                    metadata: serde_json::json!({ "user_count": audit.users.len() }),
                },
                body,
            )
            .await?;
        ctx.reporter.progress(100, None).await;
        Ok(())
    }
}

fn collect_account_audit() -> Result<AccountAudit> {
    let users = Users::new_with_refreshed_list();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let rows: Vec<AccountRow> = users
        .iter()
        .map(|u| AccountRow {
            uid: u.id().to_string(),
            name: u.name().to_string(),
            groups: u.groups().iter().map(|g| g.name().to_string()).collect(),
        })
        .collect();
    Ok(AccountAudit {
        collected_at_unix: now,
        hostname: System::host_name(),
        users: rows,
    })
}

// ---------------- hash_files ----------------

#[derive(Deserialize, Default)]
struct HashFilesParams {
    /// Root path to walk. Required.
    path: String,
    /// Walk subdirectories.
    #[serde(default)]
    recurse: bool,
    /// Skip files larger than this (bytes). Default 64 MiB.
    #[serde(default = "default_max_size")]
    max_size_bytes: u64,
    /// Cap entries to avoid runaway scans on a tree the operator
    /// pointed at by accident. Default 50_000.
    #[serde(default = "default_max_entries")]
    max_entries: usize,
}

fn default_max_size() -> u64 {
    64 * 1024 * 1024
}
fn default_max_entries() -> usize {
    50_000
}

#[derive(Serialize)]
struct HashRow {
    path: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct HashFilesResult {
    root: String,
    recurse: bool,
    skipped_too_large: usize,
    error_count: usize,
    hashes: Vec<HashRow>,
}

pub struct HashFilesHandler;

#[async_trait]
impl JobHandler for HashFilesHandler {
    fn kind(&self) -> &'static str {
        "hash_files"
    }
    async fn run(&self, ctx: &JobContext, params: JsonValue) -> Result<()> {
        let p: HashFilesParams = serde_json::from_value(params).context("hash_files params")?;
        if p.path.trim().is_empty() {
            return Err(anyhow!("hash_files requires a non-empty path"));
        }

        // tokio::spawn_blocking — directory walks + reads block. Pass
        // a clone of the reporter so the walker can pulse progress at
        // milestone boundaries (every 250 files).
        let path = p.path.clone();
        let recurse = p.recurse;
        let max_size = p.max_size_bytes;
        let max_entries = p.max_entries;

        let reporter = ctx.reporter.clone();
        let res = tokio::task::spawn_blocking(move || {
            walk_and_hash(&path, recurse, max_size, max_entries, |done, total| {
                // Best-effort: this is the only fire-and-forget path
                // we have for back-pressure from sync code into the
                // async reporter. tokio::runtime::Handle::current()
                // is set because we're inside spawn_blocking on a
                // tokio runtime.
                let pct = (done.saturating_mul(100))
                    .checked_div(total)
                    .map(|v| v as u32)
                    .unwrap_or(0);
                let reporter = reporter.clone();
                tokio::runtime::Handle::current().spawn(async move {
                    reporter
                        .progress(pct.min(99), Some(format!("hashed {done} files")))
                        .await;
                });
            })
        })
        .await
        .map_err(|e| anyhow!("join: {e}"))??;

        let count = res.hashes.len();
        let body = serde_json::to_vec_pretty(&res).context("serialize")?;
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::HashList,
                    original_filename: "hash_files.json".into(),
                    metadata: serde_json::json!({
                        "count": count,
                        "root": p.path,
                    }),
                },
                body,
            )
            .await?;
        ctx.reporter.progress(100, None).await;
        Ok(())
    }
}

fn walk_and_hash(
    root: &str,
    recurse: bool,
    max_size: u64,
    max_entries: usize,
    progress: impl Fn(usize, usize),
) -> Result<HashFilesResult> {
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::Read;
    use std::path::PathBuf;

    let mut hashes: Vec<HashRow> = Vec::new();
    let mut skipped_too_large = 0usize;
    let mut error_count = 0usize;

    let root_path = PathBuf::from(root);
    let mut stack: Vec<PathBuf> = vec![root_path.clone()];
    let mut seen: usize = 0;

    while let Some(p) = stack.pop() {
        if hashes.len() >= max_entries {
            break;
        }
        let md = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => {
                error_count += 1;
                continue;
            }
        };
        if md.file_type().is_symlink() {
            continue;
        }
        if md.is_dir() {
            if p == root_path || recurse {
                if let Ok(rd) = fs::read_dir(&p) {
                    for entry in rd.flatten() {
                        stack.push(entry.path());
                    }
                }
            }
            continue;
        }
        if !md.is_file() {
            continue;
        }
        if md.len() > max_size {
            skipped_too_large += 1;
            continue;
        }
        seen += 1;
        let mut hasher = Sha256::new();
        let mut f = match fs::File::open(&p) {
            Ok(f) => f,
            Err(_) => {
                error_count += 1;
                continue;
            }
        };
        let mut buf = [0u8; 65536];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(_) => {
                    error_count += 1;
                    break;
                }
            }
        }
        hashes.push(HashRow {
            path: p.display().to_string(),
            size_bytes: md.len(),
            sha256: hex::encode(hasher.finalize()),
        });
        if seen.rem_euclid(250) == 0 {
            progress(seen, max_entries);
        }
    }

    Ok(HashFilesResult {
        root: root.to_string(),
        recurse,
        skipped_too_large,
        error_count,
        hashes,
    })
}

// ---------------- agent_diagnostic ----------------

#[derive(Serialize)]
struct AgentDiagnostic {
    agent_version: String,
    rust_target: String,
    hostname: Option<String>,
    os_name: Option<String>,
    kernel: Option<String>,
    uptime_seconds: u64,
    cpu_count: usize,
    memory_total_bytes: u64,
    memory_available_bytes: u64,
    collected_at_unix: u64,
}

pub struct AgentDiagnosticHandler {
    agent_version: &'static str,
    rust_target: &'static str,
}

impl AgentDiagnosticHandler {
    pub const fn new(agent_version: &'static str, rust_target: &'static str) -> Self {
        Self {
            agent_version,
            rust_target,
        }
    }
}

#[async_trait]
impl JobHandler for AgentDiagnosticHandler {
    fn kind(&self) -> &'static str {
        "agent_diagnostic"
    }
    async fn run(&self, ctx: &JobContext, _params: JsonValue) -> Result<()> {
        ctx.reporter.progress(20, None).await;
        let agent_version = self.agent_version.to_string();
        let rust_target = self.rust_target.to_string();
        let diag = tokio::task::spawn_blocking(move || {
            collect_agent_diagnostic(agent_version, rust_target)
        })
        .await
        .map_err(|e| anyhow!("join: {e}"))??;
        let body = serde_json::to_vec_pretty(&diag).context("serialize")?;
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::DiagnosticBundle,
                    original_filename: "agent_diagnostic.json".into(),
                    metadata: serde_json::json!({}),
                },
                body,
            )
            .await?;
        ctx.reporter.progress(100, None).await;
        Ok(())
    }
}

fn collect_agent_diagnostic(agent_version: String, rust_target: String) -> Result<AgentDiagnostic> {
    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_cpu_list(sysinfo::CpuRefreshKind::new());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(AgentDiagnostic {
        agent_version,
        rust_target,
        hostname: System::host_name(),
        os_name: System::name(),
        kernel: System::kernel_version(),
        uptime_seconds: System::uptime(),
        cpu_count: sys.cpus().len(),
        memory_total_bytes: sys.total_memory(),
        memory_available_bytes: sys.available_memory(),
        collected_at_unix: now,
    })
}

// ---------------- registration helper ----------------

/// Register every cross-platform handler. Platform binaries call this
/// once at startup, then optionally `register()` their own platform-
/// specific handlers on top.
pub fn register_cross_platform_handlers(
    dispatcher: &mut crate::jobs::JobDispatcher,
    agent_version: &'static str,
    rust_target: &'static str,
) {
    use std::sync::Arc;
    dispatcher.register(Arc::new(ProcessSnapshotHandler));
    dispatcher.register(Arc::new(NetworkSnapshotHandler));
    dispatcher.register(Arc::new(AccountAuditHandler));
    dispatcher.register(Arc::new(HashFilesHandler));
    dispatcher.register(Arc::new(AgentDiagnosticHandler::new(
        agent_version,
        rust_target,
    )));
}
