//! Acquisition [`JobHandler`] implementations (M23.e).
//!
//! Read-only "grab the bytes" jobs. These produce real files on the
//! manager (artifacts of kind `file`), not summaries, so analysts can
//! pull them down for offline analysis.
//!
//! Implemented here:
//!   - `file_acquire`        copy specific paths to MinIO
//!   - `crash_dump_collect`  enumerate well-known dump locations
//!   - `event_log_acquire`   capture system/auth logs (Linux journal)
//!
//! `process_memory_dump` is registered as a stub that bails with a
//! clear error: full memory acquisition needs ptrace / Toolhelp /
//! MiniDumpWriteDump and is platform-specific. Lands in a follow-up.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::path::{Path, PathBuf};

use crate::jobs::{ArtifactKind, ArtifactSpec, JobContext, JobHandler};

// ---------------- file_acquire ----------------

#[derive(Deserialize)]
struct FileAcquireParams {
    /// One or more paths to acquire. Each becomes its own artifact.
    paths: Vec<String>,
    /// Skip files larger than this (bytes). Default 256 MiB.
    #[serde(default = "default_acquire_max")]
    max_size_bytes: u64,
}

fn default_acquire_max() -> u64 {
    256 * 1024 * 1024
}

#[derive(Serialize)]
struct AcquiredFileMeta {
    original_path: String,
    size_bytes: u64,
    mode: u32,
}

pub struct FileAcquireHandler;

#[async_trait]
impl JobHandler for FileAcquireHandler {
    fn kind(&self) -> &'static str {
        "file_acquire"
    }
    async fn run(&self, ctx: &JobContext, params: JsonValue) -> Result<()> {
        let p: FileAcquireParams = serde_json::from_value(params).context("file_acquire params")?;
        if p.paths.is_empty() {
            return Err(anyhow!("file_acquire requires non-empty paths"));
        }
        if p.paths.len() > 200 {
            return Err(anyhow!("file_acquire: too many paths (max 200)"));
        }

        let total = p.paths.len() as u32;
        let mut acquired = 0u32;
        let mut errors: Vec<(String, String)> = Vec::new();

        for path_str in p.paths.iter() {
            let path = PathBuf::from(path_str);
            ctx.reporter
                .progress(
                    progress_pct(acquired, total),
                    Some(format!("acquiring {}", path.display())),
                )
                .await;

            match read_one_file(&path, p.max_size_bytes).await {
                Ok((body, meta)) => {
                    let original_filename = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "file.bin".to_string());
                    ctx.uploader
                        .upload(
                            ArtifactSpec {
                                kind: ArtifactKind::File,
                                original_filename,
                                metadata: serde_json::to_value(&meta).unwrap_or_default(),
                            },
                            body,
                        )
                        .await?;
                    acquired += 1;
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "file_acquire.read_failed");
                    errors.push((path_str.clone(), e.to_string()));
                }
            }
        }

        // Always emit a small summary JSON so the operator can see
        // which paths failed without paging through all artifact rows.
        let summary = serde_json::json!({
            "acquired_count": acquired,
            "requested_count": total,
            "errors": errors,
        });
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::Json,
                    original_filename: "file_acquire_summary.json".into(),
                    metadata: serde_json::json!({
                        "acquired": acquired,
                        "requested": total,
                        "error_count": errors.len(),
                    }),
                },
                serde_json::to_vec_pretty(&summary).unwrap_or_default(),
            )
            .await?;

        if acquired == 0 {
            return Err(anyhow!(
                "file_acquire: no files acquired ({} errors)",
                errors.len()
            ));
        }
        ctx.reporter.progress(100, None).await;
        Ok(())
    }
}

fn progress_pct(done: u32, total: u32) -> u32 {
    if total == 0 {
        0
    } else {
        ((done as u64 * 95) / total as u64) as u32
    }
}

async fn read_one_file(path: &Path, max_size: u64) -> Result<(Vec<u8>, AcquiredFileMeta)> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use std::fs;
        let md = fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        if md.file_type().is_symlink() {
            return Err(anyhow!("refuse to follow symlink: {}", path.display()));
        }
        if !md.is_file() {
            return Err(anyhow!("not a regular file: {}", path.display()));
        }
        if md.len() > max_size {
            return Err(anyhow!(
                "{}: {} bytes exceeds max_size_bytes={}",
                path.display(),
                md.len(),
                max_size
            ));
        }
        let body = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let mode = mode_bits(&md);
        Ok((
            body,
            AcquiredFileMeta {
                original_path: path.display().to_string(),
                size_bytes: md.len(),
                mode,
            },
        ))
    })
    .await
    .map_err(|e| anyhow!("join: {e}"))?
}

#[cfg(unix)]
fn mode_bits(md: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    md.mode()
}

#[cfg(not(unix))]
fn mode_bits(_md: &std::fs::Metadata) -> u32 {
    0
}

// ---------------- crash_dump_collect ----------------

#[derive(Deserialize, Default)]
struct CrashDumpParams {
    /// Cap to keep an accidentally huge crash directory bounded.
    #[serde(default = "default_max_dumps")]
    max_files: usize,
    /// Skip dump files larger than this. Default 1 GiB.
    #[serde(default = "default_max_dump_size")]
    max_size_bytes: u64,
}

fn default_max_dumps() -> usize {
    32
}
fn default_max_dump_size() -> u64 {
    1024 * 1024 * 1024
}

pub struct CrashDumpCollectHandler;

#[async_trait]
impl JobHandler for CrashDumpCollectHandler {
    fn kind(&self) -> &'static str {
        "crash_dump_collect"
    }
    async fn run(&self, ctx: &JobContext, params: JsonValue) -> Result<()> {
        let p: CrashDumpParams = if params.is_null() {
            CrashDumpParams::default()
        } else {
            serde_json::from_value(params).context("crash_dump_collect params")?
        };

        ctx.reporter
            .progress(10, Some("enumerating dump paths".into()))
            .await;
        let candidates = tokio::task::spawn_blocking(enumerate_dump_paths)
            .await
            .map_err(|e| anyhow!("join: {e}"))??;

        let mut collected = 0usize;
        let mut skipped: Vec<String> = Vec::new();
        let total = candidates.len().min(p.max_files);
        for (i, path) in candidates.into_iter().take(p.max_files).enumerate() {
            ctx.reporter
                .progress(
                    progress_pct(i as u32, total.max(1) as u32),
                    Some(format!("acquiring {}", path.display())),
                )
                .await;
            match read_one_file(&path, p.max_size_bytes).await {
                Ok((body, meta)) => {
                    let original_filename = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "crash.dmp".to_string());
                    ctx.uploader
                        .upload(
                            ArtifactSpec {
                                kind: ArtifactKind::File,
                                original_filename,
                                metadata: serde_json::to_value(&meta).unwrap_or_default(),
                            },
                            body,
                        )
                        .await?;
                    collected += 1;
                }
                Err(e) => {
                    skipped.push(format!("{}: {}", path.display(), e));
                }
            }
        }

        let summary = serde_json::json!({
            "collected": collected,
            "skipped": skipped,
        });
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::Json,
                    original_filename: "crash_dump_summary.json".into(),
                    metadata: serde_json::json!({"collected": collected}),
                },
                serde_json::to_vec_pretty(&summary).unwrap_or_default(),
            )
            .await?;
        ctx.reporter.progress(100, None).await;
        Ok(())
    }
}

fn enumerate_dump_paths() -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();

    let candidates: Vec<PathBuf> = if cfg!(target_os = "linux") {
        vec![
            PathBuf::from("/var/lib/systemd/coredump"),
            PathBuf::from("/var/crash"),
            // Some distros (ubuntu) keep apport reports here.
            PathBuf::from("/var/lib/apport/coredump"),
        ]
    } else if cfg!(target_os = "windows") {
        let win = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        vec![
            PathBuf::from(format!("{win}\\Minidump")),
            PathBuf::from(format!("{win}\\MEMORY.DMP")),
            PathBuf::from(format!("{win}\\LiveKernelReports")),
        ]
    } else {
        Vec::new()
    };

    for c in candidates {
        let md = match std::fs::symlink_metadata(&c) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.is_file() {
            out.push(c);
            continue;
        }
        if md.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&c) {
                for entry in rd.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        out.push(p);
                    }
                }
            }
        }
    }

    // Sort by modification time (newest first) so quotas hit the most
    // recent crashes first if `max_files` clips the list.
    out.sort_by_key(|p| std::fs::symlink_metadata(p).and_then(|m| m.modified()).ok());
    out.reverse();
    Ok(out)
}

// ---------------- event_log_acquire ----------------

#[derive(Deserialize, Default)]
struct EventLogParams {
    /// Window in hours back from now. Default 24h.
    #[serde(default = "default_window_hours")]
    hours: u32,
    /// Cap on bytes returned. Default 32 MiB.
    #[serde(default = "default_evt_max")]
    max_size_bytes: u64,
}

fn default_window_hours() -> u32 {
    24
}
fn default_evt_max() -> u64 {
    32 * 1024 * 1024
}

pub struct EventLogAcquireHandler;

#[async_trait]
impl JobHandler for EventLogAcquireHandler {
    fn kind(&self) -> &'static str {
        "event_log_acquire"
    }
    async fn run(&self, ctx: &JobContext, params: JsonValue) -> Result<()> {
        let p: EventLogParams = if params.is_null() {
            EventLogParams::default()
        } else {
            serde_json::from_value(params).context("event_log_acquire params")?
        };
        let hours = p.hours.clamp(1, 24 * 30); // 1h..30d
        let cap = p.max_size_bytes.max(1024 * 1024);

        ctx.reporter
            .progress(20, Some(format!("collecting last {hours}h")))
            .await;

        #[cfg(target_os = "linux")]
        let (body, original_filename, kind_label) = {
            let body = tokio::task::spawn_blocking(move || collect_journal(hours, cap))
                .await
                .map_err(|e| anyhow!("join: {e}"))??;
            (body, "journal.json".to_string(), "linux_journal")
        };

        #[cfg(target_os = "windows")]
        let (body, original_filename, kind_label) = {
            let body = tokio::task::spawn_blocking(move || collect_windows_events(hours, cap))
                .await
                .map_err(|e| anyhow!("join: {e}"))??;
            (body, "windows_events.json".to_string(), "windows_events")
        };

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        let (body, original_filename, kind_label) = {
            let _ = (hours, cap);
            (
                Vec::<u8>::new(),
                "unsupported.json".to_string(),
                "unsupported",
            )
        };

        ctx.reporter
            .progress(80, Some(format!("uploading {} bytes", body.len())))
            .await;
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::Json,
                    original_filename,
                    metadata: serde_json::json!({
                        "hours": hours,
                        "size_bytes": body.len(),
                        "source": kind_label,
                    }),
                },
                body,
            )
            .await?;
        ctx.reporter.progress(100, None).await;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn collect_journal(hours: u32, cap: u64) -> Result<Vec<u8>> {
    use std::process::Command;
    let since = format!("{hours} hours ago");
    let out = Command::new("journalctl")
        .args(["--since", &since, "-o", "json", "--no-pager"])
        .output()
        .context("spawn journalctl")?;
    if !out.status.success() {
        return Err(anyhow!(
            "journalctl exited with status {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut body = out.stdout;
    if (body.len() as u64) > cap {
        body.truncate(cap as usize);
    }
    Ok(body)
}

#[cfg(target_os = "windows")]
fn collect_windows_events(hours: u32, cap: u64) -> Result<Vec<u8>> {
    use std::process::Command;
    // Use PowerShell's Get-WinEvent + ConvertTo-Json for a portable
    // JSON dump. Limits to System + Application + Security channels.
    let script = format!(
        "Get-WinEvent -FilterHashtable @{{LogName=@('System','Application','Security'); StartTime=(Get-Date).AddHours(-{hours})}} -ErrorAction SilentlyContinue | Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,LogName,Message | ConvertTo-Json -Compress -Depth 3"
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .context("spawn powershell")?;
    if !out.status.success() {
        return Err(anyhow!(
            "powershell exited with status {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut body = out.stdout;
    if (body.len() as u64) > cap {
        body.truncate(cap as usize);
    }
    Ok(body)
}

// ---------------- process_memory_dump (stub) ----------------

pub struct ProcessMemoryDumpHandler;

#[async_trait]
impl JobHandler for ProcessMemoryDumpHandler {
    fn kind(&self) -> &'static str {
        "process_memory_dump"
    }
    async fn run(&self, _ctx: &JobContext, _params: JsonValue) -> Result<()> {
        // Stub — needs ptrace on Linux and MiniDumpWriteDump on
        // Windows. The platform-specific handler crates own this.
        // Returning an error makes the JobRun fail with a clear note
        // rather than appearing to succeed with no artifact.
        Err(anyhow!(
            "process_memory_dump: platform handler not yet implemented (M23.e follow-up)"
        ))
    }
}

// ---------------- registration helper ----------------

pub fn register_acquisition_handlers(dispatcher: &mut crate::jobs::JobDispatcher) {
    use std::sync::Arc;
    dispatcher.register(Arc::new(FileAcquireHandler));
    dispatcher.register(Arc::new(CrashDumpCollectHandler));
    dispatcher.register(Arc::new(EventLogAcquireHandler));
    dispatcher.register(Arc::new(ProcessMemoryDumpHandler));
}
