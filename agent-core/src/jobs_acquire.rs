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

// ---------------- triage_collect (Phase 2 #2.10) ----------------

/// Parameters for the disk-forensics triage bundle. Each `include_*`
/// flag toggles a category; defaults match a "give me everything
/// relevant for first-look IR" preset. `max_size_mb` is a hard cap
/// on the archive size — once we cross it, the handler stops adding
/// files and returns the partial bundle with a `truncated_at` note
/// in the manifest, which is the right trade-off vs. silently
/// dropping the last category.
#[derive(Deserialize)]
struct TriageParams {
    #[serde(default = "default_true")]
    include_registry: bool,
    #[serde(default = "default_true")]
    include_mft: bool,
    #[serde(default = "default_true")]
    include_prefetch: bool,
    #[serde(default = "default_true")]
    include_browser: bool,
    #[serde(default = "default_true")]
    include_event_log: bool,
    #[serde(default = "default_true")]
    include_systemd_journal: bool,
    #[serde(default = "default_true")]
    include_persistence: bool,
    #[serde(default = "default_triage_max_size_mb")]
    max_size_mb: u64,
    /// Optional override of the staging directory. Tests inject a
    /// `tempdir` here so they can pre-seed source files outside of
    /// /var/log without needing root.
    #[serde(default)]
    source_root_override: Option<String>,
}

impl Default for TriageParams {
    fn default() -> Self {
        Self {
            include_registry: true,
            include_mft: true,
            include_prefetch: true,
            include_browser: true,
            include_event_log: true,
            include_systemd_journal: true,
            include_persistence: true,
            max_size_mb: default_triage_max_size_mb(),
            source_root_override: None,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_triage_max_size_mb() -> u64 {
    2048
}

#[derive(Serialize, Default)]
struct TriageManifest {
    /// Hostname captured at collection time.
    hostname: String,
    /// OS family — informs analyst expectations on what's inside.
    os: String,
    /// Wall-clock at archive open.
    collected_at: String,
    /// Sources collected (relative path inside the ZIP -> source path on host).
    files: Vec<TriageFileEntry>,
    /// Categories the operator asked for but that we couldn't fulfill —
    /// e.g. "registry" on a Linux host, or "/var/log/auth.log: not
    /// readable". Lets the IR analyst see what's missing without
    /// trawling the ZIP for absence-of-evidence.
    skipped: Vec<TriageSkippedEntry>,
    /// Set when the archive hit `max_size_mb` mid-collection. Counts
    /// the categories that were dropped wholesale.
    truncated: bool,
    truncated_after_bytes: u64,
}

#[derive(Serialize)]
struct TriageFileEntry {
    archive_path: String,
    source_path: String,
    size_bytes: u64,
    category: &'static str,
}

#[derive(Serialize)]
struct TriageSkippedEntry {
    source_path: String,
    category: &'static str,
    reason: String,
}

pub struct TriageCollectHandler;

#[async_trait]
impl JobHandler for TriageCollectHandler {
    fn kind(&self) -> &'static str {
        "triage_collect"
    }
    async fn run(&self, ctx: &JobContext, params: JsonValue) -> Result<()> {
        let p: TriageParams = if params.is_null() {
            TriageParams::default()
        } else {
            serde_json::from_value(params).context("triage_collect params")?
        };

        ctx.reporter
            .progress(5, Some("enumerating triage sources".into()))
            .await;

        let max_bytes = p.max_size_mb.saturating_mul(1024 * 1024);
        let zip_bytes = tokio::task::spawn_blocking(move || build_triage_archive(p, max_bytes))
            .await
            .map_err(|e| anyhow!("join: {e}"))??;

        ctx.reporter
            .progress(
                80,
                Some(format!("uploading {} bytes", zip_bytes.archive.len())),
            )
            .await;

        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::DiagnosticBundle,
                    original_filename: zip_bytes.filename.clone(),
                    metadata: serde_json::json!({
                        "size_bytes": zip_bytes.archive.len(),
                        "file_count": zip_bytes.manifest.files.len(),
                        "skipped_count": zip_bytes.manifest.skipped.len(),
                        "truncated": zip_bytes.manifest.truncated,
                        "os": zip_bytes.manifest.os,
                    }),
                },
                zip_bytes.archive,
            )
            .await?;
        ctx.reporter.progress(100, None).await;
        Ok(())
    }
}

struct BuiltArchive {
    archive: Vec<u8>,
    filename: String,
    manifest: TriageManifest,
}

fn build_triage_archive(p: TriageParams, max_bytes: u64) -> Result<BuiltArchive> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    let hostname = whoami_hostname();
    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "other"
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut manifest = TriageManifest {
        hostname: hostname.clone(),
        os: os.to_string(),
        collected_at: format!("epoch:{now}"),
        ..Default::default()
    };

    let buf: Vec<u8> = Vec::new();
    let cursor = std::io::Cursor::new(buf);
    let mut zipw = zip::ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    // running tally so we can short-circuit before adding a giant
    // file once the cap is exceeded.
    let mut total_compressed_so_far: u64 = 0;

    // Resolve sources by category. Each helper returns a list of
    // (category, source path). Source-root override lets tests
    // exercise the path under a tempdir.
    let sources = enumerate_triage_sources(&p);

    for (category, source) in sources {
        if total_compressed_so_far >= max_bytes {
            manifest.truncated = true;
            manifest.truncated_after_bytes = total_compressed_so_far;
            manifest.skipped.push(TriageSkippedEntry {
                source_path: source.display().to_string(),
                category,
                reason: "archive size cap reached".to_string(),
            });
            continue;
        }
        // Per-file ceiling so a huge MFT doesn't blow past the cap
        // in a single read.
        let remaining = max_bytes.saturating_sub(total_compressed_so_far);

        match read_file_capped(&source, remaining) {
            Ok(bytes) => {
                let archive_path = archive_path_for(category, &source);
                if let Err(e) = (|| -> Result<()> {
                    zipw.start_file(&archive_path, opts)?;
                    zipw.write_all(&bytes)?;
                    Ok(())
                })() {
                    manifest.skipped.push(TriageSkippedEntry {
                        source_path: source.display().to_string(),
                        category,
                        reason: format!("zip write failed: {e}"),
                    });
                    continue;
                }
                total_compressed_so_far =
                    total_compressed_so_far.saturating_add(bytes.len() as u64);
                manifest.files.push(TriageFileEntry {
                    archive_path,
                    source_path: source.display().to_string(),
                    size_bytes: bytes.len() as u64,
                    category,
                });
            }
            Err(e) => {
                let reason = e.to_string();
                // "exceeds remaining budget" means the cap is the
                // problem rather than the file itself — flip the
                // truncated flag so analysts know the bundle is
                // incomplete by design, not by missing data.
                if reason.contains("exceed remaining budget") {
                    manifest.truncated = true;
                    if manifest.truncated_after_bytes == 0 {
                        manifest.truncated_after_bytes = total_compressed_so_far;
                    }
                }
                manifest.skipped.push(TriageSkippedEntry {
                    source_path: source.display().to_string(),
                    category,
                    reason,
                });
            }
        }
    }

    // Synthetic outputs (commands -> in-memory bytes).
    let synth = enumerate_triage_commands(&p);
    for (category, name, body) in synth {
        if total_compressed_so_far >= max_bytes {
            manifest.truncated = true;
            manifest.truncated_after_bytes = total_compressed_so_far;
            manifest.skipped.push(TriageSkippedEntry {
                source_path: name.to_string(),
                category,
                reason: "archive size cap reached".to_string(),
            });
            continue;
        }
        let archive_path = format!("{category}/{name}");
        if let Err(e) = (|| -> Result<()> {
            zipw.start_file(&archive_path, opts)?;
            zipw.write_all(&body)?;
            Ok(())
        })() {
            manifest.skipped.push(TriageSkippedEntry {
                source_path: name.to_string(),
                category,
                reason: format!("zip write failed: {e}"),
            });
            continue;
        }
        total_compressed_so_far = total_compressed_so_far.saturating_add(body.len() as u64);
        manifest.files.push(TriageFileEntry {
            archive_path,
            source_path: name.to_string(),
            size_bytes: body.len() as u64,
            category,
        });
    }

    // Write the manifest last so it reflects everything we packed.
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap_or_default();
    zipw.start_file("MANIFEST.json", opts)?;
    zipw.write_all(&manifest_bytes)?;

    let cursor = zipw.finish().context("finalize zip")?;
    let archive = cursor.into_inner();

    let filename = format!("triage_{hostname}_{now}.zip");
    Ok(BuiltArchive {
        archive,
        filename,
        manifest,
    })
}

fn whoami_hostname() -> String {
    sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string())
}

fn archive_path_for(category: &str, src: &Path) -> String {
    // Strip leading slash + drive prefix so the ZIP unpacks cleanly
    // without writing into / or C:\.
    let s = src.display().to_string();
    let stripped = s
        .trim_start_matches('/')
        .trim_start_matches('\\')
        .replace(':', "_")
        .replace('\\', "/");
    format!("{category}/{stripped}")
}

fn read_file_capped(path: &Path, cap: u64) -> Result<Vec<u8>> {
    use std::fs;
    let md = fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if md.file_type().is_symlink() {
        return Err(anyhow!("refuse to follow symlink: {}", path.display()));
    }
    if !md.is_file() {
        return Err(anyhow!("not a regular file: {}", path.display()));
    }
    // Cap is "bytes remaining in the archive budget". If the file is
    // larger we still want SOME of it — read a capped prefix and note
    // the truncation in the file entry name. For Phase 2 #2.10 the
    // simpler path is to skip + log; analysts can re-run with a bigger
    // max_size_mb. Keep the implementation honest: skip.
    if md.len() > cap {
        return Err(anyhow!(
            "{}: {} bytes would exceed remaining budget {}",
            path.display(),
            md.len(),
            cap
        ));
    }
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

/// Source-file enumeration. Honors `source_root_override` so tests
/// can simulate `/var/log/auth.log` etc. under a tempdir.
fn enumerate_triage_sources(p: &TriageParams) -> Vec<(&'static str, PathBuf)> {
    let mut out: Vec<(&'static str, PathBuf)> = Vec::new();
    let root: Option<PathBuf> = p.source_root_override.as_ref().map(PathBuf::from);

    let join = |base: &Option<PathBuf>, abs: &str| -> PathBuf {
        match base {
            Some(b) => {
                let abs = abs.trim_start_matches('/').trim_start_matches('\\');
                b.join(abs)
            }
            None => PathBuf::from(abs),
        }
    };

    if cfg!(target_os = "windows") {
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());

        if p.include_registry {
            // SAM/SECURITY are locked; on a real host we'd open with
            // FILE_SHARE_READ|WRITE|DELETE or take a VSS snapshot.
            // The reader here is plain `fs::read`; on a live system
            // most hives surface as access-denied and land in
            // manifest.skipped. The Authenticode-signed Windows agent
            // (kernel-windows companion driver) handles the VSS path
            // — wiring that in is a follow-up.
            for hive in [
                "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "DRIVERS",
            ] {
                out.push((
                    "registry",
                    PathBuf::from(format!("{windir}\\System32\\config\\{hive}")),
                ));
            }
            // NTUSER.DAT for the calling identity. Skipped on
            // service-account agents but useful for live-response on
            // an interactive user.
            if let Some(profile) = std::env::var_os("USERPROFILE") {
                let mut nt = PathBuf::from(profile);
                nt.push("NTUSER.DAT");
                out.push(("registry", nt));
            }
        }

        if p.include_mft {
            // `\\?\C:` + `$MFT`. fs::read won't see it without raw
            // volume access — same caveat as the hives: a real
            // Authenticode-signed agent uses the kernel driver. The
            // path is enumerated regardless so the manifest records
            // the attempt.
            out.push(("mft", PathBuf::from("\\\\?\\C:\\$MFT")));
        }

        if p.include_prefetch {
            let pf = format!("{windir}\\Prefetch");
            if let Ok(rd) = std::fs::read_dir(&pf) {
                for entry in rd.flatten() {
                    let path = entry.path();
                    if path
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case("pf"))
                    {
                        out.push(("prefetch", path));
                    }
                }
            } else {
                out.push(("prefetch", PathBuf::from(pf)));
            }
        }

        if p.include_event_log {
            for ch in ["System", "Application", "Security"] {
                out.push((
                    "event_log",
                    PathBuf::from(format!("{windir}\\System32\\winevt\\Logs\\{ch}.evtx")),
                ));
            }
        }

        if p.include_browser {
            // Chrome / Edge default profile only; the manifest records
            // missing files. Both browsers lock these so the agent
            // needs to copy with FILE_SHARE_READ|DELETE — same VSS
            // story as registry hives. Real implementation: shadow
            // copy. Phase 2 #2.10 stops at enumeration.
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                let local = PathBuf::from(local);
                for prof in [
                    "Google\\Chrome\\User Data\\Default\\History",
                    "Microsoft\\Edge\\User Data\\Default\\History",
                ] {
                    out.push(("browser", local.join(prof)));
                }
            }
        }

        if p.include_persistence {
            // Scheduled Tasks store on disk. Run-key persistence
            // surfaces via the registry hives above; the .xml task
            // files are still useful even when SOFTWARE is locked.
            let tasks = format!("{windir}\\System32\\Tasks");
            if let Ok(rd) = std::fs::read_dir(&tasks) {
                for entry in rd.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        out.push(("persistence", path));
                    }
                }
            } else {
                out.push(("persistence", PathBuf::from(tasks)));
            }
        }
    } else if cfg!(target_os = "linux") {
        if p.include_event_log {
            for log in [
                "/var/log/wtmp",
                "/var/log/btmp",
                "/var/log/lastlog",
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/secure",
                "/var/log/messages",
            ] {
                out.push(("event_log", join(&root, log)));
            }
        }
        if p.include_browser {
            // Per-user copies under $HOME — root agent typically
            // can't see them; we enumerate optimistically. Mozilla
            // sqlite + chromium sqlite.
            if let Some(home) = std::env::var_os("HOME") {
                let home = PathBuf::from(home);
                out.push(("browser", home.join(".mozilla/firefox")));
                out.push((
                    "browser",
                    home.join(".config/google-chrome/Default/History"),
                ));
                out.push(("browser", home.join(".config/chromium/Default/History")));
            }
        }
        if p.include_persistence {
            // crontabs + systemd unit files. /etc/cron.{d,daily,hourly,
            // monthly,weekly} are dirs; we expand if readable.
            for path in [
                "/etc/crontab",
                "/etc/cron.d",
                "/etc/cron.daily",
                "/etc/cron.hourly",
                "/etc/cron.monthly",
                "/etc/cron.weekly",
                "/var/spool/cron",
                "/etc/rc.local",
            ] {
                let p = join(&root, path);
                if p.is_dir() {
                    if let Ok(rd) = std::fs::read_dir(&p) {
                        for e in rd.flatten() {
                            if e.path().is_file() {
                                out.push(("persistence", e.path()));
                            }
                        }
                    }
                } else {
                    out.push(("persistence", p));
                }
            }
        }
    }
    out
}

/// Synthetic outputs — commands whose stdout we want in the bundle.
/// Returns (category, archive filename, body). Errors land in
/// `manifest.skipped` via the empty-body shortcut.
fn enumerate_triage_commands(p: &TriageParams) -> Vec<(&'static str, String, Vec<u8>)> {
    let mut out: Vec<(&'static str, String, Vec<u8>)> = Vec::new();
    if cfg!(target_os = "linux") {
        if p.include_systemd_journal {
            let body = run_cmd_capped(
                "journalctl",
                &["--output=export", "--since=7 days ago", "--no-pager"],
                64 * 1024 * 1024,
            );
            out.push(("journal", "journal_export_7d.bin".into(), body));
        }
        if p.include_persistence {
            let units = run_cmd_capped(
                "systemctl",
                &["list-unit-files", "--no-pager", "--all"],
                8 * 1024 * 1024,
            );
            out.push(("persistence", "systemctl_list_unit_files.txt".into(), units));
            let timers = run_cmd_capped("systemctl", &["list-timers", "--all"], 4 * 1024 * 1024);
            out.push(("persistence", "systemctl_list_timers.txt".into(), timers));
        }
    }
    out
}

fn run_cmd_capped(cmd: &str, args: &[&str], cap: u64) -> Vec<u8> {
    use std::process::Command;
    match Command::new(cmd).args(args).output() {
        Ok(out) if out.status.success() => {
            let mut b = out.stdout;
            if (b.len() as u64) > cap {
                b.truncate(cap as usize);
            }
            b
        }
        Ok(out) => format!(
            "(command failed: status={}; stderr={})",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into_bytes(),
        Err(e) => format!("(spawn failed: {e})").into_bytes(),
    }
}

// ---------------- registration helper ----------------

pub fn register_acquisition_handlers(dispatcher: &crate::jobs::JobDispatcher) {
    use std::sync::Arc;
    dispatcher.register(Arc::new(FileAcquireHandler));
    dispatcher.register(Arc::new(CrashDumpCollectHandler));
    dispatcher.register(Arc::new(EventLogAcquireHandler));
    dispatcher.register(Arc::new(ProcessMemoryDumpHandler));
    dispatcher.register(Arc::new(TriageCollectHandler));
}
