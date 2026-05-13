//! Hunt [`JobHandler`] implementations (M23.f).
//!
//! Scan-the-filesystem jobs:
//!
//! - `yara_fs_scan`: recursive YARA scan with a subset (or all) of the
//!   agent's currently-synced YARA rules.
//! - `ioc_sweep`: hash + filename match against the agent's IOC
//!   ruleset, surfacing every hit.
//!
//! `hash_files` already lives in `jobs_handlers.rs` (M23.d) because it
//! shares plumbing with the survey suite.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::client::RuleCache;
use crate::jobs::{ArtifactKind, ArtifactSpec, JobContext, JobHandler};
use crate::proto as p;
use crate::scanner::MemoryReaderFactory;

// ---------------- yara_fs_scan ----------------

#[derive(Deserialize)]
struct YaraScanParams {
    path: String,
    #[serde(default)]
    recurse: bool,
    /// Optional rule-id allowlist. Empty / unset = use every enabled
    /// rule the agent has cached.
    #[serde(default)]
    rule_ids: Vec<String>,
    /// Skip files larger than this. Default 32 MiB — YARA on a 4 GiB
    /// container image is rarely what the operator wants.
    #[serde(default = "default_yara_max_size")]
    max_size_bytes: u64,
    /// Cap on entries scanned. Default 50k.
    #[serde(default = "default_yara_max_entries")]
    max_entries: usize,
}

fn default_yara_max_size() -> u64 {
    32 * 1024 * 1024
}
fn default_yara_max_entries() -> usize {
    50_000
}

#[derive(Serialize)]
struct YaraMatchRow {
    rule_id: String,
    rule_name: String,
    severity: i32,
    path: String,
    size_bytes: u64,
    matched_strings: Vec<String>,
}

#[derive(Serialize)]
struct YaraScanResult {
    root: String,
    recurse: bool,
    rules_compiled: usize,
    files_scanned: usize,
    skipped_too_large: usize,
    error_count: usize,
    matches: Vec<YaraMatchRow>,
}

pub struct YaraFsScanHandler {
    rules: RuleCache,
}

impl YaraFsScanHandler {
    pub fn new(rules: RuleCache) -> Self {
        Self { rules }
    }
}

#[async_trait]
impl JobHandler for YaraFsScanHandler {
    fn kind(&self) -> &'static str {
        "yara_fs_scan"
    }
    async fn run(&self, ctx: &JobContext, params: JsonValue) -> Result<()> {
        let p: YaraScanParams = serde_json::from_value(params).context("yara_fs_scan params")?;
        if p.path.trim().is_empty() {
            return Err(anyhow!("yara_fs_scan requires a non-empty path"));
        }

        let snapshot = self.rules.snapshot().await.ok_or_else(|| {
            anyhow!("yara_fs_scan: no rules cached yet — wait for the first RuleSync")
        })?;
        let yara_rules: Vec<p::YaraRule> = filter_yara_rules(&snapshot.yara, &p.rule_ids)
            .into_iter()
            .cloned()
            .collect();
        if yara_rules.is_empty() {
            // Disambiguate the two failure modes so the operator knows
            // whether to add a YARA rule or fix the rule_ids filter.
            if snapshot.yara.is_empty() {
                return Err(anyhow!(
                    "yara_fs_scan: no YARA rules cached on this agent — \
                     define and enable at least one YARA rule first"
                ));
            }
            return Err(anyhow!(
                "yara_fs_scan: rule_ids filter matched 0 of {} cached YARA rules",
                snapshot.yara.len()
            ));
        }

        ctx.reporter
            .progress(5, Some(format!("compiling {} rules", yara_rules.len())))
            .await;

        let (compiled, rule_meta) = tokio::task::spawn_blocking(move || compile_rules(&yara_rules))
            .await
            .map_err(|e| anyhow!("join: {e}"))??;

        // yara-x doesn't expose a public rule-count accessor; the
        // `meta` map already records one entry per source rule we
        // submitted, which is the operator-facing number we want.
        let rules_compiled = rule_meta.len();
        ctx.reporter
            .progress(
                15,
                Some(format!("compiled {rules_compiled} rules; scanning")),
            )
            .await;

        let reporter = ctx.reporter.clone();
        let path = p.path.clone();
        let recurse = p.recurse;
        let max_size = p.max_size_bytes;
        let max_entries = p.max_entries;

        let result = tokio::task::spawn_blocking(move || {
            walk_and_yara_scan(
                &path,
                recurse,
                max_size,
                max_entries,
                &compiled,
                &rule_meta,
                |done, total| {
                    let pct = ((done.saturating_mul(85)).checked_div(total).unwrap_or(0) as u32)
                        .saturating_add(15)
                        .min(99);
                    let reporter = reporter.clone();
                    tokio::runtime::Handle::current().spawn(async move {
                        reporter
                            .progress(pct, Some(format!("scanned {done} files")))
                            .await;
                    });
                },
            )
        })
        .await
        .map_err(|e| anyhow!("join: {e}"))??;

        let match_count = result.matches.len();
        let body = serde_json::to_vec_pretty(&result).context("serialize")?;
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::YaraMatches,
                    original_filename: "yara_matches.json".into(),
                    metadata: serde_json::json!({
                        "match_count": match_count,
                        "files_scanned": result.files_scanned,
                        "rules_compiled": result.rules_compiled,
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

fn filter_yara_rules<'a>(all: &'a [p::YaraRule], allow: &[String]) -> Vec<&'a p::YaraRule> {
    if allow.is_empty() {
        return all.iter().collect();
    }
    let want: std::collections::HashSet<&str> = allow.iter().map(|s| s.as_str()).collect();
    all.iter()
        .filter(|r| want.contains(r.id.as_str()))
        .collect()
}

#[derive(Clone)]
struct RuleMeta {
    id: String,
    name: String,
    severity: i32,
}

fn compile_rules(rules: &[p::YaraRule]) -> Result<(yara_x::Rules, HashMap<String, RuleMeta>)> {
    let mut compiler = yara_x::Compiler::new();
    let mut meta: HashMap<String, RuleMeta> = HashMap::new();
    for r in rules {
        // yara-x identifies matches by the rule's textual identifier
        // (the `rule NAME {}` head). Build a stable mapping back to
        // the manager rule_id so analysts can pivot in the UI.
        compiler
            .add_source(r.source.as_str())
            .with_context(|| format!("compile yara rule {}", r.id))?;
        // Each YaraRule source may declare multiple rules; we record
        // a meta entry per source-id. The match path looks up by
        // textual identifier and falls back to the wire id when no
        // mapping exists.
        meta.insert(
            r.name.clone(),
            RuleMeta {
                id: r.id.clone(),
                name: r.name.clone(),
                severity: r.severity,
            },
        );
    }
    Ok((compiler.build(), meta))
}

#[allow(clippy::too_many_arguments)]
fn walk_and_yara_scan(
    root: &str,
    recurse: bool,
    max_size: u64,
    max_entries: usize,
    rules: &yara_x::Rules,
    meta: &HashMap<String, RuleMeta>,
    progress: impl Fn(usize, usize),
) -> Result<YaraScanResult> {
    use std::fs;
    let root_path = PathBuf::from(root);
    let mut stack: Vec<PathBuf> = vec![root_path.clone()];
    let mut matches_out: Vec<YaraMatchRow> = Vec::new();
    let mut files_scanned = 0usize;
    let mut skipped_too_large = 0usize;
    let mut error_count = 0usize;

    let mut scanner = yara_x::Scanner::new(rules);

    while let Some(p) = stack.pop() {
        if files_scanned >= max_entries {
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
        let bytes = match fs::read(&p) {
            Ok(b) => b,
            Err(_) => {
                error_count += 1;
                continue;
            }
        };
        files_scanned += 1;
        match scanner.scan(&bytes) {
            Ok(results) => {
                for mr in results.matching_rules() {
                    let rule_name = mr.identifier().to_string();
                    let m = meta.get(&rule_name);
                    matches_out.push(YaraMatchRow {
                        rule_id: m.map(|m| m.id.clone()).unwrap_or_else(|| rule_name.clone()),
                        rule_name: m.map(|m| m.name.clone()).unwrap_or(rule_name),
                        severity: m.map(|m| m.severity).unwrap_or(0),
                        path: p.display().to_string(),
                        size_bytes: md.len(),
                        matched_strings: mr
                            .patterns()
                            .map(|pat| pat.identifier().to_string())
                            .collect(),
                    });
                }
            }
            Err(e) => {
                tracing::debug!(path = %p.display(), error = %e, "yara.scan_failed");
                error_count += 1;
            }
        }
        if files_scanned.rem_euclid(100) == 0 {
            progress(files_scanned, max_entries);
        }
    }

    Ok(YaraScanResult {
        root: root.to_string(),
        recurse,
        rules_compiled: meta.len(),
        files_scanned,
        skipped_too_large,
        error_count,
        matches: matches_out,
    })
}

// ---------------- ioc_sweep ----------------

#[derive(Deserialize)]
struct IocSweepParams {
    path: String,
    #[serde(default)]
    recurse: bool,
    /// Optional rule-id allowlist over the agent's cached IOC rules.
    #[serde(default)]
    rule_ids: Vec<String>,
    /// Skip files larger than this. Default 256 MiB — IOC hash check
    /// has to read the whole file once.
    #[serde(default = "default_ioc_max_size")]
    max_size_bytes: u64,
    /// Cap on entries scanned. Default 200k for hash sweeps.
    #[serde(default = "default_ioc_max_entries")]
    max_entries: usize,
}

fn default_ioc_max_size() -> u64 {
    256 * 1024 * 1024
}
fn default_ioc_max_entries() -> usize {
    200_000
}

#[derive(Serialize)]
struct IocMatchRow {
    rule_id: String,
    rule_name: String,
    severity: i32,
    kind: String,
    matched_value: String,
    path: String,
    size_bytes: u64,
    sha256: Option<String>,
}

#[derive(Serialize)]
struct IocSweepResult {
    root: String,
    recurse: bool,
    rules_active: usize,
    files_scanned: usize,
    skipped_too_large: usize,
    error_count: usize,
    matches: Vec<IocMatchRow>,
}

pub struct IocSweepHandler {
    rules: RuleCache,
}

impl IocSweepHandler {
    pub fn new(rules: RuleCache) -> Self {
        Self { rules }
    }
}

#[async_trait]
impl JobHandler for IocSweepHandler {
    fn kind(&self) -> &'static str {
        "ioc_sweep"
    }
    async fn run(&self, ctx: &JobContext, params: JsonValue) -> Result<()> {
        let p: IocSweepParams = serde_json::from_value(params).context("ioc_sweep params")?;
        if p.path.trim().is_empty() {
            return Err(anyhow!("ioc_sweep requires a non-empty path"));
        }
        let snap = self
            .rules
            .snapshot()
            .await
            .ok_or_else(|| anyhow!("ioc_sweep: no rules cached yet"))?;
        let rules = filter_ioc_rules(&snap.iocs, &p.rule_ids);
        if rules.is_empty() {
            return Err(anyhow!("ioc_sweep: no IOC rules to match"));
        }

        // Build lookup tables once.
        let (hash_index, name_index, path_index, rules_active) = build_ioc_indexes(&rules);

        let path = p.path.clone();
        let recurse = p.recurse;
        let max_size = p.max_size_bytes;
        let max_entries = p.max_entries;
        let reporter = ctx.reporter.clone();

        let result = tokio::task::spawn_blocking(move || {
            walk_and_ioc_sweep(
                &path,
                recurse,
                max_size,
                max_entries,
                hash_index,
                name_index,
                path_index,
                rules_active,
                |done| {
                    let reporter = reporter.clone();
                    tokio::runtime::Handle::current().spawn(async move {
                        reporter
                            .progress(
                                (done as u32 % 99).max(1),
                                Some(format!("scanned {done} files")),
                            )
                            .await;
                    });
                },
            )
        })
        .await
        .map_err(|e| anyhow!("join: {e}"))??;

        let match_count = result.matches.len();
        let body = serde_json::to_vec_pretty(&result).context("serialize")?;
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::IocMatches,
                    original_filename: "ioc_matches.json".into(),
                    metadata: serde_json::json!({
                        "match_count": match_count,
                        "files_scanned": result.files_scanned,
                        "rules_active": result.rules_active,
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

fn filter_ioc_rules<'a>(all: &'a [p::IocRule], allow: &[String]) -> Vec<&'a p::IocRule> {
    if allow.is_empty() {
        return all.iter().collect();
    }
    let want: std::collections::HashSet<&str> = allow.iter().map(|s| s.as_str()).collect();
    all.iter()
        .filter(|r| want.contains(r.id.as_str()))
        .collect()
}

type IocIndex = HashMap<String, Arc<MatchTarget>>;

/// Indexes a slice of IOC rules into three lookup tables: SHA-256 ->
/// (rule, value), lower-case filename -> (rule, value), and lower-
/// case path substring -> (rule, value). Walker hits each as
/// appropriate; SHA-256 wins, then filename, then path.
fn build_ioc_indexes(rules: &[&p::IocRule]) -> (IocIndex, IocIndex, IocIndex, usize) {
    let mut hash_index: HashMap<String, Arc<MatchTarget>> = HashMap::new();
    let mut name_index: HashMap<String, Arc<MatchTarget>> = HashMap::new();
    let mut path_index: HashMap<String, Arc<MatchTarget>> = HashMap::new();
    for r in rules {
        // IocKind values mirror the manager. We only handle the
        // text-y ones; URL/IP IOCs aren't filesystem-relevant.
        let kind_name = ioc_kind_name(r.kind);
        for v in r.values.iter() {
            let target = Arc::new(MatchTarget {
                rule_id: r.id.clone(),
                rule_name: r.name.clone(),
                severity: r.severity,
                kind: kind_name.into(),
                value: v.clone(),
            });
            match kind_name {
                "hash_sha256" => {
                    hash_index.insert(v.to_lowercase(), target);
                }
                "filename" => {
                    name_index.insert(v.to_lowercase(), target);
                }
                "filepath" => {
                    path_index.insert(v.to_lowercase(), target);
                }
                _ => {
                    // Older IocKind values (md5, sha1) aren't worth
                    // supporting on the agent.
                }
            }
        }
    }
    let active = hash_index.len() + name_index.len() + path_index.len();
    (hash_index, name_index, path_index, active)
}

#[derive(Clone)]
struct MatchTarget {
    rule_id: String,
    rule_name: String,
    severity: i32,
    kind: String,
    value: String,
}

fn ioc_kind_name(kind: i32) -> &'static str {
    // Mirrors enum IocKind in proto/edr/v1/control.proto.
    match kind {
        1 => "hash_sha256",
        2 => "hash_md5",
        3 => "hash_sha1",
        4 => "filename",
        5 => "filepath",
        _ => "unknown",
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_and_ioc_sweep(
    root: &str,
    recurse: bool,
    max_size: u64,
    max_entries: usize,
    hash_index: HashMap<String, Arc<MatchTarget>>,
    name_index: HashMap<String, Arc<MatchTarget>>,
    path_index: HashMap<String, Arc<MatchTarget>>,
    rules_active: usize,
    progress: impl Fn(usize),
) -> Result<IocSweepResult> {
    use std::fs;
    use std::io::Read;
    let root_path = PathBuf::from(root);
    let mut stack: Vec<PathBuf> = vec![root_path.clone()];
    let mut matches: Vec<IocMatchRow> = Vec::new();
    let mut files_scanned = 0usize;
    let mut skipped_too_large = 0usize;
    let mut error_count = 0usize;

    while let Some(p) = stack.pop() {
        if files_scanned >= max_entries {
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

        let path_lower = p.display().to_string().to_lowercase();
        let name_lower = p
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        // Name + path lookups need zero I/O; do them first so a
        // filename-only IOC doesn't force a full read.
        if let Some(tgt) = name_index.get(&name_lower) {
            matches.push(make_ioc_row(tgt, &p, &md, None));
        }
        for (needle, tgt) in path_index.iter() {
            if path_lower.contains(needle) {
                matches.push(make_ioc_row(tgt, &p, &md, None));
            }
        }

        // SHA-256 lookup if any hash IOCs are active.
        let need_hash = !hash_index.is_empty();
        let sha256_hex = if need_hash {
            let mut hasher = Sha256::new();
            match fs::File::open(&p) {
                Ok(mut f) => {
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
                    Some(hex::encode(hasher.finalize()))
                }
                Err(_) => {
                    error_count += 1;
                    None
                }
            }
        } else {
            None
        };
        if let Some(hex_digest) = sha256_hex.as_ref() {
            if let Some(tgt) = hash_index.get(&hex_digest.to_lowercase()) {
                matches.push(make_ioc_row(tgt, &p, &md, Some(hex_digest.clone())));
            }
        }

        files_scanned += 1;
        if files_scanned.rem_euclid(500) == 0 {
            progress(files_scanned);
        }
    }

    Ok(IocSweepResult {
        root: root.to_string(),
        recurse,
        rules_active,
        files_scanned,
        skipped_too_large,
        error_count,
        matches,
    })
}

fn make_ioc_row(
    tgt: &MatchTarget,
    path: &std::path::Path,
    md: &std::fs::Metadata,
    sha256: Option<String>,
) -> IocMatchRow {
    IocMatchRow {
        rule_id: tgt.rule_id.clone(),
        rule_name: tgt.rule_name.clone(),
        severity: tgt.severity,
        kind: tgt.kind.clone(),
        matched_value: tgt.value.clone(),
        path: path.display().to_string(),
        size_bytes: md.len(),
        sha256,
    }
}

// ---------------- memory_yara_scan ----------------

#[derive(Deserialize)]
struct MemoryYaraParams {
    pid: u32,
    /// Optional rule-id allowlist. Empty / unset = use every enabled
    /// YARA rule the agent has cached.
    #[serde(default)]
    rule_ids: Vec<String>,
    /// Per-region cap. Regions larger than this are skipped — the
    /// .bss-style very-large mappings are rarely interesting for
    /// signature matching and wreck the agent's memory footprint.
    /// Default 64 MiB.
    #[serde(default = "default_mem_region_max")]
    max_region_bytes: u64,
    /// Cap on total bytes scanned across all regions. Default 512 MiB.
    #[serde(default = "default_mem_total_max")]
    max_total_bytes: u64,
}

fn default_mem_region_max() -> u64 {
    64 * 1024 * 1024
}
fn default_mem_total_max() -> u64 {
    512 * 1024 * 1024
}

#[derive(Serialize)]
struct MemoryYaraMatchRow {
    rule_id: String,
    rule_name: String,
    severity: i32,
    /// Region base address as kernel-reported hex (no leading 0x).
    region_addr: String,
    region_name: String,
    region_size: u64,
    matched_strings: Vec<String>,
}

#[derive(Serialize)]
struct MemoryYaraResult {
    pid: u32,
    rules_compiled: usize,
    regions_scanned: usize,
    regions_skipped_too_large: usize,
    regions_skipped_unreadable: usize,
    total_bytes_scanned: u64,
    error_count: usize,
    matches: Vec<MemoryYaraMatchRow>,
}

pub struct MemoryYaraScanHandler {
    rules: RuleCache,
    reader_factory: MemoryReaderFactory,
}

impl MemoryYaraScanHandler {
    pub fn new(rules: RuleCache, reader_factory: MemoryReaderFactory) -> Self {
        Self {
            rules,
            reader_factory,
        }
    }
}

#[async_trait]
impl JobHandler for MemoryYaraScanHandler {
    fn kind(&self) -> &'static str {
        "memory_yara_scan"
    }
    async fn run(&self, ctx: &JobContext, params: JsonValue) -> Result<()> {
        let p: MemoryYaraParams =
            serde_json::from_value(params).context("memory_yara_scan params")?;
        if p.pid == 0 {
            return Err(anyhow!("memory_yara_scan requires pid > 0"));
        }

        let snapshot = self.rules.snapshot().await.ok_or_else(|| {
            anyhow!("memory_yara_scan: no rules cached yet — wait for the first RuleSync")
        })?;
        let yara_rules: Vec<p::YaraRule> = filter_yara_rules(&snapshot.yara, &p.rule_ids)
            .into_iter()
            .cloned()
            .collect();
        if yara_rules.is_empty() {
            if snapshot.yara.is_empty() {
                return Err(anyhow!(
                    "memory_yara_scan: no YARA rules cached on this agent — \
                     define and enable at least one YARA rule first"
                ));
            }
            return Err(anyhow!(
                "memory_yara_scan: rule_ids filter matched 0 of {} cached YARA rules",
                snapshot.yara.len()
            ));
        }

        ctx.reporter
            .progress(5, Some(format!("compiling {} rules", yara_rules.len())))
            .await;

        let (compiled, rule_meta) = tokio::task::spawn_blocking(move || compile_rules(&yara_rules))
            .await
            .map_err(|e| anyhow!("join: {e}"))??;
        let rules_compiled = rule_meta.len();

        ctx.reporter
            .progress(15, Some(format!("opening pid {}", p.pid)))
            .await;

        let factory = self.reader_factory;
        let reporter = ctx.reporter.clone();
        let result = tokio::task::spawn_blocking(move || {
            let reader = factory(p.pid).context("open process for memory scan")?;
            scan_regions(
                p.pid,
                reader,
                p.max_region_bytes,
                p.max_total_bytes,
                rules_compiled,
                &compiled,
                &rule_meta,
                |regions, bytes| {
                    let reporter = reporter.clone();
                    let pct = (15u32 + (regions as u32 % 80)).min(95);
                    tokio::runtime::Handle::current().spawn(async move {
                        reporter
                            .progress(
                                pct,
                                Some(format!("scanned {regions} regions, {bytes} bytes")),
                            )
                            .await;
                    });
                },
            )
        })
        .await
        .map_err(|e| anyhow!("join: {e}"))??;

        let match_count = result.matches.len();
        let body = serde_json::to_vec_pretty(&result).context("serialize")?;
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::YaraMatches,
                    original_filename: format!("memory_yara_pid{}.json", p.pid),
                    metadata: serde_json::json!({
                        "scan_kind": "memory_yara",
                        "pid": p.pid,
                        "match_count": match_count,
                        "regions_scanned": result.regions_scanned,
                        "rules_compiled": result.rules_compiled,
                    }),
                },
                body,
            )
            .await?;
        ctx.reporter.progress(100, None).await;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_regions(
    pid: u32,
    mut reader: Box<dyn crate::scanner::MemoryRegionReader + Send + 'static>,
    max_region_bytes: u64,
    max_total_bytes: u64,
    rules_compiled: usize,
    rules: &yara_x::Rules,
    meta: &HashMap<String, RuleMeta>,
    progress: impl Fn(usize, u64),
) -> Result<MemoryYaraResult> {
    let mut scanner = yara_x::Scanner::new(rules);
    let mut matches: Vec<MemoryYaraMatchRow> = Vec::new();
    let mut regions_scanned = 0usize;
    let mut regions_skipped_too_large = 0usize;
    let mut regions_skipped_unreadable = 0usize;
    let mut total_bytes_scanned = 0u64;
    let mut error_count = 0usize;

    while total_bytes_scanned < max_total_bytes {
        let region = match reader.next_region() {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(_) => {
                regions_skipped_unreadable += 1;
                continue;
            }
        };
        let size = region.bytes.len() as u64;
        if size == 0 {
            regions_skipped_unreadable += 1;
            continue;
        }
        if size > max_region_bytes {
            regions_skipped_too_large += 1;
            continue;
        }
        regions_scanned += 1;
        total_bytes_scanned += size;
        match scanner.scan(&region.bytes) {
            Ok(results) => {
                for mr in results.matching_rules() {
                    let rule_name = mr.identifier().to_string();
                    let m = meta.get(&rule_name);
                    matches.push(MemoryYaraMatchRow {
                        rule_id: m.map(|m| m.id.clone()).unwrap_or_else(|| rule_name.clone()),
                        rule_name: m.map(|m| m.name.clone()).unwrap_or(rule_name),
                        severity: m.map(|m| m.severity).unwrap_or(0),
                        region_addr: format!("{:x}", region.addr),
                        region_name: region.name.clone(),
                        region_size: size,
                        matched_strings: mr
                            .patterns()
                            .map(|pat| pat.identifier().to_string())
                            .collect(),
                    });
                }
            }
            Err(e) => {
                tracing::debug!(addr = region.addr, error = %e, "memory_yara.scan_failed");
                error_count += 1;
            }
        }
        if regions_scanned.rem_euclid(8) == 0 {
            progress(regions_scanned, total_bytes_scanned);
        }
    }

    Ok(MemoryYaraResult {
        pid,
        rules_compiled,
        regions_scanned,
        regions_skipped_too_large,
        regions_skipped_unreadable,
        total_bytes_scanned,
        error_count,
        matches,
    })
}

// ---------------- registration helper ----------------

pub fn register_hunt_handlers(dispatcher: &crate::jobs::JobDispatcher, rules: RuleCache) {
    use std::sync::Arc;
    dispatcher.register(Arc::new(YaraFsScanHandler::new(rules.clone())));
    dispatcher.register(Arc::new(IocSweepHandler::new(rules)));
}

/// Memory YARA registration is platform-aware: each platform binary
/// (`agent-linux`, `agent-windows`) provides the [`MemoryReaderFactory`]
/// for its process-memory walker and calls this after
/// `register_hunt_handlers`. Keeping the registration here (rather
/// than inline at the call site) means the wire kind ("memory_yara_scan")
/// stays owned by `agent-core`.
pub fn register_memory_yara_handler(
    dispatcher: &crate::jobs::JobDispatcher,
    rules: RuleCache,
    reader_factory: MemoryReaderFactory,
) {
    use std::sync::Arc;
    dispatcher.register(Arc::new(MemoryYaraScanHandler::new(rules, reader_factory)));
}
