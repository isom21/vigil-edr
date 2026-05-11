//! Jobs engine (M23.c): dispatcher + handler trait + supporting types.
//!
//! The agent receives a `Command::RunJob(RunJobCmd)` via the existing
//! HostStream. `RunJobCmd.job_kind` selects a handler from
//! [`JobDispatcher`]; the handler runs and reports progress + artifacts
//! through the [`JobContext`]. Platform-specific handlers
//! (agent-linux / agent-windows) plug into this trait; cross-platform
//! kinds (process_snapshot, agent_diagnostic, hash_files) live in
//! agent-core.
//!
//! This module is the protocol shape only — handler implementations
//! land in M23.d–M23.g.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Per-run scratch passed to every handler. Owns the reporter +
/// uploader; handlers should clone the Arcs rather than the context
/// itself when they need to fork tasks.
pub struct JobContext {
    pub run_id: String,
    pub job_kind: String,
    pub reporter: Arc<dyn JobReporter>,
    pub uploader: Arc<dyn ArtifactUploader>,
}

/// Reports mid-flight progress + terminal status back to the manager.
/// Wire-side: emits `JobProgress` ClientMessages.
#[async_trait]
pub trait JobReporter: Send + Sync {
    /// Mark the run as RUNNING (pct=0) at handler entry. Implementations
    /// may coalesce repeated calls.
    async fn started(&self);

    /// 0..=100. Optional human-readable message ("scanning /etc",
    /// "12/500 processes hashed").
    async fn progress(&self, pct: u32, message: Option<String>);

    /// Terminal failure. The dispatcher also sends a CommandResult
    /// when the handler returns Err — this is the early-out path for
    /// fatal errors discovered mid-stream.
    async fn failed(&self, error: String);
}

/// Uploads an artifact blob to the manager-backed object store and
/// reports the metadata so the manager creates a JobArtifact row.
#[async_trait]
pub trait ArtifactUploader: Send + Sync {
    /// Upload `body` and return the registered location. Implementations
    /// must:
    ///   1. Call manager's RequestArtifactUpload (gRPC) to get a
    ///      short-lived presigned PUT URL.
    ///   2. HTTPS PUT the body to MinIO.
    ///   3. Compute SHA-256 over `body`.
    ///   4. Send `JobArtifactReport` on the bidi stream so the manager
    ///      writes a JobArtifact row.
    async fn upload(&self, spec: ArtifactSpec, body: Vec<u8>) -> Result<UploadedArtifact>;
}

/// Stable artifact taxonomy that mirrors `JobArtifactKind` on the
/// manager. Wire format is the lowercase string for forwards-compat.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Json,
    File,
    YaraMatches,
    IocMatches,
    HashList,
    ShellOutput,
    DiagnosticBundle,
}

impl ArtifactKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::File => "file",
            Self::YaraMatches => "yara_matches",
            Self::IocMatches => "ioc_matches",
            Self::HashList => "hash_list",
            Self::ShellOutput => "shell_output",
            Self::DiagnosticBundle => "diagnostic_bundle",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactSpec {
    pub kind: ArtifactKind,
    /// Suggested filename; the manager sanitises this when building
    /// the MinIO object key, so handlers can pass the raw acquired
    /// path without escaping.
    pub original_filename: String,
    pub metadata: JsonValue,
}

#[derive(Debug, Clone)]
pub struct UploadedArtifact {
    pub bucket: String,
    pub object_key: String,
    pub size_bytes: u64,
    pub sha256: String,
}

/// One job kind's implementation. Stateless — keep config in the
/// handler struct's fields; per-run state comes via `JobContext` +
/// the parameters JSON.
#[async_trait]
pub trait JobHandler: Send + Sync {
    /// Wire string matching JobKind on the manager. The dispatcher
    /// indexes on this — be precise.
    fn kind(&self) -> &'static str;

    /// Execute the job. Long-running handlers should pulse progress
    /// frequently; if the handler returns Ok, the dispatcher emits a
    /// `CommandResult { success=true }` upstream.
    async fn run(&self, ctx: &JobContext, params: JsonValue) -> Result<()>;
}

/// Lookup table of registered handlers. Built once at agent startup
/// (Linux + Windows binaries call `register_default_handlers` plus
/// their platform-specific additions).
///
/// Interior mutability via RwLock so [`register`] only needs `&self`.
/// That lets the agent wrap the dispatcher in `Arc` and then register
/// handlers that themselves hold a `Weak<JobDispatcher>` (e.g. the
/// host_sweep handler, which dispatches sub-handlers).
#[derive(Default)]
pub struct JobDispatcher {
    handlers: RwLock<HashMap<&'static str, Arc<dyn JobHandler>>>,
}

impl JobDispatcher {
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, handler: Arc<dyn JobHandler>) {
        let kind = handler.kind();
        let mut map = self.handlers.write().expect("handlers RwLock poisoned");
        if map.insert(kind, handler).is_some() {
            tracing::warn!(kind, "job_dispatcher.duplicate_handler_overwritten");
        }
    }

    /// True if there's a handler for `kind`. Used by the platform
    /// dispatcher to fail fast on RUN_JOB commands for unsupported
    /// kinds (e.g. Linux can't run REGISTRY_QUERY).
    pub fn supports(&self, kind: &str) -> bool {
        self.handlers
            .read()
            .expect("handlers RwLock poisoned")
            .contains_key(kind)
    }

    pub async fn dispatch(&self, ctx: JobContext, params: JsonValue) -> Result<()> {
        let kind = ctx.job_kind.clone();
        let handler = {
            let map = self.handlers.read().expect("handlers RwLock poisoned");
            map.get(kind.as_str())
                .ok_or_else(|| anyhow!("no handler registered for job kind {kind}"))?
                .clone()
        };
        ctx.reporter.started().await;
        let result = handler.run(&ctx, params).await;
        if let Err(e) = &result {
            ctx.reporter.failed(e.to_string()).await;
        }
        result
    }

    /// Sorted list of supported kinds — useful for the agent's startup
    /// log line so operators can see what the binary can actually do.
    pub fn supported_kinds(&self) -> Vec<&'static str> {
        let map = self.handlers.read().expect("handlers RwLock poisoned");
        let mut v: Vec<&'static str> = map.keys().copied().collect();
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct CountingReporter {
        progress_calls: AtomicU32,
        started_calls: AtomicU32,
        failed_calls: AtomicU32,
    }

    #[async_trait]
    impl JobReporter for CountingReporter {
        async fn started(&self) {
            self.started_calls.fetch_add(1, Ordering::SeqCst);
        }
        async fn progress(&self, _pct: u32, _message: Option<String>) {
            self.progress_calls.fetch_add(1, Ordering::SeqCst);
        }
        async fn failed(&self, _error: String) {
            self.failed_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct NoopUploader;
    #[async_trait]
    impl ArtifactUploader for NoopUploader {
        async fn upload(&self, _spec: ArtifactSpec, body: Vec<u8>) -> Result<UploadedArtifact> {
            Ok(UploadedArtifact {
                bucket: "test".into(),
                object_key: "k".into(),
                size_bytes: body.len() as u64,
                sha256: "0".repeat(64),
            })
        }
    }

    struct OkHandler;
    #[async_trait]
    impl JobHandler for OkHandler {
        fn kind(&self) -> &'static str {
            "ok"
        }
        async fn run(&self, ctx: &JobContext, _params: JsonValue) -> Result<()> {
            ctx.reporter.progress(50, None).await;
            Ok(())
        }
    }

    struct FailHandler;
    #[async_trait]
    impl JobHandler for FailHandler {
        fn kind(&self) -> &'static str {
            "fail"
        }
        async fn run(&self, _ctx: &JobContext, _params: JsonValue) -> Result<()> {
            Err(anyhow!("boom"))
        }
    }

    fn ctx(kind: &str, reporter: Arc<CountingReporter>) -> JobContext {
        JobContext {
            run_id: "r".into(),
            job_kind: kind.into(),
            reporter,
            uploader: Arc::new(NoopUploader),
        }
    }

    #[tokio::test]
    async fn dispatcher_runs_handler_and_emits_started() {
        let d = JobDispatcher::new();
        d.register(Arc::new(OkHandler));
        let r = Arc::new(CountingReporter {
            progress_calls: AtomicU32::new(0),
            started_calls: AtomicU32::new(0),
            failed_calls: AtomicU32::new(0),
        });
        d.dispatch(ctx("ok", r.clone()), JsonValue::Null)
            .await
            .unwrap();
        assert_eq!(r.started_calls.load(Ordering::SeqCst), 1);
        assert_eq!(r.progress_calls.load(Ordering::SeqCst), 1);
        assert_eq!(r.failed_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn dispatcher_reports_failure() {
        let d = JobDispatcher::new();
        d.register(Arc::new(FailHandler));
        let r = Arc::new(CountingReporter {
            progress_calls: AtomicU32::new(0),
            started_calls: AtomicU32::new(0),
            failed_calls: AtomicU32::new(0),
        });
        let err = d
            .dispatch(ctx("fail", r.clone()), JsonValue::Null)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("boom"));
        assert_eq!(r.failed_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dispatcher_rejects_unknown_kind() {
        let d = JobDispatcher::new();
        let r = Arc::new(CountingReporter {
            progress_calls: AtomicU32::new(0),
            started_calls: AtomicU32::new(0),
            failed_calls: AtomicU32::new(0),
        });
        let err = d
            .dispatch(ctx("nope", r.clone()), JsonValue::Null)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no handler"));
        assert_eq!(r.started_calls.load(Ordering::SeqCst), 0);
    }
}
