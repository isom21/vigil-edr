//! Integration test for `triage_collect` (Phase 2 #2.10).
//!
//! Wires the handler against a tempdir-rooted "host" and asserts the
//! produced ZIP archive includes the seeded files plus a manifest.
//! Exercises the `source_root_override` parameter so the test stays
//! hermetic — it doesn't read /var/log on the dev box.

use std::io::Read;
use std::sync::{Arc, Mutex};

use agent_core::jobs::{
    ArtifactSpec, ArtifactUploader, JobContext, JobDispatcher, JobReporter, UploadedArtifact,
};
use agent_core::jobs_acquire::register_acquisition_handlers;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;

#[derive(Default)]
struct RecordingReporter {
    started_calls: Mutex<u32>,
    progress_calls: Mutex<u32>,
    failed_calls: Mutex<u32>,
}

#[async_trait]
impl JobReporter for RecordingReporter {
    async fn started(&self) {
        *self.started_calls.lock().unwrap() += 1;
    }
    async fn progress(&self, _pct: u32, _message: Option<String>) {
        *self.progress_calls.lock().unwrap() += 1;
    }
    async fn failed(&self, _error: String) {
        *self.failed_calls.lock().unwrap() += 1;
    }
}

#[derive(Default)]
struct CapturingUploader {
    /// (filename, kind-str, raw bytes). One entry per upload call;
    /// triage_collect makes exactly one upload (the ZIP archive).
    artifacts: Mutex<Vec<(String, String, Vec<u8>)>>,
}

#[async_trait]
impl ArtifactUploader for CapturingUploader {
    async fn upload(&self, spec: ArtifactSpec, body: Vec<u8>) -> Result<UploadedArtifact> {
        let size = body.len() as u64;
        self.artifacts.lock().unwrap().push((
            spec.original_filename.clone(),
            spec.kind.as_str().to_string(),
            body,
        ));
        Ok(UploadedArtifact {
            bucket: "test".into(),
            object_key: spec.original_filename,
            size_bytes: size,
            sha256: "0".repeat(64),
        })
    }
}

fn touch(path: &std::path::Path, content: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

#[tokio::test]
async fn triage_collect_produces_zip_with_seeded_linux_sources() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // Seed a /var/log auth.log + syslog + a cron unit so the linux
    // category enumerators have something to pick up.
    touch(
        &root.join("var/log/auth.log"),
        b"pam_unix(sudo:session): seeded\n",
    );
    touch(
        &root.join("var/log/syslog"),
        b"systemd: seeded syslog line\n",
    );
    touch(
        &root.join("etc/cron.d/seeded"),
        b"* * * * * root /usr/bin/echo seeded\n",
    );

    let dispatcher = JobDispatcher::new();
    register_acquisition_handlers(&dispatcher);
    assert!(dispatcher.supports("triage_collect"), "handler registered");

    let reporter: Arc<RecordingReporter> = Arc::new(RecordingReporter::default());
    let uploader: Arc<CapturingUploader> = Arc::new(CapturingUploader::default());
    let ctx = JobContext {
        run_id: "test-run".into(),
        job_kind: "triage_collect".into(),
        reporter: reporter.clone(),
        uploader: uploader.clone(),
    };

    let params = json!({
        // Disable the categories that shell out / read live paths so
        // the test doesn't depend on journalctl, systemctl, browsers,
        // or Windows-only sources.
        "include_registry": false,
        "include_mft": false,
        "include_prefetch": false,
        "include_browser": false,
        "include_event_log": true,
        "include_systemd_journal": false,
        "include_persistence": true,
        "max_size_mb": 16,
        "source_root_override": root.display().to_string(),
    });

    dispatcher
        .dispatch(ctx, params)
        .await
        .expect("triage_collect handler should succeed");

    let arts = uploader.artifacts.lock().unwrap();
    assert_eq!(arts.len(), 1, "exactly one upload (the ZIP)");
    let (filename, kind, body) = &arts[0];
    assert!(filename.ends_with(".zip"), "filename: {filename}");
    assert_eq!(kind, "diagnostic_bundle");

    // The dispatcher emits started() once and the handler emits
    // progress() at least a couple of times (5% staging, 80% upload,
    // 100% done).
    assert_eq!(*reporter.started_calls.lock().unwrap(), 1);
    assert!(*reporter.progress_calls.lock().unwrap() >= 2);
    assert_eq!(*reporter.failed_calls.lock().unwrap(), 0);

    // Crack the ZIP open and assert the seeded files + manifest are
    // present.
    let cursor = std::io::Cursor::new(body.clone());
    let mut zip = zip::ZipArchive::new(cursor).expect("valid zip");

    let names: Vec<String> = (0..zip.len())
        .map(|i| zip.by_index(i).unwrap().name().to_string())
        .collect();
    assert!(
        names.iter().any(|n| n == "MANIFEST.json"),
        "manifest entry missing — got {names:?}"
    );

    // Manifest content reflects what we packed.
    let mut manifest_entry = zip.by_name("MANIFEST.json").expect("manifest");
    let mut manifest_buf = String::new();
    manifest_entry.read_to_string(&mut manifest_buf).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_buf).expect("manifest json");
    let files = manifest
        .get("files")
        .and_then(|v| v.as_array())
        .expect("files array");
    let archive_paths: Vec<String> = files
        .iter()
        .filter_map(|f| f.get("archive_path").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .collect();

    // At least the seeded auth.log + syslog + cron file should appear.
    let want_substrings = ["auth.log", "syslog", "cron.d/seeded"];
    for needle in want_substrings {
        assert!(
            archive_paths.iter().any(|p| p.contains(needle)),
            "expected archive path containing {needle}; got {archive_paths:?}"
        );
    }

    // Manifest os field should be set to "linux" since the test runs
    // on Linux in CI; if a contributor runs it on macOS we'd see
    // "macos" — keep this loose.
    let os = manifest.get("os").and_then(|v| v.as_str()).unwrap_or("");
    assert!(!os.is_empty(), "os field populated");
}

#[tokio::test]
async fn triage_collect_respects_max_size_cap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // Seed three log files, each just under 1 MiB. With max_size_mb=2
    // we expect 2 of them to land inside the archive and the third
    // to surface in `manifest.skipped` with reason "archive size cap
    // reached".
    let big = vec![b'X'; 900 * 1024];
    touch(&root.join("var/log/auth.log"), &big);
    touch(&root.join("var/log/syslog"), &big);
    touch(&root.join("var/log/secure"), &big);

    let dispatcher = JobDispatcher::new();
    register_acquisition_handlers(&dispatcher);

    let reporter: Arc<RecordingReporter> = Arc::new(RecordingReporter::default());
    let uploader: Arc<CapturingUploader> = Arc::new(CapturingUploader::default());
    let ctx = JobContext {
        run_id: "test-run".into(),
        job_kind: "triage_collect".into(),
        reporter,
        uploader: uploader.clone(),
    };

    let params = json!({
        "include_registry": false,
        "include_mft": false,
        "include_prefetch": false,
        "include_browser": false,
        "include_event_log": true,
        "include_systemd_journal": false,
        "include_persistence": false,
        "max_size_mb": 2,
        "source_root_override": root.display().to_string(),
    });

    dispatcher.dispatch(ctx, params).await.expect("ok");
    let arts = uploader.artifacts.lock().unwrap();
    let (_, _, body) = &arts[0];

    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(body.clone())).unwrap();
    let mut manifest_entry = zip.by_name("MANIFEST.json").unwrap();
    let mut manifest_buf = String::new();
    manifest_entry.read_to_string(&mut manifest_buf).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_buf).unwrap();

    let truncated = manifest
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let skipped_len = manifest
        .get("skipped")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        truncated,
        "manifest.truncated should be true once cap is hit"
    );
    assert!(
        skipped_len >= 1,
        "manifest.skipped should record the dropped file(s); got {skipped_len}"
    );
}
