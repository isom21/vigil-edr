//! Deception / honeytokens (Phase 4 #4.5, Linux).
//!
//! Applies a batch of `HoneytokenSpec` to the local filesystem:
//!
//!   * `fake_file` — write the payload bytes to `target_path` and stamp
//!     `user.vigil_honeytoken=<id>` as an extended attribute. Userspace
//!     event handling looks up that xattr on every observed file_open
//!     and emits a `HoneytokenHit` when it matches a tracked id.
//!   * `fake_regkey` / `creds_in_lsass` — Windows-only primitives;
//!     logged as a no-op on Linux so the operator sees the agent
//!     received the spec.
//!
//! The hit-detection map (id ↔ canonical path) lives in
//! [`DeceptionState`]; the agent stashes the populated state on
//! `crate::ebpf` so the file_open path can do a single hash lookup
//! per event without re-syscalling `lgetxattr`.
//!
//! `apply_at` takes an explicit base dir so unit tests can target a
//! tempdir without writing to the live filesystem.

#![cfg(target_os = "linux")]

use agent_core::proto as p;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, RwLock};

/// Extended-attribute name the agent stamps onto every planted
/// `fake_file`. Keeping the namespace under `user.` so unprivileged
/// processes can also see the tag when the agent ships a YARA
/// fixture's hit through process-tree-style enrichment.
pub const VIGIL_HONEYTOKEN_XATTR: &str = "user.vigil_honeytoken";

/// One deployed token tracked in-memory so the file_open path can
/// resolve `path → honeytoken_id` in O(1).
#[derive(Clone, Debug, Default)]
pub struct DeceptionState {
    by_path: HashMap<String, String>,
}

impl DeceptionState {
    pub fn lookup_path(&self, path: &str) -> Option<&str> {
        self.by_path.get(path).map(|s| s.as_str())
    }

    /// Used by the test suite; the production agent only checks
    /// `is_empty()` on the fast path.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }
}

/// Shared handle so the apply path + the hit-detection path can both
/// reach the same map without passing it through every fn signature.
pub static DEPLOYED: LazyLock<RwLock<DeceptionState>> =
    LazyLock::new(|| RwLock::new(DeceptionState::default()));

/// Apply a batch of specs against the live filesystem.
pub fn apply(specs: &[p::HoneytokenSpec]) -> Result<()> {
    apply_at(specs, Path::new("/"))
}

/// Test-friendly entry point. `base` is prepended to every spec's
/// `target_path` so the integration test can target a tempdir.
pub fn apply_at(specs: &[p::HoneytokenSpec], base: &Path) -> Result<()> {
    let mut new_state = DeceptionState::default();
    for spec in specs {
        match spec.kind.as_str() {
            "fake_file" => {
                let path = render_target(base, &spec.target_path);
                if let Err(e) = write_fake_file(&path, &spec.payload, &spec.id) {
                    tracing::warn!(
                        id = %spec.id,
                        path = %path.display(),
                        error = %e,
                        "honeytoken.fake_file_failed"
                    );
                    continue;
                }
                tracing::info!(
                    id = %spec.id,
                    name = %spec.name,
                    path = %path.display(),
                    "honeytoken.fake_file_planted"
                );
                if let Some(canonical) = path.to_str() {
                    new_state
                        .by_path
                        .insert(canonical.to_string(), spec.id.clone());
                }
            }
            "fake_regkey" | "creds_in_lsass" => {
                tracing::info!(
                    id = %spec.id,
                    kind = %spec.kind,
                    "honeytoken.windows_only_skipped"
                );
            }
            other => {
                tracing::warn!(id = %spec.id, kind = %other, "honeytoken.unknown_kind");
            }
        }
    }
    let mut guard = DEPLOYED.write().unwrap_or_else(|e| e.into_inner());
    *guard = new_state;
    Ok(())
}

fn render_target(base: &Path, target: &str) -> PathBuf {
    if base == Path::new("/") || target.is_empty() {
        PathBuf::from(target)
    } else {
        // Strip a leading slash so `tempdir.join("/var/x")` doesn't
        // resolve back to `/var/x` (Rust's `Path::join` honours an
        // absolute right-hand side and discards `base`).
        let trimmed = target.trim_start_matches('/');
        base.join(trimmed)
    }
}

fn write_fake_file(path: &Path, payload: &[u8], id: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir -p {}", parent.display()))?;
        }
    }
    std::fs::write(path, payload).with_context(|| format!("write {}", path.display()))?;
    set_xattr(path, VIGIL_HONEYTOKEN_XATTR, id.as_bytes())
        .with_context(|| format!("set xattr {}", path.display()))?;
    Ok(())
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let cname =
        CString::new(name).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let r = unsafe {
        libc::setxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Read the honeytoken xattr off a path. Returns the id as a UTF-8
/// string when present, or None when the xattr isn't set or the file
/// has gone away. Used by the file_open hit-detection path to confirm
/// the path is still tagged (the agent re-checks rather than trusting
/// only the in-memory map so a manually-removed file doesn't keep
/// firing false positives).
pub fn read_xattr_id(path: &Path) -> Option<String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    let cname = CString::new(VIGIL_HONEYTOKEN_XATTR).ok()?;
    // Try a small buffer first; if the value is larger, libc returns
    // -1 / ERANGE and the caller would loop — for our 36-byte UUIDs
    // 64 bytes is plenty.
    let mut buf = [0u8; 64];
    let r = unsafe {
        libc::getxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if r <= 0 {
        return None;
    }
    let n = r as usize;
    std::str::from_utf8(&buf[..n]).ok().map(|s| s.to_string())
}
