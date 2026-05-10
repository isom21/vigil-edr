//! M12.a: agent binary + config integrity self-check.
//!
//! Computes SHA-256 baselines at agent startup for the on-disk
//! binary (`/proc/self/exe` on Linux, the running .exe path on
//! Windows) and the config file, then re-verifies them on a 5-minute
//! interval. A drift between the baseline and the current hash
//! indicates that the agent's image or config was modified at runtime
//! — which is exactly what an attacker swapping in a backdoored
//! binary while the agent is paused looks like, or what a sloppy
//! operator running `dpkg --force-overwrite` while the agent is up
//! looks like. Either way, it's a tamper signal.
//!
//! The first-pass check at startup is a stronger gate: if a
//! deb/rpm-installed manifest at `/etc/edr/agent.sha256` exists and
//! the actual hash doesn't match it, the agent refuses to start at
//! all (caller must opt-in to bypass via `EDR_DISABLE_INTEGRITY_CHECK`).
//! That's already wired in `agent-linux/src/main.rs` — this module
//! provides the in-process *runtime* watchdog that catches tamper
//! after startup.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Snapshot of integrity-relevant hashes captured at startup.
#[derive(Debug, Clone)]
pub struct IntegrityBaseline {
    pub binary_path: PathBuf,
    pub binary_sha256: String,
    /// Config file (TOML). May be `None` if the agent was started
    /// with no config file (env-only mode).
    pub config_path: Option<PathBuf>,
    pub config_sha256: Option<String>,
}

/// Drift between the baseline and the current state. Each `Option`
/// is set when that target's hash drifted; `None` means it still
/// matches. The actual hash is included so the manager can decide
/// whether the new state matches a known-good replacement (e.g. a
/// signed package upgrade) or whether to escalate.
#[derive(Debug, Clone, Default)]
pub struct IntegrityDrift {
    pub binary: Option<DriftDetail>,
    pub config: Option<DriftDetail>,
}

#[derive(Debug, Clone)]
pub struct DriftDetail {
    pub path: PathBuf,
    pub expected: String,
    pub actual: String,
}

impl IntegrityDrift {
    pub fn is_clean(&self) -> bool {
        self.binary.is_none() && self.config.is_none()
    }
}

impl IntegrityBaseline {
    /// Capture a baseline. The binary hash always comes from the path
    /// `binary_path` resolves to — on Linux, callers should pass
    /// `/proc/self/exe` so the value reflects the *running* image
    /// rather than whatever currently lives at the install path.
    pub fn capture(binary_path: PathBuf, config_path: Option<PathBuf>) -> Result<Self> {
        let binary_sha256 = sha256_file(&binary_path)
            .with_context(|| format!("hash binary {}", binary_path.display()))?;
        let config_sha256 = match &config_path {
            Some(p) => Some(
                sha256_file(p).with_context(|| format!("hash config {}", p.display()))?,
            ),
            None => None,
        };
        Ok(Self {
            binary_path,
            binary_sha256,
            config_path,
            config_sha256,
        })
    }

    /// Re-hash the targets and report any drift relative to the
    /// captured baseline. A read error on one of the files counts as
    /// drift (the file disappearing is itself a tamper signal).
    pub fn verify(&self) -> IntegrityDrift {
        let mut drift = IntegrityDrift::default();
        let actual_bin = sha256_file(&self.binary_path).unwrap_or_else(|e| format!("ERROR:{e}"));
        if !actual_bin.eq_ignore_ascii_case(&self.binary_sha256) {
            drift.binary = Some(DriftDetail {
                path: self.binary_path.clone(),
                expected: self.binary_sha256.clone(),
                actual: actual_bin,
            });
        }
        if let (Some(path), Some(expected)) = (self.config_path.as_ref(), self.config_sha256.as_ref()) {
            let actual = sha256_file(path).unwrap_or_else(|e| format!("ERROR:{e}"));
            if !actual.eq_ignore_ascii_case(expected) {
                drift.config = Some(DriftDetail {
                    path: path.clone(),
                    expected: expected.clone(),
                    actual,
                });
            }
        }
        drift
    }
}

fn sha256_file(p: &Path) -> Result<String> {
    let mut f = std::fs::File::open(p).with_context(|| format!("open {}", p.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).with_context(|| format!("read {}", p.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_file(content: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn capture_and_verify_clean() {
        let bin = tmp_file(b"agent-binary-bytes");
        let cfg = tmp_file(b"manager_endpoint = \"x\"\n");
        let baseline =
            IntegrityBaseline::capture(bin.path().to_path_buf(), Some(cfg.path().to_path_buf()))
                .unwrap();
        assert_eq!(baseline.binary_sha256.len(), 64);
        let drift = baseline.verify();
        assert!(drift.is_clean(), "expected clean: {drift:?}");
    }

    #[test]
    fn detects_binary_drift() {
        let bin = tmp_file(b"agent-binary-bytes");
        let baseline = IntegrityBaseline::capture(bin.path().to_path_buf(), None).unwrap();
        // Overwrite the file in place — simulates a tamper.
        std::fs::write(bin.path(), b"backdoored-bytes").unwrap();
        let drift = baseline.verify();
        assert!(drift.binary.is_some(), "expected binary drift");
        assert!(drift.config.is_none());
        let d = drift.binary.unwrap();
        assert_ne!(d.expected, d.actual);
    }

    #[test]
    fn detects_config_drift() {
        let bin = tmp_file(b"binary");
        let cfg = tmp_file(b"key = \"v1\"");
        let baseline =
            IntegrityBaseline::capture(bin.path().to_path_buf(), Some(cfg.path().to_path_buf()))
                .unwrap();
        std::fs::write(cfg.path(), b"key = \"attacker-controlled\"").unwrap();
        let drift = baseline.verify();
        assert!(drift.config.is_some());
        assert!(drift.binary.is_none());
    }

    #[test]
    fn missing_file_counts_as_drift() {
        let bin = tmp_file(b"binary");
        let baseline = IntegrityBaseline::capture(bin.path().to_path_buf(), None).unwrap();
        std::fs::remove_file(bin.path()).unwrap();
        let drift = baseline.verify();
        assert!(drift.binary.is_some());
        assert!(drift.binary.as_ref().unwrap().actual.starts_with("ERROR:"));
    }
}
