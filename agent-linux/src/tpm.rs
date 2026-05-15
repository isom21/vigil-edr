//! TPM-backed boot-state attestation (Phase 4 #4.10).
//!
//! Two surfaces:
//!
//!   * [`read_pcrs`] reads the running PCR set from the kernel's
//!     sysfs TPM interface (`/sys/class/tpm/tpm0/pcr-<bank>/<n>`).
//!     This is unsigned — fine for the periodic Hello-time report
//!     because the manager treats it as a measurement, not a proof.
//!   * [`quote`] returns a signed quote over an operator-supplied
//!     nonce. v1 ships a stub that surfaces a clear "no AK
//!     provisioned" error on hosts without an Endorsement Key
//!     chain; sites with a real TPM + tss-esapi installed can drop
//!     in the full implementation behind the same signature.
//!
//! `Missing-TPM` is *not fatal*: the caller logs a warning and
//! continues so hosts without a TPM (containers, old laptops) still
//! enrol normally.

#![cfg(target_os = "linux")]

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// One PCR slot read from the kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrValue {
    pub index: u32,
    pub bank: String,
    pub digest: Vec<u8>,
}

/// Default base path. Tests inject a tempdir target via [`read_pcrs_at`].
const TPM_SYSFS_BASE: &str = "/sys/class/tpm/tpm0";

/// Banks worth reading. The kernel exposes each available bank under
/// `pcr-<bank>/<index>`. We only ship sha256 in the wire payload
/// today; sha1 stays available for legacy firmware that doesn't have
/// sha256 PCRs, but we don't include it in `read_pcrs()` output by
/// default to keep the wire shape predictable.
const PRIMARY_BANK: &str = "sha256";

/// PCR indices the manager cares about for boot-state divergence:
///
///   * 0–7 — UEFI firmware + boot-loader + measured boot.
///   * 8–9 — kernel + initrd (systemd-boot / grub2).
///
/// Reading the full 0..=23 range is cheap (~24 × 64 bytes per cycle)
/// but the manager only diffs the first ten. Keeping the slice
/// honest avoids shipping data we never read.
pub const REPORTED_INDICES: &[u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

/// Read the current PCR set. Returns an error if no TPM device is
/// exposed under `/sys/class/tpm/tpm0/`; the caller is expected to
/// downgrade that to a warning rather than aborting startup.
pub fn read_pcrs() -> Result<Vec<PcrValue>> {
    read_pcrs_at(Path::new(TPM_SYSFS_BASE), REPORTED_INDICES)
}

/// Same as [`read_pcrs`] but takes the sysfs base path explicitly so
/// tests can pin a fixture directory under a tempdir.
pub fn read_pcrs_at(base: &Path, indices: &[u32]) -> Result<Vec<PcrValue>> {
    let bank_dir = base.join(format!("pcr-{PRIMARY_BANK}"));
    if !bank_dir.exists() {
        anyhow::bail!(
            "TPM sysfs not present at {}; host has no exposed TPM (or kernel built without TPM support)",
            bank_dir.display()
        );
    }
    let mut out = Vec::with_capacity(indices.len());
    for &i in indices {
        let path = bank_dir.join(i.to_string());
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(
                    path = %path.display(),
                    error = %e,
                    "tpm.pcr.skip"
                );
                continue;
            }
        };
        let digest = parse_pcr_digest(&raw)
            .with_context(|| format!("parse PCR {i} digest from {}", path.display()))?;
        out.push(PcrValue {
            index: i,
            bank: PRIMARY_BANK.to_string(),
            digest,
        });
    }
    if out.is_empty() {
        anyhow::bail!(
            "TPM sysfs at {} exposed no readable PCR slots",
            bank_dir.display()
        );
    }
    Ok(out)
}

/// Parse one sysfs PCR line. The kernel format is space-separated hex
/// byte pairs:
///
/// ```text
/// 00 11 22 33 ...
/// ```
///
/// Some kernels emit the digest as a single contiguous hex string with
/// no spaces. We accept both.
pub fn parse_pcr_digest(raw: &str) -> Result<Vec<u8>> {
    let s: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if s.is_empty() {
        anyhow::bail!("empty PCR line");
    }
    if s.len() % 2 != 0 {
        anyhow::bail!("odd-length PCR hex string: {} chars", s.len());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = nibble(chunk[0])?;
        let lo = nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(anyhow!("non-hex byte: {b:#x}")),
    }
}

/// Result of a TPM2_Quote: (signature, ak_cert).
///
/// v1 returns an error on every host because the real TPM2_Quote glue
/// lives behind an optional `tss-esapi` dependency — operators wire
/// that up post-install once they've provisioned an Attestation Key.
/// The manager's `verify_quote` already treats a missing
/// signature/cert as an "unsigned report" rather than rejecting it,
/// so leaving this as `bail!` keeps the agent shippable without a
/// kernel-side TPM library.
pub fn quote(_nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    anyhow::bail!(
        "TPM Quote support not compiled in; provision an Attestation Key and enable the \
         tss-esapi backend to ship signed quotes"
    )
}

/// Best-effort one-shot probe for tracing at startup. Returns the
/// sysfs base path that exists, or None when no TPM is detected.
/// Useful for the agent's capability advertisement: we only append
/// `tpm_attestation_v1` to CAPABILITIES when this returns Some.
///
/// CODE-201: temporarily unused — the capability advertisement was
/// stripped because `quote()` always bails on Linux. Kept (with
/// `allow(dead_code)`) so the future v2 path that gates the
/// capability on a real `read_pcrs()` + `quote()` round trip can
/// reuse it without re-introducing the symbol.
#[allow(dead_code)]
pub fn detect() -> Option<PathBuf> {
    let p = Path::new(TPM_SYSFS_BASE);
    if p.exists() {
        Some(p.to_path_buf())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_pcr(dir: &Path, bank: &str, idx: u32, hex: &str) {
        let bank_dir = dir.join(format!("pcr-{bank}"));
        fs::create_dir_all(&bank_dir).unwrap();
        let mut f = fs::File::create(bank_dir.join(idx.to_string())).unwrap();
        writeln!(f, "{hex}").unwrap();
    }

    #[test]
    fn read_pcrs_parses_fixture_sysfs() {
        let tmp = tempdir().unwrap();
        write_pcr(tmp.path(), "sha256", 0, "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff");
        write_pcr(tmp.path(), "sha256", 1, &"ab".repeat(32));
        let out = read_pcrs_at(tmp.path(), &[0, 1, 2]).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].index, 0);
        assert_eq!(out[0].digest.len(), 32);
        assert_eq!(out[1].digest, vec![0xab; 32]);
    }

    #[test]
    fn read_pcrs_errors_when_sysfs_missing() {
        let tmp = tempdir().unwrap();
        let err = read_pcrs_at(tmp.path(), &[0]).unwrap_err();
        assert!(err.to_string().contains("TPM sysfs not present"));
    }

    #[test]
    fn parse_pcr_digest_accepts_spaced_and_contiguous() {
        let spaced = parse_pcr_digest("00 11 22 33").unwrap();
        let contig = parse_pcr_digest("00112233").unwrap();
        assert_eq!(spaced, vec![0x00, 0x11, 0x22, 0x33]);
        assert_eq!(spaced, contig);
    }

    #[test]
    fn parse_pcr_digest_rejects_odd_length() {
        assert!(parse_pcr_digest("00112").is_err());
    }

    #[test]
    fn quote_returns_error_v1() {
        let err = quote(b"nonce").unwrap_err();
        assert!(err.to_string().contains("Attestation Key"));
    }
}
