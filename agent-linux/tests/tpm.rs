//! Phase 4 #4.10 — TPM attestation unit tests.
//!
//! Exercises the sysfs PCR reader against a fixture tempdir so the
//! parser surfaces real cases (spaced hex / contiguous hex / missing
//! TPM). The signed-quote tests are gated `#[ignore]` until a swtpm
//! fixture is wired into CI — `quote()` returns the v1 "no AK"
//! error path until then, which is the path the manager already
//! tolerates.

#![cfg(target_os = "linux")]

use agent_linux::tpm;
use std::fs;
use std::io::Write;
use std::path::Path;
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
    write_pcr(
        tmp.path(),
        "sha256",
        0,
        "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff",
    );
    write_pcr(tmp.path(), "sha256", 7, &"ab".repeat(32));
    let pcrs = tpm::read_pcrs_at(tmp.path(), &[0, 7]).unwrap();
    assert_eq!(pcrs.len(), 2);
    assert_eq!(pcrs[0].index, 0);
    assert_eq!(pcrs[0].bank, "sha256");
    assert_eq!(pcrs[0].digest.len(), 32);
    assert_eq!(pcrs[1].digest, vec![0xab; 32]);
}

#[test]
fn read_pcrs_errors_when_tpm_absent() {
    let tmp = tempdir().unwrap();
    let err = tpm::read_pcrs_at(tmp.path(), &[0]).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("TPM sysfs not present") || msg.contains("exposed no readable"),
        "{msg}"
    );
}

#[test]
fn read_pcrs_skips_missing_slot() {
    let tmp = tempdir().unwrap();
    write_pcr(tmp.path(), "sha256", 0, &"00".repeat(32));
    let pcrs = tpm::read_pcrs_at(tmp.path(), &[0, 1, 2]).unwrap();
    assert_eq!(pcrs.len(), 1);
    assert_eq!(pcrs[0].index, 0);
}

#[test]
fn parse_pcr_digest_handles_both_formats() {
    let spaced = tpm::parse_pcr_digest("00 11 22 33").unwrap();
    let contig = tpm::parse_pcr_digest("00112233").unwrap();
    assert_eq!(spaced, vec![0x00, 0x11, 0x22, 0x33]);
    assert_eq!(spaced, contig);
}

#[test]
#[ignore = "needs swtpm + tss-esapi feature"]
fn quote_signs_nonce_when_ak_provisioned() {
    // Wired up once a swtpm fixture lands in CI. Verifies that
    // `quote()` returns a non-empty signature + AK cert when invoked
    // against a real (or emulated) TPM with an Attestation Key.
    let (sig, cert) = tpm::quote(b"deadbeef").unwrap();
    assert!(!sig.is_empty());
    assert!(!cert.is_empty());
}
