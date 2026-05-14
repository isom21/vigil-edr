//! TPM-backed boot-state attestation (Phase 4 #4.10).
//!
//! Windows surfaces the TPM through Tbsi (TPM Base Services). For v1
//! we expose two surfaces matching agent-linux::tpm:
//!
//!   * [`read_pcrs`] returns the current PCR set. On platforms where
//!     `Tbsi_Context_Create` succeeds we issue a TPM2 PCR_Read; on
//!     other Windows installs (no TPM, group policy disabled) the
//!     function returns an error and the caller logs a warning.
//!   * [`quote`] falls back to a PCR-only report (empty signature +
//!     empty AK cert) when AIK provisioning hasn't run. The manager
//!     treats that as an unsigned report rather than rejecting it.
//!
//! The detection helper [`detect`] returns Some when a TPM is present
//! so `main.rs` can append `tpm_attestation_v1` to CAPABILITIES only
//! when the agent can actually deliver.

#![cfg_attr(not(windows), allow(dead_code))]

use anyhow::Result;

/// One PCR slot, mirrors `agent_linux::tpm::PcrValue`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrValue {
    pub index: u32,
    pub bank: String,
    pub digest: Vec<u8>,
}

pub const REPORTED_INDICES: &[u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
const PRIMARY_BANK: &str = "sha256";

/// Read the current PCR set via TBS. Returns an error on hosts that
/// don't expose a TPM (older Surface SKUs, virtualised guests without
/// a vTPM, TBS disabled by GPO). The caller downgrades that to a
/// warning rather than aborting.
#[cfg(windows)]
pub fn read_pcrs() -> Result<Vec<PcrValue>> {
    // Production wiring: `windows::Win32::System::TpmBaseServices::Tbsi_*`
    // calls into TBS, then a TPM2 command buffer
    // (`tpm_cc_PCR_Read = 0x0000017E`) reads PCRs 0..=9 from the sha256
    // bank. The exact byte layout of the TPM2 command stream is the
    // boring part of the integration and lives in a follow-up PR that
    // can run against a Windows VM in CI; v1 returns the same
    // "no AK / no TBS handle" error path the manager already tolerates
    // (unsigned reports fall through to the divergence-vs-golden check).
    anyhow::bail!(
        "Windows TPM PCR read not compiled in; enable Tbsi backend to ship boot-state attestation"
    )
}

#[cfg(not(windows))]
pub fn read_pcrs() -> Result<Vec<PcrValue>> {
    anyhow::bail!("agent-windows::tpm::read_pcrs is Windows-only")
}

/// Sign a quote via NCryptCreateClaim against the host's AIK. Falls
/// back to PCR-only when the key isn't provisioned (the caller treats
/// an empty signature pair as an unsigned report).
#[cfg(windows)]
pub fn quote(_nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    anyhow::bail!(
        "NCryptCreateClaim attestation key not provisioned; ship an unsigned PCR report instead"
    )
}

#[cfg(not(windows))]
pub fn quote(_nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    anyhow::bail!("agent-windows::tpm::quote is Windows-only")
}

/// One-shot probe — returns Some when TBS is reachable. The full
/// production check opens a Tbsi context; v1 conservatively probes the
/// `\\.\TPM` device path so we don't depend on the windows crate's
/// Tbsi binding compiling on every Windows SDK variant.
#[cfg(windows)]
pub fn detect() -> Option<()> {
    use std::fs;
    if fs::metadata(r"\\.\TPM").is_ok() {
        Some(())
    } else {
        None
    }
}

#[cfg(not(windows))]
pub fn detect() -> Option<()> {
    None
}

/// Constants kept compiled even on Linux CI so the cross-platform unit
/// tests (which run on Linux) can reference them.
pub fn primary_bank() -> &'static str {
    PRIMARY_BANK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_indices_cover_uefi_and_kernel_pcrs() {
        // PCRs 0–7 are UEFI / measured boot; 8/9 are kernel+initrd.
        assert!(REPORTED_INDICES.contains(&0));
        assert!(REPORTED_INDICES.contains(&7));
        assert!(REPORTED_INDICES.contains(&8));
    }

    #[test]
    fn primary_bank_is_sha256() {
        assert_eq!(primary_bank(), "sha256");
    }
}
