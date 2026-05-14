//! Deception / honeytokens (Phase 4 #4.5, Windows).
//!
//! Applies a batch of `HoneytokenSpec` against the local host:
//!
//!   * `fake_file` — write the payload bytes to `target_path` and
//!     tag it via an NTFS Alternate Data Stream
//!     `target_path:vigil_honeytoken` carrying the spec id.
//!     Process-monitor / SACL hits the agent later observes on the
//!     base path can resolve the id by reading the ADS.
//!   * `fake_regkey` — create `HKLM\<target_path>` and write the
//!     spec id under the `vigil_honeytoken` value. Hits surface via
//!     the existing registry-write ETW provider.
//!   * `creds_in_lsass` — production-grade LSASS injection is
//!     deferred (needs a signed driver and Microsoft Defender
//!     attestation). For now we write a placeholder file at
//!     `C:\ProgramData\Vigil\decoy_creds.dat` so the agent has a
//!     concrete artifact to point hits at; replace with the real
//!     LSASS path once the signing story lands.
//!
//! `apply` is the Windows entry point used by the driver dispatcher;
//! `policy_changes` is a pure function that returns the planned
//! mutations so the Linux CI can unit-test the wire layout without a
//! Windows host.

#![allow(dead_code)]

use agent_core::proto as p;

/// Default fallback file for `creds_in_lsass` until the real LSASS
/// injection ships. Exposed so the test suite can pin the path.
pub const CREDS_DECOY_PATH: &str = r"C:\ProgramData\Vigil\decoy_creds.dat";

/// NTFS Alternate Data Stream suffix used to tag `fake_file` decoys.
/// Touching a tagged file later via the kernel driver leaves a trail
/// the agent can correlate back to the source id.
pub const FAKE_FILE_ADS_SUFFIX: &str = ":vigil_honeytoken";

/// Registry value name used to tag `fake_regkey` decoys.
pub const FAKE_REGKEY_VALUE: &str = "vigil_honeytoken";

/// One pending OS mutation. Pure data — apply walks the list and
/// replays each on Windows; the test suite asserts the sequence on
/// Linux.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum DeceptionChange {
    /// Write `payload` to `path` and stamp `:vigil_honeytoken` ADS.
    WriteFileWithAds {
        path: String,
        ads_value: String,
        payload: Vec<u8>,
    },
    /// Create `HKLM\<key>` and set value `vigil_honeytoken` = `id`.
    WriteRegValue {
        key: String,
        value_name: String,
        value: String,
        body: Vec<u8>,
    },
    /// Fallback fake-creds file at `CREDS_DECOY_PATH`. Carries the
    /// payload bytes the manager passed (typically a JSON dict with a
    /// fake username/password).
    WriteCredsDecoy { path: String, payload: Vec<u8> },
}

/// Build the change list for one spec. Returns an empty vec for
/// unknown kinds so a bogus operator-side payload doesn't crash the
/// dispatch.
pub fn changes_for_spec(spec: &p::HoneytokenSpec) -> Vec<DeceptionChange> {
    match spec.kind.as_str() {
        "fake_file" if !spec.target_path.is_empty() => vec![DeceptionChange::WriteFileWithAds {
            path: spec.target_path.clone(),
            ads_value: spec.id.clone(),
            payload: spec.payload.clone(),
        }],
        "fake_regkey" if !spec.target_path.is_empty() => vec![DeceptionChange::WriteRegValue {
            key: spec.target_path.clone(),
            value_name: FAKE_REGKEY_VALUE.into(),
            value: spec.id.clone(),
            body: spec.payload.clone(),
        }],
        "creds_in_lsass" => vec![DeceptionChange::WriteCredsDecoy {
            path: CREDS_DECOY_PATH.into(),
            payload: spec.payload.clone(),
        }],
        _ => Vec::new(),
    }
}

/// Materialise the full change list for a batch. Order preserved
/// (operator-supplied spec order) so the dispatcher applies the same
/// thing the operator saw in the audit log.
pub fn changes_for_batch(specs: &[p::HoneytokenSpec]) -> Vec<DeceptionChange> {
    specs.iter().flat_map(changes_for_spec).collect()
}

/// Apply a batch on Windows. Walk `changes_for_batch` and replay each
/// change. Non-Windows: log + no-op (keeps the workspace build green
/// on Linux CI). The agent never receives this on a non-Windows host
/// in production — the manager dispatches honeytokens by host OS at
/// command-build time.
#[cfg(windows)]
pub fn apply(specs: &[p::HoneytokenSpec]) -> anyhow::Result<()> {
    for change in changes_for_batch(specs) {
        match change {
            DeceptionChange::WriteFileWithAds {
                path,
                ads_value,
                payload,
            } => {
                if let Some(parent) = std::path::Path::new(&path).parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }
                std::fs::write(&path, &payload)
                    .map_err(|e| anyhow::anyhow!("write decoy {path}: {e}"))?;
                // NTFS ADS path: `<path>:vigil_honeytoken`. Writing to
                // the ADS form creates the stream alongside the file.
                let ads_path = format!("{path}{FAKE_FILE_ADS_SUFFIX}");
                if let Err(e) = std::fs::write(&ads_path, ads_value.as_bytes()) {
                    tracing::warn!(
                        path = %path,
                        error = %e,
                        "honeytoken.ads_write_failed (decoy body still planted)"
                    );
                }
            }
            DeceptionChange::WriteRegValue {
                key,
                value_name,
                value,
                body,
            } => {
                if let Err(e) = write_regkey(&key, &value_name, &value, &body) {
                    tracing::warn!(
                        key = %key,
                        error = %e,
                        "honeytoken.regkey_write_failed"
                    );
                }
            }
            DeceptionChange::WriteCredsDecoy { path, payload } => {
                if let Some(parent) = std::path::Path::new(&path).parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }
                // TODO(Phase 4 #4.5 follow-up): real LSASS injection
                // once the agent gains a signed minifilter driver.
                if let Err(e) = std::fs::write(&path, &payload) {
                    tracing::warn!(
                        path = %path,
                        error = %e,
                        "honeytoken.creds_decoy_write_failed"
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn apply(_specs: &[p::HoneytokenSpec]) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn write_regkey(key: &str, value_name: &str, value: &str, _body: &[u8]) -> anyhow::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    // Strip an `HKLM\` prefix if the operator typed one — the
    // `HKEY_LOCAL_MACHINE` handle below already roots the open.
    let normalised = key
        .strip_prefix(r"HKLM\")
        .or_else(|| key.strip_prefix(r"HKEY_LOCAL_MACHINE\"))
        .unwrap_or(key);
    let wkey = wide(normalised);
    let mut hk: HKEY = HKEY::default();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wkey.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hk,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        anyhow::bail!("RegCreateKeyExW({key}): {:?}", status);
    }
    let wname = wide(value_name);
    let wvalue = wide(value);
    let byte_slice =
        unsafe { std::slice::from_raw_parts(wvalue.as_ptr() as *const u8, wvalue.len() * 2) };
    let status = unsafe { RegSetValueExW(hk, PCWSTR(wname.as_ptr()), 0, REG_SZ, Some(byte_slice)) };
    unsafe {
        let _ = RegCloseKey(hk);
    }
    if status != ERROR_SUCCESS {
        anyhow::bail!("RegSetValueExW({key}\\{value_name}): {:?}", status);
    }
    Ok(())
}
