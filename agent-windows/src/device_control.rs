//! Device control / USB block (Phase 3 #3.10, Windows).
//!
//! Flips Group-Policy-equivalent registry values so the Plug-and-Play
//! manager refuses to install new device drivers matching the policy.
//! Two registry trees:
//!
//!   * `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`
//!     — `DenyDeviceClasses=1` (with the USB device-setup class GUID
//!     listed under `DenyDeviceClassesRetroactive`) for `usb_block` /
//!     `usb_allow_only`. The allow-list policy adds `AllowDeviceIDs`
//!     entries before the deny.
//!   * `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies` —
//!     `WriteProtect=1` for `usb_read_only`. The PnP manager picks
//!     this up on next mass-storage attach.
//!
//! When `enabled=false` the relevant values are cleared (set to 0 or
//! deleted) so a previously-applied policy unwinds cleanly.
//!
//! Wire-format helpers (`policy_changes`) live here so they can be
//! unit-tested on Linux CI; the actual `RegSetValueEx` plumbing is
//! Windows-gated behind `#[cfg(windows)]`.

#![allow(dead_code)]

use agent_core::proto as p;

/// USB device-setup class GUID. Listed under `DenyDeviceClassesRetroactive`
/// so existing devices also detach (not just new arrivals).
pub const USB_DEVICE_SETUP_CLASS: &str = "{36fc9e60-c465-11cf-8056-444553540000}";

const RESTRICTIONS_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
const STORAGE_POLICIES_KEY: &str = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";

/// One pending registry mutation. Modeled as a sum type so the test
/// suite can pin the exact sequence the agent will replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegChange {
    /// Set a REG_DWORD value at `(key, value_name)` to `value`.
    SetDword {
        key: &'static str,
        value_name: &'static str,
        value: u32,
    },
    /// Set a REG_MULTI_SZ value at `(key, value_name)` to the supplied
    /// list. An empty list clears the value to a single NUL pair.
    SetMultiSz {
        key: &'static str,
        value_name: &'static str,
        values: Vec<String>,
    },
    /// Delete a value if present. No-op when missing.
    DeleteValue {
        key: &'static str,
        value_name: &'static str,
    },
}

/// Materialise the registry mutations for `cmd`. Pure function so the
/// test suite can assert on the emitted sequence.
pub fn policy_changes(cmd: &p::DeviceControlSyncCmd) -> Vec<RegChange> {
    if !cmd.enabled {
        // Tombstone — clear everything the policy might have set.
        return vec![
            RegChange::SetDword {
                key: RESTRICTIONS_KEY,
                value_name: "DenyDeviceClasses",
                value: 0,
            },
            RegChange::DeleteValue {
                key: RESTRICTIONS_KEY,
                value_name: "DenyDeviceClassesRetroactive",
            },
            RegChange::DeleteValue {
                key: RESTRICTIONS_KEY,
                value_name: "AllowDeviceIDs",
            },
            RegChange::SetDword {
                key: STORAGE_POLICIES_KEY,
                value_name: "WriteProtect",
                value: 0,
            },
        ];
    }

    match cmd.kind.as_str() {
        "usb_block" => vec![
            RegChange::SetDword {
                key: RESTRICTIONS_KEY,
                value_name: "DenyDeviceClasses",
                value: 1,
            },
            RegChange::SetMultiSz {
                key: RESTRICTIONS_KEY,
                value_name: "DenyDeviceClassesRetroactive",
                values: vec![USB_DEVICE_SETUP_CLASS.to_string()],
            },
            RegChange::SetMultiSz {
                key: RESTRICTIONS_KEY,
                value_name: "AllowDeviceIDs",
                values: allow_device_ids(&cmd.allowed_vids, &cmd.allowed_pids),
            },
        ],
        "usb_allow_only" => vec![
            RegChange::SetDword {
                key: RESTRICTIONS_KEY,
                value_name: "DenyDeviceClasses",
                value: 1,
            },
            RegChange::SetMultiSz {
                key: RESTRICTIONS_KEY,
                value_name: "DenyDeviceClassesRetroactive",
                values: vec![USB_DEVICE_SETUP_CLASS.to_string()],
            },
            // The allow list is the *only* permitted population in
            // allow-only mode; if it's empty the operator just locked
            // the host out of every USB device, which is the contract.
            RegChange::SetMultiSz {
                key: RESTRICTIONS_KEY,
                value_name: "AllowDeviceIDs",
                values: allow_device_ids(&cmd.allowed_vids, &cmd.allowed_pids),
            },
        ],
        "usb_read_only" => vec![RegChange::SetDword {
            key: STORAGE_POLICIES_KEY,
            value_name: "WriteProtect",
            value: 1,
        }],
        _other => Vec::new(),
    }
}

/// Render the `AllowDeviceIDs` list. Each entry follows the Windows
/// device-instance form `USB\VID_xxxx&PID_yyyy`. Same-index pairing —
/// extras with no counterpart drop out.
pub fn allow_device_ids(vids: &[String], pids: &[String]) -> Vec<String> {
    vids.iter()
        .zip(pids.iter())
        .map(|(v, p)| {
            // Windows expects uppercase hex in the device-ID form. We
            // normalised lowercase server-side; uppercase for the
            // registry value rendering.
            format!("USB\\VID_{}&PID_{}", v.to_uppercase(), p.to_uppercase())
        })
        .collect()
}

/// Apply the policy. Windows: walk `policy_changes` and replay each
/// against HKLM. Non-Windows: no-op (helps the workspace cargo build
/// pass on Linux CI without a target switch).
#[cfg(windows)]
pub fn apply(cmd: &p::DeviceControlSyncCmd) -> anyhow::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
        KEY_SET_VALUE, REG_DWORD, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn open(path: &str) -> anyhow::Result<HKEY> {
        let wpath = wide(path);
        let mut hk: HKEY = HKEY::default();
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(wpath.as_ptr()),
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
            anyhow::bail!("RegCreateKeyExW({path}) failed: {:?}", status);
        }
        Ok(hk)
    }

    for change in policy_changes(cmd) {
        match change {
            RegChange::SetDword {
                key,
                value_name,
                value,
            } => {
                let hk = open(key)?;
                let wname = wide(value_name);
                let bytes = value.to_le_bytes();
                let status = unsafe {
                    RegSetValueExW(hk, PCWSTR(wname.as_ptr()), 0, REG_DWORD, Some(&bytes))
                };
                unsafe {
                    let _ = RegCloseKey(hk);
                }
                if status != ERROR_SUCCESS {
                    return Err(anyhow::anyhow!(
                        "RegSetValueExW({key}\\{value_name}) failed: {:?}",
                        status
                    ));
                }
            }
            RegChange::SetMultiSz {
                key,
                value_name,
                values,
            } => {
                let hk = open(key)?;
                let wname = wide(value_name);
                // REG_MULTI_SZ: each string is NUL-terminated, the
                // sequence is terminated by an empty string (extra NUL).
                let mut buf: Vec<u16> = Vec::new();
                for s in &values {
                    buf.extend(s.encode_utf16());
                    buf.push(0);
                }
                buf.push(0);
                let byte_slice =
                    unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len() * 2) };
                let status = unsafe {
                    RegSetValueExW(
                        hk,
                        PCWSTR(wname.as_ptr()),
                        0,
                        REG_MULTI_SZ,
                        Some(byte_slice),
                    )
                };
                unsafe {
                    let _ = RegCloseKey(hk);
                }
                if status != ERROR_SUCCESS {
                    return Err(anyhow::anyhow!(
                        "RegSetValueExW({key}\\{value_name}) failed: {:?}",
                        status
                    ));
                }
            }
            RegChange::DeleteValue { key, value_name } => {
                let hk = match open(key) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                let wname = wide(value_name);
                let _ = unsafe { RegDeleteValueW(hk, PCWSTR(wname.as_ptr())) };
                unsafe {
                    let _ = RegCloseKey(hk);
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn apply(_cmd: &p::DeviceControlSyncCmd) -> anyhow::Result<()> {
    // Non-Windows agents never receive this command (the manager
    // dispatches by host OS via the command kind path); the stub
    // keeps the workspace `cargo build` green on Linux CI.
    Ok(())
}
