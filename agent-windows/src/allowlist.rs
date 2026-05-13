//! Application-allowlist driver bridge (Phase 2 #2.8, Windows).
//!
//! Mirrors `agent-linux/src/allowlist.rs` but talks to the kernel
//! driver via two IOCTLs:
//!
//!   * `IOCTL_VIGIL_ALLOWLIST_MODE_SET` — flips OFF / LEARN / ENFORCE.
//!   * `IOCTL_VIGIL_ALLOWLIST_SET` — replaces the kernel hash set with
//!     the supplied SHA-256 bytes.
//!
//! Wire-format helpers (`mode_request_buffer`, `set_request_buffer`)
//! live here so they can be unit-tested on Linux CI; the actual IOCTL
//! plumbing is in [`crate::driver`].
//!
//! Like the Linux side, the agent rebuilds the kernel set from the
//! manager-supplied set on every sync rather than diffing. The driver
//! caps the set at 8192 entries; entries past that are truncated with
//! a warning.

// `driver.rs` is Windows-only, so on Linux these items have no
// non-test caller. `cargo test -p agent-windows` still exercises them.
#![allow(dead_code)]

use agent_core::proto as p;

/// Mirror of `VIGIL_ALLOWLIST_MAX_HASHES` in `kernel-windows/vigil.h`.
pub const ALLOWLIST_MAX_HASHES: usize = 8192;

const SHA256_LEN: usize = 32;

/// Userspace mirror of the wire enum. Same byte values as the kernel
/// constants in `vigil.h`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllowlistMode {
    Off,
    Learn,
    Enforce,
}

impl AllowlistMode {
    pub fn from_proto(mode: i32) -> Self {
        match mode {
            1 => Self::Learn,
            2 => Self::Enforce,
            _ => Self::Off,
        }
    }

    fn as_byte(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Learn => 1,
            Self::Enforce => 2,
        }
    }
}

/// Build the `IOCTL_VIGIL_ALLOWLIST_MODE_SET` input buffer:
/// `[ Mode(1) | _Pad(3) ]`. The trailing pad bytes are part of the
/// kernel `VIGIL_ALLOWLIST_MODE_REQ` struct (4-byte aligned).
pub fn mode_request_buffer(mode: AllowlistMode) -> Vec<u8> {
    vec![mode.as_byte(), 0, 0, 0]
}

/// Build the `IOCTL_VIGIL_ALLOWLIST_SET` input buffer:
/// `[ HashCount(4 LE) | HashCount × 32-byte SHA-256 ]`. Entries
/// beyond [`ALLOWLIST_MAX_HASHES`] are truncated with a warn-log so
/// a misconfigured manager can't overflow the driver buffer; entries
/// of the wrong length are silently skipped.
pub fn set_request_buffer(hashes: &[Vec<u8>]) -> Vec<u8> {
    let mut accepted: Vec<&[u8]> = Vec::with_capacity(hashes.len().min(ALLOWLIST_MAX_HASHES));
    for h in hashes {
        if h.len() != SHA256_LEN {
            tracing::warn!(len = h.len(), "driver.allowlist.skip.bad_length");
            continue;
        }
        if accepted.len() == ALLOWLIST_MAX_HASHES {
            tracing::warn!(cap = ALLOWLIST_MAX_HASHES, "driver.allowlist.truncated");
            break;
        }
        accepted.push(h.as_slice());
    }

    let mut buf = Vec::with_capacity(4 + accepted.len() * SHA256_LEN);
    buf.extend_from_slice(&(accepted.len() as u32).to_le_bytes());
    for h in accepted {
        buf.extend_from_slice(h);
    }
    buf
}

/// Translate the proto sync command into the (mode buffer, set
/// buffer) pair the driver expects. Kept as a pure function so the
/// IOCTL caller in `driver.rs` is mechanical glue and tests can
/// pin the exact byte layout.
pub fn buffers_from_cmd(cmd: &p::AllowlistSyncCmd) -> (Vec<u8>, Vec<u8>) {
    let mode = AllowlistMode::from_proto(cmd.mode);
    (mode_request_buffer(mode), set_request_buffer(&cmd.hashes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_proto_round_trip() {
        assert_eq!(AllowlistMode::from_proto(0), AllowlistMode::Off);
        assert_eq!(AllowlistMode::from_proto(1), AllowlistMode::Learn);
        assert_eq!(AllowlistMode::from_proto(2), AllowlistMode::Enforce);
        assert_eq!(AllowlistMode::from_proto(99), AllowlistMode::Off);
    }

    #[test]
    fn mode_buffer_layout() {
        let buf = mode_request_buffer(AllowlistMode::Enforce);
        assert_eq!(buf, vec![2u8, 0, 0, 0]);
        let buf = mode_request_buffer(AllowlistMode::Off);
        assert_eq!(buf, vec![0u8, 0, 0, 0]);
    }

    #[test]
    fn set_buffer_empty() {
        let buf = set_request_buffer(&[]);
        assert_eq!(buf, vec![0u8, 0, 0, 0]);
    }

    #[test]
    fn set_buffer_packs_one_hash() {
        let h = vec![0xaau8; 32];
        let buf = set_request_buffer(std::slice::from_ref(&h));
        assert_eq!(buf.len(), 4 + 32);
        assert_eq!(&buf[0..4], &1u32.to_le_bytes());
        assert_eq!(&buf[4..36], &h[..]);
    }

    #[test]
    fn set_buffer_skips_bad_length() {
        let short = vec![0u8; 16];
        let good = vec![0xbbu8; 32];
        let buf = set_request_buffer(&[short, good.clone()]);
        // Only one hash made it past the length check.
        assert_eq!(&buf[0..4], &1u32.to_le_bytes());
        assert_eq!(&buf[4..36], &good[..]);
    }

    #[test]
    fn set_buffer_truncates_oversize() {
        // Build ALLOWLIST_MAX_HASHES + 5 entries — only the first
        // ALLOWLIST_MAX_HASHES should land in the buffer.
        let mut many: Vec<Vec<u8>> = Vec::new();
        for i in 0..(ALLOWLIST_MAX_HASHES + 5) {
            let mut h = vec![0u8; 32];
            h[0] = (i & 0xff) as u8;
            many.push(h);
        }
        let buf = set_request_buffer(&many);
        assert_eq!(
            &buf[0..4],
            &(ALLOWLIST_MAX_HASHES as u32).to_le_bytes(),
            "should have truncated to cap"
        );
        assert_eq!(buf.len(), 4 + ALLOWLIST_MAX_HASHES * 32);
    }
}
