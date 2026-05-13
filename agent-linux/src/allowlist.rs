//! Application-allowlist control plane (Phase 2 #2.8).
//!
//! Mirrors `crate::ebpf::BlockListHandle` — owns the kernel-side
//! `allowlist_hashes` HASH map and `allowlist_mode` per-CPU array,
//! and exposes a [`AllowlistHandle::sync`] entry point the command
//! worker calls on every [`p::AllowlistSyncCmd`].
//!
//! The map keys are raw 32-byte SHA-256 digests, matching the
//! `struct vigil_sha256` shape in `ebpf/vigil.bpf.c`. The wire format
//! ([`p::AllowlistSyncCmd::hashes`]) is already raw bytes; we
//! validate the length but otherwise pass through.
//!
//! The `path_hash_cache` map (populated by the M10.a hasher) is
//! shared with the BPF LSM hook for enforce-mode lookups; the
//! command worker doesn't touch it directly.

#![cfg(target_os = "linux")]
// Phase 2 #2.8 first-cut: the BPF maps for `allowlist_hashes` /
// `allowlist_mode` aren't pulled out of the loaded object in this
// PR (`take_block_lists` will grow an `allowlist_handle` companion
// in a follow-up). Until that wiring lands, `AllowlistHandle::new`
// has no call site — keep `dead_code` quiet so clippy --deny doesn't
// fail the build on a forward-declared API.
#![allow(dead_code)]

use agent_core::proto as p;
use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData, PerCpuArray, PerCpuValues};
use std::sync::{Arc, Mutex};

/// Per-CPU array index used by the BPF side (it reads `mode[0]`).
const ALLOWLIST_MODE_SLOT: u32 = 0;

const MODE_OFF: u8 = 0;
const MODE_LEARN: u8 = 1;
const MODE_ENFORCE: u8 = 2;

/// Userspace mirror of the wire enum. Kept here rather than in
/// agent-core because only the Linux agent is wired to the BPF map;
/// the Windows side passes the wire enum straight to the driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllowlistMode {
    Off,
    Learn,
    Enforce,
}

impl AllowlistMode {
    pub fn from_proto(mode: i32) -> Self {
        // proto enum: ALLOWLIST_MODE_OFF=0, _LEARN=1, _ENFORCE=2.
        match mode {
            1 => Self::Learn,
            2 => Self::Enforce,
            _ => Self::Off,
        }
    }

    fn as_byte(self) -> u8 {
        match self {
            Self::Off => MODE_OFF,
            Self::Learn => MODE_LEARN,
            Self::Enforce => MODE_ENFORCE,
        }
    }
}

#[derive(Clone)]
pub struct AllowlistHandle {
    inner: Arc<Mutex<AllowlistInner>>,
}

struct AllowlistInner {
    hashes: AyaHashMap<MapData, [u8; 32], u8>,
    mode: PerCpuArray<MapData, u8>,
}

impl AllowlistHandle {
    pub fn new(hashes: AyaHashMap<MapData, [u8; 32], u8>, mode: PerCpuArray<MapData, u8>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AllowlistInner { hashes, mode })),
        }
    }

    /// Replace the kernel hash set with `hashes` and flip the mode
    /// to `mode`. Atomic-ish from the operator's perspective: the
    /// userspace lock prevents concurrent sync IOs, but the kernel
    /// can observe an inconsistent state between map clears and
    /// inserts. That's acceptable here — the BPF hook either reads
    /// "match" or "no match"; a transient empty map in ENFORCE
    /// briefly denies everything, which is the safe failure mode.
    pub fn sync(&self, mode: AllowlistMode, hashes: &[Vec<u8>]) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();

        // Validate every digest before we touch the kernel — refuse
        // the whole sync on a malformed input rather than partially
        // apply.
        let mut keys: Vec<[u8; 32]> = Vec::with_capacity(hashes.len());
        for h in hashes {
            if h.len() != 32 {
                return Err(anyhow!(
                    "allowlist.sync: bad hash length {}, want 32",
                    h.len()
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(h);
            keys.push(key);
        }

        // Drop existing entries the operator removed. We rebuild from
        // the supplied set rather than diffing — simpler, and the
        // map size (≤8192) bounds the work.
        let existing: Vec<[u8; 32]> = inner
            .hashes
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("allowlist_hashes keys")?;
        for k in existing {
            if !keys.contains(&k) {
                let _ = inner.hashes.remove(&k);
            }
        }
        for k in keys {
            inner
                .hashes
                .insert(k, 1u8, 0)
                .with_context(|| format!("allowlist_hashes insert {}", hex(&k)))?;
        }

        // Flip mode last so the new contents are visible to the
        // BPF hook before enforcement engages.
        let cpus =
            aya::util::nr_cpus().map_err(|(label, err)| anyhow!("nr_cpus ({label}): {err}"))?;
        let values = PerCpuValues::try_from(vec![mode.as_byte(); cpus])
            .context("PerCpuValues::try_from(allowlist_mode)")?;
        inner
            .mode
            .set(ALLOWLIST_MODE_SLOT, values, 0)
            .context("allowlist_mode.set")?;

        tracing::info!(
            mode = ?mode,
            hashes = hashes.len(),
            "allowlist.sync.applied"
        );
        Ok(())
    }

    /// Dispatch helper for the command worker — takes the raw proto
    /// command so the worker doesn't need to know about
    /// [`AllowlistMode`] conversion.
    pub fn apply(&self, cmd: &p::AllowlistSyncCmd) -> Result<()> {
        let mode = AllowlistMode::from_proto(cmd.mode);
        self.sync(mode, &cmd.hashes)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_proto_round_trip() {
        assert_eq!(AllowlistMode::from_proto(0), AllowlistMode::Off);
        assert_eq!(AllowlistMode::from_proto(1), AllowlistMode::Learn);
        assert_eq!(AllowlistMode::from_proto(2), AllowlistMode::Enforce);
        // Out-of-range falls back to OFF — defensive default.
        assert_eq!(AllowlistMode::from_proto(99), AllowlistMode::Off);
    }

    #[test]
    fn as_byte_matches_kernel_constants() {
        assert_eq!(AllowlistMode::Off.as_byte(), MODE_OFF);
        assert_eq!(AllowlistMode::Learn.as_byte(), MODE_LEARN);
        assert_eq!(AllowlistMode::Enforce.as_byte(), MODE_ENFORCE);
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0xab, 0xcd, 0x01];
        assert_eq!(hex(&bytes), "abcd01");
    }
}
