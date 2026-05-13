//! DNS block list helpers (Phase 2 #2.12).
//!
//! Just the pure-function key normaliser; the kernel-map sync glue
//! lives in `command_worker.rs` next to the other command handlers
//! (the resync command rides the same dispatch path as
//! BlockProcess / IsolateHost).
//!
//! Keeping this module dependency-free means the integration test in
//! `tests/dns_block.rs` can `#[path]`-include the source without
//! pulling in aya or the proto crate.

/// Width of the BPF lookup key. Mirrors `VIGIL_BLOCK_KEY_LEN` in
/// `vigil.bpf.c`.
pub const DNS_BLOCK_KEY_LEN: usize = 256;

/// Canonicalise a domain into the 256-byte zero-padded key shape the
/// BPF map uses. Lowercased ASCII, trailing dot stripped, truncated
/// at 255 source bytes so byte [255] is always the NUL terminator —
/// matching what `bpf_probe_read_kernel_str` writes kernel-side.
pub fn normalise_dns_key(domain: &str) -> [u8; DNS_BLOCK_KEY_LEN] {
    let mut out = [0u8; DNS_BLOCK_KEY_LEN];
    let trimmed = domain.trim().trim_end_matches('.');
    let bytes = trimmed.as_bytes();
    let n = bytes.len().min(DNS_BLOCK_KEY_LEN - 1);
    for (i, &b) in bytes.iter().take(n).enumerate() {
        out[i] = if b.is_ascii_uppercase() { b + 32 } else { b };
    }
    out
}
