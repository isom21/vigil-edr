//! Phase 2 #2.12 — DNS block list helper unit tests.
//!
//! `dns_block.rs` is a private module of the `vigil-agent` binary
//! crate. We re-include the source file as an out-of-tree module
//! (same pattern as `tests/container.rs`) so the pure-function
//! normalisation helper is testable without instantiating the BPF
//! map machinery.

#![cfg(target_os = "linux")]

#[path = "../src/dns_block.rs"]
#[allow(dead_code)]
mod dns_block;

use dns_block::{normalise_dns_key, DNS_BLOCK_KEY_LEN};

#[test]
fn lowercases_and_strips_trailing_dot() {
    let k = normalise_dns_key("EVIL.example.com.");
    let expected = b"evil.example.com";
    assert_eq!(&k[..expected.len()], expected);
    // Byte immediately after the name is the NUL terminator the
    // kernel's bpf_probe_read_kernel_str leaves behind; the rest of
    // the array is zero-init from the [u8; 256] declaration.
    assert_eq!(k[expected.len()], 0);
    assert_eq!(k[DNS_BLOCK_KEY_LEN - 1], 0);
}

#[test]
fn trims_whitespace() {
    let k = normalise_dns_key("  bad.example.com  ");
    let expected = b"bad.example.com";
    assert_eq!(&k[..expected.len()], expected);
}

#[test]
fn key_is_padded_to_256_bytes() {
    let k = normalise_dns_key("a");
    assert_eq!(k.len(), DNS_BLOCK_KEY_LEN);
    assert_eq!(k[0], b'a');
    assert!(k[1..].iter().all(|&b| b == 0));
}

#[test]
fn long_domain_truncates_with_nul_at_255() {
    // 300 characters — longer than the 255-byte source budget.
    let long: String = "a.".repeat(150);
    let k = normalise_dns_key(&long);
    // Byte [255] must be NUL so kernel-side
    // bpf_probe_read_kernel_str's terminator matches.
    assert_eq!(k[DNS_BLOCK_KEY_LEN - 1], 0);
}

#[test]
fn empty_domain_is_all_zero() {
    let k = normalise_dns_key("");
    assert!(k.iter().all(|&b| b == 0));

    // Trailing-dot-only collapses to empty after the strip.
    let k2 = normalise_dns_key(".");
    assert!(k2.iter().all(|&b| b == 0));
}
