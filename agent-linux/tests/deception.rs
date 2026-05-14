//! Phase 4 #4.5 — deception / honeytoken unit tests.
//!
//! `deception.rs` is a private module of the `vigil-agent` binary
//! crate. We re-include the source so the apply path is testable
//! without root + the BPF stack. The test uses `tempfile::tempdir()`
//! as the filesystem root so writes don't escape into the live
//! `/etc` / `/var`.

#![cfg(target_os = "linux")]

#[path = "../src/deception.rs"]
#[allow(dead_code)]
mod deception;

use agent_core::proto as p;

fn spec(id: &str, kind: &str, target: &str, payload: &[u8]) -> p::HoneytokenSpec {
    p::HoneytokenSpec {
        id: id.into(),
        kind: kind.into(),
        name: format!("test-{id}"),
        target_path: target.into(),
        payload: payload.to_vec(),
    }
}

#[test]
fn fake_file_writes_payload_and_stamps_xattr() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let s = spec(
        "11111111-1111-1111-1111-111111111111",
        "fake_file",
        "/var/lib/secrets/aws.creds",
        b"AKIAFAKE",
    );
    deception::apply_at(std::slice::from_ref(&s), tmp.path()).expect("apply_at");

    let written = tmp.path().join("var/lib/secrets/aws.creds");
    assert!(
        written.exists(),
        "decoy file should exist at {}",
        written.display()
    );
    let body = std::fs::read(&written).expect("read");
    assert_eq!(body, b"AKIAFAKE");

    // xattr stamped with the spec id.
    let id = deception::read_xattr_id(&written).expect("xattr should be present");
    assert_eq!(id, "11111111-1111-1111-1111-111111111111");

    // Lookup-by-path returns the same id (the agent uses this to
    // resolve a hit back to the source row).
    let guard = deception::DEPLOYED.read().expect("read DEPLOYED");
    assert_eq!(
        guard.lookup_path(&written.to_string_lossy()),
        Some("11111111-1111-1111-1111-111111111111")
    );
}

#[test]
fn fake_regkey_kind_is_logged_noop_on_linux() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let s = spec(
        "22222222-2222-2222-2222-222222222222",
        "fake_regkey",
        "HKLM\\SOFTWARE\\Acme",
        b"{}",
    );
    let result = deception::apply_at(std::slice::from_ref(&s), tmp.path());
    // No-op on Linux but the apply call must succeed; the spec is
    // simply skipped so the map ends up empty.
    assert!(result.is_ok());
    let guard = deception::DEPLOYED.read().expect("read");
    assert!(guard.is_empty());
}

#[test]
fn apply_replaces_prior_deployment_set() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let first = spec(
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "fake_file",
        "/tmp/decoy-a",
        b"a",
    );
    deception::apply_at(std::slice::from_ref(&first), tmp.path()).expect("apply 1");
    {
        let g = deception::DEPLOYED.read().expect("read");
        assert_eq!(g.len(), 1);
    }

    // Second apply with a different spec; the map should now hold only
    // the new entry (replace, not merge).
    let second = spec(
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "fake_file",
        "/tmp/decoy-b",
        b"b",
    );
    deception::apply_at(std::slice::from_ref(&second), tmp.path()).expect("apply 2");
    let g = deception::DEPLOYED.read().expect("read");
    assert_eq!(g.len(), 1);
    assert!(g
        .lookup_path(&tmp.path().join("tmp/decoy-b").to_string_lossy())
        .is_some());
}

#[test]
fn unknown_kind_is_swallowed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let s = spec(
        "33333333-3333-3333-3333-333333333333",
        "bogus_kind",
        "/tmp/whatever",
        b"x",
    );
    let result = deception::apply_at(std::slice::from_ref(&s), tmp.path());
    assert!(result.is_ok());
    let g = deception::DEPLOYED.read().expect("read");
    assert!(g.is_empty());
}
