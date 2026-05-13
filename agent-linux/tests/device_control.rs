//! Phase 3 #3.10 — device control unit tests.
//!
//! `device_control.rs` is a private module of the `vigil-agent`
//! binary crate. We re-include the source so the pure-function rule
//! renderer is testable without writing to `/run/udev/rules.d/` or
//! spawning `udevadm`. The `apply_at` helper is exercised separately
//! against a tempdir.

#![cfg(target_os = "linux")]

#[path = "../src/device_control.rs"]
#[allow(dead_code)]
mod device_control;

use agent_core::proto as p;

fn cmd(kind: &str, vids: &[&str], pids: &[&str], enabled: bool) -> p::DeviceControlSyncCmd {
    p::DeviceControlSyncCmd {
        kind: kind.into(),
        allowed_vids: vids.iter().map(|s| (*s).to_string()).collect(),
        allowed_pids: pids.iter().map(|s| (*s).to_string()).collect(),
        enabled,
    }
}

#[test]
fn usb_block_renders_default_deny_with_allow_exceptions() {
    let r = device_control::render_rule(&cmd("usb_block", &["046d"], &["c52b"], true));
    // Allow line for the listed VID/PID appears *before* the
    // default-deny so udev's last-match-wins semantics can't flip the
    // outcome.
    let allow_pos = r.find("idVendor").expect("allow line missing");
    let deny_pos = r
        .find("authorized\"=\"0\"")
        .or_else(|| r.find("authorized}=\"0\""))
        .expect("default-deny missing");
    assert!(allow_pos < deny_pos, "expected allow before deny: {r}");
    assert!(r.contains("idVendor}==\"046d\""));
    assert!(r.contains("idProduct}==\"c52b\""));
    assert!(r.contains("SUBSYSTEM==\"usb\""));
}

#[test]
fn usb_block_no_exceptions_is_pure_deny() {
    let r = device_control::render_rule(&cmd("usb_block", &[], &[], true));
    // No allow lines, only the default deny.
    assert!(!r.contains("idVendor"));
    assert!(r.contains("ENV{DEVTYPE}==\"usb_device\""));
    assert!(r.contains("authorized}=\"0\""));
}

#[test]
fn usb_allow_only_renders_same_shape_as_block() {
    let r = device_control::render_rule(&cmd("usb_allow_only", &["046d"], &["c52b"], true));
    assert!(r.contains("idVendor}==\"046d\""));
    assert!(r.contains("authorized}=\"0\""));
}

#[test]
fn usb_read_only_targets_usb_block_subsystem() {
    let r = device_control::render_rule(&cmd("usb_read_only", &[], &[], true));
    assert!(r.contains("SUBSYSTEM==\"block\""));
    assert!(r.contains("ID_BUS}==\"usb\""));
    assert!(r.contains("ATTR{ro}=\"1\""));
}

#[test]
fn disabled_policy_renders_empty_body() {
    let r = device_control::render_rule(&cmd("usb_block", &["046d"], &["c52b"], false));
    assert_eq!(r, "");
}

#[test]
fn mismatched_vid_pid_lengths_truncate_at_shorter() {
    // Two VIDs, one PID — only the first pair forms an exception.
    let r = device_control::render_rule(&cmd("usb_block", &["046d", "04f9"], &["c52b"], true));
    assert!(r.contains("idVendor}==\"046d\""));
    assert!(!r.contains("idVendor}==\"04f9\""));
}

#[test]
fn unknown_kind_emits_comment_no_enforcement() {
    let r = device_control::render_rule(&cmd("bogus_kind", &[], &[], true));
    assert!(r.contains("unknown kind"));
    assert!(!r.contains("authorized"));
}

#[test]
fn apply_at_writes_then_tombstone_removes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("99-vigil-device.rules");

    // First apply: enabled policy lands on disk. We can't `udevadm`
    // in CI, so we tolerate that step's failure but expect the file.
    let _ = device_control::apply_at(&cmd("usb_block", &["046d"], &["c52b"], true), &path);
    assert!(path.exists(), "rule file should have been written");
    let body = std::fs::read_to_string(&path).expect("read");
    assert!(body.contains("authorized}=\"0\""));

    // Tombstone removes it.
    let _ = device_control::apply_at(&cmd("usb_block", &[], &[], false), &path);
    assert!(!path.exists(), "tombstone should remove the rule file");

    // Removing twice is idempotent (NotFound is swallowed).
    let r = device_control::apply_at(&cmd("usb_block", &[], &[], false), &path);
    assert!(r.is_ok());
}
