//! Phase 2 #2.4 — integration test for the auditd / sshd line parsers.
//!
//! The auditd module is a private module of the `vigil-agent` binary
//! crate (no library target), so we re-include the source file as an
//! out-of-tree module rather than reach in via `pub use`. The
//! `#[path]` attribute compiles the same `src/auditd.rs` once more as
//! its own module here.
//!
//! This lives alongside the unit tests inside `auditd.rs` because
//! integration tests run in their own binary and catch regressions
//! where a refactor accidentally narrows visibility of the parser
//! helpers.

#![cfg(target_os = "linux")]

#[path = "../src/auditd.rs"]
#[allow(dead_code)]
mod auditd;

use agent_core::proto as p;

#[test]
fn auditd_login_success_fixture() {
    let line = r#"type=USER_LOGIN msg=audit(1715610234.123:456): pid=1234 uid=0 auid=1000 ses=12 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=web01 addr=10.0.0.5 terminal=/dev/pts/0 res=success' acct="alice""#;
    let rec = auditd::parse_auditd_line(line).expect("USER_LOGIN parses");
    assert_eq!(rec.auth_kind, p::AuthKind::Logon);
    assert_eq!(rec.result, p::AuthResult::Success);
    assert_eq!(rec.user, "alice");
    assert_eq!(rec.source_ip, "10.0.0.5");
    assert_eq!(rec.target_host, "web01");
}

#[test]
fn auditd_auth_failure_fixture() {
    let line = r#"type=USER_AUTH msg=audit(1715610234.123:457): pid=1234 uid=0 msg='op=PAM:authentication grantors=? acct="bob" exe="/usr/sbin/sshd" addr=192.168.1.10 terminal=ssh res=failed'"#;
    let rec = auditd::parse_auditd_line(line).expect("USER_AUTH parses");
    assert_eq!(rec.result, p::AuthResult::Failure);
    assert_eq!(rec.user, "bob");
    assert_eq!(rec.source_ip, "192.168.1.10");
}

#[test]
fn sshd_accepted_password_fixture() {
    let line = "May 13 12:00:00 db01 sshd[2345]: Accepted password for alice from 10.0.0.5 port 12345 ssh2";
    let rec = auditd::parse_sshd_line(line).expect("sshd Accepted parses");
    assert_eq!(rec.auth_kind, p::AuthKind::Logon);
    assert_eq!(rec.result, p::AuthResult::Success);
    assert_eq!(rec.user, "alice");
    assert_eq!(rec.source_ip, "10.0.0.5");
}

#[test]
fn sshd_failed_password_fixture() {
    let line = "May 13 12:00:00 db01 sshd[2345]: Failed password for invalid user mallory from 203.0.113.5 port 22 ssh2";
    let rec = auditd::parse_sshd_line(line).expect("sshd Failed parses");
    assert_eq!(rec.result, p::AuthResult::Failure);
    assert_eq!(rec.user, "mallory");
    assert_eq!(rec.source_ip, "203.0.113.5");
    assert_eq!(rec.failure_reason, "bad_password");
}

#[test]
fn sshd_invalid_user_fixture() {
    let line = "May 13 12:00:00 db01 sshd[2345]: Invalid user backdoor from 198.51.100.7 port 22";
    let rec = auditd::parse_sshd_line(line).expect("sshd Invalid parses");
    assert_eq!(rec.user, "backdoor");
    assert_eq!(rec.failure_reason, "invalid_user");
}

#[test]
fn unrelated_lines_are_skipped() {
    assert!(
        auditd::parse_auditd_line("type=SYSCALL msg=audit(1715610234.123:458): arch=c000003e")
            .is_none()
    );
    assert!(auditd::parse_sshd_line(
        "May 13 12:00:00 db01 sshd[2345]: Connection closed by 10.0.0.5"
    )
    .is_none());
}
