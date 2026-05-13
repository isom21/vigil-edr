//! Phase 2 #2.4 — Linux authentication event collector.
//!
//! Tails `/var/log/audit/audit.log` for `USER_LOGIN` / `USER_AUTH`
//! records emitted by the kernel audit subsystem, and falls back to
//! `/var/log/auth.log` (or `/var/log/secure`) sshd lines when auditd
//! is not installed. Each interesting record is converted into an
//! `AuthEvent` and pushed onto the gRPC send channel as part of an
//! `EventBatch`.
//!
//! The parser is deliberately tolerant of malformed lines — auditd's
//! key=value format quotes values with spaces, sshd's syslog format
//! is freeform — so anything we can't recognise is logged at debug
//! and skipped.

use agent_core::event;
use agent_core::proto as p;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::sync::mpsc;

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const AUDITD_PATH: &str = "/var/log/audit/audit.log";
const AUTHLOG_PATH: &str = "/var/log/auth.log";
const SECURE_PATH: &str = "/var/log/secure";

#[derive(Clone)]
pub struct AuditdCtx {
    pub host_id: String,
    pub agent_id: String,
    pub agent_version: String,
}

/// Spawn the auditd tailer. Picks the first readable source out of
/// `/var/log/audit/audit.log`, `/var/log/auth.log`, `/var/log/secure`
/// — on systems with both audit.log and auth.log we prefer the
/// kernel audit stream because it carries structured key=value
/// fields the sshd syslog line doesn't.
pub async fn run(ctx: AuditdCtx, tx: mpsc::Sender<p::ClientMessage>) -> Result<()> {
    let (path, source) = pick_source().context("no readable auth log on this host")?;
    tracing::info!(path = %path.display(), source = ?source, "auditd.tailer.start");
    tail(path, source, ctx, tx).await
}

#[derive(Clone, Copy, Debug)]
enum Source {
    Auditd,
    Sshd,
}

fn pick_source() -> Option<(PathBuf, Source)> {
    for (path, source) in [
        (AUDITD_PATH, Source::Auditd),
        (AUTHLOG_PATH, Source::Sshd),
        (SECURE_PATH, Source::Sshd),
    ] {
        let p = Path::new(path);
        if p.exists() {
            return Some((p.to_path_buf(), source));
        }
    }
    None
}

async fn tail(
    path: PathBuf,
    source: Source,
    ctx: AuditdCtx,
    tx: mpsc::Sender<p::ClientMessage>,
) -> Result<()> {
    let mut file = File::open(&path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    // Start at end-of-file so we don't replay months of history at
    // boot — only events that happen after the agent starts count.
    file.seek(SeekFrom::End(0)).await.ok();
    let mut reader = BufReader::new(file);
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 {
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        }
        let line = buf.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }
        let parsed = match source {
            Source::Auditd => parse_auditd_line(line),
            Source::Sshd => parse_sshd_line(line),
        };
        let Some(rec) = parsed else { continue };
        let ev = event::auth_event(
            &ctx.host_id,
            &ctx.agent_id,
            &ctx.agent_version,
            rec.auth_kind,
            rec.result,
            &rec.user,
            "",
            &rec.source_ip,
            &rec.target_host,
            "",
            0,
            "",
            "",
            &rec.failure_reason,
            0,
        );
        let batch = p::EventBatch {
            events: vec![ev],
            batch_id: ulid::Ulid::new().to_string(),
            first_seq: 0,
            last_seq: 0,
        };
        let msg = p::ClientMessage {
            payload: Some(p::client_message::Payload::Events(batch)),
        };
        if tx.send(msg).await.is_err() {
            return Ok(());
        }
    }
}

/// Internal parsed record. We unify the auditd and sshd shapes here
/// so the tail loop only has one branch.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuthRecord {
    pub auth_kind: p::AuthKind,
    pub result: p::AuthResult,
    pub user: String,
    pub source_ip: String,
    pub target_host: String,
    pub failure_reason: String,
}

/// Parse one line of `/var/log/audit/audit.log`. Returns `None` for
/// types we don't care about (which is most of them — auditd is very
/// chatty about syscalls).
pub(crate) fn parse_auditd_line(line: &str) -> Option<AuthRecord> {
    // Auditd lines look like:
    //   type=USER_LOGIN msg=audit(1715610234.123:456): pid=1234 uid=0 ...
    //     msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=h ...
    //     addr=10.0.0.5 terminal=/dev/pts/0 res=success'
    let kind = line
        .strip_prefix("type=")
        .or_else(|| line.find("type=").map(|i| &line[i + 5..]))?;
    let kind_end = kind.find(' ').unwrap_or(kind.len());
    let kind = &kind[..kind_end];
    let (auth_kind, default_result) = match kind {
        "USER_LOGIN" => (p::AuthKind::Logon, p::AuthResult::Unknown),
        "USER_AUTH" => (p::AuthKind::Logon, p::AuthResult::Unknown),
        "USER_LOGOUT" => (p::AuthKind::Logoff, p::AuthResult::Success),
        _ => return None,
    };
    let user = audit_field(line, "acct")
        .or_else(|| audit_field(line, "id"))
        .unwrap_or_default();
    let source_ip = audit_field(line, "addr").unwrap_or_default();
    let target_host = audit_field(line, "hostname").unwrap_or_default();
    let res = audit_field(line, "res").unwrap_or_default();
    let result = match res.as_str() {
        "success" => p::AuthResult::Success,
        "failed" => p::AuthResult::Failure,
        _ => default_result,
    };
    Some(AuthRecord {
        auth_kind,
        result,
        user,
        source_ip,
        target_host: if target_host == "?" {
            String::new()
        } else {
            target_host
        },
        failure_reason: String::new(),
    })
}

/// Read a `key=value` field out of an auditd line. Values can be
/// bare, single-quoted, or double-quoted; the parser handles all
/// three.
fn audit_field(line: &str, key: &str) -> Option<String> {
    // Find " key=" or start-of-line "key=". The leading space guard
    // avoids matching key=value as a suffix of another key (e.g.
    // `subj_user=foo` matching `user`).
    let needle_space = format!(" {key}=");
    let needle_start = format!("{key}=");
    let idx = line
        .find(&needle_space)
        .map(|i| i + needle_space.len())
        .or_else(|| {
            if line.starts_with(&needle_start) {
                Some(needle_start.len())
            } else {
                None
            }
        })?;
    let rest = &line[idx..];
    let val = match rest.as_bytes().first() {
        Some(b'"') => {
            let inner = &rest[1..];
            let end = inner.find('"')?;
            &inner[..end]
        }
        Some(b'\'') => {
            let inner = &rest[1..];
            let end = inner.find('\'')?;
            &inner[..end]
        }
        _ => {
            // Stop at whitespace OR at a closing quote of an enclosing
            // `msg='...'` block — auditd nests key=value pairs inside
            // a single-quoted `msg=...` field, so the value we just
            // matched can be followed by `'` rather than a space.
            let end = rest.find([' ', '\n', '\'', '"']).unwrap_or(rest.len());
            &rest[..end]
        }
    };
    Some(val.to_string())
}

/// Parse one syslog line from `/var/log/auth.log` / `/var/log/secure`.
/// We only care about sshd's `Accepted` / `Failed password` / `Invalid
/// user` patterns.
pub(crate) fn parse_sshd_line(line: &str) -> Option<AuthRecord> {
    // Strip everything before the sshd tag so we tolerate variable
    // hostname / timestamp prefixes.
    let body = match line.find("sshd[") {
        Some(i) => match line[i..].find("]: ") {
            Some(j) => &line[i + j + 3..],
            None => return None,
        },
        None => match line.find("sshd: ") {
            Some(i) => &line[i + 6..],
            None => return None,
        },
    };
    if let Some(rest) = body.strip_prefix("Accepted ") {
        // "Accepted password for alice from 10.0.0.5 port 12345 ssh2"
        let (user, source_ip) = parse_for_from(rest)?;
        return Some(AuthRecord {
            auth_kind: p::AuthKind::Logon,
            result: p::AuthResult::Success,
            user,
            source_ip,
            target_host: String::new(),
            failure_reason: String::new(),
        });
    }
    if let Some(rest) = body.strip_prefix("Failed ") {
        // "Failed password for alice from 10.0.0.5 port 12345 ssh2"
        // or "Failed password for invalid user bob from ..."
        let (user, source_ip) = parse_for_from(rest)?;
        return Some(AuthRecord {
            auth_kind: p::AuthKind::Logon,
            result: p::AuthResult::Failure,
            user,
            source_ip,
            target_host: String::new(),
            failure_reason: "bad_password".into(),
        });
    }
    if let Some(rest) = body.strip_prefix("Invalid user ") {
        // "Invalid user bob from 10.0.0.5 port 12345"
        let mut parts = rest.split_whitespace();
        let user = parts.next()?.to_string();
        let source_ip = if parts.next() == Some("from") {
            parts.next().unwrap_or_default().to_string()
        } else {
            String::new()
        };
        return Some(AuthRecord {
            auth_kind: p::AuthKind::Logon,
            result: p::AuthResult::Failure,
            user,
            source_ip,
            target_host: String::new(),
            failure_reason: "invalid_user".into(),
        });
    }
    None
}

/// Parse the "<method> for [invalid user ]<user> from <ip> ..." tail.
/// Returns (user, source_ip).
fn parse_for_from(rest: &str) -> Option<(String, String)> {
    let for_idx = rest.find(" for ")?;
    let after_for = &rest[for_idx + 5..];
    let after_for = after_for.strip_prefix("invalid user ").unwrap_or(after_for);
    let from_idx = after_for.find(" from ")?;
    let user = after_for[..from_idx].trim().to_string();
    let after_from = &after_for[from_idx + 6..];
    let ip_end = after_from.find([' ', '\t']).unwrap_or(after_from.len());
    let source_ip = after_from[..ip_end].to_string();
    Some((user, source_ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auditd_user_login_success() {
        let line = r#"type=USER_LOGIN msg=audit(1715610234.123:456): pid=1234 uid=0 auid=1000 ses=12 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=db01 addr=10.0.0.5 terminal=/dev/pts/0 res=success' acct="alice""#;
        let rec = parse_auditd_line(line).expect("parsed");
        assert_eq!(rec.auth_kind, p::AuthKind::Logon);
        assert_eq!(rec.result, p::AuthResult::Success);
        assert_eq!(rec.user, "alice");
        assert_eq!(rec.source_ip, "10.0.0.5");
        assert_eq!(rec.target_host, "db01");
    }

    #[test]
    fn auditd_user_auth_failure() {
        let line = r#"type=USER_AUTH msg=audit(1715610234.123:457): pid=1234 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="bob" exe="/usr/sbin/sshd" hostname=? addr=192.168.1.10 terminal=ssh res=failed'"#;
        let rec = parse_auditd_line(line).expect("parsed");
        assert_eq!(rec.auth_kind, p::AuthKind::Logon);
        assert_eq!(rec.result, p::AuthResult::Failure);
        assert_eq!(rec.user, "bob");
        assert_eq!(rec.source_ip, "192.168.1.10");
        assert!(rec.target_host.is_empty(), "got {:?}", rec.target_host);
    }

    #[test]
    fn auditd_unrelated_type_ignored() {
        let line = "type=SYSCALL msg=audit(1715610234.123:458): arch=c000003e syscall=2";
        assert!(parse_auditd_line(line).is_none());
    }

    #[test]
    fn sshd_accepted_password() {
        let line =
            "May 13 12:00:00 db01 sshd[2345]: Accepted password for alice from 10.0.0.5 port 12345 ssh2";
        let rec = parse_sshd_line(line).expect("parsed");
        assert_eq!(rec.auth_kind, p::AuthKind::Logon);
        assert_eq!(rec.result, p::AuthResult::Success);
        assert_eq!(rec.user, "alice");
        assert_eq!(rec.source_ip, "10.0.0.5");
    }

    #[test]
    fn sshd_failed_password() {
        let line =
            "May 13 12:00:00 db01 sshd[2345]: Failed password for bob from 192.168.1.10 port 22 ssh2";
        let rec = parse_sshd_line(line).expect("parsed");
        assert_eq!(rec.result, p::AuthResult::Failure);
        assert_eq!(rec.user, "bob");
        assert_eq!(rec.failure_reason, "bad_password");
    }

    #[test]
    fn sshd_invalid_user() {
        let line = "May 13 12:00:00 db01 sshd[2345]: Invalid user mallory from 203.0.113.5 port 22";
        let rec = parse_sshd_line(line).expect("parsed");
        assert_eq!(rec.result, p::AuthResult::Failure);
        assert_eq!(rec.user, "mallory");
        assert_eq!(rec.source_ip, "203.0.113.5");
        assert_eq!(rec.failure_reason, "invalid_user");
    }

    #[test]
    fn sshd_non_auth_line_ignored() {
        let line = "May 13 12:00:00 db01 sshd[2345]: Connection closed by 10.0.0.5";
        assert!(parse_sshd_line(line).is_none());
    }
}
