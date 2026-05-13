//! Phase 2 #2.4 — Windows authentication event collector.
//!
//! Subscribes to the `Microsoft-Windows-Security-Auditing` user-mode
//! ETW provider (GUID `{54849625-5478-4994-A5BA-3E3B0328C30D}`) and
//! converts the well-known event IDs into `AuthEvent` records:
//!
//!   4624 — successful logon            → AUTH_KIND_LOGON / SUCCESS
//!   4625 — failed logon                → AUTH_KIND_LOGON / FAILURE
//!   4634 — logoff                      → AUTH_KIND_LOGOFF / SUCCESS
//!   4647 — user-initiated logoff       → AUTH_KIND_LOGOFF / SUCCESS
//!   4768 — Kerberos TGT request        → AUTH_KIND_KERBEROS_TGT
//!   4769 — Kerberos service ticket     → AUTH_KIND_KERBEROS_TGS
//!   4776 — NTLM credential validation  → AUTH_KIND_NT_LOGON
//!
//! Requires the agent to run as SYSTEM (the security auditing
//! provider is gated on SeAuditPrivilege / SeSecurityPrivilege).
//! The session name is unique per process so two agents on the same
//! host don't collide; a stale session from a crashed predecessor is
//! stopped at startup.

#![cfg(windows)]

use agent_core::event;
use agent_core::proto as p;
use anyhow::Result;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use ferrisetw::SchemaLocator;
use std::sync::Arc;
use tokio::sync::mpsc;

const SECURITY_AUDITING_GUID: &str = "54849625-5478-4994-A5BA-3E3B0328C30D";
const SESSION_NAME: &str = "VigilAuthSession";

#[derive(Clone)]
pub struct WatcherCtx {
    pub host_id: String,
    pub agent_id: String,
    pub agent_version: String,
}

pub fn start(ctx: WatcherCtx, tx: mpsc::Sender<p::ClientMessage>) -> Result<()> {
    let ctx = Arc::new(ctx);
    let provider = Provider::by_guid(SECURITY_AUDITING_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            on_event(record, locator, Arc::clone(&ctx), tx.clone());
        })
        .build();

    // Stop any session left behind by a crashed predecessor. Failures
    // here are non-fatal (no prior session, no privilege, etc.).
    stop_stale_session(SESSION_NAME);

    let trace = UserTrace::new()
        .named(String::from(SESSION_NAME))
        .enable(provider)
        .start_and_process()
        .map_err(|e| anyhow::anyhow!("ferrisetw start_and_process: {e:?}"))?;
    tracing::info!(session = SESSION_NAME, "etw_auth.trace.started");

    std::thread::spawn(move || {
        let _trace = trace;
        std::thread::park();
    });
    Ok(())
}

fn on_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    ctx: Arc<WatcherCtx>,
    tx: mpsc::Sender<p::ClientMessage>,
) {
    let event_id = record.event_id();
    let Some((auth_kind, result, ticket_kind)) = classify(event_id) else {
        return;
    };
    let schema = match locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = ?e, event_id, "etw_auth.schema_unavailable");
            return;
        }
    };
    let parser = Parser::create(record, &schema);

    let user: String = parser.try_parse("TargetUserName").ok().unwrap_or_default();
    let user_domain: String = parser
        .try_parse("TargetDomainName")
        .ok()
        .unwrap_or_default();
    let source_ip: String = parser.try_parse("IpAddress").ok().unwrap_or_default();
    let target_host: String = parser.try_parse("WorkstationName").ok().unwrap_or_default();
    let logon_type: i32 = parser.try_parse("LogonType").ok().unwrap_or(0);
    let service_name: String = parser.try_parse("ServiceName").ok().unwrap_or_default();
    let failure_reason: String = parser
        .try_parse::<String>("Status")
        .ok()
        .unwrap_or_default();

    let ev = event::auth_event(
        &ctx.host_id,
        &ctx.agent_id,
        &ctx.agent_version,
        auth_kind,
        result,
        &user,
        &user_domain,
        &source_ip,
        &target_host,
        "",
        logon_type,
        ticket_kind,
        &service_name,
        &failure_reason,
        event_id as u32,
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
    match tx.try_send(msg) {
        Ok(()) => tracing::debug!(event_id, user = %user, "etw_auth.sent"),
        Err(e) => tracing::warn!(event_id, error = ?e, "etw_auth.dropped"),
    }
}

/// Map a Security-Auditing event ID to the (AuthKind, AuthResult,
/// ticket_kind hint) tuple we emit. Unknown IDs return `None` so the
/// caller skips them — the security log is busy and most records
/// aren't auth-relevant.
fn classify(event_id: u16) -> Option<(p::AuthKind, p::AuthResult, &'static str)> {
    match event_id {
        4624 => Some((p::AuthKind::Logon, p::AuthResult::Success, "")),
        4625 => Some((p::AuthKind::Logon, p::AuthResult::Failure, "")),
        4634 | 4647 => Some((p::AuthKind::Logoff, p::AuthResult::Success, "")),
        4768 => Some((p::AuthKind::KerberosTgt, p::AuthResult::Unknown, "TGT")),
        4769 => Some((p::AuthKind::KerberosTgs, p::AuthResult::Unknown, "TGS")),
        4776 => Some((p::AuthKind::NtLogon, p::AuthResult::Unknown, "")),
        _ => None,
    }
}

/// Stop a previously-leaked user-mode ETW session with the given name.
/// The user-mode controller path mirrors the kernel-session shutdown
/// in `etw.rs`; we keep them separate so each module owns its own
/// session-name constant.
fn stop_stale_session(session_name: &str) {
    use windows::core::PCSTR;
    use windows::Win32::System::Diagnostics::Etw::{
        ControlTraceA, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES,
    };

    let name_bytes = session_name.as_bytes();
    let buf_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 4096;
    let mut buf = vec![0u8; buf_size];

    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    // SAFETY: the buffer is large enough for the struct + trailing
    // string region; we only write through `props` and `logger_name_ptr`
    // within that buffer.
    unsafe {
        (*props).Wnode.BufferSize = buf_size as u32;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        let logger_name_ptr = buf.as_mut_ptr().add((*props).LoggerNameOffset as usize);
        std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), logger_name_ptr, name_bytes.len());

        let Ok(session_cstr) = std::ffi::CString::new(session_name) else {
            return;
        };
        let res = ControlTraceA(
            CONTROLTRACE_HANDLE { Value: 0 },
            PCSTR(session_cstr.as_ptr() as *const u8),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );
        if res.is_ok() {
            tracing::info!(session = session_name, "etw_auth.stale_session.stopped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_4624_is_logon_success() {
        let (kind, result, _) = classify(4624).expect("known id");
        assert_eq!(kind, p::AuthKind::Logon);
        assert_eq!(result, p::AuthResult::Success);
    }

    #[test]
    fn classify_4625_is_logon_failure() {
        let (kind, result, _) = classify(4625).expect("known id");
        assert_eq!(kind, p::AuthKind::Logon);
        assert_eq!(result, p::AuthResult::Failure);
    }

    #[test]
    fn classify_4768_is_tgt() {
        let (kind, _, ticket) = classify(4768).expect("known id");
        assert_eq!(kind, p::AuthKind::KerberosTgt);
        assert_eq!(ticket, "TGT");
    }

    #[test]
    fn classify_4769_is_tgs() {
        let (kind, _, ticket) = classify(4769).expect("known id");
        assert_eq!(kind, p::AuthKind::KerberosTgs);
        assert_eq!(ticket, "TGS");
    }

    #[test]
    fn classify_unknown_skipped() {
        assert!(classify(1234).is_none());
    }
}
