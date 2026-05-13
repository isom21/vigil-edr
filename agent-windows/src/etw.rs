//! ETW collector for process events.
//!
//! Subscribes to the NT Kernel Logger session's process provider and
//! converts each ProcessStart event into an EndpointEvent. Requires the
//! agent service to run as SYSTEM (or another principal with
//! SeSystemProfilePrivilege + SeDebugPrivilege).
//!
//! NOTE: This is the M2 thin slice. It only handles ProcessStart from the
//! kernel session; image_load / file / registry providers come in M4 along
//! with the kernel driver.

#![cfg(windows)]

use agent_core::event;
use agent_core::proto as p;
use anyhow::Result;
use ferrisetw::parser::Parser;
use ferrisetw::provider::kernel_providers::PROCESS_PROVIDER;
use ferrisetw::provider::Provider;
use ferrisetw::trace::KernelTrace;
use ferrisetw::EventRecord;
use ferrisetw::SchemaLocator;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct WatcherCtx {
    pub host_id: String,
    pub agent_id: String,
    pub agent_version: String,
}

/// Spawn the kernel-session ETW trace on a dedicated thread (ferrisetw is
/// blocking) and forward ProcessStart events into the gRPC send channel.
pub fn start(ctx: WatcherCtx, tx: mpsc::Sender<p::ClientMessage>) -> Result<()> {
    // Cloned into the closure; ferrisetw runs the callback on a worker thread.
    let ctx = Arc::new(ctx);
    let tx = tx;

    let provider = Provider::kernel(&PROCESS_PROVIDER)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let ctx = Arc::clone(&ctx);
            let tx = tx.clone();
            on_event(record, locator, ctx, tx);
        })
        .build();

    // M7.7: stop any stale "VigilKernelSession" left in the kernel from a
    // previous (possibly crashed) run. Without this, start_and_process
    // returns EtwNativeError(AlreadyExist) and the agent fails to fall
    // back gracefully. We use ControlTraceA with EVENT_TRACE_CONTROL_STOP;
    // failures are non-fatal (no prior session, lack of privilege, etc.).
    stop_stale_kernel_session("VigilKernelSession");

    // Kernel sessions use a fixed name. Two agents fighting for it lose.
    // ferrisetw's TraceError doesn't impl std::error::Error, so wrap it
    // through anyhow's display.
    let trace = KernelTrace::new()
        .named(String::from("VigilKernelSession"))
        .enable(provider)
        .start_and_process()
        .map_err(|e| anyhow::anyhow!("ferrisetw start_and_process: {e:?}"))?;
    tracing::info!(session = "VigilKernelSession", "etw.kernel_trace.started");

    // ferrisetw owns the worker thread for the trace's lifetime; we just keep
    // the handle alive for the process lifetime. Named binding (`_trace`,
    // not `_`) — the bare-underscore pattern would *drop* the value
    // immediately, which silently kills the ETW session.
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
    let opcode = record.opcode();
    tracing::trace!(opcode, "etw.event");
    // Process opcode 1 = Start, 2 = End. We only forward Start for M2.
    if opcode != 1 {
        return;
    }
    let schema = match locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = ?e, "etw.schema_unavailable");
            return;
        }
    };
    let parser = Parser::create(record, &schema);

    let pid: u32 = parser.try_parse("ProcessId").unwrap_or(0);
    let ppid: u32 = parser.try_parse("ParentId").unwrap_or(0);
    let image: String = parser.try_parse("ImageFileName").unwrap_or_default();
    let cmdline: String = parser.try_parse("CommandLine").unwrap_or_default();
    let user_sid: String = parser.try_parse("UserSID").unwrap_or_default();

    // ferrisetw 1.2 renamed timestamp() -> raw_timestamp().
    let start_time_ns = record.raw_timestamp() as u64;

    let ev = event::process_started(
        &ctx.host_id,
        &ctx.agent_id,
        &ctx.agent_version,
        pid,
        start_time_ns,
        ppid,
        0,
        &image,
        std::path::Path::new(&image)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&image),
        &cmdline,
        &user_sid,
        // Phase 2 #2.9: no container attribution on Windows yet — the
        // Windows containers feature exposes its container id via the
        // HCS API, which we don't wire up here.
        None,
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
        Ok(()) => tracing::debug!(pid, image = %image, "etw.process_started.sent"),
        Err(e) => tracing::warn!(pid, error = ?e, "etw.process_started.dropped"),
    }
}

/// M7.7: stop any leftover ETW kernel session of the given name. Called
/// before `start_and_process` so a previous crashed run doesn't leave us
/// stuck on `AlreadyExist`.
///
/// The session name + EVENT_TRACE_PROPERTIES + ControlTraceA come straight
/// from the Win32 evntrace.h API. We use a minimal handcrafted props
/// buffer (the ferrisetw API doesn't expose a stop-by-name helper).
/// Failures are silent — no prior session, lack of privilege, or kernel
/// API error all manifest as a non-zero return that we ignore.
fn stop_stale_kernel_session(session_name: &str) {
    use windows::core::PCSTR;
    use windows::Win32::System::Diagnostics::Etw::{
        ControlTraceA, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES,
    };

    // The properties buffer must be sized to fit
    //     sizeof(EVENT_TRACE_PROPERTIES) + log_file_name + session_name (each NUL-terminated).
    // We don't write a log file name. session_name + a NUL slot.
    let name_bytes = session_name.as_bytes();
    let buf_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 4096;
    let mut buf = vec![0u8; buf_size];

    // SAFETY: the buffer is large enough for the struct + trailing strings,
    // and we only write into it via the &mut props pointer.
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*props).Wnode.BufferSize = buf_size as u32;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        let logger_name_ptr = buf.as_mut_ptr().add((*props).LoggerNameOffset as usize);
        std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), logger_name_ptr, name_bytes.len());
        // Trailing NUL was zeroed by vec init.

        let session_cstr = match std::ffi::CString::new(session_name) {
            Ok(s) => s,
            Err(_) => return,
        };
        let res = ControlTraceA(
            CONTROLTRACE_HANDLE { Value: 0 },
            PCSTR(session_cstr.as_ptr() as *const u8),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );
        if res.is_ok() {
            tracing::info!(session = session_name, "etw.stale_session.stopped");
        }
        // Not-found / no-permission paths are expected and silent.
    }
}
