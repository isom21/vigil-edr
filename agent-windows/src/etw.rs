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
use ferrisetw::trace::{KernelTrace, TraceTrait};
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

    // Kernel sessions use a fixed name. Two agents fighting for it lose.
    let trace = KernelTrace::new()
        .named(String::from("EDRKernelSession"))
        .enable(provider)
        .start_and_process()?;

    // ferrisetw owns the worker thread for the trace's lifetime; we just keep
    // the handle alive for the process lifetime.
    std::thread::spawn(move || {
        let _ = trace; // hold reference; dropping stops the trace
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
    // Process opcode 1 = Start, 2 = End. We only forward Start for M2.
    if record.opcode() != 1 {
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

    let start_time_ns = record.timestamp() as u64;

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
    // Best-effort send — drop on backpressure.
    let _ = tx.try_send(msg);
}
