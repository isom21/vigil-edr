//! Polls /proc to detect new processes.
//!
//! Real-time process tracing on Linux uses eBPF (M6). For M2 we use a
//! 1-second /proc poll — simple, no privileges beyond what `/proc` already
//! exposes. PID + start_time_ns disambiguates PID reuse.

use crate::container;
use agent_core::event;
use agent_core::event::ContainerAttribution;
use agent_core::proto as p;
use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;

const POLL_INTERVAL: Duration = Duration::from_millis(1000);

#[derive(Clone)]
pub struct WatcherCtx {
    pub host_id: String,
    pub agent_id: String,
    pub agent_version: String,
}

pub async fn run(ctx: WatcherCtx, tx: mpsc::Sender<p::ClientMessage>) -> Result<()> {
    let mut seen: HashMap<i32, ProcKey> = HashMap::new();

    // Bootstrap: snapshot current /proc so we don't fire alerts for everything
    // that was running before the agent started.
    for p in procfs::process::all_processes()?.flatten() {
        if let Ok(stat) = p.stat() {
            seen.insert(
                p.pid,
                ProcKey {
                    start_time_ticks: stat.starttime,
                },
            );
        }
    }
    tracing::info!(initial = seen.len(), "proc_watcher.snapshot_done");

    let ticks_per_sec = procfs::ticks_per_second() as u64;
    let boot_time_ns = procfs::boot_time_secs()
        .ok()
        .map(|s| s * 1_000_000_000)
        .unwrap_or(0);

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        match scan(&ctx, &mut seen, &tx, ticks_per_sec, boot_time_ns).await {
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "proc_watcher.scan_error"),
        }
    }
}

#[derive(Clone, Copy)]
struct ProcKey {
    start_time_ticks: u64,
}

async fn scan(
    ctx: &WatcherCtx,
    seen: &mut HashMap<i32, ProcKey>,
    tx: &mpsc::Sender<p::ClientMessage>,
    ticks_per_sec: u64,
    boot_time_ns: u64,
) -> Result<()> {
    let mut current: HashMap<i32, ProcKey> = HashMap::new();
    let mut new_events: Vec<p::EndpointEvent> = Vec::new();

    for proc in procfs::process::all_processes()? {
        let proc = match proc {
            Ok(p) => p,
            Err(_) => continue,
        };
        let stat = match proc.stat() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let key = ProcKey {
            start_time_ticks: stat.starttime,
        };
        let pid = proc.pid;
        current.insert(pid, key);

        // New process if we haven't seen the (pid, start_time) tuple before.
        if seen.get(&pid).map(|k| k.start_time_ticks) != Some(stat.starttime) {
            // Build the event before inserting.
            let exe = proc
                .exe()
                .ok()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let cmdline = proc.cmdline().ok().unwrap_or_default().join(" ");
            let name = stat.comm.clone();
            let user = uid_to_name(proc.status().ok().map(|s| s.ruid)).unwrap_or_default();

            let start_time_ns = if ticks_per_sec > 0 && boot_time_ns > 0 {
                boot_time_ns + stat.starttime * 1_000_000_000 / ticks_per_sec
            } else {
                0
            };

            // Phase 2 #2.9: enrich with container metadata when the
            // process is running inside a container. enrich() returns
            // None for bare-metal pids and is cached per (pid, id).
            let container_attr =
                container::enrich(pid as u32)
                    .await
                    .map(|info| ContainerAttribution {
                        id: info.id,
                        image: info.image,
                        runtime: info.runtime,
                    });
            new_events.push(event::process_started(
                &ctx.host_id,
                &ctx.agent_id,
                &ctx.agent_version,
                pid as u32,
                start_time_ns,
                stat.ppid as u32,
                0, // parent start_time not cheaply available; left 0 for now
                &exe,
                &name,
                &cmdline,
                &user,
                container_attr,
            ));
        }
    }

    *seen = current;

    if !new_events.is_empty() {
        let n = new_events.len();
        let batch = p::EventBatch {
            events: new_events,
            batch_id: ulid::Ulid::new().to_string(),
            first_seq: 0,
            last_seq: 0,
        };
        let msg = p::ClientMessage {
            payload: Some(p::client_message::Payload::Events(batch)),
        };
        if tx.send(msg).await.is_err() {
            anyhow::bail!("event channel closed");
        }
        tracing::debug!(n, "proc_watcher.batch_sent");
    }
    Ok(())
}

fn uid_to_name(uid: Option<u32>) -> Option<String> {
    let uid = uid?;
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
}
