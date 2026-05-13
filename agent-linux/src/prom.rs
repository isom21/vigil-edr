//! M14.b: agent-side Prometheus exporter.
//!
//! Lightweight HTTP/1.1 server bound to localhost (127.0.0.1:9101) by
//! default, serving `/metrics` in Prometheus text format from a shared
//! `MetricsSnapshot` updated by the existing 5s stats-read loop.
//!
//! Why not the `prometheus` crate: a single endpoint with no
//! cardinality dynamics doesn't need a registry abstraction. Hand-
//! rolling the response keeps the dep weight off the agent.
//!
//! Bind: `127.0.0.1:9101` by default. Override via
//! `VIGIL_AGENT_METRICS_BIND` (e.g. `0.0.0.0:9101` to expose to a
//! Prometheus instance on another host — only do this behind a
//! trusted boundary, the metrics surface includes data attackers
//! would find useful).
//!
//! Disable via `VIGIL_DISABLE_AGENT_METRICS=1`.

#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// Shared atomic snapshot. The 5s stats-read loop in main.rs updates
/// this from the BPF stats map; the metrics endpoint reads from here.
/// All fields use Relaxed ordering — the metrics endpoint is best-
/// effort and doesn't need stronger guarantees.
#[derive(Default)]
pub struct MetricsSnapshot {
    // BPF kernel-side counters (mirrors `Stat` enum).
    pub bpf_process_exec: AtomicU64,
    pub bpf_process_exit: AtomicU64,
    pub bpf_file_open: AtomicU64,
    pub bpf_network_connect: AtomicU64,
    pub bpf_module_load: AtomicU64,
    pub bpf_block_hits_process: AtomicU64,
    pub bpf_block_hits_file: AtomicU64,
    pub bpf_block_hits_network: AtomicU64,
    pub bpf_kill_requests: AtomicU64,
    pub bpf_events_dropped: AtomicU64,
    pub bpf_self_kill_blocked: AtomicU64,
    pub bpf_self_ptrace_blocked: AtomicU64,
    pub bpf_self_bpf_blocked: AtomicU64,
    pub bpf_self_unlink_blocked: AtomicU64,
    // Phase 1 #1.3 — network isolation counters.
    pub bpf_isolation_hits: AtomicU64,
    pub bpf_isolation_drops: AtomicU64,
    // Agent process-level counters.
    pub spool_entries: AtomicU64,
    pub spool_bytes: AtomicU64,
    pub last_event_unix_ns: AtomicU64,
    // M12.a runtime integrity watchdog drift counts.
    pub tamper_binary: AtomicU64,
    pub tamper_config: AtomicU64,
    // M12.b BPF program / pinned-map watchdog drift counts.
    pub tamper_bpf_detached: AtomicU64,
    pub tamper_bpf_map_missing: AtomicU64,
}

impl MetricsSnapshot {
    pub fn update_from_bpf(&self, stats: &[u64; 18]) {
        self.bpf_process_exec.store(stats[0], Ordering::Relaxed);
        self.bpf_process_exit.store(stats[1], Ordering::Relaxed);
        self.bpf_file_open.store(stats[2], Ordering::Relaxed);
        self.bpf_network_connect.store(stats[3], Ordering::Relaxed);
        self.bpf_module_load.store(stats[4], Ordering::Relaxed);
        self.bpf_block_hits_process
            .store(stats[5], Ordering::Relaxed);
        self.bpf_block_hits_file.store(stats[6], Ordering::Relaxed);
        self.bpf_block_hits_network
            .store(stats[7], Ordering::Relaxed);
        self.bpf_kill_requests.store(stats[8], Ordering::Relaxed);
        self.bpf_events_dropped.store(stats[9], Ordering::Relaxed);
        self.bpf_self_kill_blocked
            .store(stats[10], Ordering::Relaxed);
        self.bpf_self_ptrace_blocked
            .store(stats[11], Ordering::Relaxed);
        self.bpf_self_bpf_blocked
            .store(stats[12], Ordering::Relaxed);
        self.bpf_self_unlink_blocked
            .store(stats[13], Ordering::Relaxed);
        // stats[14], stats[15] are the long-path diagnostic counters;
        // they're useful in logs (format_stats) but not surfaced as
        // Prometheus metrics.
        self.bpf_isolation_hits.store(stats[16], Ordering::Relaxed);
        self.bpf_isolation_drops.store(stats[17], Ordering::Relaxed);
    }
}

pub fn spawn(bind: &str, snapshot: Arc<MetricsSnapshot>) -> tokio::task::JoinHandle<()> {
    let bind = bind.to_string();
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&bind).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, bind = %bind, "agent_metrics.bind_failed");
                return;
            }
        };
        tracing::info!(bind = %bind, "agent_metrics.listening");
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "agent_metrics.accept_failed");
                    continue;
                }
            };
            let snap = snapshot.clone();
            tokio::spawn(async move {
                let _ = handle(sock, snap).await;
            });
        }
    })
}

async fn handle(sock: tokio::net::TcpStream, snap: Arc<MetricsSnapshot>) -> std::io::Result<()> {
    let (read_half, mut write_half) = sock.into_split();
    let mut br = BufReader::new(read_half);
    let mut request_line = String::new();
    br.read_line(&mut request_line).await?;

    // Drain remaining headers.
    let mut line = String::new();
    loop {
        line.clear();
        let n = br.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    if !request_line.starts_with("GET /metrics") {
        let body = b"not found\n";
        let resp = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        write_half.write_all(resp.as_bytes()).await?;
        write_half.write_all(body).await?;
        return Ok(());
    }

    let body = render_metrics(&snap).into_bytes();
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    write_half.write_all(resp.as_bytes()).await?;
    write_half.write_all(&body).await?;
    Ok(())
}

fn render_metrics(snap: &MetricsSnapshot) -> String {
    let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
    let bpf: [(&str, &str, u64); 16] = [
        (
            "edr_agent_bpf_process_exec_total",
            "BPF tracepoint sched_process_exec hits",
            load(&snap.bpf_process_exec),
        ),
        (
            "edr_agent_bpf_process_exit_total",
            "BPF tracepoint sched_process_exit hits",
            load(&snap.bpf_process_exit),
        ),
        (
            "edr_agent_bpf_file_open_total",
            "lsm/file_open hits",
            load(&snap.bpf_file_open),
        ),
        (
            "edr_agent_bpf_network_connect_total",
            "lsm/socket_connect hits",
            load(&snap.bpf_network_connect),
        ),
        (
            "edr_agent_bpf_module_load_total",
            "tracepoint module/module_load hits",
            load(&snap.bpf_module_load),
        ),
        (
            "edr_agent_bpf_block_hits_process_total",
            "lsm/bprm_check_security blocks",
            load(&snap.bpf_block_hits_process),
        ),
        (
            "edr_agent_bpf_block_hits_file_total",
            "lsm/file_open EPERM hits",
            load(&snap.bpf_block_hits_file),
        ),
        (
            "edr_agent_bpf_block_hits_network_total",
            "lsm/socket_connect EPERM hits",
            load(&snap.bpf_block_hits_network),
        ),
        (
            "edr_agent_bpf_kill_requests_total",
            "Kill response actions issued",
            load(&snap.bpf_kill_requests),
        ),
        (
            "edr_agent_bpf_events_dropped_total",
            "BPF ringbuf drops (userspace too slow)",
            load(&snap.bpf_events_dropped),
        ),
        (
            "edr_agent_bpf_self_kill_blocked_total",
            "Self-protection: kill signals to the agent rejected by lsm/task_kill",
            load(&snap.bpf_self_kill_blocked),
        ),
        (
            "edr_agent_bpf_self_ptrace_blocked_total",
            "Self-protection: ptrace_attach to the agent rejected",
            load(&snap.bpf_self_ptrace_blocked),
        ),
        (
            "edr_agent_bpf_self_bpf_blocked_total",
            "Self-protection: bpf(2) detach attempts on agent programs rejected",
            load(&snap.bpf_self_bpf_blocked),
        ),
        (
            "edr_agent_bpf_self_unlink_blocked_total",
            "Self-protection: unlink under agent state/pin dirs rejected",
            load(&snap.bpf_self_unlink_blocked),
        ),
        (
            "edr_agent_bpf_isolation_hits_total",
            "Network isolation: connects evaluated while isolated",
            load(&snap.bpf_isolation_hits),
        ),
        (
            "edr_agent_bpf_isolation_drops_total",
            "Network isolation: connects denied (-EPERM) by lsm/socket_connect",
            load(&snap.bpf_isolation_drops),
        ),
    ];
    let mut out = String::with_capacity(2048);
    for (name, help, val) in bpf {
        out.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} counter\n{name} {val}\n"
        ));
    }
    let spool_e = load(&snap.spool_entries);
    let spool_b = load(&snap.spool_bytes);
    let last_ev = load(&snap.last_event_unix_ns);
    let tamper_bin = load(&snap.tamper_binary);
    let tamper_cfg = load(&snap.tamper_config);
    let tamper_bpf_det = load(&snap.tamper_bpf_detached);
    let tamper_bpf_map = load(&snap.tamper_bpf_map_missing);
    out.push_str(&format!(
        "# HELP edr_agent_spool_entries Number of spool entries pending replay\n\
         # TYPE edr_agent_spool_entries gauge\n\
         edr_agent_spool_entries {spool_e}\n\
         # HELP edr_agent_spool_bytes Bytes used by the disk-backed spool\n\
         # TYPE edr_agent_spool_bytes gauge\n\
         edr_agent_spool_bytes {spool_b}\n\
         # HELP edr_agent_last_event_unix_ns Unix-ns timestamp of the most recent event emitted\n\
         # TYPE edr_agent_last_event_unix_ns gauge\n\
         edr_agent_last_event_unix_ns {last_ev}\n\
         # HELP edr_agent_tamper_binary_total Runtime integrity watchdog: binary hash drift detections\n\
         # TYPE edr_agent_tamper_binary_total counter\n\
         edr_agent_tamper_binary_total {tamper_bin}\n\
         # HELP edr_agent_tamper_config_total Runtime integrity watchdog: config hash drift detections\n\
         # TYPE edr_agent_tamper_config_total counter\n\
         edr_agent_tamper_config_total {tamper_cfg}\n\
         # HELP edr_agent_tamper_bpf_detached_total BPF watchdog: pinned-link disappearance detections\n\
         # TYPE edr_agent_tamper_bpf_detached_total counter\n\
         edr_agent_tamper_bpf_detached_total {tamper_bpf_det}\n\
         # HELP edr_agent_tamper_bpf_map_missing_total BPF watchdog: pinned-map disappearance detections\n\
         # TYPE edr_agent_tamper_bpf_map_missing_total counter\n\
         edr_agent_tamper_bpf_map_missing_total {tamper_bpf_map}\n"
    ));
    out
}
