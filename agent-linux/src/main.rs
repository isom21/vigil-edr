//! Linux EDR agent entry point.
//! M0 stub — eBPF program loading lands in M6.

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("edr-agent (linux) starting — M0 stub");
    Ok(())
}
