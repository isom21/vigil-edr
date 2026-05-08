//! Windows EDR agent entry point.
//! M0 stub — full ETW + driver IPC lands in M2/M4.

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("edr-agent (windows) starting — M0 stub");
    Ok(())
}
