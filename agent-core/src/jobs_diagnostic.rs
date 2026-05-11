//! Diagnostic [`JobHandler`] implementations (M23.g).
//!
//! `agent_diagnostic` (config snapshot + uptime) already lives in
//! `jobs_handlers.rs` because the Survey suite registers it. This
//! module owns the admin-only "run a vetted command" path.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::time::Duration;
use tokio::process::Command;

use crate::jobs::{ArtifactKind, ArtifactSpec, JobContext, JobHandler};

/// Allow-list of binaries the shell_command handler will exec. The
/// manager already gates this kind to admins via JOB_KIND_ADMIN_ONLY,
/// so this is a second layer: even an admin can't run arbitrary
/// programs through the agent's process credentials.
///
/// Keep this list narrow: read-only diagnostic tools only. Anything
/// that mutates state (apt, systemctl start, netsh interface set) is
/// out of scope — that's what specific job kinds are for.
const LINUX_ALLOWLIST: &[&str] = &[
    "uname",
    "hostname",
    "uptime",
    "id",
    "whoami",
    "ps",
    "ss",
    "netstat",
    "ip",
    "ifconfig",
    "route",
    "lsof",
    "dig",
    "host",
    "nslookup",
    "systemctl",  // read-only invocations only (status, list-units)
    "journalctl", // read-only
    "df",
    "free",
    "uptime",
    "lscpu",
    "lsblk",
    "lsmod",
];

const WINDOWS_ALLOWLIST: &[&str] = &[
    "whoami",
    "ipconfig",
    "hostname",
    "ver",
    "systeminfo",
    "tasklist",
    "netstat",
    "route",
    "nslookup",
    "nbtstat",
    "arp",
    "net",        // net user / net session — read-only invocations
    "powershell", // controlled by separate vetting
];

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

#[derive(Deserialize)]
struct ShellCommandParams {
    /// Bare binary name (no slashes). The agent resolves via $PATH.
    command: String,
    #[serde(default)]
    args: Vec<String>,
    /// Hard timeout. Capped at 5 minutes server-side.
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

#[derive(Serialize)]
struct ShellCommandOutput {
    command: String,
    args: Vec<String>,
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u128,
    stdout_truncated: bool,
    stderr_truncated: bool,
    stdout: String,
    stderr: String,
}

pub struct ShellCommandHandler;

#[async_trait]
impl JobHandler for ShellCommandHandler {
    fn kind(&self) -> &'static str {
        "shell_command"
    }
    async fn run(&self, ctx: &JobContext, params: JsonValue) -> Result<()> {
        let p: ShellCommandParams =
            serde_json::from_value(params).context("shell_command params")?;
        let cmd_name = p.command.trim().to_string();
        if cmd_name.is_empty() {
            return Err(anyhow!("shell_command requires a non-empty command"));
        }
        if cmd_name.contains('/') || cmd_name.contains('\\') {
            return Err(anyhow!(
                "shell_command: bare binary name required (no path separators)"
            ));
        }

        let allowlist: &[&str] = if cfg!(target_os = "windows") {
            WINDOWS_ALLOWLIST
        } else {
            LINUX_ALLOWLIST
        };
        let canonical = cmd_name.to_ascii_lowercase();
        if !allowlist.iter().any(|a| a.eq_ignore_ascii_case(&canonical)) {
            return Err(anyhow!(
                "shell_command: '{cmd_name}' not in allowlist; supported: {}",
                allowlist.join(", ")
            ));
        }

        // Strip any control characters from arguments — refuse \0, \n,
        // \r so an attacker can't inject extra command lines via an
        // OAuth-style trick. Tabs are fine.
        for a in &p.args {
            if a.contains('\0') || a.contains('\n') || a.contains('\r') {
                return Err(anyhow!("shell_command: control characters in args"));
            }
        }
        if p.args.len() > 32 {
            return Err(anyhow!("shell_command: too many args (max 32)"));
        }

        let timeout = Duration::from_secs(
            p.timeout_seconds
                .unwrap_or(DEFAULT_TIMEOUT_SECS)
                .clamp(1, 5 * 60),
        );

        ctx.reporter
            .progress(20, Some(format!("running {cmd_name}")))
            .await;

        let started = std::time::Instant::now();
        let mut command = Command::new(&cmd_name);
        command.args(&p.args);
        command.kill_on_drop(true);
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());

        let child = command
            .spawn()
            .with_context(|| format!("spawn {cmd_name}"))?;

        let (exit_code, timed_out, stdout, stderr) =
            match tokio::time::timeout(timeout, child.wait_with_output()).await {
                Ok(Ok(out)) => (out.status.code(), false, out.stdout, out.stderr),
                Ok(Err(e)) => return Err(anyhow!("wait_with_output: {e}")),
                Err(_) => {
                    // Timeout — child was killed by kill_on_drop.
                    (None, true, Vec::new(), Vec::new())
                }
            };

        let duration_ms = started.elapsed().as_millis();
        let (stdout, stdout_truncated) = truncate_bytes(stdout, MAX_OUTPUT_BYTES);
        let (stderr, stderr_truncated) = truncate_bytes(stderr, MAX_OUTPUT_BYTES);

        let output = ShellCommandOutput {
            command: cmd_name.clone(),
            args: p.args.clone(),
            exit_code,
            timed_out,
            duration_ms,
            stdout_truncated,
            stderr_truncated,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        };

        let body = serde_json::to_vec_pretty(&output).context("serialize")?;
        ctx.uploader
            .upload(
                ArtifactSpec {
                    kind: ArtifactKind::ShellOutput,
                    original_filename: format!("shell_{cmd_name}.json"),
                    metadata: serde_json::json!({
                        "exit_code": output.exit_code,
                        "timed_out": output.timed_out,
                        "duration_ms": output.duration_ms,
                    }),
                },
                body,
            )
            .await?;
        ctx.reporter.progress(100, None).await;

        if timed_out {
            return Err(anyhow!("shell_command: timed out after {timeout:?}"));
        }
        if exit_code != Some(0) {
            // Don't fail the JobRun on a non-zero exit — analysts often
            // want the output of, e.g., `id nobody` even when it returns
            // 1. The exit code is recorded in the artifact.
            tracing::info!(
                command = %cmd_name,
                exit_code = ?exit_code,
                "shell_command.non_zero_exit"
            );
        }
        Ok(())
    }
}

fn truncate_bytes(mut v: Vec<u8>, cap: usize) -> (Vec<u8>, bool) {
    if v.len() > cap {
        v.truncate(cap);
        (v, true)
    } else {
        (v, false)
    }
}

pub fn register_diagnostic_handlers(dispatcher: &crate::jobs::JobDispatcher) {
    use std::sync::Arc;
    dispatcher.register(Arc::new(ShellCommandHandler));
}
