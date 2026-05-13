//! Phase 1 #1.4 — live-response remote shell.
//!
//! Cross-platform PTY abstraction shared by the Linux (forkpty) and
//! Windows (ConPTY) agents. The OS-specific halves live in
//! `agent-linux::terminal` and `agent-windows::terminal`; this crate
//! only defines the trait + a session config struct.
//!
//! Design constraints:
//!
//!   * The PTY child runs at the *agent process's* current uid (Linux)
//!     or LocalSystem (Windows service mode). Dropping privileges to
//!     a less-trusted user is intentionally not done here — the agent
//!     itself is the trust boundary; the manager-side RBAC plus the
//!     audit chain are the only gates on what an analyst can do.
//!
//!   * I/O is byte-oriented (Vec<u8>), not String. The PTY can emit
//!     mid-UTF-8 splits, and the WS relay base64-encodes everything
//!     anyway.
//!
//!   * Errors propagate up to the agent's terminal worker; on any
//!     error we send a `TerminalExit` with a descriptive reason and
//!     close the gRPC stream.

use std::io;

/// Initial PTY dimensions + the command-line invocation the agent
/// will run inside the new session. Both halves of the agent fill
/// this in from `TerminalOpen` + their platform defaults.
#[derive(Debug, Clone)]
pub struct TerminalSpec {
    /// Initial column count. Defaults to 80 when the operator's
    /// `TerminalOpen` carried 0.
    pub cols: u16,
    /// Initial row count. Defaults to 24 when zero.
    pub rows: u16,
    /// Shell to launch. Linux defaults to `$SHELL` or `/bin/bash`;
    /// Windows defaults to `cmd.exe` (operators can override to
    /// `powershell.exe` via `VIGIL_TERMINAL_SHELL`).
    pub shell: String,
    /// Extra args passed to the shell. Empty for an interactive shell.
    pub args: Vec<String>,
}

impl Default for TerminalSpec {
    fn default() -> Self {
        Self {
            cols: 80,
            rows: 24,
            shell: default_shell(),
            args: Vec::new(),
        }
    }
}

/// Cross-platform PTY handle. Implementations live in
/// `agent-linux::terminal` and `agent-windows::terminal`.
pub trait PtySession: Send + Sync {
    /// Write bytes to the PTY master (operator's stdin → child).
    fn write(&mut self, data: &[u8]) -> io::Result<()>;

    /// Read up to `buf.len()` bytes from the PTY master. Blocks
    /// until data is available; returns `0` on EOF. Implementations
    /// should not block past O(seconds) so the caller can poll for
    /// session-close while reads are in flight.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Update the TTY dimensions (SIGWINCH on Linux, SetWindowSize
    /// on ConPTY).
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()>;

    /// Best-effort kill of the child shell. The OS implementation
    /// reaps the child; callers shouldn't rely on the exit code
    /// being precise (it may be a SIGKILL exit on Linux).
    fn kill(&mut self) -> io::Result<()>;

    /// Wait for the child to exit and return its exit code (or a
    /// platform-dependent placeholder if the OS didn't surface one).
    fn wait(&mut self) -> io::Result<i32>;
}

/// Factory the platform crates implement so the dispatcher can ask
/// for a fresh PTY session without knowing which OS it's on.
pub trait PtyFactory: Send + Sync {
    fn open(&self, spec: &TerminalSpec) -> io::Result<Box<dyn PtySession>>;
}

/// Default shell for the current platform.
pub fn default_shell() -> String {
    if cfg!(target_os = "windows") {
        std::env::var("VIGIL_TERMINAL_SHELL").unwrap_or_else(|_| "cmd.exe".into())
    } else {
        std::env::var("VIGIL_TERMINAL_SHELL")
            .or_else(|_| std::env::var("SHELL"))
            .unwrap_or_else(|_| "/bin/bash".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_spec_dimensions() {
        let s = TerminalSpec::default();
        assert_eq!(s.cols, 80);
        assert_eq!(s.rows, 24);
        assert!(!s.shell.is_empty());
    }

    #[test]
    fn default_shell_respects_override() {
        // Save + restore so we don't bleed env state into the rest of
        // the test binary.
        let prev = std::env::var("VIGIL_TERMINAL_SHELL").ok();
        // SAFETY: setting an env var is safe in single-threaded test
        // scope; tests inside one Cargo binary are isolated per
        // `#[test]` unless they spawn threads (we don't).
        unsafe {
            std::env::set_var("VIGIL_TERMINAL_SHELL", "/usr/bin/zsh");
        }
        assert_eq!(default_shell(), "/usr/bin/zsh");
        unsafe {
            match prev {
                Some(v) => std::env::set_var("VIGIL_TERMINAL_SHELL", v),
                None => std::env::remove_var("VIGIL_TERMINAL_SHELL"),
            }
        }
    }
}
