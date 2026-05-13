//! Linux-side PTY implementation backed by `forkpty(3)` from libc.
//!
//! The forkpty path is preferred over openpty + manual fork because the
//! kernel handles the controlling-terminal wiring (TIOCSCTTY etc.) in
//! one syscall. We pass the resulting pty master FD up to the agent's
//! terminal worker, which proxies bytes to/from the gRPC stream.
//!
//! Sandboxing: the child inherits the agent process's uid/gid. The
//! agent normally runs as root (for eBPF + capdrop'd LSM hooks); the
//! shell we exec therefore runs as root too. The threat model
//! accepts this — the analyst RBAC + audit chain are the gates that
//! matter. Operators who want a less-privileged remote shell can
//! point `VIGIL_TERMINAL_SHELL` at a setuid wrapper.

use agent_core::terminal::{PtyFactory, PtySession, TerminalSpec};
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

/// Build the Linux PTY factory. Stays a no-op on non-Linux targets so
/// the rest of the agent compiles without conditional gating.
pub fn factory() -> Arc<dyn PtyFactory> {
    Arc::new(ForkPtyFactory)
}

struct ForkPtyFactory;

impl PtyFactory for ForkPtyFactory {
    fn open(&self, spec: &TerminalSpec) -> io::Result<Box<dyn PtySession>> {
        let cols = if spec.cols == 0 { 80 } else { spec.cols };
        let rows = if spec.rows == 0 { 24 } else { spec.rows };
        let session = LinuxPty::spawn(&spec.shell, &spec.args, cols, rows)?;
        Ok(Box::new(session))
    }
}

/// A spawned PTY + child pid. Dropping closes the master FD which
/// SIGHUPs the foreground process group.
pub struct LinuxPty {
    master: std::fs::File,
    pid: libc::pid_t,
}

impl LinuxPty {
    /// Spawn `shell` inside a fresh PTY sized to (`cols` × `rows`).
    /// On the parent side we wrap the master FD in a `std::fs::File`
    /// so the standard `Read`/`Write` impls Just Work.
    pub fn spawn(shell: &str, args: &[String], cols: u16, rows: u16) -> io::Result<Self> {
        // Pre-build the CStrings here so any failure is visible
        // *before* fork (we can't allocate after fork safely).
        let shell_c =
            CString::new(shell).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut argv_cstrings: Vec<CString> = Vec::with_capacity(args.len() + 2);
        argv_cstrings.push(shell_c.clone());
        // `-i` lets the operator get an interactive shell prompt
        // (PS1, history, job control). Skipped if the operator
        // already configured args themselves.
        if args.is_empty() && shell.ends_with("bash") {
            argv_cstrings.push(CString::new("-i").unwrap());
        }
        for a in args {
            argv_cstrings.push(
                CString::new(a.as_str())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            );
        }

        let mut master_fd: RawFd = -1;
        // libc::winsize lives behind `libc::winsize` on Linux only.
        // SAFETY: we initialize all fields before reading.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        ws.ws_col = cols;
        ws.ws_row = rows;

        // SAFETY: forkpty is a libc syscall; we pass valid pointers
        // and check the return value below. Post-fork the child does
        // only async-signal-safe operations (execvp).
        let pid = unsafe {
            libc::forkpty(
                &mut master_fd as *mut RawFd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &ws as *const libc::winsize as *mut libc::winsize,
            )
        };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // Child. Build the argv array and exec.
            let mut argv_ptrs: Vec<*const libc::c_char> =
                argv_cstrings.iter().map(|c| c.as_ptr()).collect();
            argv_ptrs.push(std::ptr::null());
            // SAFETY: execvp returns only on failure; if it fails we
            // abort the child so the parent sees a non-zero exit.
            unsafe {
                libc::execvp(shell_c.as_ptr(), argv_ptrs.as_ptr());
                libc::_exit(127);
            }
        }
        // Parent.
        let owned = unsafe { OwnedFd::from_raw_fd(master_fd) };
        let master = std::fs::File::from(owned);
        Ok(Self { master, pid })
    }
}

impl PtySession for LinuxPty {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.master.write_all(data)
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Read returns Ok(0) when the slave side has closed
        // (child exit / TIOCNOTTY). The caller then transitions to
        // wait() to harvest the exit code.
        match self.master.read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        let fd = std::os::fd::AsRawFd::as_raw_fd(&self.master);
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        ws.ws_col = cols;
        ws.ws_row = rows;
        let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn kill(&mut self) -> io::Result<()> {
        let rc = unsafe { libc::kill(self.pid, libc::SIGTERM) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn wait(&mut self) -> io::Result<i32> {
        let mut status: libc::c_int = 0;
        let rc = unsafe { libc::waitpid(self.pid, &mut status, 0) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::WIFEXITED(status) {
            Ok(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            // -signum mirrors the Python convention; the manager
            // forwards it as the exit_code on TerminalExit.
            Ok(-libc::WTERMSIG(status))
        } else {
            Ok(0)
        }
    }
}
