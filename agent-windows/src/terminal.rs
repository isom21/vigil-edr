//! Windows-side PTY implementation backed by ConPTY (`CreatePseudoConsole`).
//!
//! Available on Windows 10 1809+ and Windows Server 2019+ — which
//! covers every target the rest of the agent already requires. The
//! ConPTY API gives us a pair of anonymous pipes plus an opaque
//! handle; we feed stdin in one direction and read the child's
//! formatted stdout/stderr from the other.
//!
//! Shell selection: defaults to `cmd.exe`. Operators can opt in to
//! `powershell.exe` (or pwsh) via `VIGIL_TERMINAL_SHELL`. The shell
//! runs as LocalSystem when the agent is launched by SCM (the
//! default service mode). The threat-model gates are RBAC + audit;
//! we don't try to drop privileges here.

#![cfg(windows)]
// CODE-204: the agent currently doesn't wire this module into the
// command dispatcher. Kept for the future ConPTY proxy that will
// land alongside re-advertising terminal_v1.
#![allow(dead_code)]

use agent_core::terminal::{PtyFactory, PtySession, TerminalSpec};
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::sync::Arc;

use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Console::{
    ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    STARTUPINFOEXW,
};

pub fn factory() -> Arc<dyn PtyFactory> {
    Arc::new(ConPtyFactory)
}

struct ConPtyFactory;

impl PtyFactory for ConPtyFactory {
    fn open(&self, spec: &TerminalSpec) -> io::Result<Box<dyn PtySession>> {
        let cols = if spec.cols == 0 { 80 } else { spec.cols };
        let rows = if spec.rows == 0 { 24 } else { spec.rows };
        let session = ConPty::spawn(&spec.shell, &spec.args, cols, rows)?;
        Ok(Box::new(session))
    }
}

pub struct ConPty {
    hpcon: HPCON,
    stdin_write: OwnedHandle,
    stdout_read: OwnedHandle,
    process: HANDLE,
    thread: HANDLE,
    attr_buffer: Vec<u8>,
}

unsafe impl Send for ConPty {}
unsafe impl Sync for ConPty {}

impl ConPty {
    fn spawn(shell: &str, args: &[String], cols: u16, rows: u16) -> io::Result<Self> {
        // Two anonymous pipes — one each direction. ConPTY writes
        // ANSI-formatted output to `stdout_write` (we read from
        // `stdout_read`) and consumes operator input from
        // `stdin_read` (we write to `stdin_write`).
        let (stdin_read, stdin_write) = create_pipe()?;
        let (stdout_read, stdout_write) = create_pipe()?;

        let size = COORD {
            X: cols as i16,
            Y: rows as i16,
        };

        let hpcon = unsafe {
            CreatePseudoConsole(
                size,
                HANDLE(stdin_read.as_raw_handle()),
                HANDLE(stdout_write.as_raw_handle()),
                0,
            )
            .map_err(|e| io::Error::other(format!("CreatePseudoConsole: {e}")))?
        };

        // STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE so
        // the child inherits the pty rather than the agent's
        // console.
        let mut attr_size: usize = 0;
        unsafe {
            let _ = InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
                1,
                0,
                &mut attr_size,
            );
        }
        let mut attr_buffer = vec![0u8; attr_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buffer.as_mut_ptr() as *mut _);

        unsafe {
            InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size)
                .map_err(|e| io::Error::other(format!("InitializeProcThreadAttributeList: {e}")))?;
            UpdateProcThreadAttribute(
                attr_list,
                0,
                22 | 0x00020000, // PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
                Some(hpcon.0 as *const _),
                std::mem::size_of::<HPCON>(),
                None,
                None,
            )
            .map_err(|e| io::Error::other(format!("UpdateProcThreadAttribute: {e}")))?;
        }

        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_list;

        let mut pi = PROCESS_INFORMATION::default();

        let mut cmd_line = build_cmdline(shell, args);
        let cmd_line_pwstr = PWSTR(cmd_line.as_mut_ptr());

        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                cmd_line_pwstr,
                None,
                None,
                false,
                EXTENDED_STARTUPINFO_PRESENT,
                None,
                PCWSTR::null(),
                &si.StartupInfo,
                &mut pi,
            )
            .map_err(|e| io::Error::other(format!("CreateProcessW: {e}")))?;
        }

        // We don't need the slave-side ends of the pipes anymore;
        // the child inherited them via the proc attribute list.
        drop(stdin_read);
        drop(stdout_write);

        Ok(Self {
            hpcon,
            stdin_write,
            stdout_read,
            process: pi.hProcess,
            thread: pi.hThread,
            attr_buffer,
        })
    }
}

impl PtySession for ConPty {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let h = HANDLE(self.stdin_write.as_raw_handle());
        let mut written: u32 = 0;
        unsafe {
            WriteFile(h, Some(data), Some(&mut written), None)
                .map_err(|e| io::Error::other(format!("WriteFile: {e}")))?;
        }
        if (written as usize) < data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to ConPTY stdin",
            ));
        }
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let h = HANDLE(self.stdout_read.as_raw_handle());
        let mut read: u32 = 0;
        unsafe {
            ReadFile(h, Some(buf), Some(&mut read), None)
                .map_err(|e| io::Error::other(format!("ReadFile: {e}")))?;
        }
        Ok(read as usize)
    }

    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        let size = COORD {
            X: cols as i16,
            Y: rows as i16,
        };
        unsafe {
            ResizePseudoConsole(self.hpcon, size)
                .map_err(|e| io::Error::other(format!("ResizePseudoConsole: {e}")))?;
        }
        Ok(())
    }

    fn kill(&mut self) -> io::Result<()> {
        unsafe {
            ClosePseudoConsole(self.hpcon);
        }
        Ok(())
    }

    fn wait(&mut self) -> io::Result<i32> {
        unsafe {
            WaitForSingleObject(self.process, INFINITE);
            let mut code: u32 = 0;
            let _ = GetExitCodeProcess(self.process, &mut code);
            Ok(code as i32)
        }
    }
}

impl Drop for ConPty {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST(
                self.attr_buffer.as_mut_ptr() as *mut _,
            ));
            let _ = CloseHandle(self.process);
            let _ = CloseHandle(self.thread);
        }
    }
}

fn create_pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut read_h = HANDLE::default();
    let mut write_h = HANDLE::default();
    unsafe {
        CreatePipe(&mut read_h, &mut write_h, None, 0)
            .map_err(|e| io::Error::other(format!("CreatePipe: {e}")))?;
    }
    let r = unsafe { OwnedHandle::from_raw_handle(read_h.0 as RawHandle) };
    let w = unsafe { OwnedHandle::from_raw_handle(write_h.0 as RawHandle) };
    Ok((r, w))
}

fn build_cmdline(shell: &str, args: &[String]) -> Vec<u16> {
    let mut s = shell.to_string();
    for a in args {
        s.push(' ');
        s.push_str(a);
    }
    let h: HSTRING = (&s).into();
    let mut v: Vec<u16> = h.as_wide().to_vec();
    v.push(0);
    v
}
