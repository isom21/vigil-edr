//! Windows memory reader (Phase 2 #2.1).
//!
//! Opens the target process with PROCESS_QUERY_INFORMATION |
//! PROCESS_VM_READ, walks its address space with `VirtualQueryEx`, and
//! reads each committed, non-guard region via `ReadProcessMemory`. The
//! walker yields one [`MemoryRegion`] per
//! `MEMORY_BASIC_INFORMATION` whose State == MEM_COMMIT and whose
//! Protect doesn't include PAGE_GUARD / PAGE_NOACCESS.
//!
//! Image-backed regions (DLLs / EXEs) carry an "Image:<size>" name so
//! analysts can see at a glance which regions overlap a module. The
//! actual path resolution would need `GetMappedFileNameW` which we
//! skip here — a follow-up can enrich the artifact metadata.

#[cfg(windows)]
use agent_core::scanner::MemoryRegion;
use agent_core::scanner::MemoryRegionReader;
use anyhow::Result;

#[cfg(windows)]
pub use win_impl::open;
#[cfg(windows)]
pub use win_impl::WindowsMemoryReader;

/// Non-Windows fallback factory — exists so cross-platform consumers
/// can name `open` unconditionally. Returns an error at call time so
/// any path that wires the Windows reader into agent-linux fails
/// loudly rather than silently no-op'ing the scan.
#[cfg(not(windows))]
#[allow(dead_code)]
pub fn open(_pid: u32) -> Result<Box<dyn MemoryRegionReader + Send + 'static>> {
    Err(anyhow::anyhow!(
        "windows memory reader unavailable on this platform"
    ))
}

#[cfg(windows)]
mod win_impl {
    use super::*;
    use anyhow::{anyhow, Context};
    use std::mem::{size_of, MaybeUninit};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
        PAGE_GUARD, PAGE_NOACCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    pub struct WindowsMemoryReader {
        handle: HANDLE,
        cursor: usize,
    }

    impl WindowsMemoryReader {
        pub fn open(pid: u32) -> Result<Self> {
            // SAFETY: OpenProcess returns an owned HANDLE; CloseHandle
            // on Drop releases it. The handle is single-owner.
            let handle =
                unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
                    .with_context(|| format!("OpenProcess pid={pid}"))?;
            if handle.is_invalid() {
                return Err(anyhow!("OpenProcess pid={pid} returned invalid handle"));
            }
            Ok(Self { handle, cursor: 0 })
        }
    }

    impl Drop for WindowsMemoryReader {
        fn drop(&mut self) {
            // SAFETY: handle is the value we received from OpenProcess
            // and haven't given out; closing once is correct.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }

    impl MemoryRegionReader for WindowsMemoryReader {
        fn next_region(&mut self) -> Result<Option<MemoryRegion>> {
            loop {
                let mut mbi = MaybeUninit::<MEMORY_BASIC_INFORMATION>::zeroed();
                let written = unsafe {
                    VirtualQueryEx(
                        self.handle,
                        Some(self.cursor as *const _),
                        mbi.as_mut_ptr(),
                        size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };
                if written == 0 {
                    return Ok(None);
                }
                let mbi = unsafe { mbi.assume_init() };
                let base = mbi.BaseAddress as usize;
                let region_size = mbi.RegionSize;
                self.cursor = base.saturating_add(region_size);
                if region_size == 0 {
                    return Ok(None);
                }
                if mbi.State != MEM_COMMIT {
                    continue;
                }
                if mbi.Protect.0 & (PAGE_GUARD.0 | PAGE_NOACCESS.0) != 0 {
                    continue;
                }
                // Tag the region so the artifact distinguishes
                // image-backed mappings from heap / private anon.
                let name = if mbi.Type == MEM_IMAGE {
                    format!("Image:{region_size:#x}")
                } else if mbi.Type == MEM_MAPPED {
                    format!("Mapped:{region_size:#x}")
                } else if mbi.Type == MEM_PRIVATE {
                    String::new()
                } else {
                    String::new()
                };

                let mut buf = vec![0u8; region_size];
                let mut bytes_read = 0usize;
                let read_ok = unsafe {
                    ReadProcessMemory(
                        self.handle,
                        base as *const _,
                        buf.as_mut_ptr().cast(),
                        region_size,
                        Some(&mut bytes_read),
                    )
                }
                .is_ok();
                if !read_ok || bytes_read == 0 {
                    // Skip regions that refused the read (e.g. mapped
                    // sections that race with unmap). Falling through
                    // to the next region keeps the scan progressing.
                    tracing::debug!(
                        addr = base,
                        size = region_size,
                        "scanner_memory.read_process_memory_failed"
                    );
                    continue;
                }
                buf.truncate(bytes_read);
                return Ok(Some(MemoryRegion {
                    addr: base as u64,
                    bytes: buf,
                    name,
                }));
            }
        }
    }

    pub fn open(pid: u32) -> Result<Box<dyn MemoryRegionReader + Send + 'static>> {
        Ok(Box::new(WindowsMemoryReader::open(pid)?))
    }
}
