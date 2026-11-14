// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Large pages for a jailed Firecracker's guest memory (`huge_pages`).
//!
//! A jailed process cannot map large pages itself: its token is below
//! medium integrity, where no privilege can be enabled ("Lock pages in
//! memory" read back disabled after `AdjustTokenPrivileges` reported
//! success; measured on Windows 11 26H2). A process without the privilege at
//! the jail's integrity level can map a pagefile-backed large-page section
//! another process made, and gets large pages so (measured). So the jailer,
//! which runs with the operator's token and holds the privilege, makes them:
//! Firecracker's libc layer (`windows_mm`, `Broker`) asks for a section of a
//! size over a pipe, the jailer makes it (`SEC_COMMIT | SEC_LARGE_PAGES`),
//! duplicates it into Firecracker and answers with its handle there.
//!
//! As on Linux, where huge pages come from a pool an administrator reserved
//! and the hugetlb controller limits them (not `memory.max`), the sections
//! are not charged to the jail's job nor to the jailer's count of the jail's
//! memory (`commit`, which takes the bytes given off), and the jailer refuses
//! past the jail's `hugetlb.2MB.max` (the sizes it gave, in all). That limit is the pool:
//! Windows has no pool an administrator reserved, so large pages are taken
//! from the host's free physical memory, not pageable and outside the job's
//! memory limit, and a jail without a `hugetlb.2MB.max` gets no broker (a
//! VMM that an escape took over could otherwise take every large page the
//! host has). Without the limit or the privilege the jailer offers nothing,
//! and Firecracker refuses large pages naming the cause.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{
    DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_COMMITMENT_LIMIT, GetLastError, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE, SEC_COMMIT, SEC_LARGE_PAGES};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Names the pipes to Firecracker: `<request>,<reply>` (handle values).
pub(super) const ENV: &str = "WICK_LARGE_PAGES";

/// The broker's two pipes, before Firecracker runs.
pub(super) struct Broker {
    /// Firecracker writes requests to it; the jailer reads them.
    request_read: OwnedHandle,
    request_write: OwnedHandle,
    /// The jailer writes replies to it; Firecracker reads them.
    reply_read: OwnedHandle,
    reply_write: OwnedHandle,
    limit: Option<u64>,
    /// The bytes given so far, which the jailer's count of the jail's
    /// memory takes off its section commit (`commit`).
    given: Arc<AtomicU64>,
}

/// Whether this process may make large-page sections: its token holds
/// "Lock pages in memory", enabled now.
fn privilege() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NOT_ALL_ASSIGNED};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: our own token.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    // SAFETY: plain data.
    let mut tp: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    let name: Vec<u16> = "SeLockMemoryPrivilege\0".encode_utf16().collect();
    // SAFETY: a NUL-terminated name, our token and one privilege.
    let ok = unsafe {
        LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut tp.Privileges[0].Luid) != 0
            && AdjustTokenPrivileges(token, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0
            // It succeeds without the privilege, and says so.
            && GetLastError() != ERROR_NOT_ALL_ASSIGNED
    };
    // SAFETY: the token we opened.
    unsafe { CloseHandle(token) };
    ok
}

fn pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 0,
    };
    let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: out-parameters.
    if unsafe { CreatePipe(&mut r, &mut w, &sa, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the handles just made.
    Ok(unsafe { (OwnedHandle::from_raw_handle(r), OwnedHandle::from_raw_handle(w)) })
}

fn inheritable(h: &OwnedHandle) -> io::Result<()> {
    // SAFETY: a handle we own.
    if unsafe { SetHandleInformation(h.as_raw_handle(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl Broker {
    /// The broker, if the jail has a large-page limit (`limit`: the bytes it
    /// gives in all, from `hugetlb.2MB.max`) and this process can make
    /// large-page sections; none without the limit (module documentation).
    pub(super) fn new(limit: Option<u64>) -> io::Result<Option<Broker>> {
        if limit.is_none_or(|l| l == 0) || !privilege() {
            return Ok(None);
        }
        let (request_read, request_write) = pipe()?;
        let (reply_read, reply_write) = pipe()?;
        // Firecracker's ends only.
        inheritable(&request_write)?;
        inheritable(&reply_read)?;
        Ok(Some(Broker { request_read, request_write, reply_read, reply_write, limit, given: Arc::default() }))
    }

    /// The value of [`ENV`] for Firecracker.
    pub(super) fn child_value(&self) -> String {
        format!("{},{}", self.request_write.as_raw_handle() as usize, self.reply_read.as_raw_handle() as usize)
    }

    /// The bytes given so far: counted before a section reaches
    /// Firecracker, and given back if it does not.
    pub(super) fn given(&self) -> Arc<AtomicU64> {
        self.given.clone()
    }

    /// The handles Firecracker inherits.
    pub(super) fn child_handles(&self) -> [HANDLE; 2] {
        [self.request_write.as_raw_handle(), self.reply_read.as_raw_handle()]
    }

    /// Serves Firecracker (`process`, which the jailer may duplicate handles
    /// into) until it closes its end. Firecracker's ends are closed here: it
    /// has its own.
    pub(super) fn serve(self, process: HANDLE) -> JoinHandle<()> {
        let Broker { request_read, request_write, reply_read, reply_write, limit, given } = self;
        drop((request_write, reply_read));
        let process = process as usize;
        std::thread::spawn(move || {
            loop {
                let mut request = [0u8; 8];
                let mut n = 0u32;
                // SAFETY: reads into our buffer.
                let ok = unsafe {
                    ReadFile(request_read.as_raw_handle(), request.as_mut_ptr(), 8, &mut n, std::ptr::null_mut())
                };
                if ok == 0 || n != 8 {
                    // Firecracker ended.
                    return;
                }
                let len = u64::from_le_bytes(request);
                // Counted as given before Firecracker holds it, so that the
                // jail's count never sees it as a section of its own.
                let before = given.fetch_add(len, Ordering::AcqRel);
                let (handle, err) = match section(len, before, limit, process as HANDLE) {
                    Ok(h) => (h, 0),
                    Err(e) => {
                        given.fetch_sub(len, Ordering::AcqRel);
                        (0, e)
                    }
                };
                let mut reply = [0u8; 12];
                reply[..8].copy_from_slice(&handle.to_le_bytes());
                reply[8..].copy_from_slice(&err.to_le_bytes());
                // SAFETY: writes our buffer.
                if unsafe { WriteFile(reply_write.as_raw_handle(), reply.as_ptr(), 12, &mut n, std::ptr::null_mut()) } == 0 {
                    return;
                }
            }
        })
    }
}

/// A large-page section of `len` bytes, duplicated into `process`: its
/// handle value there, or the Windows error. `given`: the bytes given so
/// far, against `limit`.
fn section(len: u64, given: u64, limit: Option<u64>, process: HANDLE) -> Result<u64, u32> {
    if limit.is_some_and(|l| given.saturating_add(len) > l) {
        return Err(ERROR_COMMITMENT_LIMIT);
    }
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: a pagefile-backed section; the privilege is enabled.
    let s = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            std::ptr::null(),
            PAGE_READWRITE | SEC_COMMIT | SEC_LARGE_PAGES,
            (len >> 32) as u32,
            len as u32,
            std::ptr::null(),
        )
    };
    if s.is_null() {
        // SAFETY: plain call.
        return Err(unsafe { GetLastError() });
    }
    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: moves our section's handle into Firecracker.
    if unsafe {
        DuplicateHandle(GetCurrentProcess(), s, process, &mut out, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)
    } == 0
    {
        // SAFETY: plain call.
        return Err(unsafe { GetLastError() });
    }
    Ok(out as usize as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    // No limit, no broker: without hugetlb.2MB.max a jail gets no large
    // pages from the jailer.
    #[test]
    fn test_no_broker_without_a_limit() {
        assert!(Broker::new(None).unwrap().is_none());
        assert!(Broker::new(Some(0)).unwrap().is_none());
    }

    // The limit is the bytes given in all: a request past it is refused
    // before a section is made.
    #[test]
    fn test_section_refused_past_the_limit() {
        // SAFETY: plain call.
        let me = unsafe { GetCurrentProcess() };
        assert_eq!(section(4 << 20, 2 << 20, Some(4 << 20), me), Err(ERROR_COMMITMENT_LIMIT));
        if privilege() {
            let h = section(2 << 20, 2 << 20, Some(4 << 20), me).expect("a section within the limit");
            // SAFETY: the handle duplicated into this process, ours to close.
            drop(unsafe { OwnedHandle::from_raw_handle(h as usize as HANDLE) });
        }
    }
}
