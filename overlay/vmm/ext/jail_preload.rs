// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What a jailed process on Windows loads and reads before it reverts to the
//! jail's lockdown token (`vmm::ext::jail`), as Chromium's sandbox warms up
//! before it locks down.
//!
//! Firecracker starts on the jail's lockdown token with an initial
//! impersonation token on its main thread, which may read what the four
//! session groups, the logon SID and the user's SID are granted, and
//! reverts to the lockdown token first thing in `main`. What Windows loads
//! or reads lazily after that is checked against the lockdown token only.
//! Each step below is something Firecracker or its API process does later,
//! done once now, so that the DLL, registry key or message file stays loaded
//! or cached: each was found by a kernel trace of a jail whose lockdown token
//! held the jail's SID alone (fix (i) step 1 on Windows Server 2022 20348,
//! docs/windows-jail-reach.md), as an open denied after the revert:
//!
//! - `winsock`: `WSAStartup` and an `AF_UNIX` stream socket (Winsock's
//!   catalogue keys, `mswsock.dll`, `wshunix.dll`);
//! - `winsock-import`: a socket made from another's `WSAPROTOCOL_INFOW`, as
//!   the API process makes its listener from the one Firecracker passes,
//!   and its `SO_TYPE` read, as the epoll registration asks (`mswsock.dll`
//!   again, opened by that path only, and not after the revert, where
//!   `WSADuplicateSocketW` fails with 10022);
//! - `winsock-catalog`: `WSAEnumProtocolsW` (the providers' display strings,
//!   `mswsock.dll.mui` and `wshqos.dll.mui`);
//! - `message-text`: `FormatMessageW` of a system error, as Rust's
//!   `io::Error` renders one (`KernelBase.dll.mui`; else every OS error's
//!   text is "FormatMessageW() returned error 15100");
//! - `time-zone`: the C runtime's `localtime_s` (the zone's names from
//!   `tzres.dll`; else they read "@tzres.dll,-212");
//! - `kernel.appcore.dll`, which the process loads when it exits.
//!
//! Every step that fails is an error naming it, with the system's text for
//! its code rendered here, before the revert, so that showing it later needs
//! no message file. Nothing is skipped: a jail that could not be prepared
//! does not run.
//!
//! Shared by Firecracker (`vmm::ext::jail`) and tools/windows/jail-probe.rs,
//! which includes this file by its path: the standard library and system
//! calls only.

use std::ffi::c_void;
use std::fmt;

/// A step of [`preload`] that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreloadError {
    /// The step's name ([`STEPS`]).
    pub(crate) step: &'static str,
    /// The system's error code (a Win32 or Winsock error), or the C
    /// runtime's `errno` for `time-zone`.
    pub(crate) code: u32,
    /// What the code means, rendered when the step failed.
    pub(crate) text: String,
}

impl fmt::Display for PreloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Failed to prepare the jail ({}) before it locks down: {} (os error {})",
            self.step, self.text, self.code
        )
    }
}

/// The steps, in the order [`preload`] takes them.
pub(crate) const STEPS: [&str; 6] = [
    "winsock",
    "winsock-import",
    "winsock-catalog",
    "message-text",
    "time-zone",
    "kernel.appcore.dll",
];

#[link(name = "kernel32")]
unsafe extern "system" {
    fn FormatMessageW(
        flags: u32,
        source: *const c_void,
        id: u32,
        lang: u32,
        buf: *mut u16,
        size: u32,
        args: *const c_void,
    ) -> u32;
    fn GetLastError() -> u32;
    fn GetCurrentProcessId() -> u32;
    fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut u8) -> i32;
    fn WSAGetLastError() -> i32;
    fn socket(af: i32, ty: i32, protocol: i32) -> usize;
    fn closesocket(s: usize) -> i32;
    fn WSADuplicateSocketW(s: usize, pid: u32, info: *mut u8) -> i32;
    fn WSASocketW(af: i32, ty: i32, protocol: i32, info: *const u8, group: u32, flags: u32) -> usize;
    fn getsockopt(s: usize, level: i32, name: i32, value: *mut u8, len: *mut i32) -> i32;
    fn WSAEnumProtocolsW(protocols: *const i32, buf: *mut u8, len: *mut u32) -> i32;
}

/// The C runtime's `struct tm`.
#[repr(C)]
#[derive(Default)]
struct Tm([i32; 9]);

unsafe extern "C" {
    /// `localtime_s` (time.h): the C runtime's `localtime_s` is this, inline.
    fn _localtime64_s(tm: *mut Tm, time: *const i64) -> i32;
}

const AF_UNIX: i32 = 1;
const SOCK_STREAM: i32 = 1;
const INVALID_SOCKET: usize = usize::MAX;
/// `FROM_PROTOCOL_INFO` (winsock2.h).
const FROM_PROTOCOL_INFO: i32 = -1;
const SOL_SOCKET: i32 = 0xffff;
const SO_TYPE: i32 = 0x1008;
/// `sizeof(WSAPROTOCOL_INFOW)`.
const PROTOCOL_INFO_LEN: usize = 628;
/// `WSAENOBUFS`.
const WSAENOBUFS: u32 = 10055;
/// `FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS`.
const FROM_SYSTEM: u32 = 0x1000 | 0x200;
/// `MAKELANGID(LANG_NEUTRAL, SUBLANG_SYS_DEFAULT)`, the language Rust's
/// standard library asks `FormatMessageW` for (`std::sys::pal::windows::os`).
const SYS_DEFAULT_LANG: u32 = 0x0800;
/// `LOAD_LIBRARY_SEARCH_SYSTEM32`.
const SEARCH_SYSTEM32: u32 = 0x800;
/// `ERROR_FILE_NOT_FOUND`, the message `message-text` renders.
const ERROR_FILE_NOT_FOUND: u32 = 2;

/// The system's text for `code`, as Rust's `io::Error` renders it, or why
/// there is none.
pub(crate) fn message(code: u32) -> String {
    let mut buf = [0u16; 512];
    // SAFETY: a buffer of 512 UTF-16 units, its size passed; no inserts.
    let n = unsafe {
        FormatMessageW(
            FROM_SYSTEM,
            std::ptr::null(),
            code,
            SYS_DEFAULT_LANG,
            buf.as_mut_ptr(),
            512,
            std::ptr::null(),
        )
    };
    if n == 0 {
        // SAFETY: plain call.
        let err = unsafe { GetLastError() };
        return format!("no text for this code (FormatMessageW failed with {err})");
    }
    let len = usize::try_from(n).map_or(buf.len(), |n| n.min(buf.len()));
    String::from_utf16_lossy(&buf[..len]).trim_end().to_string()
}

fn failed(step: &'static str, code: u32) -> PreloadError {
    PreloadError { step, code, text: message(code) }
}

fn winsock_error(step: &'static str) -> PreloadError {
    // SAFETY: plain call.
    let code = unsafe { WSAGetLastError() };
    failed(step, u32::try_from(code).unwrap_or(0))
}

/// Takes each of [`STEPS`] in order; the first that fails is the error.
pub(crate) fn preload() -> Result<(), PreloadError> {
    winsock()?;
    winsock_import()?;
    winsock_catalog()?;
    message_text()?;
    time_zone()?;
    appcore()
}

/// `winsock`: Winsock started (it stays started) and an `AF_UNIX` stream
/// socket made and closed.
fn winsock() -> Result<(), PreloadError> {
    const STEP: &str = STEPS[0];
    let mut data = [0u8; 512];
    // SAFETY: a buffer larger than WSADATA.
    let r = unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
    if r != 0 {
        return Err(failed(STEP, u32::try_from(r).unwrap_or(0)));
    }
    // SAFETY: plain call.
    let s = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
    if s == INVALID_SOCKET {
        return Err(winsock_error(STEP));
    }
    // SAFETY: the socket just made.
    unsafe { closesocket(s) };
    Ok(())
}

/// `winsock-import`: an `AF_UNIX` socket duplicated to this process through
/// its `WSAPROTOCOL_INFOW`, made again from it, and its `SO_TYPE` read.
fn winsock_import() -> Result<(), PreloadError> {
    const STEP: &str = STEPS[1];
    // SAFETY: plain call.
    let s = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
    if s == INVALID_SOCKET {
        return Err(winsock_error(STEP));
    }
    let result = import_from(s, STEP);
    // SAFETY: the socket made above.
    unsafe { closesocket(s) };
    result
}

/// `winsock-import`'s socket `s` duplicated to this process and made again
/// from its protocol information, and that socket's `SO_TYPE` read.
fn import_from(s: usize, step: &'static str) -> Result<(), PreloadError> {
    let mut info = [0u8; PROTOCOL_INFO_LEN];
    // SAFETY: our socket, our own pid, a WSAPROTOCOL_INFOW-sized buffer.
    if unsafe { WSADuplicateSocketW(s, GetCurrentProcessId(), info.as_mut_ptr()) } != 0 {
        return Err(winsock_error(step));
    }
    // SAFETY: the protocol information just written.
    let t = unsafe {
        WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, info.as_ptr(), 0, 0)
    };
    if t == INVALID_SOCKET {
        return Err(winsock_error(step));
    }
    let mut ty = [0u8; 4];
    let mut len = 4i32;
    // SAFETY: an int-sized value and its length.
    let r = unsafe { getsockopt(t, SOL_SOCKET, SO_TYPE, ty.as_mut_ptr(), &mut len) };
    let r = if r == 0 { Ok(()) } else { Err(winsock_error(step)) };
    // SAFETY: the socket made from the information.
    unsafe { closesocket(t) };
    r
}

/// `winsock-catalog`: every protocol of Winsock's catalogue enumerated.
fn winsock_catalog() -> Result<(), PreloadError> {
    const STEP: &str = STEPS[2];
    let mut len = 16_384u32;
    loop {
        let mut buf = vec![0u8; len as usize];
        // SAFETY: a buffer of `len` bytes.
        if unsafe { WSAEnumProtocolsW(std::ptr::null(), buf.as_mut_ptr(), &mut len) } >= 0 {
            return Ok(());
        }
        let err = winsock_error(STEP);
        if err.code != WSAENOBUFS || len as usize <= buf.len() {
            return Err(err);
        }
    }
}

/// `message-text`: a system error's text.
fn message_text() -> Result<(), PreloadError> {
    let mut buf = [0u16; 256];
    // SAFETY: a buffer of 256 UTF-16 units, its size passed; no inserts.
    let n = unsafe {
        FormatMessageW(
            FROM_SYSTEM,
            std::ptr::null(),
            ERROR_FILE_NOT_FOUND,
            SYS_DEFAULT_LANG,
            buf.as_mut_ptr(),
            256,
            std::ptr::null(),
        )
    };
    if n == 0 {
        // SAFETY: plain call.
        let code = unsafe { GetLastError() };
        return Err(PreloadError {
            step: STEPS[3],
            code,
            text: "the system's error messages cannot be read".to_string(),
        });
    }
    Ok(())
}

/// `time-zone`: the C runtime's local time of now, which reads the zone.
fn time_zone() -> Result<(), PreloadError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let mut tm = Tm::default();
    // SAFETY: a `struct tm` and a time to read.
    let e = unsafe { _localtime64_s(&mut tm, &now) };
    if e != 0 {
        return Err(PreloadError {
            step: STEPS[4],
            code: u32::try_from(e).unwrap_or(0),
            text: format!("the C runtime's localtime_s failed with errno {e}"),
        });
    }
    Ok(())
}

/// `kernel.appcore.dll`: loaded from System32, and kept.
fn appcore() -> Result<(), PreloadError> {
    let name: Vec<u16> = STEPS[5].encode_utf16().chain([0]).collect();
    // SAFETY: a NUL-terminated name; only System32 is searched.
    let h = unsafe { LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), SEARCH_SYSTEM32) };
    if h.is_null() {
        // SAFETY: plain call.
        return Err(failed(STEPS[5], unsafe { GetLastError() }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preload_takes_every_step_in_a_plain_process() {
        // Outside a jail every step works: what fails in a jail is the
        // jail's token, which the jailer-test stages exercise.
        preload().unwrap();
        // Twice, as a process that preloads and later does the same.
        preload().unwrap();
    }

    #[test]
    fn test_a_failed_step_is_named_with_its_code_and_text() {
        let err = failed("winsock", 10093);
        assert_eq!(err.step, "winsock");
        assert_eq!(err.code, 10093);
        assert!(!err.text.is_empty() && !err.text.starts_with("no text"), "{err:?}");
        let line = err.to_string();
        assert!(line.starts_with("Failed to prepare the jail (winsock) before it locks down: "), "{line}");
        assert!(line.ends_with("(os error 10093)"), "{line}");
        // The text is the one Rust's io::Error gives for the code.
        let std_text = std::io::Error::from_raw_os_error(10093).to_string();
        assert!(std_text.starts_with(&err.text), "{std_text:?} vs {:?}", err.text);
    }

    #[test]
    fn test_a_code_without_text_says_so() {
        // 0x2000_0000: the customer bit, which no system message has.
        let text = message(0x2000_0000 | 12345);
        assert!(text.starts_with("no text for this code"), "{text}");
    }
}
