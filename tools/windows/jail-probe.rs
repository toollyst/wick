// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What a process can reach, for tools/windows/jailer-test.ps1. Run through
//! the jailer as the jailed binary, it takes the jail over as Firecracker
//! does (`RevertToSelf` first); with `low` first it starts itself again as a
//! plain low-integrity process of the user.
//!
//! ```text
//! jail-probe [low] <check>...   check: read:<path> write:<path>
//!                               open:<pid> connect:<socket path>
//! ```
//!
//! Prints one line per check: `<check> allowed` or `<check> denied <error>`.
//! No dependencies: `rustc -O jail-probe.rs` builds it.

#![allow(non_snake_case, clippy::upper_case_acronyms)]

use std::ffi::c_void;
use std::io::{Read, Write};

/// `vmm::ext::jail::HANDOVER_MARK`: the jailer starts only binaries that
/// carry it, those that take the jail over.
#[used]
static HANDOVER_MARK: [u8; 22] = *b"wick-jail-handover:v1\0";

type HANDLE = *mut c_void;

#[repr(C)]
struct STARTUPINFOW {
    cb: u32,
    rest: [usize; 12],
}

#[repr(C)]
struct PROCESS_INFORMATION {
    process: HANDLE,
    thread: HANDLE,
    pid: u32,
    tid: u32,
}

#[repr(C)]
struct SID_AND_ATTRIBUTES {
    sid: *mut c_void,
    attributes: u32,
}

#[link(name = "advapi32")]
extern "system" {
    fn RevertToSelf() -> i32;
    fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> i32;
    fn DuplicateTokenEx(t: HANDLE, access: u32, sa: *const c_void, level: i32, ty: i32, out: *mut HANDLE) -> i32;
    fn ConvertStringSidToSidW(s: *const u16, sid: *mut *mut c_void) -> i32;
    fn GetLengthSid(sid: *mut c_void) -> u32;
    fn SetTokenInformation(t: HANDLE, class: i32, info: *const c_void, len: u32) -> i32;
    fn CreateProcessAsUserW(
        token: HANDLE,
        app: *const u16,
        cmd: *mut u16,
        pa: *const c_void,
        ta: *const c_void,
        inherit: i32,
        flags: u32,
        env: *const c_void,
        cwd: *const u16,
        si: *const STARTUPINFOW,
        pi: *mut PROCESS_INFORMATION,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> HANDLE;
    fn CloseHandle(h: HANDLE) -> i32;
    fn GetCurrentProcess() -> HANDLE;
    fn GetLastError() -> u32;
    fn WaitForSingleObject(h: HANDLE, ms: u32) -> u32;
    fn GetExitCodeProcess(h: HANDLE, code: *mut u32) -> i32;
}

#[link(name = "ws2_32")]
extern "system" {
    fn WSAStartup(version: u16, data: *mut u8) -> i32;
    fn socket(af: i32, ty: i32, proto: i32) -> usize;
    fn connect(s: usize, addr: *const u8, len: i32) -> i32;
    fn closesocket(s: usize) -> i32;
    fn WSAGetLastError() -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn check(c: &str) -> String {
    let Some((kind, arg)) = c.split_once(':') else {
        return "unknown check".into();
    };
    let io = |r: std::io::Result<()>| match r {
        Ok(()) => "allowed".to_string(),
        Err(e) => format!("denied {e}"),
    };
    match kind {
        "read" => io(std::fs::File::open(arg).and_then(|mut f| f.read(&mut [0u8; 1]).map(drop))),
        "write" => io(std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(arg)
            .and_then(|mut f| f.write_all(b"x"))),
        "open" => {
            let Ok(pid) = arg.parse() else {
                return "bad pid".into();
            };
            // PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
            // SAFETY: plain call.
            let h = unsafe { OpenProcess(0x0010 | 0x0400, 0, pid) };
            if h.is_null() {
                // SAFETY: plain call.
                return format!("denied {}", std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32));
            }
            // SAFETY: the handle just opened.
            unsafe { CloseHandle(h) };
            "allowed".into()
        }
        "connect" => {
            let mut data = [0u8; 512];
            // SAFETY: room for WSADATA; then plain socket calls.
            unsafe {
                WSAStartup(0x0202, data.as_mut_ptr());
                let s = socket(1, 1, 0); // AF_UNIX, SOCK_STREAM
                if s == usize::MAX {
                    return format!("denied socket {}", WSAGetLastError());
                }
                let mut addr = [0u8; 110];
                addr[0] = 1;
                let path = arg.as_bytes();
                let n = path.len().min(107);
                addr[2..2 + n].copy_from_slice(&path[..n]);
                let rc = connect(s, addr.as_ptr(), addr.len() as i32);
                let e = WSAGetLastError();
                closesocket(s);
                if rc == 0 {
                    "allowed".into()
                } else {
                    format!("denied {}", std::io::Error::from_raw_os_error(e))
                }
            }
        }
        _ => "unknown check".into(),
    }
}

/// Starts this program again, with `checks`, as the user at low integrity.
fn low(checks: &[String]) -> std::io::Result<u32> {
    let fail = || Err(std::io::Error::last_os_error());
    let mut t = std::ptr::null_mut();
    let mut dup = std::ptr::null_mut();
    let mut sid = std::ptr::null_mut();
    // SAFETY: out-pointers; our own token.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), 0x000F_01FF, &mut t) == 0
            || DuplicateTokenEx(t, 0x000F_01FF, std::ptr::null(), 2, 1, &mut dup) == 0
            || ConvertStringSidToSidW(wide("S-1-16-4096").as_ptr(), &mut sid) == 0
        {
            return fail();
        }
        let label = SID_AND_ATTRIBUTES { sid, attributes: 0x20 }; // SE_GROUP_INTEGRITY
        let len = std::mem::size_of::<SID_AND_ATTRIBUTES>() as u32 + GetLengthSid(sid);
        if SetTokenInformation(dup, 25, (&raw const label).cast(), len) == 0 {
            return fail();
        }
        let exe = std::env::current_exe()?;
        let mut cmd = format!("\"{}\"", exe.display());
        for c in checks {
            cmd.push_str(&format!(" \"{c}\""));
        }
        let mut cmd = wide(&cmd);
        let si = STARTUPINFOW { cb: std::mem::size_of::<STARTUPINFOW>() as u32, rest: [0; 12] };
        let mut pi = PROCESS_INFORMATION { process: std::ptr::null_mut(), thread: std::ptr::null_mut(), pid: 0, tid: 0 };
        if CreateProcessAsUserW(
            dup,
            std::ptr::null(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            0,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        ) == 0
        {
            return fail();
        }
        WaitForSingleObject(pi.process, 60_000);
        let mut code = 0;
        GetExitCodeProcess(pi.process, &mut code);
        Ok(code)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("low") {
        match low(&args[1..]) {
            Ok(code) => std::process::exit(code as i32),
            Err(e) => {
                eprintln!("low: {e}");
                std::process::exit(1);
            }
        }
    }
    // Firecracker's first step in a jail (vmm::ext::jail): drop the initial
    // impersonation token. Outside a jail it does nothing.
    // SAFETY: plain call.
    unsafe { RevertToSelf() };
    std::hint::black_box(&HANDOVER_MARK);
    for c in &args {
        println!("{c} {}", check(c));
    }
}
