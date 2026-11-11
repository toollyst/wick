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
//!                               handle:<value> signal:<pid> thread:<pid>
//!                               see:<pid> ctrl:<process group> procs:0
//!                               wait:<seconds> console:0 tty:<file>
//!                               attach:<pid> inject:0 echo:<file>
//!                               job:0 affinity:0 spin:<seconds>
//! (<pid> may be `parent`: in a jail, the jailer.)
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
    reserved: [*mut u16; 3],
    geometry: [u32; 7],
    flags: u32,
    show_window: u16,
    reserved2_len: u16,
    reserved2: *mut u8,
    stdin: HANDLE,
    stdout: HANDLE,
    stderr: HANDLE,
}

/// `STARTF_USESTDHANDLES`.
const USE_STD_HANDLES: u32 = 0x100;

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
    fn GetStdHandle(which: u32) -> HANDLE;
    fn SetHandleInformation(h: HANDLE, mask: u32, flags: u32) -> i32;
    fn WaitForSingleObject(h: HANDLE, ms: u32) -> u32;
    fn GetExitCodeProcess(h: HANDLE, code: *mut u32) -> i32;
    fn ReadFile(h: HANDLE, buf: *mut u8, n: u32, read: *mut u32, ov: *mut c_void) -> i32;
    fn SetFilePointer(h: HANDLE, lo: i32, hi: *mut i32, from: u32) -> u32;
    fn GetFileType(h: HANDLE) -> u32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> HANDLE;
    fn Process32FirstW(snap: HANDLE, entry: *mut PROCESSENTRY32W) -> i32;
    fn Process32NextW(snap: HANDLE, entry: *mut PROCESSENTRY32W) -> i32;
    fn Thread32First(snap: HANDLE, entry: *mut THREADENTRY32) -> i32;
    fn Thread32Next(snap: HANDLE, entry: *mut THREADENTRY32) -> i32;
    fn OpenThread(access: u32, inherit: i32, tid: u32) -> HANDLE;
    fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
    fn K32EnumProcesses(pids: *mut u32, bytes: u32, needed: *mut u32) -> i32;
    fn FreeConsole() -> i32;
    fn AttachConsole(pid: u32) -> i32;
    fn GetConsoleWindow() -> HANDLE;
    fn GetConsoleMode(h: HANDLE, mode: *mut u32) -> i32;
    fn SetConsoleMode(h: HANDLE, mode: u32) -> i32;
    fn GetNumberOfConsoleInputEvents(h: HANDLE, n: *mut u32) -> i32;
    fn WriteConsoleInputW(h: HANDLE, recs: *const KEY_RECORD, n: u32, written: *mut u32) -> i32;
    fn WriteFile(h: HANDLE, buf: *const u8, n: u32, written: *mut u32, ov: *mut c_void) -> i32;
    fn QueryInformationJobObject(job: HANDLE, class: i32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn GetProcessAffinityMask(p: HANDLE, mine: *mut usize, system: *mut usize) -> i32;
    fn GetProcessTimes(p: HANDLE, c: *mut u64, e: *mut u64, k: *mut u64, u: *mut u64) -> i32;
}

#[repr(C)]
struct PROCESSENTRY32W {
    size: u32,
    usage: u32,
    pid: u32,
    heap: usize,
    module: u32,
    threads: u32,
    parent: u32,
    priority: i32,
    flags: u32,
    exe: [u16; 260],
}

/// An `INPUT_RECORD` holding a `KEY_EVENT_RECORD`.
#[repr(C)]
struct KEY_RECORD {
    event_type: u16,
    key_down: i32,
    repeat: u16,
    vkey: u16,
    vscan: u16,
    ch: u16,
    state: u32,
}

#[repr(C)]
struct THREADENTRY32 {
    size: u32,
    usage: u32,
    tid: u32,
    owner: u32,
    base_priority: i32,
    delta_priority: i32,
    flags: u32,
}

/// The access rights through which one process acts on another, and their
/// names: each is asked for alone, so the answer lists every one granted.
const PROCESS_RIGHTS: [(u32, &str); 11] = [
    (0x0001, "terminate"),
    (0x0002, "create_thread"),
    (0x0008, "vm_operation"),
    (0x0010, "vm_read"),
    (0x0020, "vm_write"),
    (0x0040, "dup_handle"),
    (0x0200, "set_information"),
    (0x0400, "query_information"),
    (0x0800, "suspend_resume"),
    (0x1000, "query_limited_information"),
    (0x0010_0000, "synchronize"),
];
const THREAD_RIGHTS: [(u32, &str); 6] = [
    (0x0001, "terminate"),
    (0x0002, "suspend_resume"),
    (0x0008, "get_context"),
    (0x0010, "set_context"),
    (0x0800, "query_limited_information"),
    (0x0010_0000, "synchronize"),
];

/// `allowed <rights>` for the rights `open` grants, `denied <first error>`
/// if none.
fn rights(open: impl Fn(u32) -> HANDLE, table: &[(u32, &str)]) -> String {
    let mut granted = Vec::new();
    let mut error = None;
    for (right, name) in table {
        let h = open(*right);
        if h.is_null() {
            // SAFETY: plain call.
            error.get_or_insert(unsafe { GetLastError() });
        } else {
            granted.push(*name);
            // SAFETY: the handle just opened.
            unsafe { CloseHandle(h) };
        }
    }
    match (granted.is_empty(), error) {
        (false, _) => format!("allowed {}", granted.join(",")),
        (true, Some(e)) => format!("denied {}", std::io::Error::from_raw_os_error(e as i32)),
        (true, None) => "denied".into(),
    }
}

/// The processes a snapshot shows: (pid, parent, image).
fn processes() -> Result<Vec<(u32, u32, String)>, u32> {
    // TH32CS_SNAPPROCESS
    // SAFETY: plain calls on a snapshot we own; the entry has its size set.
    unsafe {
        let snap = CreateToolhelp32Snapshot(0x2, 0);
        if snap as isize == -1 {
            return Err(GetLastError());
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.size = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut out = Vec::new();
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            let n = e.exe.iter().position(|c| *c == 0).unwrap_or(e.exe.len());
            out.push((e.pid, e.parent, String::from_utf16_lossy(&e.exe[..n])));
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
        Ok(out)
    }
}

/// A pid argument: a number, or `parent` (this process's parent, from a
/// snapshot: in a jail, the jailer).
fn pid_of(arg: &str) -> Option<u32> {
    if arg == "parent" {
        // PROCESS_BASIC_INFORMATION: InheritedFromUniqueProcessId is its 6th
        // word. A jailed process cannot see itself in a snapshot.
        let mut info = [0usize; 6];
        // SAFETY: a buffer of the size passed, on our own process.
        let st = unsafe { NtQueryInformationProcess(GetCurrentProcess(), 0, info.as_mut_ptr(), 48, std::ptr::null_mut()) };
        return (st == 0).then(|| info[5] as u32);
    }
    arg.parse().ok()
}

/// The threads of `pid` a snapshot shows.
fn threads(pid: u32) -> Result<Vec<u32>, u32> {
    // TH32CS_SNAPTHREAD
    // SAFETY: as in `processes`.
    unsafe {
        let snap = CreateToolhelp32Snapshot(0x4, 0);
        if snap as isize == -1 {
            return Err(GetLastError());
        }
        let mut e: THREADENTRY32 = std::mem::zeroed();
        e.size = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut out = Vec::new();
        let mut ok = Thread32First(snap, &mut e);
        while ok != 0 {
            if e.owner == pid {
                out.push(e.tid);
            }
            ok = Thread32Next(snap, &mut e);
        }
        CloseHandle(snap);
        Ok(out)
    }
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(p: HANDLE, class: u32, info: *mut usize, len: u32, ret: *mut u32) -> i32;
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
        // A raw handle value the jailer held (inheritably): if it reached
        // this process it names the same file and reads back its bytes.
        "handle" => {
            let Ok(value) = arg.parse::<isize>() else {
                return "bad handle".into();
            };
            let h = value as HANDLE;
            // FILE_BEGIN; -1 is INVALID_SET_FILE_POINTER.
            // SAFETY: plain calls on a handle value; they fail safely if it is
            // not a file handle of ours.
            unsafe {
                if GetFileType(h) == 0 {
                    return format!("denied {}", std::io::Error::from_raw_os_error(GetLastError() as i32));
                }
                SetFilePointer(h, 0, std::ptr::null_mut(), 0);
                let mut buf = [0u8; 64];
                let mut read = 0u32;
                if ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut read, std::ptr::null_mut()) == 0 {
                    return format!("denied {}", std::io::Error::from_raw_os_error(GetLastError() as i32));
                }
                format!("allowed {}", String::from_utf8_lossy(&buf[..read as usize]))
            }
        }
        // What this process can do to process `pid`: every right granted.
        "signal" => {
            let Some(pid) = pid_of(arg) else {
                return "bad pid".into();
            };
            // SAFETY: plain call.
            rights(|r| unsafe { OpenProcess(r, 0, pid) }, &PROCESS_RIGHTS)
        }
        // The same for the threads of process `pid`.
        "thread" => {
            let Some(pid) = pid_of(arg) else {
                return "bad pid".into();
            };
            let tids = match threads(pid) {
                Ok(t) if t.is_empty() => return "denied no thread of it is visible".into(),
                Ok(t) => t,
                Err(e) => return format!("denied {}", std::io::Error::from_raw_os_error(e as i32)),
            };
            // SAFETY: plain call.
            rights(|r| unsafe { OpenThread(r, 0, tids[0]) }, &THREAD_RIGHTS)
        }
        // Whether process `pid` shows in a process snapshot (Toolhelp) or in
        // EnumProcesses: what this process can learn of it without a handle.
        "see" => {
            let Some(pid) = pid_of(arg) else {
                return "bad pid".into();
            };
            let mut pids = vec![0u32; 4096];
            let mut needed = 0u32;
            // SAFETY: a buffer of the size passed.
            let enumerated = unsafe { K32EnumProcesses(pids.as_mut_ptr(), (pids.len() * 4) as u32, &mut needed) } != 0;
            let enumerated = enumerated && pids[..needed as usize / 4].contains(&pid);
            match processes() {
                Ok(list) => match list.iter().find(|p| p.0 == pid) {
                    Some(p) => format!("allowed {} (parent {}), {} processes visible", p.2, p.1, list.len()),
                    None if enumerated => "allowed by EnumProcesses only".into(),
                    None => format!("denied not among the {} processes visible", list.len()),
                },
                Err(e) if enumerated => format!("allowed by EnumProcesses only (snapshot: {e})"),
                Err(e) => format!("denied {}", std::io::Error::from_raw_os_error(e as i32)),
            }
        }
        // Every process this process can see: the count and the images.
        "procs" => match processes() {
            Ok(list) => {
                // Pid 0 is the idle pseudo-process every snapshot shows.
                let list: Vec<_> = list.into_iter().filter(|p| p.0 != 0 && p.0 != std::process::id()).collect();
                let other = list.len();
                let mut names: Vec<&str> = list.iter().map(|p| p.2.as_str()).collect();
                names.sort_unstable();
                names.dedup();
                if other == 0 {
                    "denied no other process is visible".into()
                } else {
                    format!("allowed {other} others: {}", names.join(","))
                }
            }
            Err(e) => format!("denied {}", std::io::Error::from_raw_os_error(e as i32)),
        },
        // A console control event (CTRL_BREAK_EVENT) to process group `arg`
        // of this process's console: the console delivers it to every process
        // of that group, whoever sent it.
        "ctrl" => {
            let Ok(group) = arg.parse::<u32>() else {
                return "bad group".into();
            };
            // SAFETY: plain call.
            if unsafe { GenerateConsoleCtrlEvent(1, group) } != 0 {
                "allowed".into()
            } else {
                // SAFETY: plain call.
                format!("denied {}", std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32))
            }
        }
        // This process's console: whether it has one with a window, and
        // whether its standard output is a console it can write to.
        "console" => {
            // SAFETY: plain calls on our own standard output.
            unsafe {
                let out = GetStdHandle(-11i32 as u32);
                let mut mode = 0;
                let is_console = GetConsoleMode(out, &mut mode) != 0;
                let mut n = 0;
                let line = b"[jail-probe console write]\r\n";
                let wrote = WriteFile(out, line.as_ptr(), line.len() as u32, &mut n, std::ptr::null_mut()) != 0;
                format!(
                    "{} window {}, stdout console {is_console}, written {wrote}",
                    if wrote { "allowed" } else { "denied" },
                    !GetConsoleWindow().is_null()
                )
            }
        }
        // What Firecracker does with a terminal on its standard handles (the
        // interactive serial console): input mode raw, input events polled,
        // output written. The answer goes to the file `arg`, as standard
        // output is the terminal.
        "tty" => {
            // SAFETY: plain calls on our own standard handles.
            let answer = unsafe {
                let (inp, out) = (GetStdHandle(-10i32 as u32), GetStdHandle(-11i32 as u32));
                let (mut mode, mut events, mut n) = (0u32, 0u32, 0u32);
                let get = GetConsoleMode(inp, &mut mode) != 0;
                let set = get && SetConsoleMode(inp, mode & !0x7) != 0 && SetConsoleMode(inp, mode) != 0;
                let poll = GetNumberOfConsoleInputEvents(inp, &mut events) != 0;
                let line = b"[jail-probe tty write]\r\n";
                let wrote = WriteFile(out, line.as_ptr(), line.len() as u32, &mut n, std::ptr::null_mut()) != 0;
                let ok = get && set && poll && wrote;
                format!(
                    "{} input mode {get}, raw {set}, poll {poll}, output {wrote}, own window {}",
                    if ok { "allowed" } else { "denied" },
                    !GetConsoleWindow().is_null()
                )
            };
            match std::fs::write(arg, &answer) {
                Ok(()) => answer,
                Err(e) => format!("denied cannot record: {e}"),
            }
        }
        // Types a key into the console of this process's standard input, as
        // Linux's TIOCSTI does: what a shell reading it would run.
        "inject" => {
            let rec = KEY_RECORD { event_type: 1, key_down: 1, repeat: 1, vkey: 0, vscan: 0, ch: u16::from(b'x'), state: 0 };
            let mut n = 0;
            // SAFETY: one record, our own standard input.
            if unsafe { WriteConsoleInputW(GetStdHandle(-10i32 as u32), &rec, 1, &mut n) } != 0 {
                "allowed".into()
            } else {
                // SAFETY: plain call.
                format!("denied {}", std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32))
            }
        }
        // Reads standard input up to a `q`, writes a marker to standard
        // output, and records the bytes read, in hex, in the file `arg`.
        "echo" => {
            let mut got = Vec::new();
            let mut b = [0u8; 1];
            while got.len() < 64 {
                match std::io::stdin().read(&mut b) {
                    Ok(1) => {
                        got.push(b[0]);
                        if b[0] == b'q' {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            println!("[jail-probe echo {}]", got.len());
            let hex: Vec<String> = got.iter().map(|b| format!("{b:02x}")).collect();
            match std::fs::write(arg, hex.join(" ")) {
                Ok(()) => format!("allowed {}", hex.join(" ")),
                Err(e) => format!("denied cannot record: {e}"),
            }
        }
        // Leaves this process's console and attaches to that of process
        // `pid`: then its console control events reach that console's
        // processes.
        "attach" => {
            let Some(pid) = pid_of(arg) else {
                return "bad pid".into();
            };
            // SAFETY: plain calls.
            unsafe {
                FreeConsole();
                if AttachConsole(pid) != 0 {
                    "allowed".into()
                } else {
                    format!("denied {}", std::io::Error::from_raw_os_error(GetLastError() as i32))
                }
            }
        }
        // The limits of the job this process is in, as Windows reports them:
        // `allowed affinity=<mask> cpu=<flags>:<rate or weight>`.
        "job" => {
            let mut basic = [0u64; 8]; // JOBOBJECT_BASIC_LIMIT_INFORMATION (64 bytes)
            let mut cpu = [0u32; 2]; // JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
            // SAFETY: buffers of the sizes passed; NULL is the caller's job.
            unsafe {
                if QueryInformationJobObject(std::ptr::null_mut(), 2, basic.as_mut_ptr().cast(), 64, std::ptr::null_mut()) == 0
                    || QueryInformationJobObject(std::ptr::null_mut(), 15, cpu.as_mut_ptr().cast(), 8, std::ptr::null_mut()) == 0
                {
                    return format!("denied {}", std::io::Error::last_os_error());
                }
            }
            // LimitFlags is at offset 16, Affinity at 48.
            let flags = basic[2] as u32;
            let affinity = if flags & 0x10 != 0 { format!("{:#x}", basic[6]) } else { "none".into() };
            format!("allowed affinity={affinity} cpu={:#x}:{}", cpu[0], cpu[1])
        }
        // The processors this process may run on.
        "affinity" => {
            let (mut mine, mut system) = (0usize, 0usize);
            // SAFETY: out-parameters.
            if unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut mine, &mut system) } == 0 {
                return format!("denied {}", std::io::Error::last_os_error());
            }
            format!("allowed {mine:#x} of {system:#x}")
        }
        // Spins for `arg` seconds of wall time: `allowed <CPU seconds used>`.
        "spin" => {
            let Ok(secs) = arg.parse() else {
                return "bad seconds".into();
            };
            let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
            while std::time::Instant::now() < end {
                std::hint::spin_loop();
            }
            let (mut c, mut e, mut k, mut u) = (0u64, 0u64, 0u64, 0u64);
            // SAFETY: four out-parameters.
            unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) };
            format!("allowed {:.3}", (k + u) as f64 / 1e7)
        }
        // Waits `arg` seconds: a process for the others to act on.
        "wait" => {
            let Ok(secs) = arg.parse() else {
                return "bad seconds".into();
            };
            std::thread::sleep(std::time::Duration::from_secs(secs));
            "allowed".into()
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
        // The child answers on our standard handles, which a pipe may be.
        let inherit = |which: u32| {
            let h = GetStdHandle(which);
            SetHandleInformation(h, 1, 1); // HANDLE_FLAG_INHERIT
            h
        };
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            reserved: [std::ptr::null_mut(); 3],
            geometry: [0; 7],
            flags: USE_STD_HANDLES,
            show_window: 0,
            reserved2_len: 0,
            reserved2: std::ptr::null_mut(),
            stdin: inherit(-10i32 as u32),
            stdout: inherit(-11i32 as u32),
            stderr: inherit(-12i32 as u32),
        };
        let mut pi = PROCESS_INFORMATION { process: std::ptr::null_mut(), thread: std::ptr::null_mut(), pid: 0, tid: 0 };
        if CreateProcessAsUserW(
            dup,
            std::ptr::null(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
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
