// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What a process can reach, for tools/windows/jailer-test.ps1. Run through
//! the jailer as the jailed binary, it takes the jail over as Firecracker
//! does (`RevertToSelf` first); with `low` first it starts itself again as a
//! plain low-integrity process of the user; with `medium` first it runs the
//! command line that follows as a plain process of the user: medium
//! integrity, no administrator's group or privileges (the token UAC gives a
//! user's programs), its exit code returned.
//!
//! ```text
//! jail-probe [low] <check>...   check: read:<path> write:<path>
//!                               open:<pid> connect:<socket path>
//!                               handle:<value> signal:<pid> thread:<pid>
//!                               see:<pid> ctrl:<process group> procs:0
//!                               wait:<seconds> console:0 tty:<file>
//!                               attach:<pid> inject:0 echo:<file>
//!                               hold:<path>:<seconds> tcp:<ip>:<port>
//!                               udp:<ip>:<port> pull:<pid>:<handle>
//!                               listen:<socket path> wsadup:<socket path>
//!                               listenpull:<socket path> sockpull:<socket path>
//!                               bind:<socket path> delete:<path>
//!                               token:0 tokenopen:0 mitigations:<pid>
//!                               job:0 affinity:0 spin:<seconds>
//!                               privileges:0 largepage:<MiB>
//!                               link:<new name>|<existing file> files:<n>
//!                               private:<MiB> sections:<MiB> filesections:<MiB>
//!                               namedjob:<object name> namespace:0
//! (<pid> may be `parent`: in a jail, the jailer.)
//! jail-probe medium <program> <argument>...
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
    fn GetTokenInformation(t: HANDLE, class: i32, info: *mut c_void, len: u32, needed: *mut u32) -> i32;
    fn CheckTokenMembership(t: HANDLE, sid: *mut c_void, member: *mut i32) -> i32;
    fn GetSidSubAuthorityCount(sid: *mut c_void) -> *mut u8;
    fn GetSidSubAuthority(sid: *mut c_void, index: u32) -> *mut u32;
    fn SetTokenInformation(t: HANDLE, class: i32, info: *const c_void, len: u32) -> i32;
    fn InitializeAcl(acl: *mut c_void, len: u32, revision: u32) -> i32;
    fn AddAccessAllowedAce(acl: *mut c_void, revision: u32, mask: u32, sid: *mut c_void) -> i32;
    fn CreateRestrictedToken(
        t: HANDLE,
        flags: u32,
        disable_count: u32,
        disable: *const c_void,
        delete_count: u32,
        delete: *const c_void,
        restrict_count: u32,
        restrict: *const c_void,
        out: *mut HANDLE,
    ) -> i32;
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
    fn DuplicateHandle(src: HANDLE, h: HANDLE, dst: HANDLE, out: *mut HANDLE, access: u32, inherit: i32, opts: u32) -> i32;
    fn CloseHandle(h: HANDLE) -> i32;
    fn GetCurrentProcess() -> HANDLE;
    fn GetProcessMitigationPolicy(process: HANDLE, policy: i32, buf: *mut c_void, len: usize) -> i32;
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
    fn CreateJobObjectW(sa: *const c_void, name: *const u16) -> HANDLE;
    fn CreateBoundaryDescriptorW(name: *const u16, flags: u32) -> HANDLE;
    fn AddSIDToBoundaryDescriptor(boundary: *mut HANDLE, sid: *mut c_void) -> i32;
    fn AddIntegrityLabelToBoundaryDescriptor(boundary: *mut HANDLE, label: *mut c_void) -> i32;
    fn CreatePrivateNamespaceW(sa: *const c_void, boundary: *const c_void, alias: *const u16) -> HANDLE;
    fn OpenPrivateNamespaceW(boundary: *const c_void, alias: *const u16) -> HANDLE;
    fn GetProcessAffinityMask(p: HANDLE, mine: *mut usize, system: *mut usize) -> i32;
    fn GetProcessTimes(p: HANDLE, c: *mut u64, e: *mut u64, k: *mut u64, u: *mut u64) -> i32;
    fn GetLargePageMinimum() -> usize;
    fn VirtualAlloc(addr: *mut c_void, size: usize, ty: u32, prot: u32) -> *mut c_void;
    fn VirtualFree(addr: *mut c_void, size: usize, ty: u32) -> i32;
    fn CreateFileMappingW(file: HANDLE, sa: *const c_void, prot: u32, hi: u32, lo: u32, name: *const u16) -> HANDLE;
    fn MapViewOfFile(section: HANDLE, access: u32, hi: u32, lo: u32, size: usize) -> *mut c_void;
    fn CreateFileW(name: *const u16, access: u32, share: u32, sa: *const c_void, disposition: u32, flags: u32, template: HANDLE) -> HANDLE;
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
    fn sendto(s: usize, buf: *const u8, len: i32, flags: i32, to: *const u8, tolen: i32) -> i32;
    fn bind(s: usize, addr: *const u8, len: i32) -> i32;
    fn listen(s: usize, backlog: i32) -> i32;
    fn accept(s: usize, addr: *mut u8, len: *mut i32) -> usize;
    fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32;
    fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32;
    fn WSAIoctl(s: usize, code: u32, inb: *const u8, inl: u32, outb: *mut u8, outl: u32, ret: *mut u32, ov: *mut c_void, routine: *mut c_void) -> i32;
    fn WSADuplicateSocketW(s: usize, pid: u32, info: *mut u8) -> i32;
    fn WSASocketW(af: i32, ty: i32, proto: i32, info: *const u8, group: u32, flags: u32) -> usize;
}

/// `SIO_AF_UNIX_GETPEERPID`.
const GETPEERPID: u32 = 0x5800_0100;
/// `sizeof(WSAPROTOCOL_INFOW)`.
const PROTOCOL_INFO: usize = 628;
/// `FROM_PROTOCOL_INFO`.
const FROM_INFO: i32 = -1;

/// A `sockaddr_un` for `path`.
fn sockaddr_un(path: &str) -> [u8; 110] {
    let mut addr = [0u8; 110];
    addr[0] = 1; // AF_UNIX
    let path = path.as_bytes();
    let n = path.len().min(107);
    addr[2..2 + n].copy_from_slice(&path[..n]);
    addr
}

/// A connected `AF_UNIX` stream socket to `path`.
fn unix_connect(path: &str) -> Result<usize, std::io::Error> {
    let mut data = [0u8; 512];
    let addr = sockaddr_un(path);
    // SAFETY: room for WSADATA; then plain socket calls on a socket we own.
    unsafe {
        WSAStartup(0x0202, data.as_mut_ptr());
        let s = socket(1, 1, 0); // AF_UNIX, SOCK_STREAM
        if s == usize::MAX {
            return Err(std::io::Error::from_raw_os_error(WSAGetLastError()));
        }
        if connect(s, addr.as_ptr(), addr.len() as i32) != 0 {
            let e = WSAGetLastError();
            closesocket(s);
            return Err(std::io::Error::from_raw_os_error(e));
        }
        Ok(s)
    }
}

/// Receives exactly `buf.len()` bytes; false at the end of the stream.
fn recv_all(s: usize, buf: &mut [u8]) -> bool {
    let mut got = 0;
    while got < buf.len() {
        // SAFETY: a buffer of the length passed.
        let n = unsafe { recv(s, buf[got..].as_mut_ptr(), (buf.len() - got) as i32, 0) };
        if n <= 0 {
            return false;
        }
        got += n as usize;
    }
    true
}

/// A `sockaddr_in` for `<ip>:<port>` (IPv4).
fn sockaddr_in(arg: &str) -> Option<[u8; 16]> {
    let (ip, port) = arg.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let octets: Vec<u8> = ip.split('.').map(|o| o.parse().ok()).collect::<Option<_>>()?;
    if octets.len() != 4 {
        return None;
    }
    let mut addr = [0u8; 16];
    addr[0] = 2; // AF_INET
    addr[2..4].copy_from_slice(&port.to_be_bytes());
    addr[4..8].copy_from_slice(&octets);
    Some(addr)
}

/// An IPv4 socket operation: `connect` (TCP) or `sendto` (UDP) to
/// `<ip>:<port>`; what a network filter denies.
fn ip_check(arg: &str, stream: bool) -> String {
    let Some(addr) = sockaddr_in(arg) else {
        return "bad address".into();
    };
    let mut data = [0u8; 512];
    // SAFETY: room for WSADATA; then plain socket calls on a socket we own.
    unsafe {
        WSAStartup(0x0202, data.as_mut_ptr());
        let s = socket(2, if stream { 1 } else { 2 }, 0); // AF_INET, SOCK_STREAM / SOCK_DGRAM
        if s == usize::MAX {
            return format!("denied socket {}", WSAGetLastError());
        }
        let rc = if stream {
            connect(s, addr.as_ptr(), addr.len() as i32)
        } else {
            sendto(s, b"x".as_ptr(), 1, 0, addr.as_ptr(), addr.len() as i32)
        };
        let e = WSAGetLastError();
        closesocket(s);
        if rc >= 0 {
            "allowed".into()
        } else {
            format!("denied {}", std::io::Error::from_raw_os_error(e))
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// The `n`th MiB of a `private`, `sections` or `filesections` check: taken,
/// every page written, and never freed.
fn take_mib(kind: &str, n: usize) -> Result<(), String> {
    const MIB: usize = 1 << 20;
    let invalid = usize::MAX as HANDLE;
    let last = || std::io::Error::last_os_error().to_string();
    // SAFETY: new allocations and mappings of our own, written within their size.
    unsafe {
        let p = match kind {
            // MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
            "private" => VirtualAlloc(std::ptr::null_mut(), MIB, 0x3000, 4),
            _ => {
                let file = if kind == "filesections" {
                    let path = std::env::temp_dir().join(format!("jail-probe-{}-{n}", std::process::id()));
                    // GENERIC_READ | GENERIC_WRITE, CREATE_NEW,
                    // FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE
                    let f = CreateFileW(wide(&path.to_string_lossy()).as_ptr(), 0xC000_0000, 0, std::ptr::null(), 1, 0x0400_0100, std::ptr::null_mut());
                    if f == invalid {
                        return Err(format!("CreateFileW {}: {}", path.display(), last()));
                    }
                    f
                } else {
                    invalid
                };
                // PAGE_READWRITE
                let s = CreateFileMappingW(file, std::ptr::null(), 4, 0, MIB as u32, std::ptr::null());
                if s.is_null() {
                    return Err(format!("CreateFileMappingW: {}", last()));
                }
                // FILE_MAP_ALL_ACCESS
                MapViewOfFile(s, 0xF001F, 0, 0, MIB)
            }
        };
        if p.is_null() {
            return Err(last());
        }
        for page in (0..MIB).step_by(4096) {
            p.cast::<u8>().add(page).write_volatile(1);
        }
    }
    Ok(())
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
        // A hard link (CreateHardLinkW), which needs write access to the
        // existing file's attributes.
        // Opens <n> files (NUL) and keeps them, as many descriptors; says
        // how many it opened, and why it stopped if it did.
        "files" => {
            let Ok(n) = arg.parse::<usize>() else { return "unknown check".into() };
            let mut kept = Vec::new();
            for _ in 0..n {
                match std::fs::File::open("NUL") {
                    Ok(f) => kept.push(f),
                    Err(e) => return format!("denied after {}: {e}", kept.len()),
                }
            }
            format!("allowed {}", kept.len())
        }
        // Removes the file `arg` (a network endpoint, say).
        "delete" => io(std::fs::remove_file(arg)),
        // Binds and listens at `arg`, as a network endpoint is made: whether
        // this process may make that name. A name it made is removed again.
        "bind" => {
            let mut data = [0u8; 512];
            let addr = sockaddr_un(arg);
            // SAFETY: room for WSADATA; then plain socket calls on a socket we own.
            unsafe {
                WSAStartup(0x0202, data.as_mut_ptr());
                let l = socket(1, 1, 0);
                if l == usize::MAX {
                    return format!("denied socket {}", std::io::Error::from_raw_os_error(WSAGetLastError()));
                }
                let made = bind(l, addr.as_ptr(), addr.len() as i32) == 0;
                let answer = if made && listen(l, 1) == 0 {
                    "allowed".to_string()
                } else {
                    format!("denied {}", std::io::Error::from_raw_os_error(WSAGetLastError()))
                };
                closesocket(l);
                if made {
                    let _ = std::fs::remove_file(arg);
                }
                answer
            }
        }
        "link" => match arg.split_once('|') {
            Some((new, existing)) => io(std::fs::hard_link(existing, new)),
            None => "unknown check".into(),
        },
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
        "connect" => match unix_connect(arg) {
            Ok(s) => {
                // SAFETY: the socket just connected.
                unsafe { closesocket(s) };
                "allowed".into()
            }
            Err(e) => format!("denied {e}"),
        },
        // The receiving side of descriptor passing from a jail: duplicates
        // handle `handle` out of process `pid` (which must be a file) and
        // reads it back, as sock_ctrl_msg's pull does.
        "pull" => {
            let Some((pid, value)) = arg.split_once(':') else {
                return "bad pull".into();
            };
            let (Ok(pid), Ok(value)) = (pid.parse::<u32>(), value.parse::<isize>()) else {
                return "bad pull".into();
            };
            // PROCESS_DUP_HANDLE
            // SAFETY: plain calls; the handles are checked and closed.
            unsafe {
                let p = OpenProcess(0x0040, 0, pid);
                if p.is_null() {
                    return format!("denied open {}", std::io::Error::from_raw_os_error(GetLastError() as i32));
                }
                let mut h: HANDLE = std::ptr::null_mut();
                // DUPLICATE_SAME_ACCESS
                let ok = DuplicateHandle(p, value as HANDLE, GetCurrentProcess(), &mut h, 0, 0, 2);
                let e = GetLastError();
                CloseHandle(p);
                if ok == 0 {
                    return format!("denied duplicate {}", std::io::Error::from_raw_os_error(e as i32));
                }
                SetFilePointer(h, 0, std::ptr::null_mut(), 0);
                let mut buf = [0u8; 64];
                let mut read = 0u32;
                let ok = ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut read, std::ptr::null_mut());
                let e = GetLastError();
                CloseHandle(h);
                if ok == 0 {
                    return format!("denied read {}", std::io::Error::from_raw_os_error(e as i32));
                }
                format!("allowed {}", String::from_utf8_lossy(&buf[..read as usize]))
            }
        }
        // The sending side of socket passing from a jail: connects twice to
        // the listener at `path` (a control connection, then the socket to
        // pass), duplicates the second for the listener's process
        // (`WSADuplicateSocketW`, as sock_ctrl_msg does for a socket) and
        // sends the protocol information over the first; allowed if the
        // listener reports the duplicate works.
        // `sockpull`: the same, but the sender duplicates the socket's
        // handle in itself and sends the handle's value, for the listener to
        // pull out of this process (what a jailed sender does, since
        // `WSADuplicateSocketW` duplicates into the target process, which a
        // jail cannot open).
        "wsadup" | "sockpull" => {
            let (s1, s2) = match (unix_connect(arg), unix_connect(arg)) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => return format!("denied connect {e}"),
            };
            let mut pid = 0u32;
            let mut n = 0u32;
            let mut info = [0u8; PROTOCOL_INFO];
            let pull = kind == "sockpull";
            // SAFETY: an out buffer for a u32, then for the protocol info.
            let answer = unsafe {
                let mut copy: HANDLE = std::ptr::null_mut();
                let sent = if pull {
                    // DUPLICATE_SAME_ACCESS, not inheritable.
                    if DuplicateHandle(GetCurrentProcess(), s2 as HANDLE, GetCurrentProcess(), &mut copy, 0, 0, 2) == 0 {
                        return format!("denied DuplicateHandle {}", std::io::Error::from_raw_os_error(GetLastError() as i32));
                    }
                    info[..8].copy_from_slice(&(copy as usize as u64).to_le_bytes());
                    8
                } else {
                    PROTOCOL_INFO
                };
                if WSAIoctl(s1, GETPEERPID, std::ptr::null(), 0, (&raw mut pid).cast(), 4, &mut n, std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
                    format!("denied peer pid {}", std::io::Error::from_raw_os_error(WSAGetLastError()))
                } else if !pull && WSADuplicateSocketW(s2, pid, info.as_mut_ptr()) != 0 {
                    format!("denied WSADuplicateSocket {}", std::io::Error::from_raw_os_error(WSAGetLastError()))
                } else if send(s1, info.as_ptr(), sent as i32, 0) != sent as i32 {
                    format!("denied send {}", std::io::Error::from_raw_os_error(WSAGetLastError()))
                } else {
                    let mut ok = [0u8; 2];
                    if recv_all(s1, &mut ok) && &ok == b"ok" {
                        format!("allowed into pid {pid}")
                    } else {
                        "denied the listener could not use the duplicate".into()
                    }
                }
            };
            // SAFETY: the sockets connected above.
            unsafe {
                closesocket(s2);
                closesocket(s1);
            }
            answer
        }
        // The receiving side of `wsadup`: listens at `path`, takes the two
        // connections, makes a socket from the protocol information sent on
        // the first, and checks that a byte sent on it arrives on the
        // second (they are the two ends of one connection).
        // `listenpull`: the receiving side of `sockpull`: the handle's
        // value arrives, and the listener duplicates it out of the sender.
        "listen" | "listenpull" => {
            let mut data = [0u8; 512];
            let addr = sockaddr_un(arg);
            let _ = std::fs::remove_file(arg);
            let pull = kind == "listenpull";
            // SAFETY: room for WSADATA; then plain socket calls on sockets we own.
            unsafe {
                WSAStartup(0x0202, data.as_mut_ptr());
                let l = socket(1, 1, 0);
                if l == usize::MAX || bind(l, addr.as_ptr(), addr.len() as i32) != 0 || listen(l, 2) != 0 {
                    return format!("denied listen {}", std::io::Error::from_raw_os_error(WSAGetLastError()));
                }
                let c1 = accept(l, std::ptr::null_mut(), std::ptr::null_mut());
                let c2 = accept(l, std::ptr::null_mut(), std::ptr::null_mut());
                if c1 == usize::MAX || c2 == usize::MAX {
                    return format!("denied accept {}", std::io::Error::from_raw_os_error(WSAGetLastError()));
                }
                let mut info = [0u8; PROTOCOL_INFO];
                if !recv_all(c1, &mut info[..if pull { 8 } else { PROTOCOL_INFO }]) {
                    return "denied no protocol information arrived".into();
                }
                let s = if pull {
                    let mut pid = 0u32;
                    let mut n = 0u32;
                    let mut out: HANDLE = std::ptr::null_mut();
                    let value = u64::from_le_bytes(info[..8].try_into().unwrap()) as usize as HANDLE;
                    if WSAIoctl(c1, GETPEERPID, std::ptr::null(), 0, (&raw mut pid).cast(), 4, &mut n, std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
                        return format!("denied peer pid {}", std::io::Error::from_raw_os_error(WSAGetLastError()));
                    }
                    let p = OpenProcess(0x0040, 0, pid);
                    if p.is_null() {
                        return format!("denied open sender {}", std::io::Error::from_raw_os_error(GetLastError() as i32));
                    }
                    // DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE
                    let ok = DuplicateHandle(p, value, GetCurrentProcess(), &mut out, 0, 0, 3);
                    let e = GetLastError();
                    CloseHandle(p);
                    if ok == 0 {
                        return format!("denied pull {}", std::io::Error::from_raw_os_error(e as i32));
                    }
                    out as usize
                } else {
                    WSASocketW(FROM_INFO, FROM_INFO, FROM_INFO, info.as_ptr(), 0, 1 /* WSA_FLAG_OVERLAPPED */)
                };
                let answer = if s == usize::MAX {
                    format!("denied WSASocket {}", std::io::Error::from_raw_os_error(WSAGetLastError()))
                } else {
                    let mut b = [0u8; 1];
                    if send(s, b"x".as_ptr(), 1, 0) == 1 && recv_all(c2, &mut b) && b[0] == b'x' {
                        send(c1, b"ok".as_ptr(), 2, 0);
                        "allowed".to_string()
                    } else {
                        format!("denied the duplicate did not carry a byte {}", std::io::Error::from_raw_os_error(WSAGetLastError()))
                    }
                };
                if s != usize::MAX {
                    closesocket(s);
                }
                closesocket(c2);
                closesocket(c1);
                closesocket(l);
                let _ = std::fs::remove_file(arg);
                answer
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
        // As Firecracker around a microVM's run, it first asks for raw mode
        // and at the end for canonical mode: through the jailer's mode pipe
        // when it is jailed on a console (vmm_sys_util::terminal, MODE_ENV).
        "echo" => {
            let mode_pipe: Option<usize> = std::env::var("WICK_CONSOLE_MODE").ok().and_then(|v| v.parse().ok());
            let ask = |request: u8| {
                if let Some(h) = mode_pipe {
                    let mut n = 0u32;
                    // SAFETY: one byte to the handle the jailer gave.
                    unsafe { WriteFile(h as HANDLE, &request, 1, &mut n, std::ptr::null_mut()) };
                }
            };
            ask(b'r');
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
            ask(b'c');
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
        // A TCP connection or a UDP datagram to an IPv4 address: what a
        // jail's network filter denies.
        "tcp" => ip_check(arg, true),
        "udp" => ip_check(arg, false),
        // Opens the file `path` and keeps it open for `seconds`, printing
        // the handle's value: for another process to duplicate out of this
        // one (the receiver's side of descriptor passing from a jail).
        "hold" => {
            let Some((path, secs)) = arg.rsplit_once(':') else {
                return "bad hold".into();
            };
            let Ok(secs) = secs.parse::<u64>() else {
                return "bad seconds".into();
            };
            let file = match std::fs::File::open(path) {
                Ok(f) => f,
                Err(e) => return format!("denied {e}"),
            };
            use std::os::windows::io::AsRawHandle;
            println!("{c} allowed {}", file.as_raw_handle() as isize);
            std::thread::sleep(std::time::Duration::from_secs(secs));
            drop(file);
            return "held".into();
        }
        // What our token is: its integrity level (the RID: 4096 low, 8192
        // medium, 12288 high), whether the administrators' group counts
        // (not when for deny only) and how many privileges it holds.
        "token" => {
            let mut t = std::ptr::null_mut();
            let mut buf = [0u8; 4096];
            let mut len = 0u32;
            let mut admin = std::ptr::null_mut();
            let mut member = 0i32;
            // SAFETY: our own token; a buffer of the size passed; out-pointers.
            unsafe {
                if OpenProcessToken(GetCurrentProcess(), 0x8, &mut t) == 0 // TOKEN_QUERY
                    || GetTokenInformation(t, 25, buf.as_mut_ptr().cast(), 4096, &mut len) == 0 // TokenIntegrityLevel
                {
                    return format!("denied {}", std::io::Error::last_os_error());
                }
                let label = buf.as_ptr().cast::<SID_AND_ATTRIBUTES>().read_unaligned();
                let count = *GetSidSubAuthorityCount(label.sid);
                let level = *GetSidSubAuthority(label.sid, u32::from(count) - 1);
                let mut privileges = [0u8; 4096];
                if GetTokenInformation(t, 3, privileges.as_mut_ptr().cast(), 4096, &mut len) == 0 // TokenPrivileges
                    || ConvertStringSidToSidW(wide("S-1-5-32-544").as_ptr(), &mut admin) == 0
                    || CheckTokenMembership(std::ptr::null_mut(), admin, &mut member) == 0
                {
                    return format!("denied {}", std::io::Error::last_os_error());
                }
                let privileges = u32::from_le_bytes([privileges[0], privileges[1], privileges[2], privileges[3]]);
                CloseHandle(t);
                format!(
                    "allowed integrity {level} administrators {} privileges {privileges}",
                    if member != 0 { "yes" } else { "no" }
                )
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
        // Makes a Job Object of the name, on record: what a jailed process
        // may do in the session's namespace (`Local\`), where a parent
        // cgroup's job is not (`namespace:0`): `allowed made` or `allowed
        // opened`, the handle kept for as long as this process runs, or
        // `denied`.
        "namedjob" => {
            // SAFETY: a NUL-terminated name; the last error read at once.
            let (h, err) = unsafe {
                let h = CreateJobObjectW(std::ptr::null(), wide(arg).as_ptr());
                (h, GetLastError())
            };
            if h.is_null() {
                return format!("denied {}", std::io::Error::from_raw_os_error(err as i32));
            }
            // 183: ERROR_ALREADY_EXISTS, the job was there and is opened.
            format!("allowed {}", if err == 183 { "opened" } else { "made" })
        }
        // The parent cgroups' private namespace, as the jailer names it
        // (overlay/jailer/platform/windows/cgroup_values.rs: `wick-cgroup`,
        // this account's SID at medium integrity), which a jail must not
        // reach: `denied` when it can neither open it nor make it, with
        // Windows's two answers, else `allowed`.
        "namespace" => {
            // GetCurrentProcessToken(): a pseudo-handle with TOKEN_QUERY
            // (Microsoft Learn), which queries without opening the token, as
            // `privileges` does: on CI's runner, whose jailer is elevated, a
            // jailed process's OpenProcessToken of its own token is denied
            // (run 43428124115, "namespace:0 unknown: Access is denied").
            let t = -4isize as HANDLE;
            let mut buf = [0u64; 32];
            let mut len = 0u32;
            let mut medium = std::ptr::null_mut();
            let name = wide("wick-cgroup");
            // SAFETY: our own token (TokenUser: a pointer to the SID first);
            // NUL-terminated strings and out-pointers.
            unsafe {
                if GetTokenInformation(t, 1, buf.as_mut_ptr().cast(), 256, &mut len) == 0 {
                    return format!("unknown: GetTokenInformation(TokenUser): {}", std::io::Error::last_os_error());
                }
                if ConvertStringSidToSidW(wide("S-1-16-8192").as_ptr(), &mut medium) == 0 {
                    return format!("unknown: ConvertStringSidToSidW: {}", std::io::Error::last_os_error());
                }
                let mut boundary = CreateBoundaryDescriptorW(name.as_ptr(), 0);
                if boundary.is_null()
                    || AddSIDToBoundaryDescriptor(&mut boundary, buf[0] as *mut c_void) == 0
                    || AddIntegrityLabelToBoundaryDescriptor(&mut boundary, medium) == 0
                {
                    return format!("unknown: the boundary: {}", std::io::Error::last_os_error());
                }
                let opened = OpenPrivateNamespaceW(boundary, name.as_ptr());
                let open_error = GetLastError();
                let made = CreatePrivateNamespaceW(std::ptr::null(), boundary, name.as_ptr());
                let make_error = GetLastError();
                if opened.is_null() && made.is_null() {
                    format!("denied open: Windows error {open_error}; make: Windows error {make_error}")
                } else {
                    format!("allowed opened: {}; made: {}", !opened.is_null(), !made.is_null())
                }
            }
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
        // The privileges in this process's token, `+` after those enabled:
        // `allowed SeChangeNotifyPrivilege+,...`.
        "privileges" => {
            // GetCurrentProcessToken(): a pseudo-handle that queries without
            // opening the token, which a jailed process may not do.
            let t = -4isize as HANDLE;
            let mut buf = vec![0u64; 1024];
            let mut len = 0u32;
            // SAFETY: our own token and a buffer of the size passed.
            if unsafe { GetTokenInformation(t, 3, buf.as_mut_ptr().cast(), 8192, &mut len) } == 0 {
                return format!("denied {}", std::io::Error::last_os_error());
            }
            // TOKEN_PRIVILEGES: a u32 count, then (LUID u64, attributes u32)
            // entries of 12 bytes from offset 4.
            // SAFETY: the 8192-byte buffer above.
            let bytes: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), 8192) };
            let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let mut names = Vec::new();
            for i in 0..word(0) as usize {
                let at = 4 + 12 * i;
                let luid = u64::from(word(at)) | (u64::from(word(at + 4)) << 32);
                // Privilege LUIDs are fixed (winnt.h, SE_*_PRIVILEGE); a
                // jailed process may not ask LSA for their names.
                let name = match luid {
                    4 => "SeLockMemoryPrivilege".to_string(),
                    23 => "SeChangeNotifyPrivilege".to_string(),
                    l => format!("privilege{l}"),
                };
                // SE_PRIVILEGE_ENABLED
                let on = if word(at + 8) & 2 != 0 { "+" } else { "" };
                names.push(format!("{name}{on}"));
            }
            format!("allowed {}", names.join(","))
        }
        // Opens this process's token to adjust its privileges, as the libc
        // layer would to enable "Lock pages in memory".
        "tokenopen" => {
            let mut t = std::ptr::null_mut();
            // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            // SAFETY: an out-pointer; our own process.
            if unsafe { OpenProcessToken(GetCurrentProcess(), 0x28, &mut t) } == 0 {
                return format!("denied {}", std::io::Error::last_os_error());
            }
            // SAFETY: the handle just opened.
            unsafe { CloseHandle(t) };
            "allowed".into()
        }
        // Takes `arg` MiB of memory 1 MiB at a time and writes every page, kept
        // until the process ends: private memory (`private`), pagefile-backed
        // sections (`sections`), or sections of delete-on-close temporary files
        // as wick's memfd makes them (`filesections`). `allowed <MiB>` or
        // `denied after <MiB>: <error>`.
        "private" | "sections" | "filesections" => {
            let Ok(mib) = arg.parse::<usize>() else {
                return "bad size".into();
            };
            for i in 0..mib {
                if let Err(e) = take_mib(kind, i) {
                    return format!("denied after {i}: {e}");
                }
            }
            format!("allowed {mib}")
        }
        // Commits `arg` MiB of large pages: `allowed <bytes>` or `denied <error>`.
        "largepage" => {
            let Ok(mib) = arg.parse::<usize>() else {
                return "bad size".into();
            };
            // SAFETY: plain query.
            let page = unsafe { GetLargePageMinimum() };
            if page == 0 {
                return "denied no large pages on this processor".into();
            }
            let size = (mib << 20).div_ceil(page) * page;
            // MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE
            // SAFETY: a new allocation, freed below.
            let p = unsafe { VirtualAlloc(std::ptr::null_mut(), size, 0x2000_3000, 4) };
            if p.is_null() {
                return format!("denied {}", std::io::Error::last_os_error());
            }
            // SAFETY: our committed allocation; MEM_RELEASE.
            unsafe {
                p.cast::<u8>().write_volatile(1);
                VirtualFree(p, 0, 0x8000);
            }
            format!("allowed {size}")
        }
        // The process mitigation policies of a process (vmm::ext::sandbox's
        // profile), as `name=flags`: the first word of each policy, which
        // holds its flags.
        "mitigations" => {
            let Ok(pid) = arg.parse() else {
                return "bad pid".into();
            };
            // SAFETY: plain call; PROCESS_QUERY_INFORMATION.
            let h = unsafe { OpenProcess(0x400, 0, pid) };
            if h.is_null() {
                return format!("denied {}", std::io::Error::last_os_error());
            }
            let mut out = String::from("allowed");
            for (name, policy) in [
                ("ExtensionPoint", 6),
                ("ImageLoad", 10),
                ("Signature", 8),
                ("StrictHandle", 3),
                ("Win32k", 4),
                ("DynamicCode", 2),
                ("ChildProcess", 13),
            ] {
                let mut flags = 0u32;
                // SAFETY: a 4-byte buffer of the size passed.
                if unsafe { GetProcessMitigationPolicy(h, policy, (&raw mut flags).cast(), 4) } == 0 {
                    let e = std::io::Error::last_os_error();
                    // SAFETY: a handle we opened.
                    unsafe { CloseHandle(h) };
                    return format!("denied {name}: {e}");
                }
                out.push_str(&format!(" {name}={flags:x}"));
            }
            // SAFETY: a handle we opened.
            unsafe { CloseHandle(h) };
            out
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
    let exe = std::env::current_exe()?;
    let mut argv = vec![exe.to_string_lossy().into_owned()];
    argv.extend(checks.iter().cloned());
    run_as("S-1-16-4096", false, &argv)
}

/// Runs `argv` as a plain process of the user: medium integrity, the
/// administrators' group for deny only and no privilege but
/// `SeChangeNotify` (`CreateRestrictedToken` with `LUA_TOKEN` and
/// `DISABLE_MAX_PRIVILEGE`: the token UAC gives a user's programs).
fn medium(argv: &[String]) -> std::io::Result<u32> {
    if argv.is_empty() {
        return Err(std::io::Error::other("medium: no program given"));
    }
    run_as("S-1-16-8192", true, argv)
}

/// Runs `argv` (a program and its arguments) with a copy of our token at the
/// integrity level `level`, filtered as UAC does when `lua`; waits for it
/// and returns its exit code.
fn run_as(level: &str, lua: bool, argv: &[String]) -> std::io::Result<u32> {
    let fail = || Err(std::io::Error::last_os_error());
    let mut t = std::ptr::null_mut();
    let mut dup = std::ptr::null_mut();
    let mut sid = std::ptr::null_mut();
    // SAFETY: out-pointers; our own token.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), 0x000F_01FF, &mut t) == 0
            || ConvertStringSidToSidW(wide(level).as_ptr(), &mut sid) == 0
        {
            return fail();
        }
        if lua {
            // LUA_TOKEN | DISABLE_MAX_PRIVILEGE: a primary token.
            if CreateRestrictedToken(
                t,
                0x4 | 0x1,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                &mut dup,
            ) == 0
            {
                return fail();
            }
        } else if DuplicateTokenEx(t, 0x000F_01FF, std::ptr::null(), 2, 1, &mut dup) == 0 {
            return fail();
        }
        let label = SID_AND_ATTRIBUTES { sid, attributes: 0x20 }; // SE_GROUP_INTEGRITY
        let len = std::mem::size_of::<SID_AND_ATTRIBUTES>() as u32 + GetLengthSid(sid);
        if SetTokenInformation(dup, 25, (&raw const label).cast(), len) == 0 {
            return fail();
        }
        // The user owns what the child makes, and its default DACL grants
        // SYSTEM and the user, as a user's own token does: an elevated
        // token's default DACL grants Administrators and SYSTEM only, which
        // the LUA token has for deny only, so its child's own process and
        // thread objects granted it nothing and a child that makes a console
        // or loads user32 (PowerShell) died at start with 0xC0000142
        // (STATUS_DLL_INIT_FAILED; measured by Windows 2, finding-0xC0000142).
        let mut user = [0u8; 256];
        let mut needed = 0;
        if GetTokenInformation(t, 1, user.as_mut_ptr().cast(), user.len() as u32, &mut needed) == 0 {
            return fail(); // TokenUser
        }
        let user_sid = *user.as_ptr().cast::<*mut c_void>();
        let mut system = std::ptr::null_mut();
        if ConvertStringSidToSidW(wide("S-1-5-18").as_ptr(), &mut system) == 0 {
            return fail();
        }
        let mut acl = [0u64; 64];
        let acl = acl.as_mut_ptr().cast::<c_void>();
        const ACL_REVISION: u32 = 2;
        const GENERIC_ALL: u32 = 0x1000_0000;
        if InitializeAcl(acl, 512, ACL_REVISION) == 0
            || AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, system) == 0
            || AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, user_sid) == 0
        {
            return fail();
        }
        // TokenOwner (4) is a TOKEN_OWNER, TokenDefaultDacl (6) a
        // TOKEN_DEFAULT_DACL: one pointer each.
        if SetTokenInformation(dup, 4, (&raw const user_sid).cast(), std::mem::size_of::<*mut c_void>() as u32) == 0
            || SetTokenInformation(dup, 6, (&raw const acl).cast(), std::mem::size_of::<*mut c_void>() as u32) == 0
        {
            return fail();
        }
        let cmd = argv.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(" ");
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
    if let Some(runner @ ("low" | "medium")) = args.first().map(String::as_str) {
        let r = if runner == "low" { low(&args[1..]) } else { medium(&args[1..]) };
        match r {
            Ok(code) => std::process::exit(code as i32),
            Err(e) => {
                eprintln!("{runner}: {e}");
                std::process::exit(1);
            }
        }
    }
    // The jailer makes a second process of its binary for Firecracker's API
    // server (vmm::ext::api_process, WICK_API_LINK); this binary has nothing
    // to serve, and a second copy running the checks would race the first
    // (two senders on a `sockpull` listener; `pull:<pid>` of the wrong one).
    if std::env::var_os("WICK_API_LINK").is_some() {
        eprintln!("jail-probe: started as the jail's API process; nothing to serve");
        return;
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
