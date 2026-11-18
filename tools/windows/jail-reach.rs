// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! jail-probe's `reachlist` and `reach` checks: what a jailed process
//! reaches of the host's named objects, for tools/windows/jailer-test.ps1's
//! `reach` stage, run in the real jail (the jailer's own spawn, after
//! Firecracker's preload and `RevertToSelf`, as jail-probe runs every
//! check). The enumeration is fs-probe's `devjail` (tools/windows/fs-probe.rs,
//! `jail_checks`, `list_objects`, `device_reach`, `walk_objects`), which ran
//! under a jail's token made by fs-probe; here the token is the jailer's.
//!
//! `reachlist:<file>`, run by the operator outside any jail: every named
//! object of the object manager's namespace (its type and path), every named
//! pipe and every mailslot, one `<type>\t<path>` line each, into `<file>`.
//!
//! `reach:<file>:<loopback port>:<external ip>:<external port>`, run in the
//! jail: each name of `<file>` opened as its type is (a device by its name,
//! refused that, a name beneath it, which only a device with
//! `FILE_DEVICE_SECURE_OPEN` checks; an ALPC port connected to; a pipe or a
//! mailslot opened; every other type opened by name with
//! `MAXIMUM_ALLOWED`), and the checks that are not names (a DLL loaded after
//! the revert, HKLM read, TCP to loopback, link-local and an external
//! address, an AF_UNIX bind, a pipe and a mailslot made, the pipes
//! listed). Its output is the format the allowlist reads:
//!
//! ```text
//! reach <type>\t<path>\t<how>        one per name reached
//! reach-check <name> <result>        one per check that is not a name
//! reach-summary <type> tried <n> reached <m>
//! ```
//!
//! It asserts nothing: it is a record of what the token reaches.

use super::{bind, closesocket, ip_check, socket, wide, GetLastError, WSAGetLastError, WSAStartup, WaitForSingleObject, HANDLE};
use std::ffi::c_void;
use std::ptr::{null, null_mut};

#[repr(C)]
struct UNICODE_STRING {
    len: u16,
    max: u16,
    buf: *const u16,
}
#[repr(C)]
struct OBJECT_ATTRIBUTES {
    len: u32,
    root: HANDLE,
    name: *const UNICODE_STRING,
    attrs: u32,
    sd: *mut c_void,
    qos: *mut c_void,
}
#[repr(C)]
struct IO_STATUS_BLOCK {
    status: usize,
    info: usize,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateFile(
        h: *mut HANDLE,
        access: u32,
        oa: *const OBJECT_ATTRIBUTES,
        io: *mut IO_STATUS_BLOCK,
        size: *const i64,
        attrs: u32,
        share: u32,
        disp: u32,
        opts: u32,
        ea: *const c_void,
        ea_len: u32,
    ) -> i32;
    fn NtReadFile(h: HANDLE, event: HANDLE, apc: *const c_void, ctx: *const c_void, io: *mut IO_STATUS_BLOCK, buf: *mut c_void, len: u32, offset: *const i64, key: *const u32) -> i32;
    fn NtWriteFile(h: HANDLE, event: HANDLE, apc: *const c_void, ctx: *const c_void, io: *mut IO_STATUS_BLOCK, buf: *const c_void, len: u32, offset: *const i64, key: *const u32) -> i32;
    fn NtDeviceIoControlFile(h: HANDLE, event: HANDLE, apc: *const c_void, ctx: *const c_void, io: *mut IO_STATUS_BLOCK, code: u32, inb: *const c_void, inl: u32, outb: *mut c_void, outl: u32) -> i32;
    fn NtQueryVolumeInformationFile(h: HANDLE, io: *mut IO_STATUS_BLOCK, buf: *mut c_void, len: u32, class: u32) -> i32;
    fn NtOpenDirectoryObject(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtQueryDirectoryObject(h: HANDLE, buf: *mut c_void, len: u32, single: u8, restart: u8, ctx: *mut u32, ret: *mut u32) -> i32;
    fn NtOpenSymbolicLinkObject(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtOpenEvent(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtOpenMutant(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtOpenSemaphore(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtOpenSection(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtOpenTimer(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtOpenJobObject(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtOpenKeyedEvent(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtOpenKey(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtOpenSession(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtOpenPartition(h: *mut HANDLE, access: u32, oa: *const OBJECT_ATTRIBUTES) -> i32;
    fn NtAlpcConnectPort(
        h: *mut HANDLE,
        name: *const UNICODE_STRING,
        oa: *const OBJECT_ATTRIBUTES,
        attrs: *const c_void,
        flags: u32,
        server_sid: *mut c_void,
        msg: *mut c_void,
        len: *mut usize,
        out_attrs: *mut c_void,
        in_attrs: *mut c_void,
        timeout: *const i64,
    ) -> i32;
    fn NtQueryObject(h: HANDLE, class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtClose(h: HANDLE) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateEventW(sa: *const c_void, manual: i32, initial: i32, name: *const u16) -> HANDLE;
    fn CancelIoEx(h: HANDLE, ov: *const c_void) -> i32;
    fn LoadLibraryW(name: *const u16) -> HANDLE;
    fn CreateNamedPipeW(name: *const u16, mode: u32, pipe: u32, max: u32, out: u32, inb: u32, timeout: u32, sa: *const c_void) -> HANDLE;
    fn CreateMailslotW(name: *const u16, max: u32, timeout: u32, sa: *const c_void) -> HANDLE;
    fn GetComputerNameW(buf: *mut u16, len: *mut u32) -> i32;
}
#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(key: usize, sub: *const u16, opts: u32, access: u32, out: *mut usize) -> i32;
    fn RegCloseKey(key: usize) -> i32;
}

const INVALID: HANDLE = -1isize as HANDLE;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const SYNCHRONIZE: u32 = 0x10_0000;
const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_OPEN: u32 = 1;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const SHARE_ALL: u32 = 7;
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
const STATUS_PENDING: i32 = 0x103;
/// STATUS_PORT_CONNECTION_REFUSED: reached, and refused by its server.
const STATUS_PORT_CONNECTION_REFUSED: u32 = 0xC000_0041;
const HKLM: usize = 0x8000_0002;
const KEY_READ: u32 = 0x2_0019;

/// A handle closed on drop (`NtClose`, which closes every kind).
struct H(HANDLE);
impl Drop for H {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID {
            // SAFETY: a handle this program owns.
            unsafe { NtClose(self.0) };
        }
    }
}

fn last() -> String {
    // SAFETY: plain call.
    format!("denied {}", unsafe { GetLastError() })
}

/// An NT name as an OBJECT_ATTRIBUTES for the call's duration.
fn with_oa<T>(name: &str, attrs: u32, f: impl FnOnce(&OBJECT_ATTRIBUTES, &UNICODE_STRING) -> T) -> T {
    let n: Vec<u16> = name.encode_utf16().collect();
    let bytes = u16::try_from(n.len() * 2).unwrap_or(u16::MAX & !1);
    let us = UNICODE_STRING { len: bytes, max: bytes, buf: n.as_ptr() };
    let oa = OBJECT_ATTRIBUTES {
        len: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        root: null_mut(),
        name: &us,
        attrs,
        sd: null_mut(),
        qos: null_mut(),
    };
    f(&oa, &us)
}

/// `NtCreateFile` of an NT path, opening only: synchronous (`opts` with
/// `FILE_SYNCHRONOUS_IO_NONALERT`) or, without it, asynchronous, so that a
/// read or an I/O control the driver keeps can be cancelled.
fn nt_open(path: &str, access: u32, opts: u32) -> Result<H, i32> {
    with_oa(path, OBJ_CASE_INSENSITIVE, |oa, _| {
        let mut h = null_mut();
        let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
        let access = if opts & FILE_SYNCHRONOUS_IO_NONALERT != 0 { access | SYNCHRONIZE } else { access };
        // SAFETY: valid structures for the call's duration.
        let st = unsafe { NtCreateFile(&mut h, access, oa, &mut io, null(), 0x80, SHARE_ALL, FILE_OPEN, opts, null(), 0) };
        if st < 0 { Err(st) } else { Ok(H(h)) }
    })
}

/// Opens the named kernel object `path` of type `ty`: Ok(handle),
/// Err(status), or Err(1) for a type opened otherwise or not at all.
fn open_object(ty: &str, path: &str, access: u32) -> Result<H, i32> {
    type Open = unsafe extern "system" fn(*mut HANDLE, u32, *const OBJECT_ATTRIBUTES) -> i32;
    let f: Open = match ty {
        "Directory" => NtOpenDirectoryObject,
        "SymbolicLink" => NtOpenSymbolicLinkObject,
        "Event" => NtOpenEvent,
        "Mutant" => NtOpenMutant,
        "Semaphore" => NtOpenSemaphore,
        "Section" => NtOpenSection,
        "Timer" => NtOpenTimer,
        "Job" => NtOpenJobObject,
        "KeyedEvent" => NtOpenKeyedEvent,
        "Key" => NtOpenKey,
        "Session" => NtOpenSession,
        "Partition" => NtOpenPartition,
        "File" => return nt_open(path, access, FILE_SYNCHRONOUS_IO_NONALERT),
        _ => return Err(1),
    };
    with_oa(path, OBJ_CASE_INSENSITIVE, |oa, _| {
        let mut h = null_mut();
        // SAFETY: valid structures for the call's duration.
        let st = unsafe { f(&mut h, access, oa) };
        if st < 0 { Err(st) } else { Ok(H(h)) }
    })
}

/// The access a handle was granted (ObjectBasicInformation).
fn granted(h: HANDLE) -> u32 {
    let mut b = [0u32; 14];
    // SAFETY: a buffer of 56 bytes.
    let st = unsafe { NtQueryObject(h, 0, b.as_mut_ptr().cast(), 56, null_mut()) };
    if st < 0 { 0 } else { b[1] }
}

/// Every object of the object manager's namespace beneath `dir`: (type,
/// path); a directory that cannot be listed is one line of its own.
fn walk_objects(dir: &str, out: &mut Vec<(String, String)>) {
    let Ok(h) = open_object("Directory", dir, 0x3) else {
        out.push(("Directory-unlisted".into(), dir.into()));
        return;
    };
    let mut ctx = 0u32;
    let mut buf = vec![0u64; 8192];
    let mut restart = 1;
    loop {
        let mut ret = 0;
        // SAFETY: a buffer of its length; OBJECT_DIRECTORY_INFORMATION entries.
        let st = unsafe { NtQueryDirectoryObject(h.0, buf.as_mut_ptr().cast(), 65536, 0, restart, &mut ctx, &mut ret) };
        restart = 0;
        if st < 0 || st == 0x8000_001A_u32 as i32 {
            break;
        }
        let mut i = 0;
        loop {
            // SAFETY: entries of two UNICODE_STRINGs (32 bytes) until an empty one.
            let (name, ty) = unsafe {
                let e = buf.as_ptr().cast::<u8>().add(i * 32).cast::<UNICODE_STRING>();
                let (n, t) = (&*e, &*e.add(1));
                if n.buf.is_null() {
                    break;
                }
                (
                    String::from_utf16_lossy(std::slice::from_raw_parts(n.buf, n.len as usize / 2)),
                    String::from_utf16_lossy(std::slice::from_raw_parts(t.buf, t.len as usize / 2)),
                )
            };
            let path = if dir == "\\" { format!("\\{name}") } else { format!("{dir}\\{name}") };
            if ty == "Directory" {
                walk_objects(&path, out);
            }
            out.push((ty, path));
            i += 1;
        }
    }
}

/// The names in a directory of a file system the object manager does not
/// list (`\\.\pipe\`, `\\.\mailslot\`); none if it cannot be listed.
fn names_in(dir: &str) -> Vec<String> {
    std::fs::read_dir(dir).map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default()
}

/// `reachlist:<file>`: the list `reach` reads, written by the operator.
pub(super) fn list(file: &str) -> String {
    let mut objs = Vec::new();
    walk_objects("\\", &mut objs);
    let pipes = names_in(r"\\.\pipe\");
    let slots = names_in(r"\\.\mailslot\");
    let lines: Vec<String> = objs
        .iter()
        .map(|(t, p)| format!("{t}\t{p}"))
        .chain(pipes.iter().map(|p| format!("Pipe\t{p}")))
        .chain(slots.iter().map(|p| format!("Mailslot\t{p}")))
        .collect();
    match std::fs::write(file, lines.join("\n") + "\n") {
        Ok(()) => format!("allowed {} names ({} objects, {} pipes, {} mailslots)", lines.len(), objs.len(), pipes.len(), slots.len()),
        Err(e) => format!("denied {e}"),
    }
}

/// `smb:0`: the host's own files and pipes through the network
/// redirectors, opened by their NT names as a jailed process may name them
/// (`\Device\Mup` and `\Device\RdpDrPort` have no
/// `FILE_DEVICE_SECURE_OPEN`: a name beneath them is the redirector's to
/// decide, not the device's security, `reach`'s record), each form once:
/// the administrative shares of this machine by 127.0.0.1, `localhost` and
/// its NetBIOS name, `ADMIN$`, the `IPC$` share and the `srvsvc` pipe
/// beneath it, the same through `\Device\LanmanRedirector` and by a Win32
/// UNC name, and the RDP client drives (`tsclient`). One line each,
/// `smb-open <form>\t<path>\t<result>`: the NTSTATUS, or the access
/// granted and, for a file, the bytes of a read. Records; asserts nothing.
/// Run by the operator too, so a refusal is told from a share this host
/// does not have (jailer-test.ps1 `reach`).
pub(super) fn smb(_arg: &str) -> String {
    let mut name = [0u16; 64];
    let mut len = name.len() as u32;
    // SAFETY: a buffer of `len` characters.
    let host = if unsafe { GetComputerNameW(name.as_mut_ptr(), &mut len) } != 0 {
        String::from_utf16_lossy(&name[..len as usize])
    } else {
        format!("<no computer name: {}>", last())
    };
    println!("smb-computer-name {host}");
    let file = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
    let any = FILE_SYNCHRONOUS_IO_NONALERT;
    let forms: Vec<(&str, String, u32)> = vec![
        ("c$-127.0.0.1", r"\Device\Mup\127.0.0.1\C$\Windows\win.ini".into(), file),
        ("c$-localhost", r"\Device\Mup\localhost\C$\Windows\win.ini".into(), file),
        ("c$-computer-name", format!(r"\Device\Mup\{host}\C$\Windows\win.ini"), file),
        ("admin$-127.0.0.1", r"\Device\Mup\127.0.0.1\ADMIN$\win.ini".into(), file),
        ("ipc$-127.0.0.1", r"\Device\Mup\127.0.0.1\IPC$".into(), any),
        ("pipe-srvsvc-127.0.0.1", r"\Device\Mup\127.0.0.1\PIPE\srvsvc".into(), file),
        ("pipe-srvsvc-localhost", r"\Device\Mup\localhost\PIPE\srvsvc".into(), file),
        ("c$-lanmanredirector", r"\Device\LanmanRedirector\127.0.0.1\C$\Windows\win.ini".into(), file),
        ("c$-unc", r"\??\UNC\127.0.0.1\C$\Windows\win.ini".into(), file),
        ("tsclient-mup", r"\Device\Mup\tsclient\C".into(), any),
        ("tsclient-rdpdrport", r"\Device\RdpDrPort\tsclient\C".into(), any),
        ("rdpdrport-beneath", r"\Device\RdpDrPort\x".into(), any),
    ];
    let mut opened = 0;
    for (form, path, opts) in &forms {
        let r = match nt_open(path, MAXIMUM_ALLOWED, *opts) {
            Ok(h) => {
                opened += 1;
                let mut line = format!("allowed granted {:#x}", granted(h.0));
                if *opts & FILE_NON_DIRECTORY_FILE != 0 && path.ends_with(".ini") {
                    let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
                    let mut buf = [0u8; 64];
                    // SAFETY: a synchronous handle; a buffer of its length.
                    let st = unsafe { NtReadFile(h.0, null_mut(), null(), null(), &mut io, buf.as_mut_ptr().cast(), 64, null(), null()) };
                    line += &format!(" read {:#010x} ({} bytes)", st as u32, if st >= 0 { io.info } else { 0 });
                }
                line
            }
            Err(st) => format!("denied {:#010x}", st as u32),
        };
        println!("smb-open {form}\t{path}\t{r}");
    }
    format!("done {opened} of {} opened", forms.len())
}

/// Waits up to `ms` for an operation that returned `st` on an asynchronous
/// handle, cancelling it then: (final status, bytes).
fn settle(h: HANDLE, ev: HANDLE, st: i32, io: &IO_STATUS_BLOCK, ms: u32) -> (String, usize) {
    if st != STATUS_PENDING {
        return (format!("{:#010x}", st as u32), io.info);
    }
    // SAFETY: our event and handle.
    unsafe {
        if WaitForSingleObject(ev, ms) == 0 {
            return (format!("{:#010x} after pending", io.status as u32), io.info);
        }
        CancelIoEx(h, null());
        WaitForSingleObject(ev, 5000);
    }
    (format!("pending {ms} ms, cancelled {:#010x}", io.status as u32), 0)
}

/// What a handle to the device `path` allows the jail: how it was opened,
/// its granted access, the device's type and characteristics, whether its
/// driver dispatches an I/O control (one no driver defines, refused after
/// dispatch), and a read and a zero-length write where granted.
fn device_reach(path: &str) -> Option<String> {
    // The device by its name; refused that, a name beneath it, which only a
    // device with FILE_DEVICE_SECURE_OPEN checks against its security.
    let (h, how) = match nt_open(path, MAXIMUM_ALLOWED, 0) {
        Ok(h) => (h, "by-name"),
        Err(st) if st == STATUS_ACCESS_DENIED => (nt_open(&format!("{path}\\wick-probe"), MAXIMUM_ALLOWED, 0).ok()?, "beneath-its-name"),
        Err(_) => return None,
    };
    let g = granted(h.0);
    let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
    let mut info = [0u32; 2];
    // SAFETY: FILE_FS_DEVICE_INFORMATION (class 4) is two ULONGs.
    let st = unsafe { NtQueryVolumeInformationFile(h.0, &mut io, info.as_mut_ptr().cast(), 8, 4) };
    let (dtype, chars) = if st >= 0 { (info[0], info[1]) } else { (0, 0) };
    // CTL_CODE(device type, 0xFFF, METHOD_BUFFERED, FILE_ANY_ACCESS): needs
    // no access right, so any handle may send it.
    let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
    // SAFETY: an unnamed manual-reset event; no buffers.
    let ioc = unsafe {
        let ev = H(CreateEventW(null(), 1, 0, null()));
        let st = NtDeviceIoControlFile(h.0, ev.0, null(), null(), &mut io, (dtype.max(1) << 16) | (0xFFF << 2), null(), 0, null_mut(), 0);
        settle(h.0, ev.0, st, &io, 2000).0
    };
    let mut line = format!("{how} granted {g:#x} type {dtype:#x} chars {chars:#x} secure-open {} unknown-ioctl {ioc}", chars & 0x100 != 0);
    if g & FILE_READ_DATA != 0 {
        let mut buf = vec![0u8; 512];
        let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
        let off = 0i64;
        // SAFETY: an unnamed event; a buffer of 512 bytes.
        let r = unsafe {
            let ev = H(CreateEventW(null(), 1, 0, null()));
            let st = NtReadFile(h.0, ev.0, null(), null(), &mut io, buf.as_mut_ptr().cast(), 512, &off, null());
            settle(h.0, ev.0, st, &io, 1000)
        };
        line += &format!(" read {} ({} bytes)", r.0, r.1);
    }
    if g & FILE_WRITE_DATA != 0 {
        let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
        let off = 0i64;
        // SAFETY: an unnamed event; zero bytes.
        let r = unsafe {
            let ev = H(CreateEventW(null(), 1, 0, null()));
            let st = NtWriteFile(h.0, ev.0, null(), null(), &mut io, null(), 0, &off, null());
            settle(h.0, ev.0, st, &io, 1000)
        };
        line += &format!(" zero-length-write {}", r.0);
    }
    Some(line)
}

/// An ALPC port connected to, with no message, for at most a second:
/// reached when the connect succeeds or its server refuses it.
fn alpc_reach(path: &str) -> Option<String> {
    let st = with_oa(path, 0, |_, us| {
        let mut h = null_mut();
        let timeout: i64 = -10_000_000;
        // SAFETY: a port name; no message; one second.
        let st = unsafe { NtAlpcConnectPort(&mut h, us, null(), null(), 0, null_mut(), null_mut(), null_mut(), null_mut(), null_mut(), &timeout) };
        if st >= 0 {
            // SAFETY: the port handle.
            unsafe { NtClose(h) };
        }
        st
    });
    let reached = st >= 0 || st as u32 == STATUS_PORT_CONNECTION_REFUSED;
    reached.then(|| format!("connect {:#010x}", st as u32))
}

fn check(name: &str, result: impl std::fmt::Display) {
    println!("reach-check {name} {result}");
}

/// `reach:<file>:<loopback port>:<external ip>:<external port>`.
pub(super) fn reach(arg: &str) -> String {
    let mut parts = arg.rsplitn(4, ':');
    let (Some(ext_port), Some(ext_ip), Some(port), Some(file)) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return "bad arguments: reach:<file>:<loopback port>:<external ip>:<external port>".into();
    };
    // Late loads: what a DLL the process had not loaded before the revert
    // gets (Firecracker loads what it uses before it, its preload).
    for dll in ["version.dll", "dbghelp.dll"] {
        // SAFETY: a NUL-terminated name.
        let h = unsafe { LoadLibraryW(wide(dll).as_ptr()) };
        check(&format!("load-library-after-revert {dll}"), if h.is_null() { last() } else { "allowed".into() });
    }
    for (name, sub) in [("hklm-read", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"), ("hklm-system-read", r"SYSTEM\CurrentControlSet\Control")] {
        let mut k = 0usize;
        // SAFETY: a NUL-terminated subkey; KEY_READ; an out-pointer.
        let e = unsafe { RegOpenKeyExW(HKLM, wide(sub).as_ptr(), 0, KEY_READ, &mut k) };
        if e == 0 {
            // SAFETY: the key just opened.
            unsafe { RegCloseKey(k) };
        }
        check(name, if e == 0 { "allowed".into() } else { format!("denied {e}") });
    }
    // IP: connects only; nothing is sent.
    check("tcp-loopback", ip_check(&format!("127.0.0.1:{port}"), true));
    check("tcp-link-local-metadata", ip_check("169.254.169.254:80", true));
    check(&format!("tcp-external {ext_ip}:{ext_port}"), ip_check(&format!("{ext_ip}:{ext_port}"), true));
    // AF_UNIX: a socket bound in the jail's own directory.
    let sock = format!("reach-{}.sock", std::process::id());
    let mut data = [0u8; 512];
    // SAFETY: room for WSADATA; plain Winsock calls on a socket made here.
    let r = unsafe {
        WSAStartup(0x0202, data.as_mut_ptr());
        let s = socket(1, 1, 0);
        if s == usize::MAX {
            format!("denied socket {}", WSAGetLastError())
        } else {
            let mut addr = [0u8; 110];
            addr[0] = 1;
            addr[2..2 + sock.len()].copy_from_slice(sock.as_bytes());
            let rc = bind(s, addr.as_ptr(), addr.len() as i32);
            let e = WSAGetLastError();
            closesocket(s);
            if rc == 0 { "allowed".to_string() } else { format!("denied bind {e}") }
        }
    };
    let _ = std::fs::remove_file(&sock);
    check("unix-socket-bind", r);
    // Names in the global namespaces: a named pipe and a mailslot made.
    let pipe = format!(r"\\.\pipe\wick-reach-{}", std::process::id());
    // SAFETY: a NUL-terminated name; PIPE_ACCESS_DUPLEX, byte mode, one instance.
    let h = H(unsafe { CreateNamedPipeW(wide(&pipe).as_ptr(), 3, 0, 1, 512, 512, 0, null()) });
    check("named-pipe-create", if h.0 != INVALID { "allowed".into() } else { last() });
    drop(h);
    let slot = format!(r"\\.\mailslot\wick-reach-{}", std::process::id());
    // SAFETY: a NUL-terminated name.
    let h = H(unsafe { CreateMailslotW(wide(&slot).as_ptr(), 0, 0, null()) });
    check("mailslot-create", if h.0 != INVALID { "allowed".into() } else { last() });
    drop(h);
    check(
        "named-pipe-list",
        match std::fs::read_dir(r"\\.\pipe\") {
            Ok(rd) => format!("allowed {} names", rd.count()),
            Err(e) => format!("denied {e}"),
        },
    );
    // Every name the operator listed.
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => return format!("denied: the list {file}: {e}"),
    };
    let mut by_type = std::collections::BTreeMap::<String, (usize, usize)>::new();
    for l in text.lines() {
        let Some((ty, path)) = l.split_once('\t') else { continue };
        let e = by_type.entry(ty.to_string()).or_default();
        e.0 += 1;
        let reached = match ty {
            "Pipe" => nt_open(&format!("\\Device\\NamedPipe\\{path}"), MAXIMUM_ALLOWED, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT)
                .ok()
                .map(|h| format!("granted {:#x}", granted(h.0))),
            "Mailslot" => nt_open(&format!("\\Device\\Mailslot\\{path}"), MAXIMUM_ALLOWED, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT)
                .ok()
                .map(|h| format!("granted {:#x}", granted(h.0))),
            "ALPC Port" => alpc_reach(path),
            "Device" => device_reach(path),
            _ => open_object(ty, path, MAXIMUM_ALLOWED).ok().map(|h| format!("granted {:#x}", granted(h.0))),
        };
        if let Some(r) = reached {
            e.1 += 1;
            println!("reach {ty}\t{path}\t{r}");
        }
    }
    let (mut tried, mut reached) = (0, 0);
    for (ty, (t, r)) in &by_type {
        println!("reach-summary {ty} tried {t} reached {r}");
        tried += t;
        reached += r;
    }
    format!("done {reached} of {tried} names reached")
}
