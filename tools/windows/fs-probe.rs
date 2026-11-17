// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! A measuring tool, not product code: what a confined virtio-fs server
//! (wick-fsd, docs/design-fs.md §6.3) could reach and do on a Windows host,
//! under each confinement considered for it. The answers go to the Windows
//! owner's notes on design-fs (fs-q8-answers.md).
//!
//! ```text
//! fs-probe run [<base>]   the whole measurement, as an elevated
//!                         administrator; <base> (default
//!                         C:\w4\fsprobe-<pid>) must not exist and must be
//!                         outside the user's profile
//! fs-probe ea <dir>       EA and stream limits of the volume of <dir>
//! ```
//!
//! The run builds one share and one outside directory under `<base>`. It
//! then starts this program again as a child under each confinement, one
//! after another:
//! - base: a plain process of the user, the control;
//! - lpac-ace: LPAC, with an ACE for its SID on the share;
//! - lpac-label: LPAC, with the ACE and a low label on the share;
//! - lpac-label-nomit: lpac-label without the Job and mitigations;
//! - other-low, other-ac: on the labelled share, a plain low-integrity
//!   process of the user and another AppContainer, which have no ACE of
//!   their own;
//! - restricted: a medium-integrity restricted token whose only restricting
//!   SID is the share's own, with an ACE for that SID and no label;
//! - restricted-nomit: restricted without the Job and mitigations.
//!
//! Each child prints one line per check: `<confinement> <check> <result>`.
//!
//! After each child, the run takes the ACE and the label off again, then
//! checks every object of the share for any SID it granted and for any
//! label. At the end it checks the files and registry keys a child may have
//! left outside, checks that the security of `<base>`'s parent is unchanged,
//! and removes `<base>`. Every grant and every clean-up is printed.
//!
//! No dependencies. Build it with
//! `rustc --edition 2021 -O -C target-feature=+crt-static fs-probe.rs`: the
//! LPAC child must load nothing from outside System32.

#![allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]

use std::ffi::c_void;
use std::io::{BufRead, Write};
use std::ptr::{null, null_mut};

type HANDLE = *mut c_void;
type PSID = *mut c_void;
const INVALID: HANDLE = -1isize as HANDLE;

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
#[repr(C)]
#[derive(Clone, Copy)]
struct SID_AND_ATTRIBUTES {
    sid: PSID,
    attributes: u32,
}
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
#[repr(C)]
struct STARTUPINFOEXW {
    si: STARTUPINFOW,
    attrs: *mut c_void,
}
#[repr(C)]
struct PROCESS_INFORMATION {
    process: HANDLE,
    thread: HANDLE,
    pid: u32,
    tid: u32,
}
#[repr(C)]
struct SECURITY_CAPABILITIES {
    sid: PSID,
    caps: *mut SID_AND_ATTRIBUTES,
    count: u32,
    reserved: u32,
}
#[repr(C)]
struct SECURITY_ATTRIBUTES {
    len: u32,
    sd: *mut c_void,
    inherit: i32,
}
#[repr(C)]
struct LUID_AND_ATTRIBUTES {
    luid: u64,
    attributes: u32,
}
#[repr(C)]
struct TOKEN_PRIVILEGES1 {
    count: u32,
    privilege: LUID_AND_ATTRIBUTES,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateFile(
        h: *mut HANDLE,
        access: u32,
        oa: *const OBJECT_ATTRIBUTES,
        io: *mut IO_STATUS_BLOCK,
        alloc: *const i64,
        attrs: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const c_void,
        ea_len: u32,
    ) -> i32;
    fn NtSetEaFile(h: HANDLE, io: *mut IO_STATUS_BLOCK, buf: *const c_void, len: u32) -> i32;
    fn NtQueryEaFile(
        h: HANDLE,
        io: *mut IO_STATUS_BLOCK,
        buf: *mut c_void,
        len: u32,
        single: u8,
        list: *const c_void,
        list_len: u32,
        index: *const u32,
        restart: u8,
    ) -> i32;
    fn NtQueryInformationFile(h: HANDLE, io: *mut IO_STATUS_BLOCK, buf: *mut c_void, len: u32, class: u32) -> i32;
    fn NtSetInformationFile(h: HANDLE, io: *mut IO_STATUS_BLOCK, buf: *const c_void, len: u32, class: u32) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn CloseHandle(h: HANDLE) -> i32;
    fn GetCurrentProcess() -> HANDLE;
    fn GetLastError() -> u32;
    fn GetStdHandle(which: u32) -> HANDLE;
    fn SetHandleInformation(h: HANDLE, mask: u32, flags: u32) -> i32;
    fn WaitForSingleObject(h: HANDLE, ms: u32) -> u32;
    fn GetExitCodeProcess(h: HANDLE, code: *mut u32) -> i32;
    fn CreateProcessW(
        app: *const u16,
        cmd: *mut u16,
        psa: *const c_void,
        tsa: *const c_void,
        inherit: i32,
        flags: u32,
        env: *const c_void,
        cwd: *const u16,
        si: *const STARTUPINFOW,
        pi: *mut PROCESS_INFORMATION,
    ) -> i32;
    fn ResumeThread(h: HANDLE) -> u32;
    fn TerminateProcess(h: HANDLE, code: u32) -> i32;
    fn InitializeProcThreadAttributeList(list: *mut c_void, count: u32, flags: u32, size: *mut usize) -> i32;
    fn UpdateProcThreadAttribute(
        list: *mut c_void,
        flags: u32,
        attr: usize,
        value: *const c_void,
        size: usize,
        prev: *mut c_void,
        ret: *const usize,
    ) -> i32;
    fn DeleteProcThreadAttributeList(list: *mut c_void);
    fn DuplicateHandle(src: HANDLE, h: HANDLE, dst: HANDLE, out: *mut HANDLE, access: u32, inherit: i32, opts: u32) -> i32;
    fn CreatePipe(read: *mut HANDLE, write: *mut HANDLE, sa: *const SECURITY_ATTRIBUTES, size: u32) -> i32;
    fn WriteFile(h: HANDLE, buf: *const u8, n: u32, written: *mut u32, ov: *mut c_void) -> i32;
    fn ReadFile(h: HANDLE, buf: *mut u8, n: u32, read: *mut u32, ov: *mut c_void) -> i32;
    fn CreateFileW(name: *const u16, access: u32, share: u32, sa: *const c_void, disp: u32, flags: u32, template: HANDLE) -> HANDLE;
    fn DeleteFileW(name: *const u16) -> i32;
    fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> HANDLE;
    fn CreateNamedPipeW(name: *const u16, mode: u32, pmode: u32, max: u32, out: u32, inn: u32, timeout: u32, sa: *const c_void) -> HANDLE;
    fn CreateEventW(sa: *const c_void, manual: i32, initial: i32, name: *const u16) -> HANDLE;
    fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> HANDLE;
    fn LoadLibraryW(name: *const u16) -> HANDLE;
    fn GetProcAddress(module: HANDLE, name: *const u8) -> *const c_void;
    fn CreateJobObjectW(sa: *const c_void, name: *const u16) -> HANDLE;
    fn SetInformationJobObject(job: HANDLE, class: i32, info: *const c_void, len: u32) -> i32;
    fn AssignProcessToJobObject(job: HANDLE, process: HANDLE) -> i32;
    fn SetProcessMitigationPolicy(policy: i32, buf: *const c_void, len: usize) -> i32;
    fn GetVolumeInformationByHandleW(
        h: HANDLE,
        name: *mut u16,
        name_len: u32,
        serial: *mut u32,
        max_component: *mut u32,
        flags: *mut u32,
        fs: *mut u16,
        fs_len: u32,
    ) -> i32;
    fn DeviceIoControl(h: HANDLE, code: u32, inb: *const c_void, inl: u32, outb: *mut c_void, outl: u32, ret: *mut u32, ov: *mut c_void) -> i32;
    fn SetFileShortNameW(h: HANDLE, name: *const u16) -> i32;
    fn GetShortPathNameW(long: *const u16, short: *mut u16, len: u32) -> u32;
    fn SetFileAttributesW(name: *const u16, attrs: u32) -> i32;
    fn LocalFree(p: *mut c_void) -> *mut c_void;
    fn Sleep(ms: u32);
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> i32;
    fn DuplicateTokenEx(t: HANDLE, access: u32, sa: *const c_void, level: i32, ty: i32, out: *mut HANDLE) -> i32;
    fn CreateRestrictedToken(
        t: HANDLE,
        flags: u32,
        ndisable: u32,
        disable: *const SID_AND_ATTRIBUTES,
        ndelete: u32,
        delete: *const c_void,
        nrestrict: u32,
        restrict: *const SID_AND_ATTRIBUTES,
        out: *mut HANDLE,
    ) -> i32;
    fn SetTokenInformation(t: HANDLE, class: i32, info: *const c_void, len: u32) -> i32;
    fn GetTokenInformation(t: HANDLE, class: i32, info: *mut c_void, len: u32, needed: *mut u32) -> i32;
    fn ConvertStringSidToSidW(s: *const u16, sid: *mut PSID) -> i32;
    fn ConvertSidToStringSidW(sid: PSID, s: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(s: *const u16, rev: u32, sd: *mut *mut c_void, len: *mut u32) -> i32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(sd: *mut c_void, rev: u32, info: u32, s: *mut *mut u16, len: *mut u32) -> i32;
    fn GetSecurityDescriptorDacl(sd: *mut c_void, present: *mut i32, dacl: *mut *mut c_void, defaulted: *mut i32) -> i32;
    fn GetSecurityDescriptorSacl(sd: *mut c_void, present: *mut i32, sacl: *mut *mut c_void, defaulted: *mut i32) -> i32;
    fn SetNamedSecurityInfoW(name: *const u16, ty: u32, info: u32, owner: PSID, group: PSID, dacl: *const c_void, sacl: *const c_void) -> u32;
    fn GetNamedSecurityInfoW(
        name: *const u16,
        ty: u32,
        info: u32,
        owner: *mut PSID,
        group: *mut PSID,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        sd: *mut *mut c_void,
    ) -> u32;
    fn CreateProcessAsUserW(
        t: HANDLE,
        app: *const u16,
        cmd: *mut u16,
        psa: *const c_void,
        tsa: *const c_void,
        inherit: i32,
        flags: u32,
        env: *const c_void,
        cwd: *const u16,
        si: *const STARTUPINFOW,
        pi: *mut PROCESS_INFORMATION,
    ) -> i32;
    fn SetThreadToken(thread: *mut HANDLE, token: HANDLE) -> i32;
    fn RevertToSelf() -> i32;
    fn RegOpenKeyExW(key: usize, sub: *const u16, opts: u32, access: u32, out: *mut usize) -> i32;
    fn RegCreateKeyExW(
        key: usize,
        sub: *const u16,
        reserved: u32,
        class: *const u16,
        opts: u32,
        access: u32,
        sa: *const c_void,
        out: *mut usize,
        disp: *mut u32,
    ) -> i32;
    fn RegDeleteKeyW(key: usize, sub: *const u16) -> i32;
    fn RegCloseKey(key: usize) -> i32;
    fn LookupPrivilegeNameW(system: *const u16, luid: *const u64, name: *mut u16, len: *mut u32) -> i32;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut u64) -> i32;
    fn AdjustTokenPrivileges(t: HANDLE, disable_all: i32, new: *const TOKEN_PRIVILEGES1, len: u32, prev: *mut c_void, ret: *mut u32) -> i32;
    fn InitializeAcl(acl: *mut c_void, len: u32, rev: u32) -> i32;
    fn GetLengthSid(sid: PSID) -> u32;
}

#[link(name = "ws2_32")]
extern "system" {
    fn WSAStartup(version: u16, data: *mut u8) -> i32;
    fn socket(af: i32, ty: i32, proto: i32) -> usize;
    fn bind(s: usize, addr: *const u8, len: i32) -> i32;
    fn listen(s: usize, backlog: i32) -> i32;
    fn accept(s: usize, addr: *mut u8, len: *mut i32) -> usize;
    fn connect(s: usize, addr: *const u8, len: i32) -> i32;
    fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32;
    fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32;
    fn closesocket(s: usize) -> i32;
    fn setsockopt(s: usize, level: i32, name: i32, val: *const u8, len: i32) -> i32;
    fn getsockname(s: usize, addr: *mut u8, len: *mut i32) -> i32;
    fn WSAGetLastError() -> i32;
}

// Access rights and flags (winnt.h, ntifs.h, winbase.h).
const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_READ_EA: u32 = 0x8;
const FILE_WRITE_EA: u32 = 0x10;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const DELETE: u32 = 0x1_0000;
const SYNCHRONIZE: u32 = 0x10_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_OPEN_BY_FILE_ID: u32 = 0x2000;
const FILE_OPEN_REPARSE_POINT: u32 = 0x20_0000;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_DONT_REPARSE: u32 = 0x1000;
const SHARE_ALL: u32 = 7;
const OPEN_EXISTING: u32 = 3;
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const SE_FILE_OBJECT: u32 = 1;
const DACL_INFO: u32 = 0x4;
const LABEL_INFO: u32 = 0x10;
const PROTECTED_DACL: u32 = 0x8000_0000;
const HKLM: usize = 0x8000_0002;
const HKCU: usize = 0x8000_0001;
/// Modify (icacls `M`): read, write, execute and delete.
const MODIFY: u32 = 0x1301BF;

/// The NT file information classes used here (ntifs.h).
const FILE_NAME_INFORMATION: u32 = 9;
const FILE_ATTRIBUTE_TAG_INFORMATION: u32 = 35;
const FILE_NORMALIZED_NAME_INFORMATION: u32 = 48;
const FILE_ID_INFORMATION: u32 = 59;
const FILE_DISPOSITION_INFORMATION_EX: u32 = 64;
const FILE_RENAME_INFORMATION_EX: u32 = 65;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn last() -> String {
    // SAFETY: plain call.
    format!("denied {}", unsafe { GetLastError() })
}

fn status(st: i32) -> String {
    format!("denied {:#010x}", st as u32)
}

/// A handle closed on drop.
struct H(HANDLE);
impl Drop for H {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID {
            // SAFETY: a handle this program owns.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// `NtCreateFile` of `name` beneath `root`, synchronous.
fn nt_open_raw(root: HANDLE, name: &[u16], access: u32, disp: u32, opts: u32, attrs: u32) -> Result<H, i32> {
    let bytes = u16::try_from(name.len() * 2).unwrap();
    let us = UNICODE_STRING { len: bytes, max: bytes, buf: name.as_ptr() };
    let oa = OBJECT_ATTRIBUTES {
        len: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        root,
        name: &us,
        attrs,
        sd: null_mut(),
        qos: null_mut(),
    };
    let mut h = null_mut();
    let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
    // SAFETY: valid structures for the call's duration.
    let st = unsafe {
        NtCreateFile(&mut h, access | SYNCHRONIZE, &oa, &mut io, null(), 0x80, SHARE_ALL, disp, opts | FILE_SYNCHRONOUS_IO_NONALERT, null(), 0)
    };
    if st < 0 { Err(st) } else { Ok(H(h)) }
}

fn nt_open(root: HANDLE, name: &str, access: u32, disp: u32, opts: u32, attrs: u32) -> Result<H, i32> {
    let n: Vec<u16> = name.encode_utf16().collect();
    nt_open_raw(root, &n, access, disp, opts, attrs)
}

fn query(h: HANDLE, class: u32, buf: &mut [u64]) -> Result<usize, i32> {
    let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
    // SAFETY: a buffer of the length given.
    let st = unsafe { NtQueryInformationFile(h, &mut io, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, class) };
    if st < 0 { Err(st) } else { Ok(io.info) }
}

fn set_info(h: HANDLE, class: u32, buf: &[u8]) -> Result<(), i32> {
    let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
    // SAFETY: a buffer of the length given.
    let st = unsafe { NtSetInformationFile(h, &mut io, buf.as_ptr().cast(), buf.len() as u32, class) };
    if st < 0 { Err(st) } else { Ok(()) }
}

/// (volume serial, 128-bit file id) of `h`.
fn file_id(h: HANDLE) -> Result<(u64, u128), i32> {
    let mut b = [0u64; 3];
    query(h, FILE_ID_INFORMATION, &mut b)?;
    Ok((b[0], u128::from(b[1]) | (u128::from(b[2]) << 64)))
}

/// (attributes, reparse tag) of `h`.
fn tag(h: HANDLE) -> Result<(u32, u32), i32> {
    let mut b = [0u64; 1];
    query(h, FILE_ATTRIBUTE_TAG_INFORMATION, &mut b)?;
    Ok((b[0] as u32, (b[0] >> 32) as u32))
}

/// A FILE_NAME_INFORMATION-shaped answer as a string.
fn name_of(h: HANDLE, class: u32) -> Result<String, i32> {
    let mut b = [0u64; 512];
    query(h, class, &mut b)?;
    let len = (b[0] as u32) as usize / 2;
    // SAFETY: the name's UTF-16 units follow the 4-byte length.
    let units = unsafe { std::slice::from_raw_parts(b.as_ptr().cast::<u16>().add(2), len.min(2040)) };
    Ok(String::from_utf16_lossy(units))
}

fn last_component(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

/// `FileDispositionInformationEx`: delete (POSIX semantics, ignoring the
/// read-only attribute).
fn dispose(h: HANDLE) -> Result<(), i32> {
    set_info(h, FILE_DISPOSITION_INFORMATION_EX, &(0x1u32 | 0x2 | 0x10).to_le_bytes())
}

/// `FileRenameInformationEx` (POSIX semantics) to `name` beneath `root`.
fn rename(h: HANDLE, root: HANDLE, name: &str) -> Result<(), i32> {
    let n: Vec<u16> = name.encode_utf16().collect();
    let mut buf = vec![0u8; 20 + n.len() * 2 + 2];
    buf[0..4].copy_from_slice(&2u32.to_le_bytes());
    buf[8..16].copy_from_slice(&(root as usize as u64).to_le_bytes());
    buf[16..20].copy_from_slice(&((n.len() * 2) as u32).to_le_bytes());
    for (i, u) in n.iter().enumerate() {
        buf[20 + 2 * i..22 + 2 * i].copy_from_slice(&u.to_le_bytes());
    }
    set_info(h, FILE_RENAME_INFORMATION_EX, &buf)
}

/// One FILE_FULL_EA_INFORMATION entry, `next` its NextEntryOffset.
fn ea_entry(name: &str, value: &[u8], next: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9 + name.len() + value.len());
    buf.extend_from_slice(&next.to_le_bytes());
    buf.push(0);
    buf.push(name.len() as u8);
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(name.as_bytes());
    buf.push(0);
    buf.extend_from_slice(value);
    buf
}

fn set_ea(h: HANDLE, buf: &[u8]) -> Result<(), i32> {
    let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
    // SAFETY: a buffer of the length given.
    let st = unsafe { NtSetEaFile(h, &mut io, buf.as_ptr().cast(), buf.len() as u32) };
    if st < 0 { Err(st) } else { Ok(()) }
}

fn read_ea(h: HANDLE) -> Result<usize, i32> {
    let mut buf = vec![0u64; 9000];
    let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
    // SAFETY: a buffer of the length given.
    let st = unsafe { NtQueryEaFile(h, &mut io, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, 0, null(), 0, null(), 1) };
    if st < 0 { Err(st) } else { Ok(io.info) }
}

fn sid(s: &str) -> PSID {
    let mut p = null_mut();
    // SAFETY: a NUL-terminated string and an out-pointer.
    if unsafe { ConvertStringSidToSidW(wide(s).as_ptr(), &mut p) } == 0 {
        panic!("SID {s}: {}", last());
    }
    p
}

fn sid_string(p: PSID) -> String {
    let mut s = null_mut();
    // SAFETY: a valid SID; the string is LocalAlloc'd.
    unsafe {
        if ConvertSidToStringSidW(p, &mut s) == 0 {
            return "?".into();
        }
        let mut n = 0;
        while *s.add(n) != 0 {
            n += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
        LocalFree(s.cast());
        out
    }
}

fn token_info(t: HANDLE, class: i32) -> Vec<u64> {
    let mut buf = vec![0u64; 1024];
    let mut needed = 0;
    // SAFETY: a buffer of the length given.
    unsafe { GetTokenInformation(t, class, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut needed) };
    buf
}

/// The SID a TOKEN_USER (class 1) or TOKEN_MANDATORY_LABEL (25) begins with.
fn token_sid(t: HANDLE, class: i32) -> String {
    let b = token_info(t, class);
    sid_string(b[0] as usize as PSID)
}

/// The SDDL of a security descriptor's parts `info`.
fn sddl_of(sd: *mut c_void, info: u32) -> String {
    let mut s = null_mut();
    let mut len = 0;
    // SAFETY: a valid descriptor; the string is LocalAlloc'd.
    unsafe {
        if ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, info, &mut s, &mut len) == 0 {
            return format!("? {}", GetLastError());
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, len as usize).split(|&c| c == 0).next().unwrap());
        LocalFree(s.cast());
        out
    }
}

/// The DACL and label of a file's security descriptor, as SDDL.
fn file_sddl(path: &str) -> String {
    let (mut dacl, mut sacl, mut sd) = (null_mut(), null_mut(), null_mut());
    // SAFETY: out-pointers; the descriptor is LocalAlloc'd.
    let err = unsafe {
        GetNamedSecurityInfoW(wide(path).as_ptr(), SE_FILE_OBJECT, DACL_INFO | LABEL_INFO, null_mut(), null_mut(), &mut dacl, &mut sacl, &mut sd)
    };
    if err != 0 {
        return format!("? {err}");
    }
    let s = sddl_of(sd, DACL_INFO | LABEL_INFO);
    // SAFETY: allocated by the call.
    unsafe { LocalFree(sd) };
    s
}

/// A security descriptor from SDDL (leaked: the program is short-lived).
fn sd_from(sddl: &str) -> *mut c_void {
    let mut sd = null_mut();
    // SAFETY: NUL-terminated SDDL and an out-pointer.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sddl).as_ptr(), 1, &mut sd, null_mut()) } == 0 {
        panic!("SDDL {sddl}: {}", last());
    }
    sd
}

/// Sets a file's DACL (protected) from SDDL, propagated to its children.
fn set_dacl(path: &str, sddl: &str) -> u32 {
    let sd = sd_from(sddl);
    let (mut present, mut dacl, mut def) = (0, null_mut(), 0);
    // SAFETY: a descriptor from the conversion above.
    unsafe {
        GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut def);
        SetNamedSecurityInfoW(wide(path).as_ptr(), SE_FILE_OBJECT, DACL_INFO | PROTECTED_DACL, null_mut(), null_mut(), dacl, null())
    }
}

/// Sets a file's mandatory label, propagated; `None` removes it.
fn set_label(path: &str, label: Option<&str>) -> u32 {
    let mut empty = [0u64; 4];
    let sacl: *mut c_void = match label {
        Some(l) => {
            let sd = sd_from(l);
            let (mut present, mut sacl, mut def) = (0, null_mut(), 0);
            // SAFETY: a descriptor from the conversion.
            unsafe { GetSecurityDescriptorSacl(sd, &mut present, &mut sacl, &mut def) };
            sacl
        }
        None => {
            // SAFETY: a buffer of 32 bytes for an empty ACL.
            unsafe { InitializeAcl(empty.as_mut_ptr().cast(), 32, 2) };
            empty.as_mut_ptr().cast()
        }
    };
    // SAFETY: a valid ACL.
    unsafe { SetNamedSecurityInfoW(wide(path).as_ptr(), SE_FILE_OBJECT, LABEL_INFO, null_mut(), null_mut(), null(), sacl) }
}

fn create_file(path: &str, data: &[u8]) {
    std::fs::write(path, data).unwrap_or_else(|e| panic!("{path}: {e}"));
}

/// A file with its own protected DACL.
fn create_file_sd(path: &str, data: &[u8], sddl: &str) {
    create_file(path, data);
    let e = set_dacl(path, sddl);
    assert_eq!(e, 0, "DACL of {path}");
}

fn file_id_of_path(path: &str) -> (u64, u128) {
    // SAFETY: NUL-terminated path.
    let h = H(unsafe {
        CreateFileW(wide(path).as_ptr(), FILE_READ_ATTRIBUTES, SHARE_ALL, null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, null_mut())
    });
    file_id(h.0).unwrap_or_else(|s| panic!("id of {path}: {s:#x}"))
}

// ----------------------------------------------------------------------------
// The child: what one confinement reaches.

struct Child {
    scn: String,
    base: String,
    root: HANDLE,
    secret_id: u64,
    share_id: u64,
    parent: u32,
    dummy: u32,
    tcp_port: u16,
    pid_tag: String,
}

impl Child {
    fn out(&self, check: &str, result: impl AsRef<str>) {
        let mut o = std::io::stdout().lock();
        let _ = writeln!(o, "{} {} {}", self.scn, check, result.as_ref());
        let _ = o.flush();
    }

    fn open(&self, check: &str, name: &str, access: u32, disp: u32, opts: u32, attrs: u32) -> Option<H> {
        match nt_open(self.root, name, access, disp, opts, attrs) {
            Ok(h) => Some(h),
            Err(st) => {
                self.out(check, status(st));
                None
            }
        }
    }

    fn token(&self) {
        let mut t = null_mut();
        // SAFETY: our own token.
        unsafe { OpenProcessToken(GetCurrentProcess(), 0x8, &mut t) };
        let t = H(t);
        let il = token_sid(t.0, 25);
        let ac = token_info(t.0, 29)[0] as u32;
        let restricted = token_info(t.0, 11)[0] as u32;
        let privs = token_info(t.0, 3);
        let count = privs[0] as u32 as usize;
        let mut names = Vec::new();
        for i in 0..count {
            // SAFETY: LUID_AND_ATTRIBUTES entries of 12 bytes follow the count.
            let luid = unsafe { std::ptr::read_unaligned(privs.as_ptr().cast::<u8>().add(4 + 12 * i).cast::<u64>()) };
            let mut name = [0u16; 64];
            let mut len = 64u32;
            // SAFETY: a LUID and a buffer.
            if unsafe { LookupPrivilegeNameW(null(), &luid, name.as_mut_ptr(), &mut len) } != 0 {
                names.push(String::from_utf16_lossy(&name[..len as usize]));
            }
        }
        self.out("token", format!("integrity {il} appcontainer {ac} restricting-sids {restricted} privileges {}", names.join(",")));
    }

    fn mitigate(&self) {
        // ProcessDynamicCodePolicy 2, StrictHandleCheck 3, SystemCallDisable
        // (win32k) 4, ExtensionPointDisable 6, Signature 8, ImageLoad 10,
        // ChildProcess 13: wick's profile (overlay/vmm/ext/sandbox.rs).
        for (name, policy, flags) in [
            ("extension-points", 6, 1u32),
            ("signature", 8, 1),
            ("strict-handles", 3, 0b11),
            ("win32k", 4, 1),
            ("child-process", 13, 1),
            ("image-load", 10, 0b111),
            ("dynamic-code", 2, 1),
        ] {
            // SAFETY: a flags word of 4 bytes.
            let ok = unsafe { SetProcessMitigationPolicy(policy, (&raw const flags).cast(), 4) };
            self.out(&format!("mitigation-{name}"), if ok != 0 { "allowed".into() } else { last() });
        }
    }

    fn share(&self) {
        let s = &self.scn;
        let r = self.root;
        // Read, by a relative open beneath the node handle.
        if let Some(h) = self.open("share-read", "f.txt", FILE_READ_DATA, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
            let mut b = [0u8; 16];
            let mut n = 0;
            // SAFETY: a buffer of 16 bytes.
            let ok = unsafe { ReadFile(h.0, b.as_mut_ptr(), 16, &mut n, null_mut()) };
            self.out("share-read", if ok != 0 { format!("allowed {n} bytes") } else { last() });
        }
        // The same file by its full path (traversal from the drive root).
        let path = format!("{}\\share\\f.txt", self.base);
        // SAFETY: NUL-terminated path.
        let h = H(unsafe { CreateFileW(wide(&path).as_ptr(), GENERIC_READ, SHARE_ALL, null(), OPEN_EXISTING, 0, null_mut()) });
        self.out("share-read-by-path", if h.0 != INVALID { "allowed".into() } else { last() });
        // Create, write.
        if let Some(h) = self.open("share-create", &format!("n-{s}.txt"), FILE_WRITE_DATA, FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
            let mut n = 0;
            // SAFETY: two bytes.
            let ok = unsafe { WriteFile(h.0, b"x\n".as_ptr(), 2, &mut n, null_mut()) };
            self.out("share-create", if ok != 0 { "allowed".into() } else { last() });
        }
        if let Some(h) = self.open("share-write", &format!("w-{s}.txt"), FILE_WRITE_DATA, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
            let mut n = 0;
            // SAFETY: two bytes.
            let ok = unsafe { WriteFile(h.0, b"y\n".as_ptr(), 2, &mut n, null_mut()) };
            self.out("share-write", if ok != 0 { "allowed".into() } else { last() });
        }
        // The metadata record as an EA, written then read back.
        if let Some(h) = self.open("share-ea-write", &format!("w-{s}.txt"), FILE_WRITE_EA, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
            let rec = [0x5au8; 40];
            self.out("share-ea-write", match set_ea(h.0, &ea_entry("WICK.STAT", &rec, 0)) {
                Ok(()) => "allowed".into(),
                Err(st) => status(st),
            });
        }
        if let Some(h) = self.open("share-ea-read", &format!("w-{s}.txt"), FILE_READ_EA, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
            self.out("share-ea-read", match read_ea(h.0) {
                Ok(n) => format!("allowed {n} bytes"),
                Err(st) => status(st),
            });
        }
        if let Some(_h) = self.open("share-mkdir", &format!("d-{s}"), FILE_READ_ATTRIBUTES, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
            self.out("share-mkdir", "allowed");
        }
        // Unlink with the identity checked on the handle that deletes.
        for (check, name) in [("share-unlink-expect", format!("del-{s}.txt")), ("share-unlink-readonly", format!("ro-{s}.txt"))] {
            let Some(look) = self.open(&check, &name, FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) else {
                continue;
            };
            let expect = file_id(look.0);
            drop(look);
            if let Some(h) = self.open(&check, &name, DELETE | FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
                let same = file_id(h.0) == expect && expect.is_ok();
                self.out(&check, match (same, dispose(h.0)) {
                    (true, Ok(())) => "allowed (identity checked on the deleting handle)".into(),
                    (false, _) => "identity changed".into(),
                    (_, Err(st)) => status(st),
                });
                drop(h);
                let gone = nt_open(r, &name, FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE).err();
                self.out(&format!("{check}-name-after"), match gone {
                    Some(st) => format!("gone {:#010x}", st as u32),
                    None => "still there".into(),
                });
            }
        }
        if let Some(h) = self.open("share-rename", &format!("ren-{s}.txt"), DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
            self.out("share-rename", match rename(h.0, r, &format!("ren2-{s}.txt")) {
                Ok(()) => "allowed".into(),
                Err(st) => status(st),
            });
        }
        // Objects an earlier LPAC child made (labelled low by Windows).
        if let Some(h) = self.open("share-write-lpac-made-file", "n-lpac-ace.txt", FILE_WRITE_DATA, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
            let mut n = 0;
            // SAFETY: two bytes.
            let ok = unsafe { WriteFile(h.0, b"q\n".as_ptr(), 2, &mut n, null_mut()) };
            self.out("share-write-lpac-made-file", if ok != 0 { "allowed".into() } else { last() });
        }
        if let Some(_h) = self.open("share-create-in-lpac-made-dir", &format!("d-lpac-ace\\c-{s}.txt"), FILE_WRITE_DATA, FILE_CREATE, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
            self.out("share-create-in-lpac-made-dir", "allowed");
        }
        if let Some(h) = self.open("share-rmdir", &format!("rd-{s}"), DELETE, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
            self.out("share-rmdir", match dispose(h.0) {
                Ok(()) => "allowed".into(),
                Err(st) => status(st),
            });
        }
    }

    fn names(&self) {
        let r = self.root;
        let root_id = file_id(r);
        // "." and "..": what the file system makes of them as NT names.
        for name in [".", ".."] {
            let check = format!("name-{}", if name == "." { "dot" } else { "dotdot" });
            if let Some(h) = self.open(&check, name, FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_OPEN_REPARSE_POINT, 0) {
                let id = file_id(h.0);
                self.out(&check, if id == root_id { "opened the root itself".to_string() } else { format!("opened another object {id:?}") });
            }
        }
        // DOS device names, trailing dot and space, a stream, two components.
        for (check, name) in [
            ("name-con", "CON"),
            ("name-nul-ext", "nul.txt"),
            ("name-trailing-dot", "t."),
            ("name-trailing-space", "t "),
            ("name-stream", "f.txt:s"),
            ("name-wildcard", "a*b"),
            ("name-two-components", "sub\\f2.txt"),
        ] {
            let create = check != "name-two-components";
            let disp = if create { FILE_CREATE } else { FILE_OPEN };
            let access = if create { FILE_WRITE_DATA | DELETE } else { FILE_READ_ATTRIBUTES };
            if let Some(h) = self.open(check, name, access, disp, FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
                let n = name_of(h.0, FILE_NORMALIZED_NAME_INFORMATION).map(|n| last_component(&n).to_string());
                self.out(check, format!("allowed as {n:?}"));
                if create {
                    let _ = dispose(h.0);
                }
            }
        }
        // Aliases: the 8.3 name and a case variant.
        for (check, name, attrs) in [
            ("alias-short", "LONGFI~1.TXT", OBJ_CASE_INSENSITIVE),
            ("alias-case-insensitive", "F.TXT", OBJ_CASE_INSENSITIVE),
            ("alias-case-sensitive", "F.TXT", 0),
        ] {
            if let Some(h) = self.open(check, name, FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_OPEN_REPARSE_POINT, attrs | OBJ_DONT_REPARSE) {
                let opened = name_of(h.0, FILE_NAME_INFORMATION).map(|n| last_component(&n).to_string());
                let norm = name_of(h.0, FILE_NORMALIZED_NAME_INFORMATION).map(|n| last_component(&n).to_string());
                self.out(check, format!("allowed name {opened:?} normalized {norm:?}"));
            }
        }
        // Open by file id, relative to the share's handle: an outside file
        // and a file of the share.
        for (check, id) in [("by-id-outside", self.secret_id), ("by-id-share", self.share_id)] {
            let units: Vec<u16> = id.to_le_bytes().chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            match nt_open_raw(r, &units, FILE_READ_DATA, FILE_OPEN, FILE_OPEN_BY_FILE_ID | FILE_NON_DIRECTORY_FILE, 0) {
                Ok(_) => self.out(check, "allowed"),
                Err(st) => self.out(check, status(st)),
            }
        }
    }

    fn reparse(&self) {
        for link in ["jn", "sl", "sld"] {
            if let Some(h) = self.open(&format!("{link}-open-link"), link, FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_OPEN_REPARSE_POINT, OBJ_DONT_REPARSE) {
                self.out(&format!("{link}-open-link"), format!("allowed tag {:?}", tag(h.0).map(|(a, t)| format!("attrs {a:#x} tag {t:#010x}"))));
            }
            for (check, attrs) in [(format!("{link}-follow"), 0), (format!("{link}-follow-dont-reparse"), OBJ_DONT_REPARSE)] {
                if let Some(_h) = self.open(&check, link, FILE_READ_ATTRIBUTES, FILE_OPEN, 0, attrs) {
                    self.out(&check, "allowed");
                }
            }
            if link == "sl" {
                continue;
            }
            for (file, attrs, suffix) in [
                ("secret.txt", 0, "secret"),
                ("secret.txt", OBJ_DONT_REPARSE, "secret-dont-reparse"),
                ("public.txt", 0, "public"),
            ] {
                let check = format!("{link}-through-{suffix}");
                if let Some(_h) = self.open(&check, &format!("{link}\\{file}"), FILE_READ_DATA, FILE_OPEN, FILE_NON_DIRECTORY_FILE, attrs) {
                    self.out(&check, "allowed");
                }
            }
        }
    }

    fn sockets(&self, inherited: usize, dup: usize) {
        for (check, s) in [("sock-inherited", inherited), ("sock-duplicated", dup)] {
            if s == 0 {
                self.out(check, "no handle");
                continue;
            }
            // SAFETY: a connected socket handle this process holds.
            let r = unsafe {
                if send(s, b"ping".as_ptr(), 4, 0) != 4 {
                    Err(WSAGetLastError())
                } else {
                    let mut b = [0u8; 8];
                    let n = recv(s, b.as_mut_ptr(), 8, 0);
                    if n == 4 && &b[..4] == b"pong" { Ok(()) } else { Err(WSAGetLastError()) }
                }
            };
            self.out(check, match r {
                Ok(()) => "allowed (ping, pong)".into(),
                Err(e) => format!("denied wsa {e}"),
            });
        }
        // A new AF_UNIX socket, connected to a listener outside the share.
        // SAFETY: plain Winsock calls.
        let s = unsafe { socket(1, 1, 0) };
        if s == usize::MAX {
            // SAFETY: plain call.
            self.out("sock-new", format!("denied wsa {}", unsafe { WSAGetLastError() }));
        } else {
            let addr = unix_addr(&format!("{}\\l.sock", self.base));
            // SAFETY: a sockaddr_un of its size.
            let ok = unsafe { connect(s, addr.as_ptr(), addr.len() as i32) };
            // SAFETY: plain call.
            self.out("sock-new-connect-outside", if ok == 0 { "allowed".into() } else { format!("denied wsa {}", unsafe { WSAGetLastError() }) });
            // SAFETY: our socket.
            unsafe { closesocket(s) };
        }
        // Loopback TCP.
        // SAFETY: plain Winsock calls.
        let s = unsafe { socket(2, 1, 6) };
        if s == usize::MAX {
            // SAFETY: plain call.
            self.out("tcp-loopback", format!("denied wsa {}", unsafe { WSAGetLastError() }));
        } else {
            let mut a = [0u8; 16];
            a[0] = 2;
            a[2..4].copy_from_slice(&self.tcp_port.to_be_bytes());
            a[4..8].copy_from_slice(&[127, 0, 0, 1]);
            // SAFETY: a sockaddr_in.
            let ok = unsafe { connect(s, a.as_ptr(), 16) };
            // SAFETY: plain call.
            self.out("tcp-loopback", if ok == 0 { "allowed".into() } else { format!("denied wsa {}", unsafe { WSAGetLastError() }) });
            // SAFETY: our socket.
            unsafe { closesocket(s) };
        }
    }

    fn outside(&self) {
        let b = &self.base;
        for (check, path) in [
            ("outside-read-user-only", format!("{b}\\outside\\secret.txt")),
            ("outside-read-everyone", format!("{b}\\outside\\public.txt")),
            ("outside-read-restricted-sid", format!("{b}\\outside\\restricted.txt")),
            ("outside-read-null-dacl", format!("{b}\\outside\\nulldacl.txt")),
            ("outside-read-hosts", r"C:\Windows\System32\drivers\etc\hosts".to_string()),
            ("outside-read-win-ini", r"C:\Windows\win.ini".to_string()),
        ] {
            // SAFETY: NUL-terminated path.
            let h = H(unsafe { CreateFileW(wide(&path).as_ptr(), GENERIC_READ, SHARE_ALL, null(), OPEN_EXISTING, 0, null_mut()) });
            self.out(check, if h.0 != INVALID { "allowed".into() } else { last() });
        }
        let temp = std::env::var("TEMP").unwrap_or_default();
        for (check, dir) in [
            ("outside-write-users-public", r"C:\Users\Public".to_string()),
            ("outside-write-programdata", r"C:\ProgramData".to_string()),
            ("outside-write-windows-temp", r"C:\Windows\Temp".to_string()),
            ("outside-write-user-temp", temp),
            ("outside-write-base", b.clone()),
        ] {
            let path = format!("{dir}\\wick-fsprobe-{}-{}.txt", self.pid_tag, self.scn);
            // SAFETY: NUL-terminated path.
            let h = H(unsafe { CreateFileW(wide(&path).as_ptr(), GENERIC_WRITE | DELETE, SHARE_ALL, null(), CREATE_NEW, 0, null_mut()) });
            if h.0 != INVALID {
                drop(h);
                // SAFETY: NUL-terminated path.
                let del = unsafe { DeleteFileW(wide(&path).as_ptr()) };
                self.out(check, format!("allowed (removed: {}) {dir}", del != 0));
            } else {
                self.out(check, format!("{} {dir}", last()));
            }
        }
        // The registry.
        let mut k = 0usize;
        // SAFETY: an out-pointer.
        let e = unsafe { RegOpenKeyExW(HKLM, wide(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").as_ptr(), 0, 0x20019, &mut k) };
        self.out("registry-read-hklm", if e == 0 { "allowed".into() } else { format!("denied {e}") });
        if e == 0 {
            // SAFETY: the key just opened.
            unsafe { RegCloseKey(k) };
        }
        // SAFETY: an out-pointer.
        let e = unsafe { RegOpenKeyExW(HKCU, wide("Software").as_ptr(), 0, 0x20019, &mut k) };
        self.out("registry-read-hkcu", if e == 0 { "allowed".into() } else { format!("denied {e}") });
        if e == 0 {
            // SAFETY: the key just opened.
            unsafe { RegCloseKey(k) };
        }
        let sub = format!("Software\\wick-fsprobe-{}-{}", self.pid_tag, self.scn);
        let mut disp = 0;
        // SAFETY: out-pointers.
        let e = unsafe { RegCreateKeyExW(HKCU, wide(&sub).as_ptr(), 0, null(), 0, 0xF003F, null(), &mut k, &mut disp) };
        if e == 0 {
            // SAFETY: the key just made.
            unsafe { RegCloseKey(k) };
            // SAFETY: NUL-terminated name.
            let d = unsafe { RegDeleteKeyW(HKCU, wide(&sub).as_ptr()) };
            self.out("registry-write-hkcu", format!("allowed (removed: {})", d == 0));
        } else {
            self.out("registry-write-hkcu", format!("denied {e}"));
        }
        // Processes: the elevated parent and a plain medium process of the user.
        for (check, pid, access) in [
            ("process-parent-query", self.parent, 0x1000u32),
            ("process-user-query", self.dummy, 0x1000),
            ("process-user-dup-handle", self.dummy, 0x40),
            ("process-user-terminate", self.dummy, 0x1),
            ("process-user-read-memory", self.dummy, 0x10),
        ] {
            // SAFETY: plain call.
            let h = H(unsafe { OpenProcess(access, 0, pid) });
            self.out(check, if !h.0.is_null() { "allowed".into() } else { last() });
        }
        // Named pipes and named objects.
        let mine = format!(r"\\.\pipe\wick-fsprobe-{}-{}", self.pid_tag, self.scn);
        // SAFETY: NUL-terminated name.
        let h = H(unsafe { CreateNamedPipeW(wide(&mine).as_ptr(), 3, 0, 1, 512, 512, 0, null()) });
        self.out("pipe-create", if h.0 != INVALID { "allowed".into() } else { last() });
        let theirs = format!(r"\\.\pipe\wick-fsprobe-{}-user", self.pid_tag);
        // SAFETY: NUL-terminated name.
        let h = H(unsafe { CreateFileW(wide(&theirs).as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, null(), OPEN_EXISTING, 0, null_mut()) });
        self.out("pipe-connect-user", if h.0 != INVALID { "allowed".into() } else { last() });
        // SAFETY: NUL-terminated names.
        let h = H(unsafe { CreateEventW(null(), 1, 0, wide(&format!("Local\\wick-fsprobe-{}-{}", self.pid_tag, self.scn)).as_ptr()) });
        self.out("event-create-local", if !h.0.is_null() { "allowed".into() } else { last() });
        // SAFETY: NUL-terminated name.
        let h = H(unsafe { OpenEventW(SYNCHRONIZE, 0, wide(&format!("Local\\wick-fsprobe-{}-user", self.pid_tag)).as_ptr()) });
        self.out("event-open-user", if !h.0.is_null() { "allowed".into() } else { last() });
        // A child process.
        let mut cmd = wide("cmd.exe /c exit 0");
        // SAFETY: plain data.
        let si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        let mut si = si;
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi = PROCESS_INFORMATION { process: null_mut(), thread: null_mut(), pid: 0, tid: 0 };
        // SAFETY: a mutable command line and plain structures.
        let ok = unsafe { CreateProcessW(null(), cmd.as_mut_ptr(), null(), null(), 0, 0x0800_0000, null(), null(), &si, &mut pi) };
        if ok != 0 {
            // SAFETY: handles from the call.
            unsafe {
                WaitForSingleObject(pi.process, 5000);
                CloseHandle(pi.process);
                CloseHandle(pi.thread);
            }
            self.out("child-process", "allowed");
        } else {
            self.out("child-process", last());
        }
        // The window station and desktop, through user32 (last: under
        // win32k lockdown its load fails).
        // SAFETY: a NUL-terminated name.
        let u32dll = unsafe { LoadLibraryW(wide("user32.dll").as_ptr()) };
        if u32dll.is_null() {
            self.out("user32-load", last());
            return;
        }
        self.out("user32-load", "allowed");
        type OpenWinSta = unsafe extern "system" fn(*const u16, i32, u32) -> HANDLE;
        type OpenDesk = unsafe extern "system" fn(*const u16, u32, i32, u32) -> HANDLE;
        // SAFETY: exported functions of these types.
        unsafe {
            let ows: OpenWinSta = std::mem::transmute(GetProcAddress(u32dll, b"OpenWindowStationW\0".as_ptr()));
            let od: OpenDesk = std::mem::transmute(GetProcAddress(u32dll, b"OpenDesktopW\0".as_ptr()));
            let w = ows(wide("WinSta0").as_ptr(), 0, 0x100 /* WINSTA_ENUMERATE */);
            self.out("winsta0-open", if !w.is_null() { "allowed".into() } else { last() });
            let d = od(wide("Default").as_ptr(), 0, 0, 0x1 /* DESKTOP_READOBJECTS */);
            self.out("desktop-default-open", if !d.is_null() { "allowed".into() } else { last() });
        }
    }
}

fn unix_addr(path: &str) -> Vec<u8> {
    let mut a = vec![0u8; 110];
    a[0] = 1; // AF_UNIX
    a[2..2 + path.len()].copy_from_slice(path.as_bytes());
    a
}

fn wsa() {
    let mut data = [0u8; 512];
    // SAFETY: a WSADATA-sized buffer.
    unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
}

fn child(args: &[String]) {
    let a = |i: usize| args[i].clone();
    let n = |i: usize| args[i].parse::<u64>().unwrap();
    let c = Child {
        scn: a(0),
        base: a(1),
        root: n(2) as usize as HANDLE,
        secret_id: n(4),
        share_id: n(5),
        parent: n(6) as u32,
        dummy: n(7) as u32,
        tcp_port: n(8) as u16,
        pid_tag: a(11),
    };
    let inherited = n(3) as usize;
    let revert = a(9) == "1";
    let mitigate = a(10) == "1";
    // Load what the checks use while the initial token (if any) is on this
    // thread: Winsock and its AF_UNIX provider.
    wsa();
    // SAFETY: plain Winsock calls.
    unsafe {
        let s = socket(1, 1, 0);
        c.out("preload-unix-socket", if s != usize::MAX { "allowed".into() } else { format!("denied wsa {}", WSAGetLastError()) });
        if s != usize::MAX {
            closesocket(s);
        }
    }
    if revert {
        // SAFETY: plain call.
        let ok = unsafe { RevertToSelf() };
        c.out("revert-to-lockdown-token", if ok != 0 { "allowed".into() } else { last() });
    }
    c.token();
    if mitigate {
        c.mitigate();
    }
    // The duplicated socket's value comes on standard input, written after
    // the parent duplicated it into this (suspended) process.
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    let dup = line.trim().parse::<usize>().unwrap_or(0);
    c.share();
    c.names();
    c.reparse();
    c.sockets(inherited, dup);
    c.outside();
    c.out("done", "");
}

// ----------------------------------------------------------------------------
// The run: the share, the confinements, the clean-up.

/// A dynamically loaded export (userenv, kernelbase).
fn export(dll: &str, name: &str) -> *const c_void {
    // SAFETY: NUL-terminated names.
    unsafe {
        let m = LoadLibraryW(wide(dll).as_ptr());
        assert!(!m.is_null(), "{dll}");
        let f = GetProcAddress(m, format!("{name}\0").as_ptr());
        assert!(!f.is_null(), "{dll}!{name}");
        f
    }
}

fn appcontainer_sid(name: &str) -> PSID {
    type Derive = unsafe extern "system" fn(*const u16, *mut PSID) -> i32;
    // SAFETY: the export has this type.
    let f: Derive = unsafe { std::mem::transmute(export("userenv.dll", "DeriveAppContainerSidFromAppContainerName")) };
    let mut s = null_mut();
    // SAFETY: a NUL-terminated name and an out-pointer.
    let hr = unsafe { f(wide(name).as_ptr(), &mut s) };
    assert_eq!(hr, 0, "DeriveAppContainerSidFromAppContainerName {hr:#x}");
    s
}

fn capability_sid(name: &str) -> PSID {
    type Derive = unsafe extern "system" fn(*const u16, *mut *mut PSID, *mut u32, *mut *mut PSID, *mut u32) -> i32;
    // SAFETY: the export has this type.
    let f: Derive = unsafe { std::mem::transmute(export("kernelbase.dll", "DeriveCapabilitySidsFromName")) };
    let (mut g, mut gn, mut c, mut cn) = (null_mut(), 0, null_mut(), 0);
    // SAFETY: out-pointers.
    let ok = unsafe { f(wide(name).as_ptr(), &mut g, &mut gn, &mut c, &mut cn) };
    assert!(ok != 0 && cn >= 1, "DeriveCapabilitySidsFromName {name}");
    // SAFETY: at least one capability SID.
    unsafe { *c }
}

/// Our own primary token.
fn own_token() -> HANDLE {
    let mut t = null_mut();
    // SAFETY: an out-pointer.
    assert!(unsafe { OpenProcessToken(GetCurrentProcess(), 0x000F_01FF, &mut t) } != 0);
    t
}

fn set_integrity(t: HANDLE, level: &str) {
    let s = sid(level);
    let label = SID_AND_ATTRIBUTES { sid: s, attributes: 0x20 };
    // SAFETY: the label and its SID.
    let len = std::mem::size_of::<SID_AND_ATTRIBUTES>() as u32 + unsafe { GetLengthSid(s) };
    // SAFETY: as above.
    assert!(unsafe { SetTokenInformation(t, 25, (&raw const label).cast(), len) } != 0, "integrity {level}: {}", last());
}

fn set_default_dacl(t: HANDLE, sddl: &str) {
    let sd = sd_from(sddl);
    let (mut present, mut dacl, mut def) = (0, null_mut(), 0);
    // SAFETY: a descriptor from the conversion; TOKEN_DEFAULT_DACL is one pointer.
    unsafe {
        GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut def);
        assert!(SetTokenInformation(t, 6, (&raw const dacl).cast(), 8) != 0, "default DACL: {}", last());
    }
}

/// The token UAC gives the user's programs: administrators deny-only, no
/// privilege but traversal, medium integrity, the user its owner and in its
/// default DACL (as tools/windows/jail-probe.rs `run_as`).
fn lua_token(own: HANDLE, user: &str) -> HANDLE {
    let mut t = null_mut();
    // SAFETY: our token; LUA_TOKEN | DISABLE_MAX_PRIVILEGE.
    assert!(unsafe { CreateRestrictedToken(own, 0x4 | 0x1, 0, null(), 0, null(), 0, null(), &mut t) } != 0, "LUA: {}", last());
    set_integrity(t, "S-1-16-8192");
    let u = sid(user);
    // SAFETY: TOKEN_OWNER is one pointer.
    assert!(unsafe { SetTokenInformation(t, 4, (&raw const u).cast(), 8) } != 0);
    set_default_dacl(t, &format!("D:(A;;GA;;;SY)(A;;GA;;;{user})"));
    t
}

/// A restricted token made from our own (so that `CreateProcessAsUser`
/// needs no privilege): filtered as UAC does (administrators deny-only, no
/// privilege but traversal), medium integrity, `restricting` SIDs only, the
/// user its owner and `dacl_sids` in its default DACL.
fn restricted_token(own: HANDLE, user: &str, restricting: &[&str], dacl_sids: &[&str]) -> HANDLE {
    let sids: Vec<SID_AND_ATTRIBUTES> = restricting.iter().map(|s| SID_AND_ATTRIBUTES { sid: sid(s), attributes: 0 }).collect();
    let mut t = null_mut();
    // SAFETY: valid SID array; LUA_TOKEN | DISABLE_MAX_PRIVILEGE.
    assert!(
        unsafe { CreateRestrictedToken(own, 0x4 | 0x1, 0, null(), 0, null(), sids.len() as u32, sids.as_ptr(), &mut t) } != 0,
        "restricted: {}",
        last()
    );
    set_integrity(t, "S-1-16-8192");
    let u = sid(user);
    // SAFETY: TOKEN_OWNER is one pointer.
    assert!(unsafe { SetTokenInformation(t, 4, (&raw const u).cast(), 8) } != 0);
    let aces: String = dacl_sids.iter().map(|s| format!("(A;;GA;;;{s})")).collect();
    set_default_dacl(t, &format!("D:(A;;GA;;;SY){aces}"));
    t
}

fn impersonation(t: HANDLE) -> HANDLE {
    let mut out = null_mut();
    // SAFETY: SecurityImpersonation, TokenImpersonation.
    assert!(unsafe { DuplicateTokenEx(t, 0x000F_01FF, null(), 2, 2, &mut out) } != 0);
    out
}

enum Who {
    Lua,
    Low,
    AppContainer { sid: PSID, caps: Vec<PSID>, lpac: bool },
    Restricted { primary: HANDLE, initial: HANDLE },
}

struct Started {
    process: H,
    thread: H,
    pid: u32,
    _job: Option<H>,
}

/// Starts `cmd` suspended as `who`, inheriting only `inherit`, in a Job
/// with wick's limits when `job`.
fn start(cmd: &str, cwd: &str, who: &Who, lua: HANDLE, low: HANDLE, inherit: &[HANDLE], std: [HANDLE; 3], job: bool) -> Result<Started, String> {
    let mut caps_sa: Vec<SID_AND_ATTRIBUTES> = Vec::new();
    let mut sc = SECURITY_CAPABILITIES { sid: null_mut(), caps: null_mut(), count: 0, reserved: 0 };
    let opt_out: u32 = 1;
    let mut count = 1;
    if let Who::AppContainer { sid, caps, lpac } = who {
        caps_sa = caps.iter().map(|&c| SID_AND_ATTRIBUTES { sid: c, attributes: 4 }).collect();
        sc = SECURITY_CAPABILITIES { sid: *sid, caps: caps_sa.as_mut_ptr(), count: caps_sa.len() as u32, reserved: 0 };
        count += 1 + u32::from(*lpac);
    }
    let mut size = 0;
    // SAFETY: a size query.
    unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
    let mut list = vec![0u64; size.div_ceil(8)];
    let l = list.as_mut_ptr().cast::<c_void>();
    // SAFETY: a buffer of the size asked for; values outlive the creation.
    unsafe {
        assert!(InitializeProcThreadAttributeList(l, count, 0, &mut size) != 0);
        assert!(UpdateProcThreadAttribute(l, 0, 0x20002, inherit.as_ptr().cast(), inherit.len() * 8, null_mut(), null()) != 0);
        if let Who::AppContainer { lpac, .. } = who {
            assert!(UpdateProcThreadAttribute(l, 0, 0x20009, (&raw const sc).cast(), std::mem::size_of::<SECURITY_CAPABILITIES>(), null_mut(), null()) != 0);
            if *lpac {
                assert!(UpdateProcThreadAttribute(l, 0, 0x2000F, (&raw const opt_out).cast(), 4, null_mut(), null()) != 0);
            }
        }
    }
    // SAFETY: plain data.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.si.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.si.flags = 0x100; // STARTF_USESTDHANDLES
    si.si.stdin = std[0];
    si.si.stdout = std[1];
    si.si.stderr = std[2];
    si.attrs = l;
    let mut pi = PROCESS_INFORMATION { process: null_mut(), thread: null_mut(), pid: 0, tid: 0 };
    let mut c = wide(cmd);
    // CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | DETACHED_PROCESS: no
    // console, whose device a restricted token may not open.
    let flags = 0x4 | 0x8_0000 | 0x8;
    let token = match who {
        Who::Lua | Who::AppContainer { .. } => lua,
        Who::Low => low,
        Who::Restricted { primary, .. } => *primary,
    };
    // SAFETY: valid strings, structures and attribute list.
    let ok = unsafe { CreateProcessAsUserW(token, null(), c.as_mut_ptr(), null(), null(), 1, flags, null(), wide(cwd).as_ptr(), &si.si, &mut pi) };
    let err = last();
    // SAFETY: initialised above.
    unsafe { DeleteProcThreadAttributeList(l) };
    if ok == 0 {
        return Err(err);
    }
    let process = H(pi.process);
    let mut thread = H(pi.thread);
    let job_h = if job {
        // SAFETY: plain calls; JOBOBJECT_EXTENDED_LIMIT_INFORMATION is 144 bytes.
        unsafe {
            let j = H(CreateJobObjectW(null(), null()));
            let mut info = [0u8; 144];
            // ACTIVE_PROCESS | PROCESS_MEMORY | DIE_ON_UNHANDLED_EXCEPTION | KILL_ON_JOB_CLOSE.
            info[16..20].copy_from_slice(&(0x8u32 | 0x100 | 0x400 | 0x2000).to_le_bytes());
            info[40..44].copy_from_slice(&1u32.to_le_bytes());
            info[112..120].copy_from_slice(&(256u64 << 20).to_le_bytes());
            if SetInformationJobObject(j.0, 9, info.as_ptr().cast(), 144) == 0 || AssignProcessToJobObject(j.0, process.0) == 0 {
                let e = last();
                TerminateProcess(process.0, 1);
                return Err(format!("job {e}"));
            }
            Some(j)
        }
    } else {
        None
    };
    if let Who::Restricted { initial, .. } = who {
        // SAFETY: the suspended child's main thread and an impersonation token.
        if unsafe { SetThreadToken(&mut thread.0, *initial) } == 0 {
            let e = last();
            // SAFETY: our child.
            unsafe { TerminateProcess(process.0, 1) };
            return Err(format!("SetThreadToken {e}"));
        }
    }
    let _ = &caps_sa;
    Ok(Started { process, thread, pid: pi.pid, _job: job_h })
}

/// A connected AF_UNIX pair through a listener at `path`: (client, server).
fn unix_pair(path: &str) -> (usize, usize) {
    // SAFETY: plain Winsock calls on sockets made here.
    unsafe {
        let l = socket(1, 1, 0);
        let addr = unix_addr(path);
        assert_eq!(bind(l, addr.as_ptr(), addr.len() as i32), 0, "bind {path}: {}", WSAGetLastError());
        assert_eq!(listen(l, 1), 0);
        let c = socket(1, 1, 0);
        assert_eq!(connect(c, addr.as_ptr(), addr.len() as i32), 0, "connect {path}");
        let s = accept(l, null_mut(), null_mut());
        assert_ne!(s, usize::MAX);
        closesocket(l);
        (c, s)
    }
}

/// Answers one "ping" with "pong" on `s` (15 s at most), then closes it.
fn pong(s: usize) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // SAFETY: a socket this thread now owns.
        unsafe {
            let t: u32 = 15_000;
            setsockopt(s, 0xffff, 0x1006, (&raw const t).cast(), 4); // SO_RCVTIMEO
            let mut b = [0u8; 8];
            if recv(s, b.as_mut_ptr(), 8, 0) == 4 && &b[..4] == b"ping" {
                send(s, b"pong".as_ptr(), 4, 0);
            }
            closesocket(s);
        }
    })
}

/// Accepts and drops connections on `l` for the whole run.
fn sink(l: usize) {
    std::thread::spawn(move || loop {
        // SAFETY: a listening socket this thread owns.
        let s = unsafe { accept(l, null_mut(), null_mut()) };
        if s == usize::MAX {
            return;
        }
        // SAFETY: the accepted socket.
        unsafe { closesocket(s) };
    });
}

fn inheritable(h: HANDLE) -> HANDLE {
    let mut out = null_mut();
    // SAFETY: a handle of this process; an inheritable copy.
    assert!(unsafe { DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &mut out, 0, 1, 2) } != 0);
    out
}

fn enable_privilege(name: &str) -> bool {
    let mut luid = 0u64;
    let t = H(own_token());
    // SAFETY: a NUL-terminated name, out-pointers.
    unsafe {
        if LookupPrivilegeValueW(null(), wide(name).as_ptr(), &mut luid) == 0 {
            return false;
        }
        let tp = TOKEN_PRIVILEGES1 { count: 1, privilege: LUID_AND_ATTRIBUTES { luid, attributes: 2 } };
        AdjustTokenPrivileges(t.0, 0, &tp, std::mem::size_of::<TOKEN_PRIVILEGES1>() as u32, null_mut(), null_mut()) != 0 && GetLastError() == 0
    }
}

/// Every path beneath `dir`, `dir` included, links not followed.
fn walk(dir: &str, out: &mut Vec<String>) {
    out.push(dir.to_string());
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path().to_string_lossy().into_owned();
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => walk(&p, out),
            _ => out.push(p),
        }
    }
}

/// Whether no object beneath `share` names any of `sids` or carries an
/// inherited mandatory label (what a grant leaves); objects with a label of
/// their own (Windows labels what a low-integrity process makes) are listed
/// apart, since revoking a grant cannot remove them.
fn verify_clean(what: &str, share: &str, sids: &[String]) -> bool {
    let mut paths = Vec::new();
    walk(share, &mut paths);
    let mut dirty = 0;
    let mut own_labels = Vec::new();
    for p in &paths {
        let s = file_sddl(p);
        if s.contains("(ML;ID") || s.contains("(ML;OICIID") || sids.iter().any(|x| s.contains(x.as_str())) {
            dirty += 1;
            println!("revert {what} DIRTY {p} {s}");
        } else if s.contains("(ML;") {
            own_labels.push(last_component(p).to_string());
        }
    }
    println!(
        "revert {what} {} ({} objects checked; objects with a label of their own: {})",
        if dirty == 0 { "clean" } else { "NOT CLEAN" },
        paths.len(),
        if own_labels.is_empty() { "none".to_string() } else { own_labels.join(" ") }
    );
    dirty == 0
}

fn ea_limits(dir: &str) {
    let path = format!("{dir}\\ea-limits.bin");
    create_file(&path, b"");
    // SAFETY: NUL-terminated path.
    let h = H(unsafe { CreateFileW(wide(&path).as_ptr(), FILE_READ_EA | FILE_WRITE_EA | GENERIC_READ, SHARE_ALL, null(), OPEN_EXISTING, 0, null_mut()) });
    assert_ne!(h.0, INVALID);
    let mut flags = 0;
    let mut fs = [0u16; 32];
    // SAFETY: out-pointers and a buffer of 32 characters.
    unsafe { GetVolumeInformationByHandleW(h.0, null_mut(), 0, null_mut(), null_mut(), &mut flags, fs.as_mut_ptr(), 32) };
    let fs = String::from_utf16_lossy(&fs).trim_end_matches('\0').to_string();
    println!(
        "host volume {fs} flags {flags:#010x} extended-attributes {} named-streams {}",
        flags & 0x0080_0000 != 0,
        flags & 0x0004_0000 != 0
    );
    let largest = |name: &str| {
        let (mut lo, mut hi) = (0usize, 65535usize);
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if set_ea(h.0, &ea_entry(name, &vec![1u8; mid], 0)).is_ok() { lo = mid } else { hi = mid - 1 }
        }
        lo
    };
    let one = largest("WICK.X");
    let first = set_ea(h.0, &ea_entry("WICK.X", &[1], 0));
    println!("host ea-largest-single-value {one} bytes (name WICK.X; first set {first:?})");
    let _ = set_ea(h.0, &ea_entry("WICK.X", &[], 0));
    let stat = set_ea(h.0, &ea_entry("WICK.STAT", &[0; 40], 0));
    let with = largest("WICK.X");
    println!("host ea-largest-value-beside-a-40-byte-record {with} bytes (record set {stat:?})");
    let _ = set_ea(h.0, &ea_entry("WICK.X", &[], 0));
    let _ = set_ea(h.0, &ea_entry("WICK.STAT", &[], 0));
    let mut n = 0;
    let mut packed = 0;
    while n < 100 {
        let name = format!("E{n:03}");
        if set_ea(h.0, &ea_entry(&name, &[2u8; 1000], 0)).is_err() {
            break;
        }
        packed += 4 + name.len() + 1 + 1000;
        n += 1;
    }
    println!("host ea-many-of-1000-bytes {n} entries, packed about {packed} bytes; read back {:?}", read_ea(h.0));
    drop(h);
    let stream = format!("{path}:wick.stat");
    // SAFETY: NUL-terminated path.
    let s = H(unsafe { CreateFileW(wide(&stream).as_ptr(), GENERIC_WRITE, SHARE_ALL, null(), CREATE_ALWAYS, 0, null_mut()) });
    println!("host ads-create {}", if s.0 != INVALID { "allowed".into() } else { last() });
    drop(s);
    let _ = std::fs::remove_file(&path);
}

/// EA on a reparse point and a reparse point on a directory with an EA.
fn ea_and_reparse(base: &str) {
    let jn = format!("{base}\\share\\jn");
    // SAFETY: NUL-terminated path.
    let h = H(unsafe {
        CreateFileW(wide(&jn).as_ptr(), FILE_WRITE_EA, SHARE_ALL, null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, null_mut())
    });
    println!("host ea-on-a-junction {}", match set_ea(h.0, &ea_entry("WICK.STAT", &[0; 40], 0)) {
        Ok(()) => "allowed".into(),
        Err(st) => status(st),
    });
    drop(h);
    let dir = format!("{base}\\eadir");
    std::fs::create_dir(&dir).unwrap();
    // SAFETY: NUL-terminated path.
    let h = H(unsafe {
        CreateFileW(wide(&dir).as_ptr(), GENERIC_WRITE | FILE_WRITE_EA, SHARE_ALL, null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, null_mut())
    });
    let ea = set_ea(h.0, &ea_entry("WICK.STAT", &[0; 40], 0));
    // A mount point to the outside directory (REPARSE_DATA_BUFFER).
    let target: Vec<u16> = format!("\\??\\{base}\\outside").encode_utf16().collect();
    let mut path = target.clone();
    path.push(0);
    path.extend_from_slice(&[0]);
    let data_len = 8 + path.len() * 2;
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xA000_0003u32.to_le_bytes());
    buf.extend_from_slice(&(data_len as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&((target.len() * 2) as u16).to_le_bytes());
    buf.extend_from_slice(&((target.len() * 2 + 2) as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    for u in &path {
        buf.extend_from_slice(&u.to_le_bytes());
    }
    let mut ret = 0;
    // SAFETY: FSCTL_SET_REPARSE_POINT with a buffer of its length.
    let ok = unsafe { DeviceIoControl(h.0, 0x0009_00A4, buf.as_ptr().cast(), buf.len() as u32, null_mut(), 0, &mut ret, null_mut()) };
    println!("host reparse-point-on-a-directory-with-an-ea ea {ea:?} then {}", if ok != 0 { "allowed".into() } else { last() });
}

/// What holding share-delete handles does to the host's own renames and
/// deletes: the server holds a handle on every node it looked up.
fn held_handles(base: &str) {
    let open = |p: &str, access: u32| {
        // SAFETY: NUL-terminated path.
        H(unsafe { CreateFileW(wide(p).as_ptr(), access, SHARE_ALL, null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, null_mut()) })
    };
    for (case, hold_dir, hold_file, hold_sub) in [
        ("dir-handle", true, false, false),
        ("subdir-handle-inside", false, false, true),
        ("file-handle-inside", false, true, false),
        ("no-handle", false, false, false),
    ] {
        let a = format!("{base}\\hp-{case}\\a");
        std::fs::create_dir_all(format!("{a}\\s")).unwrap();
        let file = format!("{a}\\b.txt");
        create_file(&file, b"b");
        let hd = if hold_dir { Some(open(&a, FILE_READ_ATTRIBUTES)) } else { None };
        let hf = if hold_file { Some(open(&file, FILE_READ_ATTRIBUTES)) } else { None };
        let hs = if hold_sub { Some(open(&format!("{a}\\s"), FILE_READ_ATTRIBUTES)) } else { None };
        let a2 = format!("{base}\\hp-{case}\\a2");
        // SAFETY: NUL-terminated paths.
        let mv = unsafe { MoveFileExW(wide(&a).as_ptr(), wide(&a2).as_ptr(), 0) };
        println!("host rename-a-directory-while-the-server-holds-{case} movefile {}", if mv != 0 { "allowed".into() } else { last() });
        if mv == 0 {
            // The same with POSIX semantics on a handle (what a host tool
            // would not do, but shows whether NTFS itself refuses).
            let h = open(&a, DELETE);
            let parent = open(&format!("{base}\\hp-{case}"), FILE_READ_ATTRIBUTES);
            let r = rename(h.0, parent.0, "a2");
            println!("host rename-a-directory-while-the-server-holds-{case} posix-rename {}", match r {
                Ok(()) => "allowed".into(),
                Err(st) => status(st),
            });
        }
        drop((hd, hf, hs));
    }
    let file = format!("{base}\\hp-file.txt");
    create_file(&file, b"b");
    let hf = open(&file, FILE_READ_ATTRIBUTES);
    // SAFETY: NUL-terminated path.
    let del = unsafe { DeleteFileW(wide(&file).as_ptr()) };
    println!("host delete-a-file-the-server-holds {}", if del != 0 { "allowed".into() } else { last() });
    // SAFETY: NUL-terminated path.
    let again = H(unsafe { CreateFileW(wide(&file).as_ptr(), GENERIC_WRITE, SHARE_ALL, null(), CREATE_NEW, 0, null_mut()) });
    println!("host same-name-again-while-held {}", if again.0 != INVALID { "allowed (the name was freed at once)".into() } else { last() });
    drop((hf, again));
}

/// Makes the AppContainer profile `name` if it has none: (sid, made here).
fn appcontainer_profile(name: &str) -> (PSID, bool) {
    type Create = unsafe extern "system" fn(*const u16, *const u16, *const u16, *const SID_AND_ATTRIBUTES, u32, *mut PSID) -> i32;
    // SAFETY: the export has this type.
    let f: Create = unsafe { std::mem::transmute(export("userenv.dll", "CreateAppContainerProfile")) };
    let mut s = null_mut();
    // SAFETY: NUL-terminated strings and an out-pointer.
    let hr = unsafe { f(wide(name).as_ptr(), wide(name).as_ptr(), wide("wick fs-probe").as_ptr(), null(), 0, &mut s) };
    println!("host appcontainer-profile {name} create {hr:#010x}");
    if hr == 0 { (s, true) } else { (appcontainer_sid(name), false) }
}

fn delete_appcontainer_profile(name: &str) {
    type Delete = unsafe extern "system" fn(*const u16) -> i32;
    // SAFETY: the export has this type.
    let f: Delete = unsafe { std::mem::transmute(export("userenv.dll", "DeleteAppContainerProfile")) };
    // SAFETY: a NUL-terminated name.
    let hr = unsafe { f(wide(name).as_ptr()) };
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let folder = format!("{local}\\Packages\\{name}");
    println!("cleanup appcontainer-profile {name} delete {hr:#010x} folder-exists-after {}", std::fs::metadata(&folder).is_ok());
}

struct Scenario {
    name: &'static str,
    who: &'static str,
    /// Whose ACE the share gets: "lpac" (the LPAC SID), "share" (the
    /// restricted token's SID), or none.
    ace: Option<&'static str>,
    /// The share's inheritable label: "LW" low, "ME" medium, or none.
    label: Option<&'static str>,
    job: bool,
}

const SCENARIOS: &[Scenario] = &[
    Scenario { name: "base", who: "lua", ace: None, label: None, job: false },
    Scenario { name: "lpac-ace", who: "lpac", ace: Some("lpac"), label: None, job: true },
    Scenario { name: "lpac-label", who: "lpac", ace: Some("lpac"), label: Some("LW"), job: true },
    Scenario { name: "lpac-label-nomit", who: "lpac", ace: Some("lpac"), label: Some("LW"), job: false },
    Scenario { name: "lpac-medium-label", who: "lpac", ace: Some("lpac"), label: Some("ME"), job: true },
    Scenario { name: "low-noace", who: "low", ace: None, label: None, job: false },
    Scenario { name: "low-share-sid-ace", who: "low", ace: Some("share"), label: None, job: false },
    Scenario { name: "lua-ace", who: "lua", ace: Some("lpac"), label: None, job: false },
    Scenario { name: "other-low-nolabel", who: "low", ace: Some("lpac"), label: None, job: false },
    Scenario { name: "other-low", who: "low", ace: Some("lpac"), label: Some("LW"), job: false },
    Scenario { name: "other-ac", who: "other-ac", ace: Some("lpac"), label: Some("LW"), job: false },
    Scenario { name: "restricted", who: "restricted", ace: Some("share"), label: None, job: true },
    Scenario { name: "restricted-nomit", who: "restricted", ace: Some("share"), label: None, job: false },
];

fn run(base: &str) {
    let tag = format!("{}", std::process::id());
    let profile = std::env::var("USERPROFILE").unwrap_or_default().to_lowercase();
    assert!(!profile.is_empty() && !base.to_lowercase().starts_with(&profile), "{base} is inside the user's profile");
    assert!(std::fs::metadata(base).is_err(), "{base} exists");
    let parent_dir = std::path::Path::new(base).parent().unwrap().to_string_lossy().into_owned();
    let parent_before = file_sddl(&parent_dir);
    std::fs::create_dir(base).unwrap();
    wsa();

    let own = own_token();
    let user = token_sid(own, 1);
    let lua = lua_token(own, &user);
    let low = lua_token(own, &user);
    set_integrity(low, "S-1-16-4096");
    // The share's SIDs: an LPAC SID per share, a random SID per share for
    // the restricted token (as the jail's), another AppContainer's.
    let lpac_name = format!("wick.fsprobe.{tag}");
    let lpac = appcontainer_sid(&lpac_name);
    let other_name = format!("wick.fsprobe.other.{tag}");
    let other_ac = appcontainer_sid(&other_name);
    let mut profiles: Vec<String> = Vec::new();
    let caps = vec![capability_sid("registryRead"), capability_sid("lpacCom")];
    let r = std::collections::hash_map::RandomState::new();
    let rnd = |i: u64| {
        use std::hash::{BuildHasher, Hasher};
        let mut h = r.build_hasher();
        h.write_u64(i);
        h.finish() as u32
    };
    let share_sid = format!("S-1-9-{}-{}-{}-{}", rnd(1), rnd(2), rnd(3), rnd(4));
    let lpac_s = sid_string(lpac);
    let other_s = sid_string(other_ac);
    println!("host user {user} lpac-sid {lpac_s} share-sid {share_sid} other-ac-sid {other_s}");
    println!("host token {}", sddl_of_token(own));

    // The share: protected DACL for SYSTEM, administrators and the user.
    let share = format!("{base}\\share");
    let outside = format!("{base}\\outside");
    let bin = format!("{base}\\bin");
    let share_dacl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})");
    for d in [&share, &outside, &bin] {
        std::fs::create_dir(d).unwrap();
    }
    assert_eq!(set_dacl(&share, &share_dacl), 0);
    assert_eq!(set_dacl(&outside, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})")), 0);
    // The child's copy of this program, readable by every AppContainer.
    let exe = format!("{bin}\\fs-probe.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    assert_eq!(set_dacl(&bin, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})(A;OICI;0x1200a9;;;AC)(A;OICI;0x1200a9;;;S-1-15-2-2)(A;OICI;0x1200a9;;;{share_sid})")), 0);
    create_file(&format!("{outside}\\secret.txt"), b"secret");
    create_file_sd(&format!("{outside}\\public.txt"), b"public", &format!("D:P(A;;FA;;;{user})(A;;FR;;;WD)(A;;FR;;;BU)(A;;FR;;;AU)"));
    create_file_sd(&format!("{outside}\\restricted.txt"), b"restricted", &format!("D:P(A;;FA;;;{user})(A;;FR;;;RC)"));
    create_file(&format!("{outside}\\nulldacl.txt"), b"null");
    // SAFETY: NUL-terminated path; a NULL DACL (SE_DACL_PRESENT with no ACL).
    let e = unsafe { SetNamedSecurityInfoW(wide(&format!("{outside}\\nulldacl.txt")).as_ptr(), SE_FILE_OBJECT, DACL_INFO | PROTECTED_DACL, null_mut(), null_mut(), null(), null()) };
    println!("host null-dacl-file set {e}");
    create_file(&format!("{share}\\f.txt"), b"hello");
    create_file(&format!("{share}\\Long File Name.txt"), b"long");
    std::fs::create_dir(format!("{share}\\sub")).unwrap();
    create_file(&format!("{share}\\sub\\f2.txt"), b"f2");
    for s in SCENARIOS {
        let n = s.name;
        for f in ["w", "del", "ro", "ren"] {
            create_file(&format!("{share}\\{f}-{n}.txt"), b"z");
        }
        // SAFETY: NUL-terminated path; FILE_ATTRIBUTE_READONLY.
        unsafe { SetFileAttributesW(wide(&format!("{share}\\ro-{n}.txt")).as_ptr(), 1) };
        std::fs::create_dir(format!("{share}\\rd-{n}")).unwrap();
    }
    // Links out of the share: a junction, a file symlink, a directory symlink.
    let jn = std::process::Command::new("cmd").args(["/c", "mklink", "/J", &format!("{share}\\jn"), &outside]).output();
    println!("host junction {:?}", jn.map(|o| o.status.success()));
    println!("host file-symlink {:?}", std::os::windows::fs::symlink_file(format!("{outside}\\secret.txt"), format!("{share}\\sl")).map_err(|e| e.to_string()));
    println!("host dir-symlink {:?}", std::os::windows::fs::symlink_dir(&outside, format!("{share}\\sld")).map_err(|e| e.to_string()));
    // An 8.3 name for "Long File Name.txt", made if the volume makes none.
    let long = format!("{share}\\Long File Name.txt");
    let mut short = [0u16; 512];
    // SAFETY: a buffer of 512 characters.
    let n = unsafe { GetShortPathNameW(wide(&long).as_ptr(), short.as_mut_ptr(), 512) } as usize;
    let short_name = String::from_utf16_lossy(&short[..n]);
    if last_component(&short_name).contains('~') {
        println!("host short-name {}", last_component(&short_name));
    } else {
        let priv_ok = enable_privilege("SeRestorePrivilege");
        // SAFETY: NUL-terminated path.
        let h = H(unsafe { CreateFileW(wide(&long).as_ptr(), GENERIC_ALL, SHARE_ALL, null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, null_mut()) });
        // SAFETY: a handle opened with GENERIC_ALL.
        let ok = unsafe { SetFileShortNameW(h.0, wide("LONGFI~1.TXT").as_ptr()) };
        println!("host short-name none made by the volume; set LONGFI~1.TXT: privilege {priv_ok} {}", if ok != 0 { "allowed".into() } else { last() });
    }
    let secret_id = file_id_of_path(&format!("{outside}\\secret.txt")).1 as u64;
    let share_file_id = file_id_of_path(&format!("{share}\\f.txt")).1 as u64;

    // Host-side measurements.
    ea_limits(base);
    ea_and_reparse(base);
    held_handles(base);

    // A plain medium process of the user, whose pipe, event and process
    // the children try to reach.
    let dummy_cmd = format!("\"{exe}\" dummy {tag}");
    // SAFETY: NUL-terminated name.
    let null_in = inheritable(H(unsafe { CreateFileW(wide("NUL").as_ptr(), GENERIC_READ, SHARE_ALL, null(), OPEN_EXISTING, 0, null_mut()) }).0);
    let out = inheritable(GetStd(-11));
    let dummy = start(&dummy_cmd, &bin, &Who::Lua, lua, low, &[null_in, out], [null_in, out, out], false).expect("dummy");
    // SAFETY: the suspended dummy's thread.
    unsafe { ResumeThread(dummy.thread.0) };
    // SAFETY: plain call.
    unsafe { Sleep(1500) };

    // A listener outside the share, and loopback TCP.
    // SAFETY: plain Winsock calls.
    let tcp_port = unsafe {
        let l = socket(1, 1, 0);
        let addr = unix_addr(&format!("{base}\\l.sock"));
        assert_eq!(bind(l, addr.as_ptr(), addr.len() as i32), 0);
        listen(l, 8);
        sink(l);
        let t = socket(2, 1, 6);
        let mut a = [0u8; 16];
        a[0] = 2;
        a[4..8].copy_from_slice(&[127, 0, 0, 1]);
        assert_eq!(bind(t, a.as_ptr(), 16), 0);
        listen(t, 8);
        let mut len = 16;
        getsockname(t, a.as_mut_ptr(), &mut len);
        sink(t);
        u16::from_be_bytes([a[2], a[3]])
    };

    let test_sids = vec![lpac_s.clone(), other_s.clone(), share_sid.clone()];
    for s in SCENARIOS {
        let ace_sid = match s.ace {
            Some("share") => share_sid.clone(),
            _ => lpac_s.clone(),
        };
        if s.ace.is_some() {
            let e = set_dacl(&share, &format!("{share_dacl}(A;OICI;{MODIFY:#x};;;{ace_sid})"));
            println!("grant {} ace {ace_sid} {}", s.name, if e == 0 { "set".into() } else { format!("failed {e}") });
        }
        if let Some(level) = s.label {
            let e = set_label(&share, Some(&format!("S:(ML;OICI;NW;;;{level})")));
            println!("grant {} low-label {}", s.name, if e == 0 { "set".into() } else { format!("failed {e}") });
        }
        // The node handle the server would hold for the share's root.
        // SAFETY: NUL-terminated path.
        let root = H(unsafe { CreateFileW(wide(&share).as_ptr(), FILE_READ_ATTRIBUTES | SYNCHRONIZE, SHARE_ALL, null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, null_mut()) });
        let root_i = inheritable(root.0);
        let (c1, s1) = unix_pair(&format!("{base}\\p1-{}.sock", s.name));
        let (c2, s2) = unix_pair(&format!("{base}\\p2-{}.sock", s.name));
        let s1i = s1 as HANDLE;
        // SAFETY: our socket, made inheritable for the child's handle list.
        unsafe { SetHandleInformation(s1i, 1, 1) };
        let t1 = pong(c1);
        let t2 = pong(c2);
        let (mut rd, mut wr) = (null_mut(), null_mut());
        let sa = SECURITY_ATTRIBUTES { len: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, sd: null_mut(), inherit: 1 };
        // SAFETY: out-pointers.
        assert!(unsafe { CreatePipe(&mut rd, &mut wr, &sa, 0) } != 0);
        // SAFETY: the write end stays with us.
        unsafe { SetHandleInformation(wr, 1, 0) };
        let (revert, who) = match s.who {
            "lua" => (false, Who::Lua),
            "low" => (false, Who::Low),
            "lpac" => (false, Who::AppContainer { sid: lpac, caps: caps.clone(), lpac: true }),
            "other-ac" => (false, Who::AppContainer { sid: other_ac, caps: Vec::new(), lpac: false }),
            _ => {
                let primary = restricted_token(own, &user, &[&share_sid], &[&user, &share_sid]);
                // The initial token: what the loader needs (the jailer's
                // pattern), removed by the child's RevertToSelf.
                let logon = logon_sid(own);
                let initial = impersonation(restricted_token(
                    own,
                    &user,
                    &[&share_sid, "S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4", &logon, &user],
                    &[&user, &share_sid],
                ));
                (true, Who::Restricted { primary, initial })
            }
        };
        let cmd = format!(
            "\"{exe}\" child {} {base} {} {} {secret_id} {share_file_id} {} {} {tcp_port} {} {} {tag}",
            s.name,
            root_i as usize,
            s1i as usize,
            std::process::id(),
            dummy.pid,
            u8::from(revert),
            u8::from(s.job)
        );
        let mut started = start(&cmd, &bin, &who, lua, low, &[root_i, s1i, rd, out], [rd, out, out], s.job);
        if let (Err(e), Who::AppContainer { sid, caps, lpac: is_lpac }) = (&started, &who) {
            println!("host {} start-without-profile {e}", s.name);
            let name = if *sid == lpac { lpac_name.clone() } else { other_name.clone() };
            let (psid, made) = appcontainer_profile(&name);
            if made {
                profiles.push(name.clone());
            }
            println!("host {} profile-sid-matches {}", s.name, sid_string(psid) == sid_string(*sid));
            let who2 = Who::AppContainer { sid: *sid, caps: caps.clone(), lpac: *is_lpac };
            started = start(&cmd, &bin, &who2, lua, low, &[root_i, s1i, rd, out], [rd, out, out], s.job);
        }
        println!("host {} sddl-of-f.txt {}", s.name, file_sddl(&format!("{share}\\f.txt")));
        match started {
            Ok(child) => {
                let mut dup = null_mut();
                // SAFETY: our socket, duplicated into the suspended child.
                let ok = unsafe { DuplicateHandle(GetCurrentProcess(), s2 as HANDLE, child.process.0, &mut dup, 0, 0, 2) };
                println!("host {} duplicate-socket-into-child {}", s.name, if ok != 0 { "allowed".into() } else { last() });
                let line = format!("{}\n", if ok != 0 { dup as usize } else { 0 });
                let mut n = 0;
                // SAFETY: the pipe's write end; then the child's thread.
                unsafe {
                    WriteFile(wr, line.as_ptr(), line.len() as u32, &mut n, null_mut());
                    ResumeThread(child.thread.0);
                    let w = WaitForSingleObject(child.process.0, 120_000);
                    let mut code = 0;
                    GetExitCodeProcess(child.process.0, &mut code);
                    if w != 0 {
                        TerminateProcess(child.process.0, 1);
                    }
                    println!("host {} child-exit {code:#x}{}", s.name, if w != 0 { " (timed out)" } else { "" });
                }
            }
            Err(e) => println!("host {} start {e}", s.name),
        }
        // SAFETY: our handles.
        unsafe {
            CloseHandle(wr);
            CloseHandle(rd);
            CloseHandle(root_i);
            closesocket(s1);
            closesocket(s2);
        }
        let _ = (t1.join(), t2.join());
        drop(root);
        // Take the grant off again and check that nothing of it is left.
        if s.label.is_some() {
            let e = set_label(&share, None);
            println!("revert {} low-label {}", s.name, if e == 0 { "removed".into() } else { format!("failed {e}") });
        }
        if s.ace.is_some() {
            let e = set_dacl(&share, &share_dacl);
            println!("revert {} ace {}", s.name, if e == 0 { "removed".into() } else { format!("failed {e}") });
        }
        for made in [format!("n-{}.txt", s.name), format!("d-{}", s.name)] {
            let p = format!("{share}\\{made}");
            if std::fs::metadata(&p).is_ok() {
                println!("host {} made-by-child {made} {}", s.name, file_sddl(&p));
            }
        }
        verify_clean(s.name, &share, &test_sids);
        verify_clean(&format!("{}-outside", s.name), &outside, &test_sids);
    }

    // SAFETY: the dummy; its image must be unmapped before <base> goes.
    unsafe {
        TerminateProcess(dummy.process.0, 0);
        WaitForSingleObject(dummy.process.0, 10_000);
    }
    for p in &profiles {
        delete_appcontainer_profile(p);
    }
    // What a child may have left outside <base>.
    let temp = std::env::var("TEMP").unwrap_or_default();
    let mut left = 0;
    for s in SCENARIOS {
        for dir in [r"C:\Users\Public", r"C:\ProgramData", r"C:\Windows\Temp", temp.as_str()] {
            let p = format!("{dir}\\wick-fsprobe-{tag}-{}.txt", s.name);
            if std::fs::metadata(&p).is_ok() {
                left += 1;
                println!("cleanup leftover {p} removed {:?}", std::fs::remove_file(&p).is_ok());
            }
        }
        let sub = format!("Software\\wick-fsprobe-{tag}-{}", s.name);
        let mut k = 0;
        // SAFETY: an out-pointer.
        if unsafe { RegOpenKeyExW(HKCU, wide(&sub).as_ptr(), 0, 0x20019, &mut k) } == 0 {
            left += 1;
            // SAFETY: the key and its name.
            unsafe {
                RegCloseKey(k);
                println!("cleanup leftover HKCU\\{sub} removed {}", RegDeleteKeyW(HKCU, wide(&sub).as_ptr()) == 0);
            }
        }
    }
    println!("cleanup leftovers outside the base: {left}");
    let mut all = Vec::new();
    walk(base, &mut all);
    for p in &all {
        // SAFETY: NUL-terminated path; FILE_ATTRIBUTE_NORMAL clears read-only.
        unsafe { SetFileAttributesW(wide(p).as_ptr(), 0x80) };
    }
    let removed = std::fs::remove_dir_all(base);
    println!("cleanup base removed {:?} exists-after {}", removed.map_err(|e| e.to_string()), std::fs::metadata(base).is_ok());
    let parent_after = file_sddl(&parent_dir);
    println!("cleanup {parent_dir} security {}", if parent_after == parent_before { "unchanged".to_string() } else { format!("CHANGED {parent_before} -> {parent_after}") });
}

#[allow(non_snake_case)]
fn GetStd(which: i32) -> HANDLE {
    // SAFETY: plain call.
    unsafe { GetStdHandle(which as u32) }
}

fn logon_sid(t: HANDLE) -> String {
    let b = token_info(t, 2);
    let count = b[0] as u32 as usize;
    // SAFETY: TOKEN_GROUPS: a count then SID_AND_ATTRIBUTES entries (16 bytes, from offset 8).
    unsafe {
        let entries = std::slice::from_raw_parts(b.as_ptr().cast::<u8>().add(8).cast::<SID_AND_ATTRIBUTES>(), count);
        for e in entries {
            if e.attributes & 0xC000_0000 == 0xC000_0000 {
                return sid_string(e.sid);
            }
        }
    }
    panic!("no logon SID");
}

fn sddl_of_token(t: HANDLE) -> String {
    format!("integrity {} user {}", token_sid(t, 25), token_sid(t, 1))
}

/// A plain medium process of the user with a pipe and an event to reach.
fn dummy(tag: &str) {
    let name = format!(r"\\.\pipe\wick-fsprobe-{tag}-user");
    let mut pipes = Vec::new();
    for _ in 0..16 {
        // SAFETY: NUL-terminated name; up to 255 instances.
        pipes.push(H(unsafe { CreateNamedPipeW(wide(&name).as_ptr(), 3, 0, 255, 512, 512, 0, null()) }));
    }
    // SAFETY: NUL-terminated name.
    let _e = H(unsafe { CreateEventW(null(), 1, 0, wide(&format!("Local\\wick-fsprobe-{tag}-user")).as_ptr()) });
    // SAFETY: plain call.
    unsafe { Sleep(600_000) };
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("child") => child(&args[1..]),
        Some("dummy") => dummy(&args[1]),
        Some("ea") => ea_limits(&args[1]),
        Some("run") => {
            let base = args.get(1).cloned().unwrap_or_else(|| format!(r"C:\w4\fsprobe-{}", std::process::id()));
            run(&base);
        }
        _ => {
            eprintln!("usage: fs-probe run [<base>] | fs-probe ea <dir>");
            std::process::exit(2);
        }
    }
}
