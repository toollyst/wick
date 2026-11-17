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
//! fs-probe reach [<base>] what (b), the restricted token, reaches on the
//!                         whole host, and opens by file id; as run, an
//!                         elevated administrator, <base> (default
//!                         C:\w4\fsreach-<pid>) new and outside the profile
//! fs-probe devices [<base>] each device object, opened by its name and by
//!                         a name beneath it, and TCP, under (b), LPAC and a
//!                         plain AppContainer; as `reach`
//! fs-probe whp-token [<base>] the Windows Hypervisor Platform (capability,
//!                         partition, setup, memory map, vCPU, one run to a
//!                         HLT) in this process and in a child under each
//!                         lockdown token the jailer could make: the jail's
//!                         SID with the four groups as now, alone, alone
//!                         without the WHP DLLs preloaded, with each group
//!                         alone, with Authenticated Users and Everyone, with
//!                         Authenticated Users and Users, with the
//!                         hypervisorPlatform capability SID, and alone or as
//!                         now with the partition made and set up before the
//!                         revert; alone and as now with option P's whole
//!                         VM (the partition made as kvm-ioctls makes one,
//!                         before the revert, with what both partitions cost;
//!                         after it, every capability read again, each
//!                         property set again, two of four vCPUs, one run to
//!                         the guest's OUT under a 5 s watchdog, each call a
//!                         running VM makes, 64 MiB of guest memory against
//!                         the Job's count, a second partition, the partition
//!                         used again); in
//!                         an AppContainer with and without that capability,
//!                         and with it on a SID with no profile; and in an
//!                         LPAC with it, alone and with registryRead and
//!                         lpacCom. Each child with
//!                         the jail's initial token until it reverts, then
//!                         opening `\Device\VidExo` and `\Device\HvService`
//!                         itself; every step goes on past a refusal. And the
//!                         SDDL of the devices the partition opens. As an
//!                         elevated administrator; <base> (default
//!                         C:\w4\whptoken-<pid>) must not exist
//! ```
//!
//! `reach` lists every named kernel object, named pipe, file and directory of
//! the fixed volumes and registry key (HKLM and HKU) as the administrator,
//! then a child under (b) (its initial token reverted, wick's mitigations, a
//! Job) opens each with `MAXIMUM_ALLOWED` and writes what it reached; the run
//! prints each with its security descriptor. Before that sweep the child
//! opens files by id beneath the share's root handle and beneath the
//! volume's, files the host moved out of the share among them, and walks
//! each hard link's parents up to the share's root; the run renames the
//! share's parent while the child holds the share's root (opened by path),
//! the volume's root alone, a file of the share opened by id, the share's
//! root opened by id, and a file opened by name beneath that.
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

/// Firecracker's preload before its revert (vmm::ext::jail), the same code:
/// the jail-variants children take it before they revert.
#[path = "../../overlay/vmm/ext/jail_preload.rs"]
mod preload;

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
    // LUID is two DWORDs (4-byte aligned); a u64 here would put the entry
    // at offset 8 of TOKEN_PRIVILEGES, where Windows reads it at 4.
    luid: [u32; 2],
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
        // The win32k policy as the process has it before this sets it (on
        // when set at creation), and whether user32 is loaded, after which
        // the policy cannot be set.
        let mut flags = 0u32;
        // SAFETY: a flags word of 4 bytes; ProcessSystemCallDisablePolicy.
        let got = unsafe { GetProcessMitigationPolicy(GetCurrentProcess(), 4, (&raw mut flags).cast(), 4) };
        self.out("mitigation-win32k-before", if got != 0 { format!("flags {flags:#x}") } else { last() });
        // SAFETY: a NUL-terminated name; this loads nothing.
        let user32 = unsafe { GetModuleHandleW(wide("user32.dll").as_ptr()) };
        self.out("user32-loaded", if user32.is_null() { "no" } else { "yes" });
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
    /// An LPAC made from the restricted token: both confinements at once.
    RestrictedLpac { primary: HANDLE, initial: HANDLE, sid: PSID, caps: Vec<PSID> },
    /// An AppContainer (or LPAC) given, besides, an impersonation token on
    /// its main thread until it reverts (`initial`), as the jailer gives
    /// Firecracker its initial token, and process mitigation policies set at
    /// its creation (`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`, 0 for none).
    AppContainerWith { sid: PSID, caps: Vec<PSID>, lpac: bool, initial: Option<HANDLE>, mitigations: u64 },
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
    let ac = match who {
        Who::AppContainer { sid, caps, lpac } => Some((sid, caps, lpac)),
        Who::RestrictedLpac { sid, caps, .. } => Some((sid, caps, &true)),
        Who::AppContainerWith { sid, caps, lpac, .. } => Some((sid, caps, lpac)),
        _ => None,
    };
    let mitigations: u64 = if let Who::AppContainerWith { mitigations, .. } = who { *mitigations } else { 0 };
    if mitigations != 0 {
        count += 1;
    }
    if let Some((sid, caps, lpac)) = ac {
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
        if let Some((_, _, lpac)) = ac {
            assert!(UpdateProcThreadAttribute(l, 0, 0x20009, (&raw const sc).cast(), std::mem::size_of::<SECURITY_CAPABILITIES>(), null_mut(), null()) != 0);
            if *lpac {
                assert!(UpdateProcThreadAttribute(l, 0, 0x2000F, (&raw const opt_out).cast(), 4, null_mut(), null()) != 0);
            }
        }
        if mitigations != 0 {
            // PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: a DWORD64.
            assert!(UpdateProcThreadAttribute(l, 0, 0x20007, (&raw const mitigations).cast(), 8, null_mut(), null()) != 0);
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
        Who::Lua | Who::AppContainer { .. } | Who::AppContainerWith { .. } => lua,
        Who::Low => low,
        Who::Restricted { primary, .. } | Who::RestrictedLpac { primary, .. } => *primary,
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
    let initial = match who {
        Who::Restricted { initial, .. } | Who::RestrictedLpac { initial, .. } => Some(initial),
        Who::AppContainerWith { initial: Some(initial), .. } => Some(initial),
        _ => None,
    };
    if let Some(initial) = initial {
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
        let tp = TOKEN_PRIVILEGES1 { count: 1, privilege: LUID_AND_ATTRIBUTES { luid: [luid as u32, (luid >> 32) as u32], attributes: 2 } };
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

// ----------------------------------------------------------------------------
// `fs-probe reach`: what the chosen confinement, (b), reaches on the whole
// host, and whether a server that holds no handle per node (a node is its
// file id, reopened beneath one handle) stays confined and leaves the host's
// renames alone (fs-q8-answers.md §M.6, "Handles the server holds").

#[link(name = "ntdll")]
extern "system" {
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
        server_sid: PSID,
        msg: *mut c_void,
        len: *mut usize,
        out_attrs: *mut c_void,
        in_attrs: *mut c_void,
        timeout: *const i64,
    ) -> i32;
    fn NtQueryObject(h: HANDLE, class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQuerySecurityObject(h: HANDLE, info: u32, sd: *mut c_void, len: u32, needed: *mut u32) -> i32;
    fn NtClose(h: HANDLE) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn SetEvent(h: HANDLE) -> i32;
    fn CreateHardLinkW(link: *const u16, existing: *const u16, sa: *const c_void) -> i32;
    fn GetLogicalDriveStringsW(len: u32, buf: *mut u16) -> u32;
    fn GetDriveTypeW(root: *const u16) -> u32;
}

#[link(name = "advapi32")]
extern "system" {
    fn RegEnumKeyExW(key: usize, i: u32, name: *mut u16, len: *mut u32, r: *mut u32, class: *mut u16, cl: *mut u32, t: *mut u64) -> i32;
}

const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const READ_CONTROL: u32 = 0x2_0000;
const WRITE_DAC: u32 = 0x4_0000;
const FILE_LINKS_INFORMATION: u32 = 46;
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022u32 as i32;

/// An NT name as a UNICODE_STRING for the call's duration.
fn with_oa<T>(root: HANDLE, name: &str, attrs: u32, f: impl FnOnce(&OBJECT_ATTRIBUTES, &UNICODE_STRING) -> T) -> T {
    let n: Vec<u16> = name.encode_utf16().collect();
    let bytes = u16::try_from(n.len() * 2).unwrap_or(u16::MAX & !1);
    let us = UNICODE_STRING { len: bytes, max: bytes, buf: n.as_ptr() };
    let oa = OBJECT_ATTRIBUTES { len: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32, root, name: &us, attrs, sd: null_mut(), qos: null_mut() };
    f(&oa, &us)
}

/// Opens the named kernel object `path` of type `ty` with `access`: Ok(handle),
/// Err(status), or Err(1) for a type this probe does not open by name.
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
        "Device" | "File" => {
            let n: Vec<u16> = path.encode_utf16().collect();
            return nt_open_raw(null_mut(), &n, access, FILE_OPEN, 0, OBJ_CASE_INSENSITIVE);
        }
        _ => return Err(1),
    };
    with_oa(null_mut(), path, OBJ_CASE_INSENSITIVE, |oa, _| {
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

/// The DACL, owner and label of a handle opened with READ_CONTROL, as SDDL.
fn handle_sddl(h: HANDLE) -> String {
    let mut buf = vec![0u64; 1024];
    let mut need = 0;
    // SAFETY: a buffer of its length; OWNER | DACL | LABEL.
    let st = unsafe { NtQuerySecurityObject(h, 0x1 | DACL_INFO | LABEL_INFO, buf.as_mut_ptr().cast(), 8192, &mut need) };
    if st < 0 {
        return format!("sd {:#010x}", st as u32);
    }
    sddl_of(buf.as_mut_ptr().cast(), 0x1 | DACL_INFO | LABEL_INFO)
}

/// Every object of the object manager's namespace beneath `dir`: (type, path).
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
        if st == 0 {
            continue;
        }
    }
}

/// Every key beneath `root` (an open key named `nt` in NT form).
fn walk_keys(root: usize, nt: &str, out: &mut Vec<String>, unlisted: &mut usize) {
    out.push(nt.to_string());
    let mut i = 0;
    let mut name = [0u16; 512];
    loop {
        let mut len = 512;
        // SAFETY: a buffer of 512 characters.
        let e = unsafe { RegEnumKeyExW(root, i, name.as_mut_ptr(), &mut len, null_mut(), null_mut(), null_mut(), null_mut()) };
        if e != 0 {
            break;
        }
        i += 1;
        let sub = String::from_utf16_lossy(&name[..len as usize]);
        let mut k = 0;
        // SAFETY: an out-pointer; REG_OPTION_BACKUP_RESTORE (SeBackupPrivilege).
        let e = unsafe { RegOpenKeyExW(root, wide(&sub).as_ptr(), 0x4, 0x8 | 0x100, &mut k) };
        if e != 0 {
            *unlisted += 1;
            out.push(format!("{nt}\\{sub}"));
            continue;
        }
        walk_keys(k, &format!("{nt}\\{sub}"), out, unlisted);
        // SAFETY: the key just opened.
        unsafe { RegCloseKey(k) };
    }
}

/// Every path on the fixed volumes, `skip` (the probe's own base) left out.
fn walk_volumes(skip: &str, out: &mut Vec<String>, unlisted: &mut usize) {
    let mut buf = [0u16; 512];
    // SAFETY: a buffer of 512 characters.
    let n = unsafe { GetLogicalDriveStringsW(512, buf.as_mut_ptr()) } as usize;
    for root in String::from_utf16_lossy(&buf[..n]).split('\0').filter(|s| !s.is_empty()) {
        // SAFETY: NUL-terminated root; DRIVE_FIXED is 3.
        if unsafe { GetDriveTypeW(wide(root).as_ptr()) } != 3 {
            continue;
        }
        let mut stack = vec![root.trim_end_matches('\\').to_string() + "\\"];
        while let Some(d) = stack.pop() {
            out.push(d.clone());
            let Ok(rd) = std::fs::read_dir(&d) else {
                *unlisted += 1;
                continue;
            };
            for e in rd.flatten() {
                let p = e.path().to_string_lossy().into_owned();
                if p.to_lowercase().starts_with(&skip.to_lowercase()) {
                    continue;
                }
                match e.file_type() {
                    Ok(t) if t.is_dir() && !t.is_symlink() => {
                        // Junctions are not followed either.
                        let attrs = e.metadata().map(|m| std::os::windows::fs::MetadataExt::file_attributes(&m)).unwrap_or(0);
                        if attrs & 0x400 == 0 { stack.push(p) } else { out.push(p) }
                    }
                    _ => out.push(p),
                }
            }
        }
    }
}

fn write_list(path: &str, lines: impl Iterator<Item = String>) -> usize {
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let mut n = 0;
    for l in lines {
        writeln!(f, "{l}").unwrap();
        n += 1;
    }
    n
}

/// The id as the 8 bytes `FILE_OPEN_BY_FILE_ID` takes.
fn by_id(rel: HANDLE, id: u64, access: u32, opts: u32) -> Result<H, i32> {
    let units: Vec<u16> = id.to_le_bytes().chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    nt_open_raw(rel, &units, access, FILE_OPEN, FILE_OPEN_BY_FILE_ID | opts, 0)
}

/// Whether `h` lies beneath the share whose root has id `root_id`: each
/// hard link's parent is opened by id beneath `rel`, up to the root. The
/// confined server can open no directory outside the share, so a parent it
/// cannot open ends that link's walk.
fn beneath(rel: HANDLE, h: HANDLE, root_id: u64) -> String {
    let mut tried = Vec::new();
    let mut b = [0u64; 512];
    if let Err(st) = query(h, FILE_LINKS_INFORMATION, &mut b) {
        return format!("links {:#010x}", st as u32);
    }
    // FILE_LINKS_INFORMATION: BytesNeeded, EntriesReturned, then entries of
    // NextEntryOffset (4), ParentFileId (8), FileNameLength (4), FileName.
    let bytes = b.as_ptr().cast::<u8>();
    // SAFETY: within the buffer the call filled.
    let count = unsafe { std::ptr::read_unaligned(bytes.add(4).cast::<u32>()) };
    let mut off = 8usize;
    for _ in 0..count {
        // SAFETY: as above.
        let (next, mut parent) = unsafe { (std::ptr::read_unaligned(bytes.add(off).cast::<u32>()), std::ptr::read_unaligned(bytes.add(off + 8).cast::<u64>())) };
        let mut depth = 0;
        let verdict = loop {
            if parent & 0x0000_FFFF_FFFF_FFFF == root_id & 0x0000_FFFF_FFFF_FFFF {
                break "root".to_string();
            }
            depth += 1;
            if depth > 64 {
                break "too deep".to_string();
            }
            match by_id(rel, parent, FILE_READ_ATTRIBUTES, FILE_DIRECTORY_FILE) {
                Ok(p) => {
                    let mut lb = [0u64; 512];
                    if query(p.0, FILE_LINKS_INFORMATION, &mut lb).is_err() {
                        break "parent links unreadable".to_string();
                    }
                    // SAFETY: the first entry's parent id of the buffer filled.
                    let up = unsafe { std::ptr::read_unaligned(lb.as_ptr().cast::<u8>().add(16).cast::<u64>()) };
                    if up == parent {
                        break "volume root".to_string();
                    }
                    parent = up;
                }
                Err(st) => break format!("ancestor {parent:#x} {}", status(st)),
            }
        };
        tried.push(verdict);
        if next == 0 {
            break;
        }
        off += next as usize;
    }
    if tried.iter().any(|v| v == "root") {
        format!("beneath the share ({})", tried.join("; "))
    } else {
        format!("NOT beneath the share ({})", tried.join("; "))
    }
}

struct ReachArgs {
    base: String,
    share: String,
    root: HANDLE,
    vol: HANDLE,
    ids: Vec<(String, u64)>,
    root_id: u64,
    ready: [HANDLE; 6],
    go: [HANDLE; 6],
}

fn reach_child(args: &[String]) {
    let a = |i: usize| args[i].clone();
    let n = |i: usize| args[i].parse::<u64>().unwrap();
    let hd = |i: usize| n(i) as usize as HANDLE;
    let ids_arg = a(18);
    let ids = ids_arg.split(',').map(|kv| {
        let (k, v) = kv.split_once('=').unwrap();
        (k.to_string(), v.parse::<u64>().unwrap())
    });
    let r = ReachArgs {
        base: a(0),
        share: a(1),
        root: hd(2),
        vol: hd(3),
        root_id: n(4),
        ready: [hd(5), hd(6), hd(7), hd(8), hd(9), hd(10)],
        go: [hd(11), hd(12), hd(13), hd(14), hd(15), hd(16)],
        ids: ids.collect(),
    };
    let c = Child { scn: "reach".into(), base: r.base.clone(), root: r.root, secret_id: 0, share_id: 0, parent: 0, dummy: 0, tcp_port: 0, pid_tag: String::new() };
    // SAFETY: plain call (the initial token goes; nothing is loaded after).
    let ok = unsafe { RevertToSelf() };
    c.out("revert-to-lockdown-token", if ok != 0 { "allowed".into() } else { last() });
    c.token();
    c.mitigate();
    let sync = |i: usize| {
        // SAFETY: inherited event handles.
        unsafe {
            SetEvent(r.ready[i]);
            WaitForSingleObject(r.go[i], 600_000);
        }
    };
    // 1. Open by id: beneath the share's root handle and beneath a handle on
    //    the volume's root, each file the run made or moved.
    for (name, id) in &r.ids {
        for (rel_name, rel) in [("share-root", r.root), ("volume-root", r.vol)] {
            let check = format!("by-id-{name}-beneath-{rel_name}");
            match by_id(rel, *id, FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL, 0) {
                Ok(h) => {
                    let path = name_of(h.0, FILE_NORMALIZED_NAME_INFORMATION).unwrap_or_else(|s| format!("? {s:#x}"));
                    c.out(&check, format!("allowed granted {:#x} as {path}; {}", granted(h.0), beneath(rel, h.0, r.root_id)));
                }
                Err(st) => c.out(&check, status(st)),
            }
        }
    }
    // The owner's implicit rights: a file of the user's, the user its owner,
    // its DACL the user's alone.
    let owned = format!("{}\\outside\\owned-by-user.txt", r.base);
    for (check, access) in [("owner-read-control", READ_CONTROL), ("owner-write-dac", WRITE_DAC), ("owner-maximum-allowed", MAXIMUM_ALLOWED)] {
        let n: Vec<u16> = format!("\\??\\{owned}").encode_utf16().collect();
        match nt_open_raw(null_mut(), &n, access, FILE_OPEN, 0, 0) {
            Ok(h) => c.out(check, format!("allowed granted {:#x}", granted(h.0))),
            Err(st) => c.out(check, status(st)),
        }
    }
    // 2. The host renames, while this server holds the share's root handle
    //    and the volume's, then the volume's alone, then a file of the share.
    sync(0);
    // SAFETY: the inherited share root handle.
    unsafe { CloseHandle(r.root) };
    sync(1);
    let f_id = r.ids.iter().find(|(k, _)| k == "f").map(|(_, v)| *v).unwrap();
    match by_id(r.vol, f_id, FILE_READ_DATA, 0) {
        Ok(h) => c.out("by-id-after-the-host-renamed-the-shares-parent", format!("allowed as {}; {}", name_of(h.0, FILE_NORMALIZED_NAME_INFORMATION).unwrap_or_default(), beneath(r.vol, h.0, r.root_id))),
        Err(st) => c.out("by-id-after-the-host-renamed-the-shares-parent", status(st)),
    }
    let g_id = r.ids.iter().find(|(k, _)| k == "g").map(|(_, v)| *v).unwrap();
    let held = by_id(r.vol, g_id, FILE_READ_DATA, 0);
    c.out("hold-a-file-in-sub-opened-by-id", match &held {
        Ok(_) => "allowed".into(),
        Err(st) => status(*st),
    });
    sync(2);
    drop(held);
    // The share's root opened by id beneath the volume's handle: held alone,
    // then with a file of the share opened by name beneath it.
    let root_by_id = by_id(r.vol, r.root_id, FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_DIRECTORY_FILE);
    c.out("hold-the-share-root-opened-by-id", match &root_by_id {
        Ok(h) => format!("allowed as {}", name_of(h.0, FILE_NORMALIZED_NAME_INFORMATION).unwrap_or_default()),
        Err(st) => status(*st),
    });
    sync(3);
    let by_name = match &root_by_id {
        Ok(rb) => {
            let n: Vec<u16> = "sub\\g.txt".encode_utf16().collect();
            nt_open_raw(rb.0, &n, FILE_READ_DATA | SYNCHRONIZE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, OBJ_DONT_REPARSE)
        }
        Err(st) => Err(*st),
    };
    c.out("hold-a-file-in-sub-opened-by-name-beneath-the-root-opened-by-id", match &by_name {
        Ok(h) => format!("allowed as {}", name_of(h.0, FILE_NORMALIZED_NAME_INFORMATION).unwrap_or_default()),
        Err(st) => status(*st),
    });
    sync(4);
    drop((by_name, root_by_id));
    // The run puts the share back where it was before the sweep.
    sync(5);
    // 3. The sweep of the host's names, from the lists the run wrote.
    let lists = format!("{}\\lists", r.share);
    let out_path = format!("{}\\reach.txt", r.share);
    let mut out = std::io::BufWriter::new(std::fs::File::create(&out_path).unwrap());
    let lines = |f: &str| std::io::BufReader::new(std::fs::File::open(format!("{lists}\\{f}")).unwrap()).lines().map_while(Result::ok);
    let mut summary = Vec::new();
    // Kernel objects.
    let (mut tried, mut reached, mut skipped) = (0, 0, std::collections::BTreeMap::<String, usize>::new());
    for l in lines("objects.txt") {
        let Some((ty, path)) = l.split_once('\t') else { continue };
        tried += 1;
        if ty == "ALPC Port" {
            // A connection: the port's own access check first.
            let r2 = with_oa(null_mut(), path, 0, |_, us| {
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
            // Connected, or refused by the server after the access check
            // (STATUS_PORT_CONNECTION_REFUSED), is reached.
            if r2 >= 0 || r2 as u32 == 0xC000_0041 {
                reached += 1;
                writeln!(out, "object\t{ty}\t{path}\tconnect {:#010x}", r2 as u32).unwrap();
            } else if r2 != STATUS_ACCESS_DENIED {
                writeln!(out, "object-other\t{ty}\t{path}\tconnect {:#010x}", r2 as u32).unwrap();
            }
            continue;
        }
        let opened = open_object(ty, path, MAXIMUM_ALLOWED);
        if ty == "Device" && matches!(opened, Err(st) if st == STATUS_ACCESS_DENIED) {
            // A name beneath a device opened without FILE_DEVICE_SECURE_OPEN
            // is not checked against the device's security.
            let n: Vec<u16> = format!("{path}\\wick-probe").encode_utf16().collect();
            if let Ok(h) = nt_open_raw(null_mut(), &n, MAXIMUM_ALLOWED, FILE_OPEN, 0, OBJ_CASE_INSENSITIVE) {
                reached += 1;
                writeln!(out, "device-subname\t{ty}\t{path}\tgranted {:#x}", granted(h.0)).unwrap();
            }
        }
        match opened {
            Ok(h) => {
                reached += 1;
                writeln!(out, "object\t{ty}\t{path}\tgranted {:#x}", granted(h.0)).unwrap();
            }
            Err(1) => *skipped.entry(ty.to_string()).or_default() += 1,
            Err(st) if st == STATUS_ACCESS_DENIED => {}
            Err(st) => {
                if !matches!(st as u32, 0xC000_0034 | 0xC000_003A | 0xC000_0024 | 0xC000_0033 | 0xC000_0010 | 0xC000_000D) {
                    writeln!(out, "object-other\t{ty}\t{path}\t{:#010x}", st as u32).unwrap();
                }
            }
        }
        if tried % 2000 == 0 {
            c.out("sweep-objects-progress", format!("{tried}"));
        }
    }
    summary.push(format!("objects tried {tried} reached {reached} not-opened-by-type {skipped:?}"));
    // Named pipes: a connection is an open of the pipe's name.
    let (mut tried, mut reached, mut busy) = (0, 0, 0);
    for name in lines("pipes.txt") {
        tried += 1;
        let n: Vec<u16> = format!("\\Device\\NamedPipe\\{name}").encode_utf16().collect();
        match nt_open_raw(null_mut(), &n, MAXIMUM_ALLOWED, FILE_OPEN, FILE_NON_DIRECTORY_FILE, 0) {
            Ok(h) => {
                reached += 1;
                writeln!(out, "pipe\t{name}\tgranted {:#x}", granted(h.0)).unwrap();
            }
            Err(st) if st == STATUS_ACCESS_DENIED => {}
            Err(st) => {
                busy += 1;
                writeln!(out, "pipe-other\t{name}\t{:#010x}", st as u32).unwrap();
            }
        }
    }
    summary.push(format!("pipes tried {tried} reached {reached} other-status {busy}"));
    // Files and directories.
    let (mut tried, mut reached) = (0, 0);
    for p in lines("files.txt") {
        tried += 1;
        let n: Vec<u16> = format!("\\??\\{p}").encode_utf16().collect();
        if let Ok(h) = nt_open_raw(null_mut(), &n, MAXIMUM_ALLOWED, FILE_OPEN, FILE_OPEN_REPARSE_POINT, 0) {
            reached += 1;
            writeln!(out, "file\t{p}\tgranted {:#x}", granted(h.0)).unwrap();
        }
        if tried % 50_000 == 0 {
            c.out("sweep-files-progress", format!("{tried}"));
        }
    }
    summary.push(format!("files tried {tried} reached {reached}"));
    // Registry keys.
    let (mut tried, mut reached) = (0, 0);
    for k in lines("keys.txt") {
        tried += 1;
        if let Ok(h) = open_object("Key", &k, MAXIMUM_ALLOWED) {
            reached += 1;
            writeln!(out, "key\t{k}\tgranted {:#x}", granted(h.0)).unwrap();
        }
        if tried % 50_000 == 0 {
            c.out("sweep-keys-progress", format!("{tried}"));
        }
    }
    summary.push(format!("keys tried {tried} reached {reached}"));
    drop(out);
    for s in summary {
        c.out("sweep", s);
    }
    c.out("done", "");
}

fn reach(base: &str) {
    let tag = format!("{}", std::process::id());
    let profile = std::env::var("USERPROFILE").unwrap_or_default().to_lowercase();
    assert!(!profile.is_empty() && !base.to_lowercase().starts_with(&profile), "{base} is inside the user's profile");
    assert!(std::fs::metadata(base).is_err(), "{base} exists");
    let parent_dir = std::path::Path::new(base).parent().unwrap().to_string_lossy().into_owned();
    let parent_before = file_sddl(&parent_dir);
    std::fs::create_dir(base).unwrap();
    println!("host privileges backup {} restore {}", enable_privilege("SeBackupPrivilege"), enable_privilege("SeRestorePrivilege"));
    let own = own_token();
    let user = token_sid(own, 1);
    let r = std::collections::hash_map::RandomState::new();
    let rnd = |i: u64| {
        use std::hash::{BuildHasher, Hasher};
        let mut h = r.build_hasher();
        h.write_u64(i);
        h.finish() as u32
    };
    let share_sid = format!("S-1-9-{}-{}-{}-{}", rnd(1), rnd(2), rnd(3), rnd(4));
    println!("host user {user} share-sid {share_sid}");
    // <base>\up\share is the share; <base>\up is its parent, which the host
    // renames; <base>\bin holds the child's image, outside what is renamed.
    let up = format!("{base}\\up");
    let share = format!("{up}\\share");
    let outside = format!("{base}\\outside");
    let bin = format!("{base}\\bin");
    for d in [&up, &share, &outside, &bin, &format!("{share}\\sub"), &format!("{share}\\lists"), &format!("{share}\\moveddir")] {
        std::fs::create_dir(d).unwrap();
    }
    let share_dacl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})");
    assert_eq!(set_dacl(&share, &share_dacl), 0);
    assert_eq!(set_dacl(&outside, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})")), 0);
    let exe = format!("{bin}\\fs-probe.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    assert_eq!(set_dacl(&bin, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;0x1200a9;;;{share_sid})")), 0);
    let e = set_dacl(&share, &format!("{share_dacl}(A;OICI;{MODIFY:#x};;;{share_sid})"));
    println!("grant reach ace {share_sid} {}", if e == 0 { "set" } else { "failed" });
    // The files of the by-id checks.
    create_file(&format!("{share}\\f.txt"), b"f");
    create_file(&format!("{share}\\sub\\g.txt"), b"g");
    create_file(&format!("{share}\\moved.txt"), b"m");
    create_file(&format!("{share}\\moveddir\\c.txt"), b"c");
    create_file(&format!("{share}\\linked.txt"), b"l");
    create_file(&format!("{outside}\\never.txt"), b"n");
    create_file(&format!("{outside}\\nulldacl.txt"), b"z");
    create_file(&format!("{outside}\\owned-by-user.txt"), b"o");
    // SAFETY: NUL-terminated paths; a NULL DACL; then the user as owner and a DACL of the user's alone.
    unsafe {
        SetNamedSecurityInfoW(wide(&format!("{outside}\\nulldacl.txt")).as_ptr(), SE_FILE_OBJECT, DACL_INFO | PROTECTED_DACL, null_mut(), null_mut(), null(), null());
        let u = sid(&user);
        let e = SetNamedSecurityInfoW(wide(&format!("{outside}\\owned-by-user.txt")).as_ptr(), SE_FILE_OBJECT, 0x1, u, null_mut(), null(), null());
        println!("host owned-by-user owner set {e}");
    }
    assert_eq!(set_dacl(&format!("{outside}\\owned-by-user.txt"), &format!("D:P(A;;FA;;;{user})")), 0);
    println!("host owned-by-user {}", file_sddl(&format!("{outside}\\owned-by-user.txt")));
    // SAFETY: NUL-terminated paths.
    let hl = unsafe { CreateHardLinkW(wide(&format!("{outside}\\linked-outside.txt")).as_ptr(), wide(&format!("{share}\\linked.txt")).as_ptr(), null()) };
    println!("host hard-link-outside {}", if hl != 0 { "made".into() } else { last() });
    let id = |p: &str| file_id_of_path(p).1 as u64;
    let mut ids = vec![
        ("f".to_string(), id(&format!("{share}\\f.txt"))),
        ("g".to_string(), id(&format!("{share}\\sub\\g.txt"))),
        ("moved".to_string(), id(&format!("{share}\\moved.txt"))),
        ("moveddir-c".to_string(), id(&format!("{share}\\moveddir\\c.txt"))),
        ("linked".to_string(), id(&format!("{share}\\linked.txt"))),
        ("never".to_string(), id(&format!("{outside}\\never.txt"))),
        ("nulldacl".to_string(), id(&format!("{outside}\\nulldacl.txt"))),
    ];
    // The host moves a file and a directory out of the share, on the volume.
    for (from, to) in [(format!("{share}\\moved.txt"), format!("{outside}\\moved.txt")), (format!("{share}\\moveddir"), format!("{outside}\\moveddir"))] {
        // SAFETY: NUL-terminated paths.
        let ok = unsafe { MoveFileExW(wide(&from).as_ptr(), wide(&to).as_ptr(), 0) };
        println!("host move-out {to} {} sddl-after {}", if ok != 0 { "moved".into() } else { last() }, file_sddl(&to));
    }
    ids.push(("moveddir".to_string(), id(&format!("{outside}\\moveddir"))));
    let root_id = id(&share);
    // The lists the child sweeps, written into the share (the child reads them).
    let t = std::time::Instant::now();
    let mut objects = Vec::new();
    walk_objects("\\", &mut objects);
    let mut types = std::collections::BTreeMap::<String, usize>::new();
    for (ty, _) in &objects {
        *types.entry(ty.clone()).or_default() += 1;
    }
    let n_obj = write_list(&format!("{share}\\lists\\objects.txt"), objects.iter().map(|(t, p)| format!("{t}\t{p}")));
    println!("host list objects {n_obj} by type {types:?}");
    let pipes: Vec<String> = std::fs::read_dir(r"\\.\pipe\").map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    println!("host list pipes {}", write_list(&format!("{share}\\lists\\pipes.txt"), pipes.into_iter()));
    let (mut files, mut f_unlisted) = (Vec::new(), 0);
    walk_volumes(base, &mut files, &mut f_unlisted);
    println!("host list files {} directories-not-listed {f_unlisted}", write_list(&format!("{share}\\lists\\files.txt"), files.into_iter()));
    let (mut keys, mut k_unlisted) = (Vec::new(), 0);
    for (hk, nt) in [(HKLM, "\\REGISTRY\\MACHINE"), (0x8000_0003usize, "\\REGISTRY\\USER")] {
        walk_keys(hk, nt, &mut keys, &mut k_unlisted);
    }
    println!("host list keys {} keys-not-opened {k_unlisted} ({} s for all lists)", write_list(&format!("{share}\\lists\\keys.txt"), keys.into_iter()), t.elapsed().as_secs());
    // The handles the child holds: the share's root, the volume's root.
    let open_dir = |p: &str| {
        // SAFETY: NUL-terminated path.
        H(unsafe { CreateFileW(wide(p).as_ptr(), FILE_READ_ATTRIBUTES | SYNCHRONIZE, SHARE_ALL, null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, null_mut()) })
    };
    let root = open_dir(&share);
    let vol = open_dir(&format!("{}\\", &base[..2]));
    let (root_i, vol_i) = (inheritable(root.0), inheritable(vol.0));
    drop((root, vol));
    let sa = SECURITY_ATTRIBUTES { len: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, sd: null_mut(), inherit: 1 };
    // SAFETY: unnamed auto-reset events.
    let ev: Vec<HANDLE> = (0..12).map(|_| unsafe { CreateEventW((&raw const sa).cast(), 0, 0, null()) }).collect();
    let primary = restricted_token(own, &user, &[&share_sid], &[&user, &share_sid]);
    let logon = logon_sid(own);
    let initial = impersonation(restricted_token(own, &user, &[&share_sid, "S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4", &logon, &user], &[&user, &share_sid]));
    let ids_arg: Vec<String> = ids.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let cmd = format!(
        "\"{exe}\" reach-child {base} {share} {} {} {root_id} {} {tag} {}",
        root_i as usize,
        vol_i as usize,
        ev.iter().map(|h| (*h as usize).to_string()).collect::<Vec<_>>().join(" "),
        ids_arg.join(",")
    );
    // SAFETY: NUL-terminated name.
    let null_in = inheritable(H(unsafe { CreateFileW(wide("NUL").as_ptr(), GENERIC_READ, SHARE_ALL, null(), OPEN_EXISTING, 0, null_mut()) }).0);
    let out = inheritable(GetStd(-11));
    let mut inherit = vec![root_i, vol_i, null_in, out];
    inherit.extend_from_slice(&ev);
    let who = Who::Restricted { primary, initial };
    let child = match start(&cmd, &bin, &who, null_mut(), null_mut(), &inherit, [null_in, out, out], true) {
        Ok(c) => c,
        Err(e) => panic!("start: {e}"),
    };
    // SAFETY: the suspended child; then our copies of the handles it holds.
    unsafe {
        ResumeThread(child.thread.0);
        CloseHandle(root_i);
        CloseHandle(vol_i);
    }
    let up2 = format!("{base}\\up2");
    let up3 = format!("{base}\\up3");
    let up4 = format!("{base}\\up4");
    let up5 = format!("{base}\\up5");
    // Where the share's parent is now.
    let ups = [up.clone(), up2.clone(), up3.clone(), up4.clone(), up5.clone()];
    let now_up = || ups.iter().find(|u| std::fs::metadata(u).is_ok()).unwrap().clone();
    let mv = |from: &str, to: &str| {
        // SAFETY: NUL-terminated paths.
        let ok = unsafe { MoveFileExW(wide(from).as_ptr(), wide(to).as_ptr(), 0) };
        if ok != 0 { "allowed".to_string() } else { last() }
    };
    let wait = |i: usize| {
        // SAFETY: our event.
        let w = unsafe { WaitForSingleObject(ev[i], 600_000) };
        assert_eq!(w, 0, "the child's step {i} did not come");
    };
    let go = |i: usize| {
        // SAFETY: our event.
        unsafe { SetEvent(ev[6 + i]) };
    };
    wait(0);
    let r1 = mv(&up, &up2);
    println!("host rename-the-shares-parent-while-the-server-holds-the-share-root-and-the-volume-root {r1}");
    if r1 == "allowed" {
        mv(&up2, &up);
    }
    let r2 = mv(&format!("{share}\\sub"), &format!("{share}\\sub-renamed"));
    println!("host rename-a-directory-of-the-share-while-the-server-holds-the-share-root {r2}");
    if r2 == "allowed" {
        mv(&format!("{share}\\sub-renamed"), &format!("{share}\\sub"));
    }
    go(0);
    wait(1);
    println!("host rename-the-shares-parent-while-the-server-holds-the-volume-root-only {}", mv(&up, &up2));
    go(1);
    wait(2);
    // The share is at up2 now. The renames inside it first, each undone,
    // then the parent's, so no rename names a path an earlier one moved.
    let share2 = format!("{up2}\\share");
    let r3 = mv(&format!("{share2}\\sub"), &format!("{share2}\\sub-renamed"));
    println!("host rename-the-held-files-directory {r3}");
    if r3 == "allowed" {
        mv(&format!("{share2}\\sub-renamed"), &format!("{share2}\\sub"));
    }
    let r4 = mv(&format!("{share2}\\lists"), &format!("{share2}\\lists-renamed"));
    println!("host rename-a-sibling-directory-of-the-held-file {r4}");
    if r4 == "allowed" {
        mv(&format!("{share2}\\lists-renamed"), &format!("{share2}\\lists"));
    }
    println!("host rename-the-shares-parent-while-the-server-holds-a-file-of-the-share {}", mv(&up2, &up3));
    go(2);
    wait(3);
    // The server holds the share's root, opened by id.
    let cur = now_up();
    let next = if cur == up3 { &up4 } else { &up3 };
    println!("host rename-the-shares-parent-while-the-server-holds-the-share-root-opened-by-id {}", mv(&cur, next));
    let cur = now_up();
    let r5 = mv(&format!("{cur}\\share"), &format!("{cur}\\share-renamed"));
    println!("host rename-the-share-itself-while-the-server-holds-its-root-opened-by-id {r5}");
    if r5 == "allowed" {
        mv(&format!("{cur}\\share-renamed"), &format!("{cur}\\share"));
    }
    go(3);
    wait(4);
    // The server holds the root opened by id and a file opened by name
    // beneath it.
    let cur = now_up();
    let s4 = format!("{cur}\\share");
    let r6 = mv(&format!("{s4}\\sub"), &format!("{s4}\\sub-renamed"));
    println!("host rename-the-held-files-directory-while-it-is-held-by-name {r6}");
    if r6 == "allowed" {
        mv(&format!("{s4}\\sub-renamed"), &format!("{s4}\\sub"));
    }
    let r7 = mv(&format!("{s4}\\lists"), &format!("{s4}\\lists-renamed"));
    println!("host rename-a-sibling-directory-of-the-file-held-by-name {r7}");
    if r7 == "allowed" {
        mv(&format!("{s4}\\lists-renamed"), &format!("{s4}\\lists"));
    }
    println!("host rename-the-shares-parent-while-the-server-holds-a-file-by-name-beneath-the-root-opened-by-id {}", mv(&cur, &up5));
    go(4);
    wait(5);
    // The share back at <base>\up for the sweep.
    let cur = now_up();
    if cur != up {
        println!("host rename-back {cur} {}", mv(&cur, &up));
    }
    go(5);
    // SAFETY: the child.
    unsafe {
        let w = WaitForSingleObject(child.process.0, 3_600_000);
        let mut code = 0;
        GetExitCodeProcess(child.process.0, &mut code);
        if w != 0 {
            TerminateProcess(child.process.0, 1);
        }
        println!("host reach child-exit {code:#x}{}", if w != 0 { " (timed out)" } else { "" });
    }
    // Wherever the share is now: up, up2 or up3.
    let now = ups.iter().map(|u| format!("{u}\\share")).find(|s| std::fs::metadata(s).is_ok()).unwrap();
    // What the child reached, explained by the security of each object.
    let reached = std::fs::read_to_string(format!("{now}\\reach.txt")).unwrap_or_default();
    for l in reached.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        let sd = match f[0] {
            "object" => open_object(f[1], f[2], READ_CONTROL).map(|h| handle_sddl(h.0)).unwrap_or_else(|s| format!("sd-open {:#010x}", s as u32)),
            "file" => file_sddl(f[1]),
            "pipe" => file_sddl(&format!(r"\\.\pipe\{}", f[1])),
            "key" => open_object("Key", f[1], READ_CONTROL).map(|h| handle_sddl(h.0)).unwrap_or_else(|s| format!("sd-open {:#010x}", s as u32)),
            _ => String::new(),
        };
        let kind = if sd.contains("D:NO_ACCESS_CONTROL") {
            "NULL-DACL"
        } else if sd.contains(&share_sid) {
            "share-SID-ACE"
        } else if !sd.contains("D:") && !sd.is_empty() {
            "no-DACL-read"
        } else {
            "other"
        };
        println!("reached {kind} {l} | {sd}");
    }
    // Clean-up: the ACE off, then everything checked and removed.
    let e = set_dacl(&now, &share_dacl);
    println!("revert reach ace {}", if e == 0 { "removed" } else { "failed" });
    verify_clean("reach", &now, &[share_sid.clone()]);
    verify_clean("reach-outside", &outside, &[share_sid.clone()]);
    for h in ev {
        // SAFETY: our events.
        unsafe { CloseHandle(h) };
    }
    let mut all = Vec::new();
    walk(base, &mut all);
    for p in &all {
        // SAFETY: NUL-terminated path; FILE_ATTRIBUTE_NORMAL.
        unsafe { SetFileAttributesW(wide(p).as_ptr(), 0x80) };
    }
    let removed = std::fs::remove_dir_all(base);
    println!("cleanup base removed {:?} exists-after {}", removed.map_err(|e| e.to_string()), std::fs::metadata(base).is_ok());
    let parent_after = file_sddl(&parent_dir);
    println!("cleanup {parent_dir} security {}", if parent_after == parent_before { "unchanged".to_string() } else { format!("CHANGED {parent_before} -> {parent_after}") });
}

// ----------------------------------------------------------------------------
// `fs-probe devices`: the device objects `reach` found open beneath their
// names (no FILE_DEVICE_SECURE_OPEN), and TCP, under (b), LPAC and a plain
// AppContainer side by side: whether an AppContainer token closes what (b)
// leaves open.

#[link(name = "ntdll")]
extern "system" {
    fn NtReadFile(h: HANDLE, event: HANDLE, apc: *const c_void, ctx: *const c_void, io: *mut IO_STATUS_BLOCK, buf: *mut c_void, len: u32, offset: *const i64, key: *const u32) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn CancelIoEx(h: HANDLE, ov: *const c_void) -> i32;
}
#[link(name = "fltlib")]
extern "system" {
    fn FilterConnectCommunicationPort(name: *const u16, options: u32, ctx: *const c_void, size: u16, sa: *const c_void, port: *mut HANDLE) -> i32;
}

/// A read of the input class device `path`, opened by a name beneath it:
/// whether the driver queues it (and so would complete it with input).
fn input_read(path: &str, access: u32) -> String {
    let n: Vec<u16> = format!("{path}\\wick-probe").encode_utf16().collect();
    // An asynchronous handle.
    let h = match nt_open_raw(null_mut(), &n, access, FILE_OPEN, 0, OBJ_CASE_INSENSITIVE) {
        Ok(h) => h,
        Err(st) => return format!("open for read {:#010x}", st as u32),
    };
    // SAFETY: an unnamed manual-reset event; a buffer of 10 input records
    // (12 bytes each for KEYBOARD_INPUT_DATA, 24 for MOUSE_INPUT_DATA).
    unsafe {
        let ev = H(CreateEventW(null(), 1, 0, null()));
        let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
        let mut buf = [0u8; 240];
        let st = NtReadFile(h.0, ev.0, null(), null(), &mut io, buf.as_mut_ptr().cast(), 240, null(), null());
        if st == 0x103 {
            let w = WaitForSingleObject(ev.0, 2000);
            if w == 0 {
                return format!("granted {:#x}, read pending, then completed {:#010x} with {} bytes", granted(h.0), io.status as u32, io.info);
            }
            CancelIoEx(h.0, null());
            WaitForSingleObject(ev.0, 5000);
            format!("granted {:#x}, read pending (queued; no input came in 2 s), cancelled {:#010x}", granted(h.0), io.status as u32)
        } else {
            format!("granted {:#x}, read {:#010x}", granted(h.0), st as u32)
        }
    }
}

/// A TCP connect to `ip:port`: "allowed", or the error of socket or connect.
fn tcp_connect(ip: [u8; 4], port: u16) -> String {
    // SAFETY: plain Winsock calls on a socket made here.
    unsafe {
        let s = socket(2, 1, 6);
        if s == usize::MAX {
            return format!("socket denied wsa {}", WSAGetLastError());
        }
        let mut a = [0u8; 16];
        a[0] = 2;
        a[2..4].copy_from_slice(&port.to_be_bytes());
        a[4..8].copy_from_slice(&ip);
        let r = if connect(s, a.as_ptr(), 16) == 0 { "allowed".to_string() } else { format!("connect denied wsa {}", WSAGetLastError()) };
        closesocket(s);
        r
    }
}

fn devices_child(args: &[String]) {
    let c = Child { scn: args[0].clone(), base: String::new(), root: null_mut(), secret_id: 0, share_id: 0, parent: 0, dummy: 0, tcp_port: 0, pid_tag: String::new() };
    let revert = args[1] == "1";
    let port = args[2].parse::<u16>().unwrap();
    // Winsock is loaded while the initial token (if any) is on the thread.
    wsa();
    // SAFETY: plain Winsock calls.
    unsafe {
        let s = socket(2, 1, 6);
        c.out("preload-tcp-socket", if s != usize::MAX { "allowed".into() } else { format!("denied wsa {}", WSAGetLastError()) });
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
    c.mitigate();
    c.out("tcp-loopback", tcp_connect([127, 0, 0, 1], port));
    // The cloud metadata server of the test VM: a connect only, nothing sent.
    c.out("tcp-link-local-metadata", tcp_connect([169, 254, 169, 254], 80));
    let (mut tried, mut plain, mut sub) = (0, 0, 0);
    let (mut ports, mut ports_reached) = (0, 0);
    for l in std::io::stdin().lock().lines().map_while(Result::ok) {
        let Some((ty, path)) = l.trim().split_once('\t') else { continue };
        if ty == "FilterConnectionPort" {
            ports += 1;
            let mut h = null_mut();
            // SAFETY: a NUL-terminated port name, no context, an out-pointer.
            let hr = unsafe { FilterConnectCommunicationPort(wide(path).as_ptr(), 0, null(), 0, null(), &mut h) };
            if hr >= 0 {
                ports_reached += 1;
                // SAFETY: the port handle.
                unsafe { CloseHandle(h) };
                c.out("filter-port", format!("{path} connected"));
            } else if hr as u32 != 0x8007_0005 {
                c.out("filter-port-other", format!("{path} {:#010x}", hr as u32));
            }
            continue;
        }
        tried += 1;
        match open_object("Device", path, MAXIMUM_ALLOWED) {
            Ok(h) => {
                plain += 1;
                c.out("device-plain", format!("{path} granted {:#x}", granted(h.0)));
            }
            Err(st) if st == STATUS_ACCESS_DENIED => {
                let n: Vec<u16> = format!("{path}\\wick-probe").encode_utf16().collect();
                match nt_open_raw(null_mut(), &n, MAXIMUM_ALLOWED, FILE_OPEN, 0, OBJ_CASE_INSENSITIVE) {
                    Ok(h) => {
                        sub += 1;
                        c.out("device-subname", format!("{path} granted {:#x}", granted(h.0)));
                    }
                    Err(st) if st == STATUS_ACCESS_DENIED => {}
                    Err(st) => c.out("device-subname-other", format!("{path} {:#010x}", st as u32)),
                }
            }
            Err(_) => {}
        }
    }
    c.out("devices", format!("tried {tried} plain {plain} subname {sub}"));
    c.out("filter-ports", format!("tried {ports} connected {ports_reached}"));
    for d in [r"\Device\KeyboardClass0", r"\Device\PointerClass0"] {
        c.out("input-read-asking-read-data", format!("{d} {}", input_read(d, 0x1 | SYNCHRONIZE)));
        c.out("input-read-asking-maximum-allowed", format!("{d} {}", input_read(d, MAXIMUM_ALLOWED)));
    }
}

fn devices(base: &str) {
    let tag = format!("{}", std::process::id());
    assert!(std::fs::metadata(base).is_err(), "{base} exists");
    let parent_dir = std::path::Path::new(base).parent().unwrap().to_string_lossy().into_owned();
    let parent_before = file_sddl(&parent_dir);
    std::fs::create_dir(base).unwrap();
    wsa();
    let own = own_token();
    let user = token_sid(own, 1);
    let lua = lua_token(own, &user);
    let r = std::collections::hash_map::RandomState::new();
    let rnd = |i: u64| {
        use std::hash::{BuildHasher, Hasher};
        let mut h = r.build_hasher();
        h.write_u64(i);
        h.finish() as u32
    };
    let share_sid = format!("S-1-9-{}-{}-{}-{}", rnd(1), rnd(2), rnd(3), rnd(4));
    let bin = format!("{base}\\bin");
    std::fs::create_dir(&bin).unwrap();
    let exe = format!("{bin}\\fs-probe.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    assert_eq!(set_dacl(&bin, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;0x1200a9;;;AC)(A;OICI;0x1200a9;;;S-1-15-2-2)(A;OICI;0x1200a9;;;{share_sid})")), 0);
    let mut objs = Vec::new();
    walk_objects("\\", &mut objs);
    let list = format!("{base}\\devices.txt");
    for (_, p) in objs.iter().filter(|(t, _)| t == "Directory-unlisted") {
        println!("host directory-unlisted {p}");
    }
    let n = write_list(&list, objs.iter().filter(|(t, _)| t == "Device" || t == "FilterConnectionPort").map(|(t, p)| format!("{t}\t{p}")));
    println!("host devices and filter ports {n}");
    // A loopback listener.
    // SAFETY: plain Winsock calls.
    let port = unsafe {
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
    println!("host control tcp-link-local-metadata {}", tcp_connect([169, 254, 169, 254], 80));
    for d in [r"\Device\KeyboardClass0", r"\Device\PointerClass0"] {
        println!("host control input-read-asking-read-data {d} {}", input_read(d, 0x1 | SYNCHRONIZE));
        println!("host control input-read-asking-maximum-allowed {d} {}", input_read(d, MAXIMUM_ALLOWED));
    }
    let lpac_name = format!("wick.fsprobe.dev.{tag}");
    let ac_name = format!("wick.fsprobe.devac.{tag}");
    let mut profiles = Vec::new();
    let caps = vec![capability_sid("registryRead"), capability_sid("lpacCom")];
    let logon = logon_sid(own);
    // The jail's: its own SID and four session groups restricting, at the
    // jail's integrity level (overlay/jailer/platform/windows/mod.rs).
    let jail_groups = [share_sid.as_str(), "S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4"];
    let both_name = format!("wick.fsprobe.devboth.{tag}");
    for scn in ["restricted", "jail", "restricted-lpac", "lpac", "appcontainer"] {
        let who = match scn {
            "restricted" => Who::Restricted {
                primary: restricted_token(own, &user, &[&share_sid], &[&user, &share_sid]),
                initial: impersonation(restricted_token(own, &user, &[&share_sid, "S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4", &logon, &user], &[&user, &share_sid])),
            },
            "jail" => {
                let primary = restricted_token(own, &user, &jail_groups, &[&user, &share_sid]);
                set_integrity(primary, "S-1-16-6144");
                let mut all = jail_groups.to_vec();
                all.extend([logon.as_str(), user.as_str()]);
                let initial = restricted_token(own, &user, &all, &[&user, &share_sid]);
                set_integrity(initial, "S-1-16-6144");
                Who::Restricted { primary, initial: impersonation(initial) }
            }
            "restricted-lpac" => Who::RestrictedLpac {
                primary: restricted_token(own, &user, &[&share_sid], &[&user, &share_sid]),
                initial: impersonation(restricted_token(own, &user, &[&share_sid, "S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4", &logon, &user], &[&user, &share_sid])),
                sid: appcontainer_sid(&both_name),
                caps: caps.clone(),
            },
            "lpac" => Who::AppContainer { sid: appcontainer_sid(&lpac_name), caps: caps.clone(), lpac: true },
            _ => Who::AppContainer { sid: appcontainer_sid(&ac_name), caps: Vec::new(), lpac: false },
        };
        // SAFETY: NUL-terminated path; a fresh read handle at offset 0 for each child.
        let input = inheritable(H(unsafe { CreateFileW(wide(&list).as_ptr(), GENERIC_READ, SHARE_ALL, null(), OPEN_EXISTING, 0, null_mut()) }).0);
        let out = inheritable(GetStd(-11));
        let cmd = format!("\"{exe}\" devices-child {scn} {} {port}", u8::from(matches!(scn, "restricted" | "jail" | "restricted-lpac")));
        let mut started = start(&cmd, &bin, &who, lua, lua, &[input, out], [input, out, out], true);
        if let (Err(e), false) = (&started, matches!(scn, "restricted" | "jail")) {
            println!("host {scn} start-without-profile {e}");
            let name = match scn {
                "lpac" => &lpac_name,
                "restricted-lpac" => &both_name,
                _ => &ac_name,
            };
            let (_, made) = appcontainer_profile(name);
            if made {
                profiles.push(name.clone());
            }
            started = start(&cmd, &bin, &who, lua, lua, &[input, out], [input, out, out], true);
        }
        match started {
            // SAFETY: the suspended child.
            Ok(child) => unsafe {
                ResumeThread(child.thread.0);
                let w = WaitForSingleObject(child.process.0, 600_000);
                let mut code = 0;
                GetExitCodeProcess(child.process.0, &mut code);
                if w != 0 {
                    TerminateProcess(child.process.0, 1);
                }
                println!("host {scn} child-exit {code:#x}{}", if w != 0 { " (timed out)" } else { "" });
            },
            Err(e) => println!("host {scn} start {e}"),
        }
        // SAFETY: our copy of the list handle.
        unsafe { CloseHandle(input) };
    }
    for p in &profiles {
        delete_appcontainer_profile(p);
    }
    let removed = std::fs::remove_dir_all(base);
    println!("cleanup base removed {:?} exists-after {}", removed.map_err(|e| e.to_string()), std::fs::metadata(base).is_ok());
    let parent_after = file_sddl(&parent_dir);
    println!("cleanup {parent_dir} security {}", if parent_after == parent_before { "unchanged".to_string() } else { format!("CHANGED {parent_before} -> {parent_after}") });
}

// ----------------------------------------------------------------------------
// `fs-probe devjail`: run by the jailer as the jailed binary (it carries the
// jailer's handover mark), what the jailed VMM's token reaches: every named
// kernel object, named pipe and device, and for each device what a handle
// to it allows (data read and write, a driver's I/O controls). Also IP, the
// randomness device, network configuration, and names made in global
// namespaces. `fs-probe list-objects` writes the list it reads, readable by
// every jail; `fs-probe jail-variants` runs the same checks under tokens the
// jailer could make instead (fix option (i)), or only those named after
// <ip:port>.

/// `vmm::ext::jail::HANDOVER_MARK`: the jailer starts only binaries that
/// carry it, those that take the jail over (tools/windows/jail-probe.rs).
#[used]
static HANDOVER_MARK: [u8; 22] = *b"wick-jail-handover:v1\0";

#[link(name = "ntdll")]
extern "system" {
    fn NtDeviceIoControlFile(h: HANDLE, event: HANDLE, apc: *const c_void, ctx: *const c_void, io: *mut IO_STATUS_BLOCK, code: u32, inb: *const c_void, inl: u32, outb: *mut c_void, outl: u32) -> i32;
    fn NtQueryVolumeInformationFile(h: HANDLE, io: *mut IO_STATUS_BLOCK, buf: *mut c_void, len: u32, class: u32) -> i32;
    fn NtWriteFile(h: HANDLE, event: HANDLE, apc: *const c_void, ctx: *const c_void, io: *mut IO_STATUS_BLOCK, buf: *const c_void, len: u32, offset: *const i64, key: *const u32) -> i32;
}
#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(alg: HANDLE, buf: *mut u8, len: u32, flags: u32) -> i32;
}
#[link(name = "iphlpapi")]
extern "system" {
    fn GetAdaptersAddresses(family: u32, flags: u32, reserved: *const c_void, buf: *mut u8, size: *mut u32) -> u32;
}
#[link(name = "kernel32")]
extern "system" {
    fn CreateMailslotW(name: *const u16, max: u32, timeout: u32, sa: *const c_void) -> HANDLE;
}

const STATUS_PENDING: i32 = 0x103;

/// `\Device\...` opened asynchronously (no `FILE_SYNCHRONOUS_IO_*`), so
/// that a read or an I/O control the driver keeps can be cancelled.
fn open_async(path: &str, access: u32) -> Result<H, i32> {
    let name: Vec<u16> = path.encode_utf16().collect();
    let bytes = u16::try_from(name.len() * 2).unwrap();
    let us = UNICODE_STRING { len: bytes, max: bytes, buf: name.as_ptr() };
    let oa = OBJECT_ATTRIBUTES { len: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32, root: null_mut(), name: &us, attrs: OBJ_CASE_INSENSITIVE, sd: null_mut(), qos: null_mut() };
    let mut h = null_mut();
    let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
    // SAFETY: valid structures for the call's duration.
    let st = unsafe { NtCreateFile(&mut h, access, &oa, &mut io, null(), 0x80, SHARE_ALL, FILE_OPEN, 0, null(), 0) };
    if st < 0 { Err(st) } else { Ok(H(h)) }
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

/// An I/O control on `h`: (status, bytes returned).
fn ioctl(h: HANDLE, code: u32, inb: &[u8], out: &mut [u8]) -> (String, usize) {
    let mut io = IO_STATUS_BLOCK { status: 0, info: 0 };
    // SAFETY: an unnamed manual-reset event; buffers of their lengths.
    unsafe {
        let ev = H(CreateEventW(null(), 1, 0, null()));
        let st = NtDeviceIoControlFile(h, ev.0, null(), null(), &mut io, code, inb.as_ptr().cast(), inb.len() as u32, out.as_mut_ptr().cast(), out.len() as u32);
        settle(h, ev.0, st, &io, 2000)
    }
}

/// What a handle to the device `path` allows the caller: its granted
/// access, the device's type and characteristics, whether its driver
/// dispatches an I/O control (one no driver defines, so it is refused after
/// dispatch), and a read and a zero-length write where granted.
fn device_reach(path: &str) -> Option<String> {
    // The device by its name; refused that, a name beneath it, which only a
    // device with FILE_DEVICE_SECURE_OPEN checks against its security.
    let (h, how) = match open_async(path, MAXIMUM_ALLOWED) {
        Ok(h) => (h, "by-name"),
        Err(st) if st == STATUS_ACCESS_DENIED => (open_async(&format!("{path}\\wick-probe"), MAXIMUM_ALLOWED).ok()?, "beneath-its-name"),
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
    let (ioc, _) = ioctl(h.0, (dtype.max(1) << 16) | (0xFFF << 2), &[], &mut []);
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

/// I/O controls that read what a device knows, named by the device; the
/// data itself is not printed.
fn device_info(c: &Child) {
    let mut out = vec![0u8; 16384];
    let probe = |path: &str, name: &str, code: u32, inb: &[u8], out: &mut [u8]| match open_async(path, MAXIMUM_ALLOWED) {
        Ok(h) => {
            let (st, n) = ioctl(h.0, code, inb, out);
            c.out("device-info", format!("{path} {name} {st} {n} bytes"));
            n
        }
        Err(st) => {
            c.out("device-info", format!("{path} {name} open {:#010x}", st as u32));
            0
        }
    };
    // IOCTL_STORAGE_QUERY_PROPERTY, StorageDeviceProperty, standard query.
    let q = [0u8; 12];
    let n = probe(r"\Device\Harddisk0\DR0", "storage-query-property", 0x002D_1400, &q, &mut out);
    if n >= 40 {
        let serial_off = u32::from_le_bytes(out[24..28].try_into().unwrap()) as usize;
        let serial = if serial_off != 0 && serial_off < n { out[serial_off..n].iter().take_while(|b| **b != 0).count() } else { 0 };
        c.out("device-info", format!(r"\Device\Harddisk0\DR0 serial-number-returned {} characters", serial));
    }
    // IOCTL_DISK_GET_DRIVE_LAYOUT_EX: the partition table.
    let n = probe(r"\Device\Harddisk0\DR0", "disk-get-drive-layout-ex", 0x0007_0050, &[], &mut out);
    if n >= 8 {
        c.out("device-info", format!(r"\Device\Harddisk0\DR0 partitions {}", u32::from_le_bytes(out[4..8].try_into().unwrap())));
    }
    // IOCTL_MOUNTMGR_QUERY_POINTS with an empty MOUNTMGR_MOUNT_POINT: every
    // volume, letter and volume GUID.
    let mp = [0u8; 24];
    let n = probe(r"\Device\MountPointManager", "mountmgr-query-points", 0x006D_0008, &mp, &mut out);
    if n >= 8 {
        c.out("device-info", format!(r"\Device\MountPointManager mount-points {}", u32::from_le_bytes(out[4..8].try_into().unwrap())));
    }
    // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS on each volume.
    for v in 1..=4 {
        probe(&format!(r"\Device\HarddiskVolume{v}"), "volume-get-disk-extents", 0x0056_0000, &[], &mut out);
    }
    // IOCTL_SERIAL_GET_BAUD_RATE.
    for s in 0..=2 {
        probe(&format!(r"\Device\Serial{s}"), "serial-get-baud-rate", 0x001B_0050, &[], &mut out);
    }
    // Raw reads ask FILE_READ_DATA explicitly.
    for p in [r"\Device\Harddisk0\DR0", r"\Device\HarddiskVolume1", r"\Device\HarddiskVolume2", r"\Device\HarddiskVolume3", r"\Device\PhysicalMemory"] {
        let r = match open_async(p, FILE_READ_DATA | SYNCHRONIZE) {
            Ok(_) => "allowed".to_string(),
            Err(st) => format!("{:#010x}", st as u32),
        };
        c.out("raw-open-for-read", format!("{p} {r}"));
    }
}

/// What the jailed side reaches; `list` is `-` for standard input.
fn jail_checks(c: &Child, revert: bool, list: &str, port: u16, ext: ([u8; 4], u16), sockdir: &str) {
    // What the checks load, loaded while the initial token is on the
    // thread, as Firecracker loads what it uses before `RevertToSelf`.
    wsa();
    // SAFETY: plain Winsock calls, size queries and a buffer of 16 bytes.
    unsafe {
        for af in [2, 1] {
            let s = socket(af, 1, 0);
            if s != usize::MAX {
                closesocket(s);
            }
        }
        let mut size = 0u32;
        GetAdaptersAddresses(0, 0, null(), null_mut(), &mut size);
        let mut b = [0u8; 16];
        BCryptGenRandom(null_mut(), b.as_mut_ptr(), 16, 2);
    }
    if revert {
        // The main thread's initial token, if any: its impersonation level
        // (TokenImpersonationLevel; 2 is SecurityImpersonation, below it
        // Windows lets the thread identify but not act), and Firecracker's
        // preload taken under it (jail_preload.rs, the same code).
        let mut t = null_mut();
        // SAFETY: our own thread's token, opened as ourselves.
        let level = if unsafe { OpenThreadToken(GetCurrentThread(), 0x8, 1, &mut t) } != 0 {
            let t = H(t);
            format!("impersonation-level {}", token_info(t.0, 9)[0] as u32)
        } else {
            format!("none {}", last())
        };
        c.out("initial-token", level);
        c.out("preload", match preload::preload() { Ok(()) => "allowed".to_string(), Err(e) => e.to_string() });
        // SAFETY: plain call.
        let ok = unsafe { RevertToSelf() };
        c.out("revert-to-lockdown-token", if ok != 0 { "allowed".into() } else { last() });
    }
    c.token();
    c.mitigate();
    // What the jail's session groups give a process after RevertToSelf: a
    // System32 DLL loaded late, and HKLM read.
    for dll in ["version.dll", "dbghelp.dll"] {
        // SAFETY: NUL-terminated name.
        let h = unsafe { LoadLibraryW(wide(dll).as_ptr()) };
        c.out("load-library-after-revert", format!("{dll} {}", if h.is_null() { last() } else { "allowed".into() }));
    }
    let mut k = 0usize;
    // SAFETY: NUL-terminated subkey; KEY_READ; an out-pointer.
    let e = unsafe { RegOpenKeyExW(HKLM, wide(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").as_ptr(), 0, 0x20019, &mut k) };
    c.out("hklm-read", if e == 0 { "allowed".into() } else { format!("error {e}") });
    // IP: loopback, the cloud metadata server, an external address
    // (connects only; nothing is sent).
    c.out("tcp-loopback", tcp_connect([127, 0, 0, 1], port));
    c.out("tcp-link-local-metadata", tcp_connect([169, 254, 169, 254], 80));
    c.out("tcp-external", format!("{}.{}.{}.{}:{} {}", ext.0[0], ext.0[1], ext.0[2], ext.0[3], ext.1, tcp_connect(ext.0, ext.1)));
    // AF_UNIX: a socket bound where the jail may make files.
    // SAFETY: plain Winsock calls.
    unsafe {
        let s = socket(1, 1, 0);
        if s == usize::MAX {
            c.out("unix-socket", format!("denied wsa {}", WSAGetLastError()));
        } else {
            let addr = unix_addr(&format!("{sockdir}\\p{}.sock", std::process::id()));
            let r = bind(s, addr.as_ptr(), addr.len() as i32);
            c.out("unix-socket-bind", if r == 0 { "allowed".into() } else { format!("denied wsa {}", WSAGetLastError()) });
            closesocket(s);
            let _ = std::fs::remove_file(format!("{sockdir}\\p{}.sock", std::process::id()));
        }
    }
    // Randomness (the counterpart of /dev/urandom).
    let mut b = [0u8; 16];
    // SAFETY: a buffer of 16 bytes; BCRYPT_USE_SYSTEM_PREFERRED_RNG.
    let st = unsafe { BCryptGenRandom(null_mut(), b.as_mut_ptr(), 16, 2) };
    c.out("bcrypt-gen-random", format!("{:#010x}", st as u32));
    // The host's network configuration (\Device\Nsi).
    let mut size = 0u32;
    // SAFETY: a size query, then a buffer of that size.
    let r = unsafe {
        GetAdaptersAddresses(0, 0, null(), null_mut(), &mut size);
        let mut buf = vec![0u8; size as usize + 1];
        let e = GetAdaptersAddresses(0, 0, null(), buf.as_mut_ptr(), &mut size);
        if e == 0 {
            let mut n = 0;
            let mut p = buf.as_ptr();
            while !p.is_null() {
                n += 1;
                // IP_ADAPTER_ADDRESSES: Length (4), IfIndex (4), Next (8).
                p = std::ptr::read_unaligned(p.add(8).cast::<*const u8>());
            }
            format!("allowed {n} adapters")
        } else {
            format!("error {e}")
        }
    };
    c.out("network-configuration", r);
    // Names in the global namespaces: a named pipe and a mailslot.
    let pipe = format!(r"\\.\pipe\wick-probe-squat-{}", std::process::id());
    // SAFETY: NUL-terminated name; PIPE_ACCESS_DUPLEX, byte mode, one instance.
    let h = H(unsafe { CreateNamedPipeW(wide(&pipe).as_ptr(), 3, 0, 1, 512, 512, 0, null()) });
    c.out("named-pipe-create", if h.0 != INVALID { "allowed".into() } else { last() });
    let slot = format!(r"\\.\mailslot\wick-probe-{}", std::process::id());
    // SAFETY: NUL-terminated name.
    let h = H(unsafe { CreateMailslotW(wide(&slot).as_ptr(), 0, 0, null()) });
    c.out("mailslot-create", if h.0 != INVALID { "allowed".into() } else { last() });
    c.out("named-pipe-list", match std::fs::read_dir(r"\\.\pipe\") {
        Ok(rd) => format!("allowed {} names", rd.count()),
        Err(e) => format!("denied {e}"),
    });
    device_info(c);
    // Every name.
    let text = if list == "-" {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut s);
        s
    } else {
        std::fs::read_to_string(list).unwrap_or_else(|e| {
            c.out("list", format!("unreadable {e}"));
            String::new()
        })
    };
    let mut by_type = std::collections::BTreeMap::<String, (usize, usize)>::new();
    for l in text.lines() {
        let Some((ty, path)) = l.split_once('\t') else { continue };
        let e = by_type.entry(ty.to_string()).or_default();
        e.0 += 1;
        let reached = match ty {
            "Pipe" => {
                let n: Vec<u16> = format!("\\Device\\NamedPipe\\{path}").encode_utf16().collect();
                nt_open_raw(null_mut(), &n, MAXIMUM_ALLOWED, FILE_OPEN, FILE_NON_DIRECTORY_FILE, 0).ok().map(|h| format!("granted {:#x}", granted(h.0)))
            }
            "ALPC Port" => {
                let st = with_oa(null_mut(), path, 0, |_, us| {
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
                (st >= 0 || st as u32 == 0xC000_0041).then(|| format!("connect {:#010x}", st as u32))
            }
            "Device" => device_reach(path),
            _ => open_object(ty, path, MAXIMUM_ALLOWED).ok().map(|h| format!("granted {:#x}", granted(h.0))),
        };
        if let Some(r) = reached {
            e.1 += 1;
            c.out("reached", format!("{ty}\t{path}\t{r}"));
        }
    }
    for (ty, (tried, reached)) in &by_type {
        c.out("summary", format!("{ty} tried {tried} reached {reached}"));
    }
    c.out("done", "");
}

fn devjail(args: &[String]) {
    let c = Child { scn: "jail".into(), base: String::new(), root: null_mut(), secret_id: 0, share_id: 0, parent: 0, dummy: 0, tcp_port: 0, pid_tag: String::new() };
    let ip: Vec<u8> = args[2].split('.').map(|p| p.parse().unwrap()).collect();
    let cwd = std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    c.out("cwd", &cwd);
    jail_checks(&c, true, &args[0], args[1].parse().unwrap(), ([ip[0], ip[1], ip[2], ip[3]], args[3].parse().unwrap()), &cwd);
}

/// The list `devjail` reads: every named kernel object and named pipe, in
/// a file every jail may read (Everyone is among a jail's restricting SIDs).
fn list_objects(path: &str) {
    let mut objs = Vec::new();
    walk_objects("\\", &mut objs);
    let pipes: Vec<String> = std::fs::read_dir(r"\\.\pipe\").map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    let n = write_list(path, objs.iter().map(|(t, p)| format!("{t}\t{p}")).chain(pipes.iter().map(|p| format!("Pipe\t{p}"))));
    assert_eq!(set_dacl(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)"), 0);
    println!("host list-objects {n} ({} objects, {} pipes)", objs.len(), pipes.len());
}

/// `jail_checks` under tokens the jailer could make instead of its own
/// (fix option (i)): the jail's integrity level and a jail SID of its own,
/// with fewer restricting SIDs; and option Q's AppContainer and LPAC with
/// WHP's capability. Each child gets the list on standard input and a
/// socket directory its SID may write, labelled as a jail's (an
/// AppContainer's labelled low), then `q_checks`.
fn jail_variants(base: &str, ext: &str, only: &[String]) {
    assert!(std::fs::metadata(base).is_err(), "{base} exists");
    let parent_dir = std::path::Path::new(base).parent().unwrap().to_string_lossy().into_owned();
    let parent_before = file_sddl(&parent_dir);
    std::fs::create_dir(base).unwrap();
    wsa();
    let own = own_token();
    let user = token_sid(own, 1);
    let r = std::collections::hash_map::RandomState::new();
    let rnd = |i: u64| {
        use std::hash::{BuildHasher, Hasher};
        let mut h = r.build_hasher();
        h.write_u64(i);
        h.finish() as u32
    };
    let jail_sid = format!("S-1-9-{}-{}-{}-{}", rnd(1), rnd(2), rnd(3), rnd(4));
    let bin = format!("{base}\\bin");
    let sock = format!("{base}\\sock");
    std::fs::create_dir(&bin).unwrap();
    std::fs::create_dir(&sock).unwrap();
    let exe = format!("{bin}\\fs-probe.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    assert_eq!(set_dacl(&bin, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;0x1200a9;;;{jail_sid})")), 0);
    assert_eq!(set_dacl(&sock, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;FA;;;{jail_sid})")), 0);
    assert_eq!(set_label(&sock, Some("S:(ML;OICI;NWNRNX;;;S-1-16-6144)")), 0);
    let list = format!("{base}\\all.txt");
    let mut objs = Vec::new();
    walk_objects("\\", &mut objs);
    let pipes: Vec<String> = std::fs::read_dir(r"\\.\pipe\").map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    write_list(&list, objs.iter().map(|(t, p)| format!("{t}\t{p}")).chain(pipes.iter().map(|p| format!("Pipe\t{p}"))));
    // SAFETY: plain Winsock calls.
    let port = unsafe {
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
    let logon = logon_sid(own);
    let session = ["S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4"];
    // ALL APPLICATION PACKAGES and ALL RESTRICTED APPLICATION PACKAGES in
    // place of the four groups: what Windows grants AppContainers, which
    // SECURITY names as the planned replacement.
    // And the two the jail's own SID alone would need for WHP
    // (docs/windows-jail-reach.md): Authenticated Users, which
    // `\Device\VidExo` grants, or the hypervisorPlatform capability it
    // grants too.
    let cap = sid_string(capability_sid("hypervisorPlatform"));
    // (name, the lockdown token's restricting SIDs besides the jail's, or
    // None for an AppContainer with the capabilities given; LPAC).
    let hv = vec!["hypervisorPlatform"];
    let variants: Vec<(&str, Option<Vec<&str>>, Vec<&str>, bool)> = vec![
        ("jail-as-now", Some(session.to_vec()), Vec::new(), false),
        ("jail-own-sid-only", Some(Vec::new()), Vec::new(), false),
        ("jail-all-app-packages", Some(vec!["S-1-15-2-1"]), Vec::new(), false),
        ("jail-all-restricted-app-packages", Some(vec!["S-1-15-2-2"]), Vec::new(), false),
        ("jail-sid-au", Some(vec!["S-1-5-11"]), Vec::new(), false),
        // WHP's two devices' groups (`whp-token`'s jail-au-everyone).
        ("jail-sid-au-everyone", Some(vec!["S-1-5-11", "S-1-1-0"]), Vec::new(), false),
        // `whp-token`'s jail-au-users, which runs WHP: what it reaches.
        ("jail-sid-au-users", Some(vec!["S-1-5-11", "S-1-5-32-545"]), Vec::new(), false),
        ("jail-sid-hypervisor-platform", Some(vec![cap.as_str()]), Vec::new(), false),
        // Option Q's tokens (docs/windows-jail-reach.md): an AppContainer
        // with WHP's capability, and an LPAC with it, alone and with the two
        // capabilities Winsock needs in an LPAC.
        ("appcontainer-cap", None, hv.clone(), false),
        ("lpac-cap", None, hv.clone(), true),
        ("lpac-cap-registry-com", None, vec!["hypervisorPlatform", "registryRead", "lpacCom"], true),
    ];
    // The AppContainer's profile, its SID's ACEs on the binary's directory
    // and on a socket directory of its own: an AppContainer runs at low
    // integrity, which a jail's label (0x1800, no write up) keeps out of
    // `sock`, so `sock-low` is labelled low.
    let profile = format!("wick.jail-variants.{}", std::process::id());
    // Option Q's follow-ups, after the variants (below).
    let followups = ["lpac-cap-preload", "lpac-cap-win32k-at-create", "appcontainer-other"];
    let want = |n: &str| only.is_empty() || only.iter().any(|o| o == n);
    let ac = variants.iter().any(|v| v.1.is_none() && want(v.0)) || followups.iter().any(|n| want(n));
    let (ac_psid, ac_made) = if ac { appcontainer_profile(&profile) } else { (null_mut(), false) };
    let sock_low = format!("{base}\\sock-low");
    if ac {
        let ac_sid = sid_string(ac_psid);
        assert_eq!(set_dacl(&bin, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;0x1200a9;;;{jail_sid})(A;OICI;0x1200a9;;;{ac_sid})")), 0);
        std::fs::create_dir(&sock_low).unwrap();
        assert_eq!(set_dacl(&sock_low, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;FA;;;{ac_sid})")), 0);
        assert_eq!(set_label(&sock_low, Some("S:(ML;OICI;NWNRNX;;;LW)")), 0);
        // The jail's directory as the jailer labels it grants the
        // AppContainer too: whether its label alone keeps it out.
        assert_eq!(set_dacl(&sock, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;FA;;;{jail_sid})(A;OICI;FA;;;{ac_sid})")), 0);
        assert_eq!(set_label(&sock, Some("S:(ML;OICI;NWNRNX;;;S-1-16-6144)")), 0);
    }
    // What `jail-labelled-dir-create` asks of each directory.
    for dir in [sock.as_str(), sock_low.as_str()] {
        if std::fs::metadata(dir).is_ok() {
            println!("host labelled-dir {dir} {}", file_sddl(dir));
        }
    }
    // A Unix socket listening in each socket directory, as the API process
    // listens for Firecracker (`vmm::ext::api_process`): the jailed side
    // connects to it.
    for dir in [sock.as_str(), sock_low.as_str()] {
        if std::fs::metadata(dir).is_err() {
            continue;
        }
        // SAFETY: plain Winsock calls.
        unsafe {
            let l = socket(1, 1, 0);
            let a = unix_addr(&format!("{dir}\\link.sock"));
            assert_eq!(bind(l, a.as_ptr(), a.len() as i32), 0, "bind link.sock wsa {}", WSAGetLastError());
            listen(l, 8);
            sink(l);
        }
    }
    // A section the jailed side is given, as the jailer gives Firecracker a
    // large-page one (overlay/jailer/platform/windows/large_pages.rs), and a
    // large-page one where this process may make it.
    // SAFETY: a pagefile-backed section of 64 KiB, PAGE_READWRITE; a view of it.
    let plain = unsafe {
        let s = H(CreateFileMappingW(INVALID, null(), 0x04, 0, 0x1_0000, null()));
        let v = MapViewOfFile(s.0, 0x2, 0, 0, 0);
        std::ptr::copy_nonoverlapping(b"wick".as_ptr(), v.cast::<u8>(), 4);
        s
    };
    let large = if enable_privilege("SeLockMemoryPrivilege") {
        // SAFETY: PAGE_READWRITE | SEC_COMMIT | SEC_LARGE_PAGES, 2 MiB.
        let s = H(unsafe { CreateFileMappingW(INVALID, null(), 0x04 | 0x0800_0000 | 0x8000_0000, 0, 0x20_0000, null()) });
        println!("host large-page-section {}", if s.0.is_null() { last() } else { "made".into() });
        (!s.0.is_null()).then_some(s)
    } else {
        println!("host large-page-section not made: this process does not hold SeLockMemoryPrivilege");
        None
    };
    for (name, groups, caps, lpac) in &variants {
        if !only.is_empty() && !only.iter().any(|o| o == name) {
            continue;
        }
        let Some(groups) = groups else {
            let who = Who::AppContainer { sid: ac_psid, caps: caps.iter().map(|c| capability_sid(c)).collect(), lpac: *lpac };
            jail_variant_run(name, &exe, &bin, &who, &list, port, ext, &sock_low, &sock, &plain, large.as_ref());
            continue;
        };
        let mut restricting = vec![jail_sid.as_str()];
        restricting.extend(groups.iter().copied());
        // Whether Windows takes these as restricting SIDs at all.
        let sids: Vec<SID_AND_ATTRIBUTES> = restricting.iter().map(|s| SID_AND_ATTRIBUTES { sid: sid(s), attributes: 0 }).collect();
        let mut t = null_mut();
        // SAFETY: valid SID array; LUA_TOKEN | DISABLE_MAX_PRIVILEGE.
        if unsafe { CreateRestrictedToken(own, 0x4 | 0x1, 0, null(), 0, null(), sids.len() as u32, sids.as_ptr(), &mut t) } == 0 {
            println!("host {name} restricted-token refused {}", last());
            continue;
        }
        // SAFETY: the token just made.
        unsafe { CloseHandle(t) };
        let primary = restricted_token(own, &user, &restricting, &[&user, &jail_sid]);
        set_integrity(primary, "S-1-16-6144");
        // The jailer's initial token: the four groups, the logon SID and
        // the user's, for the loader.
        let mut all = vec![jail_sid.as_str()];
        all.extend(session);
        all.extend([logon.as_str(), user.as_str()]);
        let initial = restricted_token(own, &user, &all, &[&user, &jail_sid]);
        set_integrity(initial, "S-1-16-6144");
        let who = Who::Restricted { primary, initial: impersonation(initial) };
        jail_variant_run(name, &exe, &bin, &who, &list, port, ext, &sock, &sock, &plain, large.as_ref());
    }
    // Option Q's follow-ups (docs/windows-jail-reach.md):
    // - lpac-cap-preload: the LPAC with the jailer's initial token on its
    //   main thread (at the AppContainer's low integrity, which it may
    //   impersonate) and Firecracker's preload taken under it: whether
    //   Winsock then works after the revert without registryRead and
    //   lpacCom;
    // - lpac-cap-win32k-at-create: the LPAC with win32k's lockdown set at
    //   its creation (PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_
    //   DISABLE_ALWAYS_ON, bit 28), where setting it later was denied;
    // - appcontainer-other: an AppContainer of another profile, as a second
    //   jail or another app of the user, against the first's directory and
    //   socket (`sock-low`, which grants the first's SID only).
    if ac {
        let hv_caps = || vec![capability_sid("hypervisorPlatform")];
        if want("lpac-cap-preload") {
            let mut all = vec![jail_sid.as_str()];
            all.extend(session);
            all.extend([logon.as_str(), user.as_str()]);
            let initial = restricted_token(own, &user, &all, &[&user, &jail_sid]);
            set_integrity(initial, "S-1-16-4096");
            let who = Who::AppContainerWith { sid: ac_psid, caps: hv_caps(), lpac: true, initial: Some(impersonation(initial)), mitigations: 0 };
            jail_variant_run("lpac-cap-preload", &exe, &bin, &who, &list, port, ext, &sock_low, &sock, &plain, large.as_ref());
        }
        if want("lpac-cap-win32k-at-create") {
            let who = Who::AppContainerWith { sid: ac_psid, caps: hv_caps(), lpac: true, initial: None, mitigations: 1 << 28 };
            jail_variant_run("lpac-cap-win32k-at-create", &exe, &bin, &who, &list, port, ext, &sock_low, &sock, &plain, large.as_ref());
        }
        if want("appcontainer-other") {
            let other = format!("{profile}.other");
            let (other_psid, other_made) = appcontainer_profile(&other);
            let other_sid = sid_string(other_psid);
            // It may run the probe, as the first may: nothing else of the
            // first's is granted to it.
            let ac_sid = sid_string(ac_psid);
            assert_eq!(set_dacl(&bin, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;0x1200a9;;;{jail_sid})(A;OICI;0x1200a9;;;{ac_sid})(A;OICI;0x1200a9;;;{other_sid})")), 0);
            let who = Who::AppContainer { sid: other_psid, caps: Vec::new(), lpac: false };
            jail_variant_run("appcontainer-other", &exe, &bin, &who, &list, port, ext, &sock_low, &sock_low, &plain, large.as_ref());
            if other_made {
                delete_appcontainer_profile(&other);
            }
        }
    }
    if ac_made {
        delete_appcontainer_profile(&profile);
    }
    let removed = std::fs::remove_dir_all(base);
    println!("cleanup base removed {:?} exists-after {}", removed.map_err(|e| e.to_string()), std::fs::metadata(base).is_ok());
    let parent_after = file_sddl(&parent_dir);
    println!("cleanup {parent_dir} security {}", if parent_after == parent_before { "unchanged".to_string() } else { format!("CHANGED {parent_before} -> {parent_after}") });
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileMappingW(file: HANDLE, sa: *const SECURITY_ATTRIBUTES, protect: u32, high: u32, low: u32, name: *const u16) -> HANDLE;
    fn MapViewOfFile(section: HANDLE, access: u32, high: u32, low: u32, size: usize) -> *mut c_void;
    fn VirtualFree(addr: *mut c_void, size: usize, ty: u32) -> i32;
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThread() -> HANDLE;
    fn GetModuleHandleW(name: *const u16) -> HANDLE;
    fn GetProcessMitigationPolicy(process: HANDLE, policy: i32, buf: *mut c_void, len: usize) -> i32;
    fn K32GetProcessMemoryInfo(process: HANDLE, counters: *mut u64, size: u32) -> i32;
    fn QueryInformationJobObject(job: HANDLE, class: i32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
}
#[link(name = "advapi32")]
extern "system" {
    fn OpenThreadToken(thread: HANDLE, access: u32, as_self: i32, token: *mut HANDLE) -> i32;
}
#[link(name = "ws2_32")]
extern "system" {
    fn select(nfds: i32, read: *mut FdSet, write: *mut FdSet, except: *mut FdSet, timeout: *const [i32; 2]) -> i32;
}

/// Winsock's `fd_set`.
#[repr(C)]
struct FdSet {
    count: u32,
    sockets: [usize; 64],
}

/// One `jail-variants` child under `who`, its sockets in `sockdir` and
/// `labelled` the jail's directory as the jailer labels it. Before it runs:
/// its process's security printed and the process opened from here (as the
/// uffd mirror's reader and the jailer's count of its memory open it); the
/// plain section, and the large-page one where made, duplicated into it, as
/// the jailer gives Firecracker a large-page section; then a connection made
/// to the socket it listens on.
#[allow(clippy::too_many_arguments)]
fn jail_variant_run(name: &str, exe: &str, bin: &str, who: &Who, list: &str, port: u16, ext: &str, sockdir: &str, labelled: &str, plain: &H, large: Option<&H>) {
    // SAFETY: NUL-terminated path.
    let input = inheritable(H(unsafe { CreateFileW(wide(list).as_ptr(), GENERIC_READ, SHARE_ALL, null(), OPEN_EXISTING, 0, null_mut()) }).0);
    let out = inheritable(GetStd(-11));
    let handoff = format!("{sockdir}\\handoff-{name}.txt");
    // SAFETY: plain call.
    let me = unsafe { GetCurrentProcessId() };
    let cmd = format!("\"{exe}\" jail-variant-child {name} {port} {ext} {sockdir} {labelled} {me} {handoff}");
    match start(&cmd, bin, who, null_mut(), null_mut(), &[input, out], [input, out, out], true) {
        Ok(child) => {
            println!("host {name} process-sddl {}", handle_sddl(child.process.0));
            for (what, access) in [("dup-handle", 0x40u32), ("query-information", 0x400), ("vm-read", 0x10)] {
                // SAFETY: a pid.
                let h = H(unsafe { OpenProcess(access, 0, child.pid) });
                println!("host {name} open-child {what} {}", if h.0.is_null() { last() } else { "allowed".into() });
            }
            let give = |s: &H| -> String {
                let mut v = null_mut();
                // SAFETY: our section; the child's process handle; FILE_MAP_READ.
                if unsafe { DuplicateHandle(GetCurrentProcess(), s.0, child.process.0, &mut v, 0x4, 0, 0) } == 0 {
                    format!("refused:{}", last().replace(' ', "_"))
                } else {
                    format!("{}", v as usize)
                }
            };
            std::fs::write(&handoff, format!("{} {}", give(plain), large.map_or_else(|| "none".to_string(), give))).unwrap();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let connector = {
                let (path, tag, stop) = (format!("{sockdir}\\c-{name}.sock"), name.to_string(), stop.clone());
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                        if std::fs::metadata(&path).is_ok() {
                            std::thread::sleep(std::time::Duration::from_millis(200));
                            // SAFETY: plain Winsock calls on a socket made here.
                            let r = unsafe {
                                let s = socket(1, 1, 0);
                                let a = unix_addr(&path);
                                let r = if connect(s, a.as_ptr(), a.len() as i32) == 0 { "allowed".to_string() } else { format!("denied wsa {}", WSAGetLastError()) };
                                closesocket(s);
                                r
                            };
                            println!("host {tag} unix-connect-to-jailed-listener {r}");
                            return;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    println!("host {tag} unix-connect-to-jailed-listener no socket file while the child ran");
                })
            };
            // SAFETY: the suspended child.
            unsafe {
                ResumeThread(child.thread.0);
                let w = WaitForSingleObject(child.process.0, 900_000);
                let mut code = 0;
                GetExitCodeProcess(child.process.0, &mut code);
                if w != 0 {
                    TerminateProcess(child.process.0, 1);
                }
                stop.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = connector.join();
                println!("host {name} child-exit {code:#x}{}", if w != 0 { " (timed out)" } else { "" });
            }
        }
        Err(e) => println!("host {name} start {e}"),
    }
    // SAFETY: our copy.
    unsafe { CloseHandle(input) };
}

fn jail_variant_child(args: &[String]) {
    let c = Child { scn: args[0].clone(), base: String::new(), root: null_mut(), secret_id: 0, share_id: 0, parent: 0, dummy: 0, tcp_port: 0, pid_tag: String::new() };
    let (ip, port) = args[2].split_once(':').unwrap();
    let ip: Vec<u8> = ip.split('.').map(|p| p.parse().unwrap()).collect();
    jail_checks(&c, true, "-", args[1].parse().unwrap(), ([ip[0], ip[1], ip[2], ip[3]], port.parse().unwrap()), &args[3]);
    if args.len() >= 7 {
        q_checks(&c, &args[3], &args[4], args[5].parse().unwrap(), &args[6]);
    }
}

/// Option Q's questions (docs/windows-jail-reach.md), asked by every
/// variant after its revert: a file made in the jail's directory as the
/// jailer labels it (0x1800); a connection to a socket a process outside
/// listens on; a socket listening for one from outside; the parent opened
/// to duplicate a handle into it; the sections given (`handoff`) mapped;
/// memory committed past the Job's limit.
fn q_checks(c: &Child, sockdir: &str, labelled: &str, parent: u32, handoff: &str) {
    let name = format!("{labelled}\\q-{}.txt", std::process::id());
    // SAFETY: NUL-terminated path.
    let h = H(unsafe { CreateFileW(wide(&name).as_ptr(), GENERIC_WRITE, 0, null(), CREATE_NEW, 0, null_mut()) });
    let made = h.0 != INVALID;
    c.out("jail-labelled-dir-create", if made { "allowed".into() } else { last() });
    drop(h);
    if made {
        let _ = std::fs::remove_file(&name);
    }
    // SAFETY: plain Winsock calls on sockets made here.
    unsafe {
        let s = socket(1, 1, 0);
        let a = unix_addr(&format!("{sockdir}\\link.sock"));
        c.out("unix-connect-outside-listener", if s == usize::MAX { format!("socket denied wsa {}", WSAGetLastError()) } else if connect(s, a.as_ptr(), a.len() as i32) == 0 { "allowed".into() } else { format!("denied wsa {}", WSAGetLastError()) });
        if s != usize::MAX {
            closesocket(s);
        }
        let l = socket(1, 1, 0);
        let path = format!("{sockdir}\\c-{}.sock", c.scn);
        let a = unix_addr(&path);
        let r = if l == usize::MAX {
            format!("socket denied wsa {}", WSAGetLastError())
        } else if bind(l, a.as_ptr(), a.len() as i32) != 0 || listen(l, 1) != 0 {
            format!("bind or listen denied wsa {}", WSAGetLastError())
        } else {
            let mut set = FdSet { count: 1, sockets: [0; 64] };
            set.sockets[0] = l;
            let timeout = [15i32, 0];
            match select(0, &mut set, null_mut(), null_mut(), &timeout) {
                1 => {
                    let s = accept(l, null_mut(), null_mut());
                    if s == usize::MAX { format!("accept failed wsa {}", WSAGetLastError()) } else { closesocket(s); "accepted".into() }
                }
                0 => "no connection in 15 s".into(),
                _ => format!("select failed wsa {}", WSAGetLastError()),
            }
        };
        c.out("unix-listen-for-outside", r);
        if l != usize::MAX {
            closesocket(l);
        }
        let _ = std::fs::remove_file(&path);
    }
    // SAFETY: a pid.
    let p = H(unsafe { OpenProcess(0x40, 0, parent) });
    c.out("open-parent-dup-handle", if p.0.is_null() { last() } else { "allowed".into() });
    match std::fs::read_to_string(handoff) {
        Ok(text) => {
            for (what, v) in ["plain-section", "large-page-section"].iter().zip(text.split(' ')) {
                let r = match v.parse::<usize>() {
                    Ok(v) => {
                        // SAFETY: a handle value the parent duplicated into this process; FILE_MAP_READ.
                        let view = unsafe { MapViewOfFile(v as HANDLE, 0x4, 0, 0, 0) };
                        if view.is_null() {
                            format!("given, map {}", last())
                        } else {
                            // SAFETY: a view of at least 64 KiB.
                            let head = unsafe { std::slice::from_raw_parts(view.cast::<u8>(), 4) };
                            format!("given, mapped, reads {:?}", String::from_utf8_lossy(head))
                        }
                    }
                    Err(_) => format!("not given ({v})"),
                };
                c.out(what, r);
            }
        }
        Err(e) => c.out("handoff-read", format!("denied {e}")),
    }
    // The Job's process memory limit is 256 MiB (`start`).
    // SAFETY: MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE; released below.
    let m = unsafe { VirtualAlloc(null_mut(), 300 << 20, 0x3000, 0x04) };
    c.out("job-commit-300-mib", if m.is_null() { format!("refused {}", last()) } else { "allowed".into() });
    if !m.is_null() {
        // SAFETY: the allocation above; MEM_RELEASE.
        unsafe { VirtualFree(m, 0, 0x8000) };
    }
    c.out("q-done", "");
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
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // The jailer makes a second process of its binary for Firecracker's API
    // server (vmm::ext::api_process); this binary serves nothing.
    if std::env::var_os("WICK_API_LINK").is_some() {
        eprintln!("fs-probe: started as the jail's API process; nothing to serve");
        return;
    }
    // Under the jailer, upstream's four arguments with their values come
    // first (env.rs `exec_command`: --id, then the three times).
    if args.first().map(String::as_str) == Some("--id") {
        args.drain(..8.min(args.len()));
    }
    std::hint::black_box(&HANDOVER_MARK);
    match args.first().map(String::as_str) {
        Some("devjail") => devjail(&args[1..]),
        Some("list-objects") => list_objects(&args[1]),
        Some("jail-variants") => jail_variants(&args[1], &args[2], &args[3..]),
        Some("jail-variant-child") => jail_variant_child(&args[1..]),
        Some("whp-token") => {
            let base = args.get(1).cloned().unwrap_or_else(|| format!(r"C:\w4\whptoken-{}", std::process::id()));
            whp_token(&base);
        }
        Some("whp-token-child") => whp_token_child(&args[1..]),
        Some("child") => child(&args[1..]),
        Some("dummy") => dummy(&args[1]),
        Some("ea") => ea_limits(&args[1]),
        Some("reach-child") => reach_child(&args[1..]),
        Some("devices-child") => devices_child(&args[1..]),
        Some("devices") => {
            let base = args.get(1).cloned().unwrap_or_else(|| format!(r"C:\w4\fsdev-{}", std::process::id()));
            devices(&base);
        }
        Some("reach") => {
            let base = args.get(1).cloned().unwrap_or_else(|| format!(r"C:\w4\fsreach-{}", std::process::id()));
            reach(&base);
        }
        Some("run") => {
            let base = args.get(1).cloned().unwrap_or_else(|| format!(r"C:\w4\fsprobe-{}", std::process::id()));
            run(&base);
        }
        _ => {
            eprintln!("usage: fs-probe run [<base>] | reach [<base>] | devices [<base>] | list-objects <file> | devjail <list> <port> <ip> <port> (under the jailer) | jail-variants <base> <ip:port> [<variant>...] | whp-token [<base>] | ea <dir>");
            std::process::exit(2);
        }
    }
}

// `whp-token`: the Windows Hypervisor Platform under the jail's tokens.

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(h: HANDLE, class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: HANDLE, flags: u32) -> HANDLE;
    fn VirtualAlloc(addr: *mut c_void, size: usize, ty: u32, protect: u32) -> *mut c_void;
}
#[link(name = "advapi32")]
extern "system" {
    fn IsTokenRestricted(t: HANDLE) -> i32;
}

/// `LOAD_LIBRARY_SEARCH_SYSTEM32`: as kvm-ioctls loads the WHP DLLs.
const SEARCH_SYSTEM32: u32 = 0x800;
/// `WHvPartitionPropertyCodeProcessorCount`.
const WHV_PROCESSOR_COUNT: u32 = 0x1fff;
/// `WHvRunVpExitReasonX64Halt`.
const WHV_EXIT_HALT: u32 = 8;
/// `sizeof(WHV_RUN_VP_EXIT_CONTEXT)`: exit reason and reserved word (8),
/// `WHV_VP_EXIT_CONTEXT` (40), the union, whose largest member is
/// `WHV_HYPERCALL_CONTEXT` (176) (WinHvPlatformDefs.h).
const WHV_EXIT_CONTEXT_SIZE: u32 = 224;

/// The name of the object behind handle `h`, or why there is none: asked on
/// a thread of its own, since a name query can wait on a pipe for ever.
fn object_name(h: HANDLE) -> String {
    let hv = h as usize;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = vec![0u64; 1024];
        // SAFETY: a buffer of 8 KiB; ObjectNameInformation.
        let st = unsafe { NtQueryObject(hv as HANDLE, 1, buf.as_mut_ptr().cast(), 8192, null_mut()) };
        let _ = tx.send(if st < 0 { format!("<name {:#010x}>", st as u32) } else { counted(&buf) });
    });
    rx.recv_timeout(std::time::Duration::from_millis(500)).unwrap_or_else(|_| "<name query did not return>".into())
}

/// The UNICODE_STRING at the start of `buf`.
fn counted(buf: &[u64]) -> String {
    // SAFETY: NtQueryObject wrote a UNICODE_STRING (length, maximum, pointer at 8) there.
    unsafe {
        let len = usize::from(*buf.as_ptr().cast::<u16>()) / 2;
        let ptr = *buf.as_ptr().cast::<u8>().add(8).cast::<*const u16>();
        if ptr.is_null() || len == 0 { String::new() } else { String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len)) }
    }
}

/// This process's `File` handles: "<handle> <name> <granted access>".
fn file_handles() -> Vec<String> {
    let mut buf = vec![0u32; 8192];
    let mut ret = 0u32;
    // SAFETY: ProcessHandleTable (58) of this process into 32 KiB.
    let st = unsafe { NtQueryInformationProcess(GetCurrentProcess(), 58, buf.as_mut_ptr().cast(), 32768, &mut ret) };
    if st < 0 {
        return vec![format!("<handle table {:#010x}>", st as u32)];
    }
    let mut out = Vec::new();
    for &v in &buf[..ret as usize / 4] {
        let h = v as usize as HANDLE;
        let mut t = vec![0u64; 128];
        // SAFETY: ObjectTypeInformation into 1 KiB.
        if unsafe { NtQueryObject(h, 2, t.as_mut_ptr().cast(), 1024, null_mut()) } < 0 || counted(&t) != "File" {
            continue;
        }
        out.push(format!("{:#x} {} {:#010x}", v, object_name(h), granted(h)));
    }
    out
}

/// WinHvPlatform.dll's exports this probe calls.
struct Whp {
    get_cap: unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32,
    create: unsafe extern "system" fn(*mut HANDLE) -> i32,
    set_prop: unsafe extern "system" fn(HANDLE, u32, *const c_void, u32) -> i32,
    setup: unsafe extern "system" fn(HANDLE) -> i32,
    map: unsafe extern "system" fn(HANDLE, *mut c_void, u64, u64, u32) -> i32,
    create_vp: unsafe extern "system" fn(HANDLE, u32, u32) -> i32,
    run: unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32) -> i32,
    delete_vp: unsafe extern "system" fn(HANDLE, u32) -> i32,
    delete: unsafe extern "system" fn(HANDLE) -> i32,
    /// The other exports the backend calls once a VM runs (`p_steps`), each
    /// by name; one missing is printed and its step left out.
    more: Vec<(&'static str, usize)>,
}

/// The exports of WinHvPlatform.dll that kvm-ioctls' WHP backend calls on a
/// partition set up (crates/compat/kvm-ioctls/src/whp/whv.rs), besides
/// [`Whp`]'s own.
const WHP_MORE: &[&str] = &[
    "WHvGetPartitionProperty",
    "WHvUnmapGpaRange",
    "WHvGetVirtualProcessorRegisters",
    "WHvSetVirtualProcessorRegisters",
    "WHvGetVirtualProcessorXsaveState",
    "WHvGetVirtualProcessorInterruptControllerState",
    "WHvRequestInterrupt",
    "WHvSuspendPartitionTime",
    "WHvResumePartitionTime",
    "WHvCancelRunVirtualProcessor",
    "WHvTranslateGva",
    "WHvQueryGpaRangeDirtyBitmap",
    "WHvAdviseGpaRange",
];

/// Every capability code of `WHV_CAPABILITY_CODE` (WinHvPlatformDefs.h;
/// windows-sys' Win32::System::Hypervisor), the backend's among them.
const WHP_CAPS: &[(u32, &str)] = &[
    (0, "HypervisorPresent"),
    (1, "Features"),
    (2, "ExtendedVmExits"),
    (3, "ExceptionExitBitmap"),
    (4, "X64MsrExitBitmap"),
    (5, "GpaRangePopulateFlags"),
    (6, "SchedulerFeatures"),
    (0x1000, "ProcessorVendor"),
    (0x1001, "ProcessorFeatures"),
    (0x1002, "ProcessorClFlushSize"),
    (0x1003, "ProcessorXsaveFeatures"),
    (0x1004, "ProcessorClockFrequency"),
    (0x1005, "InterruptClockFrequency"),
    (0x1006, "ProcessorFeaturesBanks"),
    (0x1007, "ProcessorFrequencyCap"),
    (0x1008, "SyntheticProcessorFeaturesBanks"),
    (0x1009, "ProcessorPerfmonFeatures"),
];

/// `WHV_PARTITION_PROPERTY_CODE`s (windows-sys' Win32::System::Hypervisor).
const WHV_PROP_EXTENDED_VM_EXITS: u32 = 1;
const WHV_PROP_EXCEPTION_EXIT_BITMAP: u32 = 2;
const WHV_PROP_X64_MSR_EXIT_BITMAP: u32 = 5;
const WHV_PROP_CPUID_EXIT_LIST: u32 = 0x1003;
const WHV_PROP_LOCAL_APIC_EMULATION_MODE: u32 = 0x1005;
const WHV_PROP_PROCESSOR_XSAVE_FEATURES: u32 = 0x1006;
const WHV_PROP_PROCESSOR_FEATURES_BANKS: u32 = 0x100A;

fn show_hr(tag: &str, step: &str, hr: i32) {
    println!("{tag} {step} {:#010x}{}", hr as u32, if hr < 0 { " FAILED" } else { "" });
}

impl Whp {
    /// The exports of `m`, or none (each missing one printed).
    fn load(tag: &str, m: HANDLE) -> Option<Whp> {
        let names = ["WHvGetCapability", "WHvCreatePartition", "WHvSetPartitionProperty", "WHvSetupPartition", "WHvMapGpaRange", "WHvCreateVirtualProcessor", "WHvRunVirtualProcessor", "WHvDeleteVirtualProcessor", "WHvDeletePartition"];
        let p: Vec<*const c_void> = names
            .iter()
            .map(|name| {
                // SAFETY: a module handle and a NUL-terminated name.
                let p = unsafe { GetProcAddress(m, format!("{name}\0").as_ptr()) };
                if p.is_null() {
                    println!("{tag} {name} missing");
                }
                p
            })
            .collect();
        if p.iter().any(|x| x.is_null()) {
            return None;
        }
        let more = WHP_MORE
            .iter()
            .filter_map(|&name| {
                // SAFETY: a module handle and a NUL-terminated name.
                let p = unsafe { GetProcAddress(m, format!("{name}\0").as_ptr()) };
                if p.is_null() {
                    println!("{tag} {name} missing");
                    None
                } else {
                    Some((name, p as usize))
                }
            })
            .collect();
        // SAFETY: the exports of WinHvPlatform.dll, with their documented signatures.
        unsafe {
            Some(Whp {
                more,
                get_cap: std::mem::transmute::<*const c_void, _>(p[0]),
                create: std::mem::transmute::<*const c_void, _>(p[1]),
                set_prop: std::mem::transmute::<*const c_void, _>(p[2]),
                setup: std::mem::transmute::<*const c_void, _>(p[3]),
                map: std::mem::transmute::<*const c_void, _>(p[4]),
                create_vp: std::mem::transmute::<*const c_void, _>(p[5]),
                run: std::mem::transmute::<*const c_void, _>(p[6]),
                delete_vp: std::mem::transmute::<*const c_void, _>(p[7]),
                delete: std::mem::transmute::<*const c_void, _>(p[8]),
            })
        }
    }

    /// WHvGetCapability(HypervisorPresent), printed; the partition steps go
    /// on whatever it says, so that a refusal shows where it is.
    fn present(&self, tag: &str) {
        let mut present = 0u32;
        let mut written = 0u32;
        // SAFETY: WHvCapabilityCodeHypervisorPresent into a BOOL.
        let hr = unsafe { (self.get_cap)(0, (&raw mut present).cast(), 4, &mut written) };
        show_hr(tag, "WHvGetCapability(HypervisorPresent)", hr);
        println!("{tag} hypervisor-present {present}");
    }

    /// Create, ProcessorCount = 1 and Setup, each printed, with the File
    /// handles each left new (pushed to `devices`): the partition, or none
    /// if it was not made; and whether Setup succeeded.
    fn make(&self, tag: &str, devices: &mut Vec<String>) -> Option<(HANDLE, bool)> {
        let new_handles = |before: &[String], when: &str, devices: &mut Vec<String>| {
            for h in file_handles() {
                if !before.contains(&h) {
                    println!("{tag} handle-after-{when} {h}");
                    if let Some(name) = h.split(' ').nth(1) {
                        devices.push(name.to_string());
                    }
                }
            }
        };
        let before = file_handles();
        let mut part = null_mut();
        // SAFETY: an out-pointer.
        let hr = unsafe { (self.create)(&mut part) };
        show_hr(tag, "WHvCreatePartition", hr);
        if hr < 0 {
            return None;
        }
        new_handles(&before, "create", devices);
        let before = file_handles();
        let one = 1u32;
        // SAFETY: the partition; a UINT32 property.
        show_hr(tag, "WHvSetPartitionProperty(ProcessorCount=1)", unsafe { (self.set_prop)(part, WHV_PROCESSOR_COUNT, (&raw const one).cast(), 4) });
        // SAFETY: the partition.
        let hr = unsafe { (self.setup)(part) };
        show_hr(tag, "WHvSetupPartition", hr);
        new_handles(&before, "setup", devices);
        Some((part, hr >= 0))
    }

    /// Map, a vCPU and one run of it to a HLT, then the deletes, each
    /// printed; the run's steps only on a partition set up.
    fn run_and_delete(&self, tag: &str, part: HANDLE, set_up: bool) {
        if set_up {
            // SAFETY: two committed read-write pages of our own.
            let mem = unsafe { VirtualAlloc(null_mut(), 0x2000, 0x3000, 0x04) };
            assert!(!mem.is_null(), "VirtualAlloc {}", last());
            // HLT where the reset vector may be: 0xFFFFFFF0 (CS base 0xFFFF0000,
            // IP 0xFFF0, the architectural reset state) and 0xFFFF0 (a CS base
            // of 0xF0000), each the last 16 bytes of a page of its own.
            for (page, gpa) in [(0usize, 0xFFFF_F000u64), (0x1000, 0xF_F000)] {
                // SAFETY: within the two pages.
                unsafe { *mem.cast::<u8>().add(page + 0xFF0) = 0xF4 };
                // SAFETY: the partition, our page; WHvMapGpaRangeFlagRead | Write | Execute.
                show_hr(tag, &format!("WHvMapGpaRange({gpa:#x})"), unsafe { (self.map)(part, mem.cast::<u8>().add(page).cast(), gpa, 0x1000, 0x7) });
            }
            // SAFETY: the partition; vCPU 0, no flags.
            let hr = unsafe { (self.create_vp)(part, 0, 0) };
            show_hr(tag, "WHvCreateVirtualProcessor", hr);
            if hr >= 0 {
                let mut ctx = [0u64; WHV_EXIT_CONTEXT_SIZE as usize / 8];
                // SAFETY: the partition, vCPU 0, an exit context of its size.
                let hr = unsafe { (self.run)(part, 0, ctx.as_mut_ptr().cast(), WHV_EXIT_CONTEXT_SIZE) };
                show_hr(tag, "WHvRunVirtualProcessor", hr);
                if hr >= 0 {
                    let reason = ctx[0] as u32;
                    println!("{tag} exit-reason {reason:#x}{}", if reason == WHV_EXIT_HALT { " (X64Halt: the guest's HLT)" } else { " (not the HLT)" });
                    // WHvRunVpExitReasonMemoryAccess: the GPA (at 72: the union at
                    // 48, then 1 + 3 + 16 instruction bytes and the 4-byte access info).
                    if reason == 1 {
                        println!("{tag} exit-gpa {:#x}", ctx[9]);
                    }
                }
                // SAFETY: the vCPU made above.
                show_hr(tag, "WHvDeleteVirtualProcessor", unsafe { (self.delete_vp)(part, 0) });
            }
        }
        // SAFETY: the partition made above.
        show_hr(tag, "WHvDeletePartition", unsafe { (self.delete)(part) });
    }

    /// The export `name` of [`WHP_MORE`], or none (printed missing at load).
    fn more(&self, name: &str) -> Option<usize> {
        self.more.iter().find(|(n, _)| *n == name).map(|&(_, p)| p)
    }

    /// Every capability code, one line each (HRESULT, bytes written, the
    /// bytes); the lines, to compare a later read with.
    fn caps(&self, tag: &str) -> Vec<String> {
        WHP_CAPS
            .iter()
            .map(|&(code, name)| {
                let mut buf = [0u8; 64];
                let mut written = 0u32;
                // SAFETY: a buffer of its size.
                let hr = unsafe { (self.get_cap)(code, buf.as_mut_ptr().cast(), 64, &mut written) };
                let hex: String = buf[..(written as usize).min(64)].iter().map(|b| format!("{b:02x}")).collect();
                let line = format!("{name} {:#010x} {written} bytes {hex}", hr as u32);
                println!("{tag} capability {line}");
                line
            })
            .collect()
    }

    /// `WHvGetPartitionProperty` of `size` bytes, printed: the bytes, or none.
    fn get_prop(&self, tag: &str, part: HANDLE, code: u32, name: &str, size: usize) -> Option<Vec<u8>> {
        type F = unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;
        let f = self.more("WHvGetPartitionProperty")?;
        let mut buf = vec![0u8; size];
        let mut written = 0u32;
        // SAFETY: the export, of type F; a buffer of its size.
        let hr = unsafe { std::mem::transmute::<usize, F>(f)(part, code, buf.as_mut_ptr().cast(), size as u32, &mut written) };
        let hex: String = buf.iter().take(written as usize).map(|b| format!("{b:02x}")).collect();
        println!("{tag} WHvGetPartitionProperty({name}) {:#010x}{} {written} bytes {hex}", hr as u32, if hr < 0 { " FAILED" } else { "" });
        (hr >= 0).then_some(buf)
    }

    /// `WHvSetPartitionProperty` of `bytes`, printed.
    fn set_prop_bytes(&self, tag: &str, part: HANDLE, code: u32, name: &str, bytes: &[u8]) -> i32 {
        // SAFETY: the partition; a buffer of its size.
        let hr = unsafe { (self.set_prop)(part, code, bytes.as_ptr().cast(), bytes.len() as u32) };
        show_hr(tag, &format!("WHvSetPartitionProperty({name})"), hr);
        hr
    }

    /// Option P's partition, made and set up before the revert as the
    /// backend's `configure` makes a VM's (crates/compat/kvm-ioctls/src/whp/
    /// vm.rs): more processors than the vCPUs made later, the exits, the
    /// CPUID exit list, an xAPIC, the XSAVE components and processor
    /// features WHP offers. Also the backend's second partition (its
    /// register probe, `probe_registers`), made, set up, given a vCPU and
    /// deleted. Returns the partition and the capabilities read, or none.
    fn p_before(&self, tag: &str) -> Option<(HANDLE, Vec<String>)> {
        let caps = self.caps(tag);
        let mut devices = Vec::new();
        // What the two partitions cost (time, this process's commit and its
        // Job's peak), made under the initial token.
        memory_line(tag, "before-partitions");
        let t = std::time::Instant::now();
        if let Some((probe, set_up)) = self.make(&format!("{tag} register-probe-partition"), &mut devices) {
            if set_up {
                // SAFETY: the partition; vCPU 0, no flags.
                show_hr(&format!("{tag} register-probe-partition"), "WHvCreateVirtualProcessor", unsafe { (self.create_vp)(probe, 0, 0) });
            }
            // SAFETY: the partition made above, with its vCPU.
            show_hr(&format!("{tag} register-probe-partition"), "WHvDeletePartition", unsafe { (self.delete)(probe) });
        }
        println!("{tag} register-probe-partition took {} us (made, set up, a vCPU, deleted)", t.elapsed().as_micros());
        memory_line(tag, "after-register-probe-partition");
        let t = std::time::Instant::now();
        let mut part = null_mut();
        // SAFETY: an out-pointer.
        let hr = unsafe { (self.create)(&mut part) };
        show_hr(tag, "WHvCreatePartition", hr);
        if hr < 0 {
            return None;
        }
        self.set_prop_bytes(tag, part, WHV_PROCESSOR_COUNT, "ProcessorCount=4", &4u32.to_le_bytes());
        let mut offered = 0u64;
        let mut n = 0u32;
        // SAFETY: a u64 of its size.
        unsafe { (self.get_cap)(2, (&raw mut offered).cast(), 8, &mut n) };
        // X64CpuidExit | X64MsrExit | HypercallExit where offered (debug::extended_vm_exits).
        let exits = 0x3 | (offered & (1 << 5));
        self.set_prop_bytes(tag, part, WHV_PROP_EXTENDED_VM_EXITS, &format!("ExtendedVmExits={exits:#x}"), &exits.to_le_bytes());
        let leaves: Vec<u8> = (0x0u32..=0x24).chain([0x4000_0000, 0x4000_0001]).chain(0x8000_0000..=0x8000_0028).flat_map(u32::to_le_bytes).collect();
        self.set_prop_bytes(tag, part, WHV_PROP_CPUID_EXIT_LIST, "CpuidExitList", &leaves);
        // WHvX64LocalApicEmulationModeXApic.
        self.set_prop_bytes(tag, part, WHV_PROP_LOCAL_APIC_EMULATION_MODE, "LocalApicEmulationMode=XApic", &1u32.to_le_bytes());
        let mut xsave = 0u64;
        // SAFETY: a u64 of its size.
        if unsafe { (self.get_cap)(0x1003, (&raw mut xsave).cast(), 8, &mut n) } >= 0 && xsave != 0 {
            self.set_prop_bytes(tag, part, WHV_PROP_PROCESSOR_XSAVE_FEATURES, "ProcessorXsaveFeatures", &xsave.to_le_bytes());
        }
        if let Some(banks) = self.get_prop(tag, part, WHV_PROP_PROCESSOR_FEATURES_BANKS, "ProcessorFeaturesBanks", 24) {
            self.set_prop_bytes(tag, part, WHV_PROP_PROCESSOR_FEATURES_BANKS, "ProcessorFeaturesBanks", &banks);
        }
        // SAFETY: the partition.
        let hr = unsafe { (self.setup)(part) };
        show_hr(tag, "WHvSetupPartition", hr);
        println!("{tag} vm-partition took {} us (made, its properties set, set up)", t.elapsed().as_micros());
        memory_line(tag, "after-vm-partition-setup");
        if hr < 0 {
            // SAFETY: the partition made above.
            unsafe { (self.delete)(part) };
            return None;
        }
        Some((part, caps))
    }

    /// The rest of a VM's life on `p_before`'s partition, after the revert:
    /// the capabilities read again (`before`: the lines read before the
    /// revert); each property read; the properties the backend sets before
    /// set-up, set again now; the two it sets later (exception exits, MSR
    /// exits); memory with dirty tracking; two of the four vCPUs made and
    /// one run to its HLT; each call the backend makes on a running VM; a
    /// second partition; then the deletes.
    fn p_after(&self, tag: &str, part: HANDLE, before: &[String]) {
        let after = self.caps(tag);
        let differ: Vec<&str> = WHP_CAPS.iter().zip(before.iter().zip(&after)).filter(|(_, (b, a))| b != a).map(|(&(_, n), _)| n).collect();
        println!("{tag} capabilities-as-before-revert {}", if differ.is_empty() { "same".to_string() } else { format!("DIFFER {}", differ.join(",")) });
        let props: [(u32, &str, usize); 7] = [
            (WHV_PROCESSOR_COUNT, "ProcessorCount", 4),
            (WHV_PROP_EXTENDED_VM_EXITS, "ExtendedVmExits", 8),
            (WHV_PROP_EXCEPTION_EXIT_BITMAP, "ExceptionExitBitmap", 8),
            (WHV_PROP_X64_MSR_EXIT_BITMAP, "X64MsrExitBitmap", 8),
            (WHV_PROP_LOCAL_APIC_EMULATION_MODE, "LocalApicEmulationMode", 4),
            (WHV_PROP_PROCESSOR_XSAVE_FEATURES, "ProcessorXsaveFeatures", 8),
            (WHV_PROP_PROCESSOR_FEATURES_BANKS, "ProcessorFeaturesBanks", 24),
        ];
        let mut values = std::collections::HashMap::new();
        for (code, name, size) in props {
            if let Some(v) = self.get_prop(tag, part, code, name, size) {
                values.insert(code, v);
            }
        }
        // Set before set-up by the backend; each set again with the value it
        // has (ProcessorCount with another), after set-up.
        let late = format!("{tag} after-setup");
        self.set_prop_bytes(&late, part, WHV_PROCESSOR_COUNT, "ProcessorCount=8", &8u32.to_le_bytes());
        for (code, name) in [
            (WHV_PROP_EXTENDED_VM_EXITS, "ExtendedVmExits"),
            (WHV_PROP_LOCAL_APIC_EMULATION_MODE, "LocalApicEmulationMode"),
            (WHV_PROP_PROCESSOR_XSAVE_FEATURES, "ProcessorXsaveFeatures"),
            (WHV_PROP_PROCESSOR_FEATURES_BANKS, "ProcessorFeaturesBanks"),
        ] {
            if let Some(v) = values.get(&code) {
                self.set_prop_bytes(&late, part, code, name, v);
            }
        }
        let leaves: Vec<u8> = (0x0u32..=0x24).flat_map(u32::to_le_bytes).collect();
        self.set_prop_bytes(&late, part, WHV_PROP_CPUID_EXIT_LIST, "CpuidExitList", &leaves);
        // Set after set-up by the backend: the #GP exit (vm.rs `write_exits`,
        // the gdb stub's and the x2APIC's) and TscMsrWrite (`tsc_write_exit`).
        self.set_prop_bytes(&late, part, WHV_PROP_EXCEPTION_EXIT_BITMAP, "ExceptionExitBitmap=#GP", &(1u64 << 13).to_le_bytes());
        self.set_prop_bytes(&late, part, WHV_PROP_EXCEPTION_EXIT_BITMAP, "ExceptionExitBitmap=0", &0u64.to_le_bytes());
        if let Some(v) = values.get(&WHV_PROP_X64_MSR_EXIT_BITMAP) {
            let with = u64::from_le_bytes(v[..8].try_into().unwrap()) | (1 << 1);
            self.set_prop_bytes(&late, part, WHV_PROP_X64_MSR_EXIT_BITMAP, &format!("X64MsrExitBitmap={with:#x}"), &with.to_le_bytes());
        }
        // SAFETY: three committed read-write pages of our own.
        let mem = unsafe { VirtualAlloc(null_mut(), 0x3000, 0x3000, 0x04) };
        assert!(!mem.is_null(), "VirtualAlloc {}", last());
        for (page, gpa, flags) in [(0usize, 0xFFFF_F000u64, 0x7u32), (0x1000, 0xF_F000, 0x7), (0x2000, 0x1000, 0xB)] {
            if flags == 0x7 {
                // `out 0x80, al; hlt` at the reset vector: an I/O port
                // exit, which WHP always gives the VMM, where a HLT with
                // the local APIC emulated halts in the hypervisor and never
                // returns (crates/compat/kvm-ioctls/src/whp/vcpu.rs,
                // `WHvRunVpExitReasonX64Halt`; the first P record's run
                // never returned).
                // SAFETY: within the pages.
                unsafe { std::ptr::copy_nonoverlapping([0xE6u8, 0x80, 0xF4].as_ptr(), mem.cast::<u8>().add(page + 0xFF0), 3) };
            }
            // SAFETY: the partition, our page; Read | Write | Execute, or Read | Write | TrackDirtyPages.
            show_hr(tag, &format!("WHvMapGpaRange({gpa:#x},{flags:#x})"), unsafe { (self.map)(part, mem.cast::<u8>().add(page).cast(), gpa, 0x1000, flags) });
        }
        // Two of the four processors, as the backend makes the guest's vCPUs
        // (fewer than ProcessorCount, its MAX_VCPUS).
        let mut made = Vec::new();
        for vp in [0u32, 1] {
            // SAFETY: the partition; vCPU `vp`, no flags.
            let hr = unsafe { (self.create_vp)(part, vp, 0) };
            show_hr(tag, &format!("WHvCreateVirtualProcessor({vp} of 4)"), hr);
            if hr >= 0 {
                made.push(vp);
            }
        }
        if made.contains(&0) {
            self.run_bounded(tag, part);
            self.p_running_calls(tag, part);
        }
        // Guest memory as Firecracker's: 64 MiB committed by this process
        // and mapped, with the Job's count read before and after, as
        // `memory.max` must count it with the partition made under the
        // initial token.
        memory_line(tag, "before-guest-memory");
        // SAFETY: a fresh committed read-write region of 64 MiB.
        let guest = unsafe { VirtualAlloc(null_mut(), 64 << 20, 0x3000, 0x04) };
        memory_line(tag, "after-guest-memory-committed");
        if !guest.is_null() {
            // SAFETY: the partition; our region; Read | Write.
            show_hr(tag, "WHvMapGpaRange(0x10000000, 64 MiB)", unsafe { (self.map)(part, guest, 0x1000_0000, 64 << 20, 0x3) });
            memory_line(tag, "after-guest-memory-mapped");
        }
        // A partition made now, as a retried InstanceStart or a second
        // `Kvm`'s register probe would: option P has none after the revert.
        let mut devices = Vec::new();
        if let Some((second, set_up)) = self.make(&format!("{tag} second-partition"), &mut devices) {
            println!("{tag} second-partition made, set-up {set_up}");
            // SAFETY: the partition made above.
            unsafe { (self.delete)(second) };
        }
        for vp in made.iter().rev() {
            // SAFETY: a vCPU made above.
            show_hr(tag, &format!("WHvDeleteVirtualProcessor({vp})"), unsafe { (self.delete_vp)(part, *vp) });
        }
        // The partition used again, as a retried InstanceStart would need
        // under option P: its memory unmapped and its vCPUs gone, then
        // mapped, a vCPU made and run again.
        let again = format!("{tag} reuse");
        if let Some(unmap) = self.more("WHvUnmapGpaRange") {
            // SAFETY: the export, of this type (WinHvPlatform.h).
            let unmap = unsafe { std::mem::transmute::<usize, unsafe extern "system" fn(HANDLE, u64, u64) -> i32>(unmap) };
            for gpa in [0xFFFF_F000u64, 0xF_F000] {
                // SAFETY: the partition; a range mapped above.
                show_hr(&again, &format!("WHvUnmapGpaRange({gpa:#x})"), unsafe { unmap(part, gpa, 0x1000) });
            }
            for (page, gpa) in [(0usize, 0xFFFF_F000u64), (0x1000, 0xF_F000)] {
                // SAFETY: the partition, our page; Read | Write | Execute.
                show_hr(&again, &format!("WHvMapGpaRange({gpa:#x})"), unsafe { (self.map)(part, mem.cast::<u8>().add(page).cast(), gpa, 0x1000, 0x7) });
            }
            // SAFETY: the partition; vCPU 0, no flags.
            let hr = unsafe { (self.create_vp)(part, 0, 0) };
            show_hr(&again, "WHvCreateVirtualProcessor(0)", hr);
            if hr >= 0 {
                self.run_bounded(&again, part);
                // SAFETY: the vCPU just made.
                show_hr(&again, "WHvDeleteVirtualProcessor(0)", unsafe { (self.delete_vp)(part, 0) });
            }
        }
        // SAFETY: the partition made before the revert.
        show_hr(tag, "WHvDeletePartition", unsafe { (self.delete)(part) });
    }

    /// One run of vCPU 0 of `part`, cancelled from another thread after 5 s
    /// if it has not returned (`WHvCancelRunVirtualProcessor`), so that a
    /// run that does not return is a line, not a child that times out: the
    /// HRESULT and the exit reason printed.
    fn run_bounded(&self, tag: &str, part: HANDLE) -> Option<u32> {
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let watchdog = self.more("WHvCancelRunVirtualProcessor").map(|cancel| {
            let (done, p) = (done.clone(), part as usize);
            std::thread::spawn(move || {
                for _ in 0..50 {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    if done.load(SeqCst) {
                        return false;
                    }
                }
                // SAFETY: the export, of this type (WinHvPlatform.h).
                let cancel = unsafe { std::mem::transmute::<usize, unsafe extern "system" fn(HANDLE, u32, u32) -> i32>(cancel) };
                // SAFETY: the partition, vCPU 0, no flags.
                unsafe { cancel(p as HANDLE, 0, 0) };
                true
            })
        });
        let mut ctx = [0u64; WHV_EXIT_CONTEXT_SIZE as usize / 8];
        // SAFETY: the partition, vCPU 0, an exit context of its size.
        let hr = unsafe { (self.run)(part, 0, ctx.as_mut_ptr().cast(), WHV_EXIT_CONTEXT_SIZE) };
        done.store(true, SeqCst);
        let cancelled = watchdog.is_some_and(|w| w.join().unwrap_or(false));
        show_hr(tag, "WHvRunVirtualProcessor(0)", hr);
        if hr < 0 {
            return None;
        }
        let reason = ctx[0] as u32;
        println!("{tag} exit-reason {reason:#x} ({}){}", exit_name(reason), if cancelled { ", after the watchdog's cancel at 5 s" } else { "" });
        Some(reason)
    }

    /// The calls kvm-ioctls' WHP backend makes on a running VM, each once on
    /// vCPU 0 and the pages `p_after` mapped, printed.
    fn p_running_calls(&self, tag: &str, part: HANDLE) {
        macro_rules! call {
            ($name:literal, $ty:ty, |$f:ident| $body:expr) => {
                if let Some(p) = self.more($name) {
                    // SAFETY: the export, of the type given (WinHvPlatform.h).
                    let $f = unsafe { std::mem::transmute::<usize, $ty>(p) };
                    let hr: i32 = $body;
                    show_hr(tag, $name, hr);
                }
            };
        }
        let rip = [16u32];
        let mut value = [0u128; 1];
        call!("WHvGetVirtualProcessorRegisters", unsafe extern "system" fn(HANDLE, u32, *const u32, u32, *mut u128) -> i32, |f| unsafe {
            f(part, 0, rip.as_ptr(), 1, value.as_mut_ptr())
        });
        call!("WHvSetVirtualProcessorRegisters", unsafe extern "system" fn(HANDLE, u32, *const u32, u32, *const u128) -> i32, |f| unsafe {
            f(part, 0, rip.as_ptr(), 1, value.as_ptr())
        });
        let mut buf = vec![0u64; 2048];
        let mut written = 0u32;
        call!("WHvGetVirtualProcessorXsaveState", unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32, |f| unsafe {
            f(part, 0, buf.as_mut_ptr().cast(), 16384, &mut written)
        });
        call!("WHvGetVirtualProcessorInterruptControllerState", unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32, |f| unsafe {
            f(part, 0, buf.as_mut_ptr().cast(), 16384, &mut written)
        });
        // WHV_INTERRUPT_CONTROL: fixed, physical, edge; APIC 0, vector 0x30.
        let interrupt = [0u64, 0x30u64 << 32];
        call!("WHvRequestInterrupt", unsafe extern "system" fn(HANDLE, *const u64, u32) -> i32, |f| unsafe { f(part, interrupt.as_ptr(), 16) });
        call!("WHvSuspendPartitionTime", unsafe extern "system" fn(HANDLE) -> i32, |f| unsafe { f(part) });
        call!("WHvResumePartitionTime", unsafe extern "system" fn(HANDLE) -> i32, |f| unsafe { f(part) });
        call!("WHvCancelRunVirtualProcessor", unsafe extern "system" fn(HANDLE, u32, u32) -> i32, |f| unsafe { f(part, 0, 0) });
        let (mut result, mut gpa) = (0u64, 0u64);
        // WHvTranslateGvaFlagValidateRead.
        call!("WHvTranslateGva", unsafe extern "system" fn(HANDLE, u32, u64, u32, *mut u64, *mut u64) -> i32, |f| unsafe {
            f(part, 0, 0xFFF0, 1, &mut result, &mut gpa)
        });
        let mut bitmap = 0u64;
        call!("WHvQueryGpaRangeDirtyBitmap", unsafe extern "system" fn(HANDLE, u64, u64, *mut u64, u32) -> i32, |f| unsafe {
            f(part, 0x1000, 0x1000, &mut bitmap, 8)
        });
        // WHvAdviseGpaRangeCodePopulate of the dirty-tracked page, for read.
        let range = [0x1000u64, 0x1000];
        let populate = [0u32, 0];
        call!("WHvAdviseGpaRange", unsafe extern "system" fn(HANDLE, *const u64, u32, i32, *const c_void, u32) -> i32, |f| unsafe {
            f(part, range.as_ptr(), 1, 0, populate.as_ptr().cast(), 8)
        });
        call!("WHvUnmapGpaRange", unsafe extern "system" fn(HANDLE, u64, u64) -> i32, |f| unsafe { f(part, 0x1000, 0x1000) });
    }
}

/// `WHV_RUN_VP_EXIT_REASON`'s name for `reason` (WinHvPlatformDefs.h).
fn exit_name(reason: u32) -> &'static str {
    match reason {
        0x1 => "MemoryAccess",
        0x2 => "X64IoPortAccess: the guest's OUT",
        0x4 => "UnrecoverableException",
        0x5 => "InvalidVpRegisterValue",
        0x6 => "UnsupportedFeature",
        0x7 => "X64InterruptWindow",
        WHV_EXIT_HALT => "X64Halt: the guest's HLT",
        0x9 => "X64ApicEoi",
        0x1000 => "X64MsrAccess",
        0x1001 => "X64Cpuid",
        0x1002 => "Exception",
        0x2001 => "Canceled",
        _ => "another",
    }
}

/// This process's commit (`PROCESS_MEMORY_COUNTERS_EX.PrivateUsage`) and
/// its Job's peak (`JOBOBJECT_EXTENDED_LIMIT_INFORMATION.PeakJobMemoryUsed`,
/// of the Job the process is in), printed as `<tag> memory <what> ...`.
fn memory_line(tag: &str, what: &str) {
    // PROCESS_MEMORY_COUNTERS_EX: 80 bytes, `cb` first, PrivateUsage last.
    let mut c = [0u64; 10];
    c[0] = 80;
    // SAFETY: our process; a structure of the size given.
    let private = if unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), c.as_mut_ptr(), 80) } != 0 { format!("{} KiB", c[9] >> 10) } else { last() };
    let mut info = [0u64; 18];
    let mut n = 0u32;
    // SAFETY: the calling process's Job; JobObjectExtendedLimitInformation, 144 bytes.
    let job = if unsafe { QueryInformationJobObject(null_mut(), 9, info.as_mut_ptr().cast(), 144, &mut n) } != 0 { format!("{} KiB", info[17] >> 10) } else { last() };
    println!("{tag} memory {what} private {private} job-peak {job}");
}

/// One microVM's worth of WHP, step by step, through `m` (WinHvPlatform.dll):
/// each step's HRESULT, the device handles the partition holds, and the exit
/// of one run of a vCPU whose first instruction (at the reset vector) is HLT.
/// Returns the device names the partition opened.
fn whp_steps(tag: &str, m: HANDLE) -> Vec<String> {
    let mut devices = Vec::new();
    let Some(whp) = Whp::load(tag, m) else {
        return devices;
    };
    whp.present(tag);
    if let Some((part, set_up)) = whp.make(tag, &mut devices) {
        whp.run_and_delete(tag, part, set_up);
    }
    devices
}

/// The WHP devices opened directly, as this process's token may: for the
/// access WinHvPlatform's handle had (0x120089) and for the most allowed;
/// each NTSTATUS and the access granted.
fn whp_device_opens(tag: &str) {
    for device in [r"\Device\VidExo", r"\Device\HvService"] {
        for (what, access) in [("0x120089", 0x0012_0089u32), ("maximum-allowed", 0x0200_0000)] {
            match open_object("Device", device, access) {
                Ok(h) => println!("{tag} open {device} {what} 0x00000000 granted {:#010x}", granted(h.0)),
                Err(st) => println!("{tag} open {device} {what} {:#010x} FAILED", st as u32),
            }
        }
    }
}

/// Loads `dll` from System32 as kvm-ioctls does; prints the result.
fn load_system32(tag: &str, what: &str, dll: &str) -> HANDLE {
    // SAFETY: a NUL-terminated name.
    let m = unsafe { LoadLibraryExW(wide(dll).as_ptr(), null_mut(), SEARCH_SYSTEM32) };
    println!("{tag} {what} {dll} {}", if m.is_null() { last() } else { "loaded".into() });
    m
}

/// The measurement: WHP in this (elevated) process as the control; the
/// security of the device objects the partition opened and of every device
/// whose name says WHP, VID or the hypervisor, as SDDL; then a child under
/// each token the jailer could give Firecracker, each in a Job, with the
/// jail's initial token on its main thread until it reverts.
fn whp_token(base: &str) {
    assert!(std::fs::metadata(base).is_err(), "{base} exists");
    let own = own_token();
    let user = token_sid(own, 1);
    // TokenElevation (20): a DWORD.
    let elevated = token_info(own, 20)[0] as u32 != 0;
    println!("host user {user} elevated {elevated}");
    let mut devices = Vec::new();
    let m = load_system32("host", "load", "WinHvPlatform.dll");
    if !m.is_null() {
        devices = whp_steps("host", m);
    }
    let mut objs = Vec::new();
    walk_objects("\\Device", &mut objs);
    // VID (the virtualization infrastructure driver WinHvPlatform works
    // through), WinHv and the hypervisor's other devices; not video ones.
    let keys = ["winhv", "hypervisor", "hvsocket", "vmbus", "hvservice"];
    for (_, path) in &objs {
        let last = path.rsplit('\\').next().unwrap_or("").to_lowercase();
        let vid = last.starts_with("vid") && !last.starts_with("video");
        if (vid || keys.iter().any(|k| last.contains(k))) && !devices.contains(path) {
            devices.push(path.clone());
        }
    }
    let mut sddls = String::new();
    for d in &devices {
        // The device object itself (READ_CONTROL), not a name beneath it.
        let device = d.split('\\').take(3).collect::<Vec<_>>().join("\\");
        match open_object("Device", &device, 0x0002_0000) {
            Ok(h) => {
                let sddl = handle_sddl(h.0);
                println!("host device {device} sddl {sddl}");
                sddls.push_str(&sddl);
            }
            Err(st) => println!("host device {device} open {:#010x}", st as u32),
        }
    }
    whp_device_opens("host");
    // The capability VidExo grants besides Authenticated Users: its SID is
    // DeriveCapabilitySidsFromName's for the name (the SHA-256 of the name
    // in upper case, UTF-16LE, as eight sub-authorities after
    // S-1-15-3-1024), checked here against the descriptors just read.
    let cap = sid_string(capability_sid("hypervisorPlatform"));
    println!("host capability hypervisorPlatform {cap} in-a-whp-device-dacl {}", sddls.contains(&cap));
    let parent_dir = std::path::Path::new(base).parent().unwrap().to_string_lossy().into_owned();
    let parent_before = file_sddl(&parent_dir);
    std::fs::create_dir(base).unwrap();
    let r = std::collections::hash_map::RandomState::new();
    let rnd = |i: u64| {
        use std::hash::{BuildHasher, Hasher};
        let mut h = r.build_hasher();
        h.write_u64(i);
        h.finish() as u32
    };
    let jail_sid = format!("S-1-9-{}-{}-{}-{}", rnd(1), rnd(2), rnd(3), rnd(4));
    let bin = format!("{base}\\bin");
    std::fs::create_dir(&bin).unwrap();
    let exe = format!("{bin}\\fs-probe.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    let logon = logon_sid(own);
    let session = ["S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4"];
    // An AppContainer of its own, for the variants that run in one.
    let profile = format!("wick.whp-token.{}", std::process::id());
    let (ac_psid, ac_made) = appcontainer_profile(&profile);
    let ac_sid = sid_string(ac_psid);
    // An AppContainer SID with no profile: DeriveAppContainerSidFromAppContainerName
    // of a name never registered, as a jailer could give each jail without
    // making and deleting a profile.
    let bare_psid = appcontainer_sid(&format!("{profile}.bare"));
    let bare_sid = sid_string(bare_psid);
    // (name, the lockdown token's restricting SIDs besides the jail's, or
    // None for an AppContainer with the given capabilities; LPAC; the
    // profile's SID or the bare one; preload; when the partition is made:
    // "0" after the revert, "1" made and set up before it, "p" option P's
    // whole life, `Whp::p_before` and `Whp::p_after`).
    let none: Vec<&str> = Vec::new();
    let hv = vec!["hypervisorPlatform"];
    let variants: Vec<(&str, Option<Vec<&str>>, Vec<&str>, bool, bool, bool, &str)> = vec![
        ("jail-as-now", Some(session.to_vec()), none.clone(), false, true, true, "0"),
        ("jail-own-sid", Some(Vec::new()), none.clone(), false, true, true, "0"),
        ("jail-own-sid-no-preload", Some(Vec::new()), none.clone(), false, true, false, "0"),
        ("jail-au", Some(vec!["S-1-5-11"]), none.clone(), false, true, true, "0"),
        ("jail-everyone", Some(vec!["S-1-1-0"]), none.clone(), false, true, true, "0"),
        ("jail-users", Some(vec!["S-1-5-32-545"]), none.clone(), false, true, true, "0"),
        ("jail-interactive", Some(vec!["S-1-5-4"]), none.clone(), false, true, true, "0"),
        // The two devices' groups together (VidExo's Authenticated Users,
        // HvService's Everyone), and Authenticated Users with Users.
        ("jail-au-everyone", Some(vec!["S-1-5-11", "S-1-1-0"]), none.clone(), false, true, true, "0"),
        ("jail-au-users", Some(vec!["S-1-5-11", "S-1-5-32-545"]), none.clone(), false, true, true, "0"),
        ("jail-own-sid-made-before-revert", Some(Vec::new()), none.clone(), false, true, true, "1"),
        ("jail-as-now-made-before-revert", Some(session.to_vec()), none.clone(), false, true, true, "1"),
        ("jail-own-sid-p", Some(Vec::new()), none.clone(), false, true, true, "p"),
        // The control: the same configured VM's life under the jail's token
        // as now.
        ("jail-as-now-p", Some(session.to_vec()), none.clone(), false, true, true, "p"),
        ("jail-cap", Some(vec![cap.as_str()]), none.clone(), false, true, true, "0"),
        ("appcontainer", None, none.clone(), false, true, true, "0"),
        ("appcontainer-cap", None, hv.clone(), false, true, true, "0"),
        ("appcontainer-cap-bare-sid", None, hv.clone(), false, false, true, "0"),
        ("lpac-cap", None, hv.clone(), true, true, true, "0"),
        ("lpac-cap-registry-com", None, vec!["hypervisorPlatform", "registryRead", "lpacCom"], true, true, true, "0"),
    ];
    // As the jail's root: the jail's SID may read and run what is there,
    // and the AppContainers'.
    assert_eq!(set_dacl(&bin, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;0x1200a9;;;{jail_sid})(A;OICI;0x1200a9;;;{ac_sid})(A;OICI;0x1200a9;;;{bare_sid})")), 0);
    for (name, groups, caps, lpac, profiled, preload, early) in &variants {
        let who = if let Some(groups) = groups {
            let mut restricting = vec![jail_sid.as_str()];
            restricting.extend(groups.iter().copied());
            // Whether Windows takes these as restricting SIDs at all.
            let sids: Vec<SID_AND_ATTRIBUTES> = restricting.iter().map(|s| SID_AND_ATTRIBUTES { sid: sid(s), attributes: 0 }).collect();
            let mut t = null_mut();
            // SAFETY: valid SID array; LUA_TOKEN | DISABLE_MAX_PRIVILEGE.
            if unsafe { CreateRestrictedToken(own, 0x4 | 0x1, 0, null(), 0, null(), sids.len() as u32, sids.as_ptr(), &mut t) } == 0 {
                println!("host {name} restricted-token refused {}: the variant is not run", last());
                continue;
            }
            // SAFETY: the token just made.
            unsafe { CloseHandle(t) };
            // The lockdown token, as the jailer makes it: below medium integrity.
            let primary = restricted_token(own, &user, &restricting, &[&user, &jail_sid]);
            set_integrity(primary, "S-1-16-6144");
            // The jailer's initial token: the jail's SID, the four groups, the
            // logon SID and the user's, for the loader and the preload.
            let mut all = vec![jail_sid.as_str()];
            all.extend(session);
            all.extend([logon.as_str(), user.as_str()]);
            let initial = restricted_token(own, &user, &all, &[&user, &jail_sid]);
            set_integrity(initial, "S-1-16-6144");
            Who::Restricted { primary, initial: impersonation(initial) }
        } else {
            let sid = if *profiled { ac_psid } else { bare_psid };
            Who::AppContainer { sid, caps: caps.iter().map(|c| capability_sid(c)).collect(), lpac: *lpac }
        };
        let out = inheritable(GetStd(-11));
        let cmd = format!("\"{exe}\" whp-token-child {name} {} {early}", u8::from(*preload));
        match start(&cmd, &bin, &who, null_mut(), null_mut(), &[out], [out, out, out], true) {
            // SAFETY: the suspended child.
            Ok(child) => unsafe {
                ResumeThread(child.thread.0);
                let w = WaitForSingleObject(child.process.0, 120_000);
                let mut code = 0;
                GetExitCodeProcess(child.process.0, &mut code);
                if w != 0 {
                    TerminateProcess(child.process.0, 1);
                }
                println!("host {name} child-exit {code:#x}{}", if w != 0 { " (timed out)" } else { "" });
            },
            Err(e) => println!("host {name} start {e}"),
        }
    }
    if ac_made {
        delete_appcontainer_profile(&profile);
    }
    let removed = std::fs::remove_dir_all(base);
    println!("cleanup base removed {:?} exists-after {}", removed.map_err(|e| e.to_string()), std::fs::metadata(base).is_ok());
    let parent_after = file_sddl(&parent_dir);
    println!("cleanup {parent_dir} security {}", if parent_after == parent_before { "unchanged".to_string() } else { format!("CHANGED {parent_before} -> {parent_after}") });
}

/// A child of `whp-token`: the preload under the initial token (the WHP
/// DLLs, as Firecracker would), with the partition made and set up then too
/// when asked (`early`), the revert to the lockdown token, the WHP devices
/// opened directly, then WHP: every step, or the rest of them on the
/// partition made before.
fn whp_token_child(args: &[String]) {
    let tag = &args[0];
    let preload = args[1] == "1";
    let p = args.get(2).is_some_and(|a| a == "p");
    let early = p || args.get(2).is_some_and(|a| a == "1");
    let mut m = null_mut();
    if preload {
        m = load_system32(tag, "preload", "WinHvPlatform.dll");
        load_system32(tag, "preload", "WinHvEmulation.dll");
    }
    let mut devices = Vec::new();
    let before = format!("{tag} before-revert");
    if p {
        let whp = if m.is_null() { None } else { Whp::load(tag, m) };
        let made = whp.as_ref().and_then(|w| w.p_before(&before));
        // SAFETY: plain call; the initial token goes.
        let reverted = unsafe { RevertToSelf() } != 0;
        // SAFETY: the pseudo handle of this process's token (GetCurrentProcessToken).
        let restricted = unsafe { IsTokenRestricted(-4isize as HANDLE) } != 0;
        println!("{tag} revert {reverted} token-restricted {restricted}");
        whp_device_opens(tag);
        match (whp, made) {
            (Some(w), Some((part, caps))) => w.p_after(&format!("{tag} after-revert"), part, &caps),
            _ => println!("{tag} no partition was made before the revert"),
        }
        return;
    }
    let made = if early && !m.is_null() {
        Whp::load(tag, m).and_then(|w| {
            w.present(&before);
            w.make(&before, &mut devices)
        })
    } else {
        None
    };
    // SAFETY: plain call; the initial token goes.
    let reverted = unsafe { RevertToSelf() } != 0;
    // SAFETY: the pseudo handle of this process's token (GetCurrentProcessToken).
    let restricted = unsafe { IsTokenRestricted(-4isize as HANDLE) } != 0;
    println!("{tag} revert {reverted} token-restricted {restricted}");
    whp_device_opens(tag);
    if m.is_null() {
        m = load_system32(tag, "load-after-revert", "WinHvPlatform.dll");
        if m.is_null() {
            return;
        }
    }
    let Some(whp) = Whp::load(tag, m) else {
        return;
    };
    if early {
        match made {
            Some((part, set_up)) => whp.run_and_delete(&format!("{tag} after-revert"), part, set_up),
            None => println!("{tag} no partition was made before the revert"),
        }
    } else {
        whp.present(tag);
        if let Some((part, set_up)) = whp.make(tag, &mut devices) {
            whp.run_and_delete(tag, part, set_up);
        }
    }
}
