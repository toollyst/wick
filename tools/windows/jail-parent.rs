// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! A parent cgroup for jails on Windows: what `mkdir` and `echo` into the
//! parent's directory are on Linux.
//!
//! The jailer's `--parent-cgroup <name>` is on Windows the Job Object
//! `wick-cgroup\<name>`, in a private namespace of the account's that
//! nothing below medium integrity, a jailed process among it, can make or
//! open, in which every jail of that parent has its
//! own job (overlay/jailer/platform/windows/parent.rs). This tool makes that
//! job, or opens it, writes the limits named to it, with the cgroup file
//! names and values the jailer takes, and then holds it:
//!
//! ```text
//! jail-parent --name <parent>[/<level>]... [--cgroup-version 1|2] [--cgroup <file>=<value>]... [--forever]
//!   version 2 (the default): memory.max  cpu.max  cpuset.cpus
//!   version 1:               memory.limit_in_bytes  cpu.cfs_quota_us  cpu.cfs_period_us  cpuset.cpus
//! ```
//!
//! A parent's limits bound its jails together: the memory limit their sum
//! (commit), the CPU cap their sum, the processors every one of them.
//!
//! A parent of several levels (`a/b`) is a job for each level, each under
//! the one above. The tool makes the levels that are missing, the top
//! first, without limits, as `mkdir -p` does, writes the limits named to
//! the last, and holds them all. Every level's limits hold what is under
//! it: memory the least limit along the path, and the CPU cap and the
//! processors by Linux's rule for the cgroup version against what the
//! levels above come to (cgroup v1 refuses a quota above them and
//! processors outside theirs; v2 takes the lower quota and the processors
//! in common, or theirs when none is). So a parent is written from the top
//! down.
//!
//! A Job Object lasts while a handle to it is open, or a process is in it;
//! its name lasts only while a handle is open. So the tool keeps running:
//! until its standard input ends (or for ever with `--forever`, for a
//! service, which has no input). While it runs the parent is there, empty
//! or not, with its limits. Each jailer holds the parent too while its jail
//! lives, so ending the tool takes nothing from running jails or from jails
//! started while one still runs; once the tool and the last jail are gone
//! the parent is gone, and a jail that names it then makes a new one without
//! limits. Run again, it changes the limits of the level that is there, as a
//! write to a cgroup's file does at any time. A job under another holds its
//! CPU rate as a share of that one's and its processors within that one's,
//! worked out once, where Linux works the hierarchy out again at every
//! write; so a write to a level's CPU cap or processors writes every job
//! below it again, levels and jails, from what each was asked for, which is
//! kept beside each job (`cgroup_values::rewrite`, where the order of the
//! writes is derived: no job has at any moment more CPU than Linux gave it
//! before or gives it after, nor a processor Linux gave it neither before
//! nor after). The jobs below are those the namespace lists
//! (`NtQueryDirectoryObject`, which Microsoft documents as subject to
//! change: Microsoft Learn, "NtQueryDirectoryObject function"); if they
//! cannot be listed, or one cannot be opened, or what it was asked for is
//! not beside it, nothing is written and the tool says which. Where cgroup
//! v1 fails such a write on Linux (a jail below asked for more than the new
//! quota, or for processors outside the new ones), the tool fails it too.
//!
//! Run as the account the jailers run as, at medium integrity or above: the
//! namespace's boundary is that account's SID, the namespace and the job
//! grant the system and that account, and a jailer joins only a job of its
//! own account, the administrators or the system.
//!
//! No dependencies: `rustc --edition 2021 -O jail-parent.rs` builds it.

#![allow(non_snake_case, clippy::upper_case_acronyms)]

#[path = "../../overlay/jailer/platform/windows/cgroup_values.rs"]
#[allow(dead_code)]
mod cgroup_values;

use std::ffi::c_void;
use std::io::Read;

use cgroup_values::{
    DEFAULT_PERIOD_US, PARENT_JOB_PREFIX, PARENT_NAMESPACE, cpu_groups, cpu_rate, cpus_of_levels, parent_job_names,
    parent_namespace_sddl, parse_list, rate_of_levels, rewrite, strstrip, trusted_parent, ASKED_BYTES, Above, Asked, Below, Held, Step,
    asked_name, parent_lock_name,
};

type HANDLE = *mut c_void;

const ERROR_ALREADY_EXISTS: u32 = 183;
const TOKEN_QUERY: u32 = 8;
const TOKEN_USER_CLASS: i32 = 1;
const TOKEN_OWNER_CLASS: i32 = 4;
const SE_KERNEL_OBJECT: i32 = 6;
const OWNER_AND_LABEL: u32 = 0x1 | 0x10;
const SDDL_REVISION_1: u32 = 1;
const ALL_PROCESSOR_GROUPS: u16 = 0xffff;
// JOBOBJECTINFOCLASS, limit and rate flags (winnt.h).
const BASIC_ACCOUNTING: i32 = 1;
const EXTENDED_LIMIT: i32 = 9;
const GROUP_INFORMATION_EX: i32 = 14;
const CPU_RATE_CONTROL: i32 = 15;
const LIMIT_AFFINITY: u32 = 0x10;
const LIMIT_JOB_MEMORY: u32 = 0x200;
const RATE_ENABLE: u32 = 1;
const RATE_HARD_CAP: u32 = 4;
const MANDATORY_LABEL_ACE: u8 = 0x11;

#[repr(C)]
struct SECURITY_ATTRIBUTES {
    nLength: u32,
    lpSecurityDescriptor: *mut c_void,
    bInheritHandle: i32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct BASIC_LIMIT {
    PerProcessUserTimeLimit: i64,
    PerJobUserTimeLimit: i64,
    LimitFlags: u32,
    MinimumWorkingSetSize: usize,
    MaximumWorkingSetSize: usize,
    ActiveProcessLimit: u32,
    Affinity: usize,
    PriorityClass: u32,
    SchedulingClass: u32,
}

/// `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct EXTENDED {
    Basic: BASIC_LIMIT,
    IoInfo: [u64; 6],
    ProcessMemoryLimit: usize,
    JobMemoryLimit: usize,
    PeakProcessMemoryUsed: usize,
    PeakJobMemoryUsed: usize,
}

/// `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION` (its union is one number).
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CPU_RATE {
    ControlFlags: u32,
    CpuRate: u32,
}

/// `JOBOBJECT_BASIC_ACCOUNTING_INFORMATION`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ACCOUNTING {
    Times: [i64; 4],
    TotalPageFaultCount: u32,
    TotalProcesses: u32,
    ActiveProcesses: u32,
    TotalTerminatedProcesses: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct GROUP_AFFINITY {
    Mask: usize,
    Group: u16,
    Reserved: [u16; 3],
}

// The sizes winnt.h's structures have on x86-64, checked when this builds.
const _: () = assert!(std::mem::size_of::<BASIC_LIMIT>() == 64 && std::mem::size_of::<EXTENDED>() == 144);
const _: () = assert!(std::mem::size_of::<ACCOUNTING>() == 48 && std::mem::size_of::<CPU_RATE>() == 8);
const _: () = assert!(std::mem::size_of::<GROUP_AFFINITY>() == 16 && std::mem::size_of::<SECURITY_ATTRIBUTES>() == 24);

#[link(name = "kernel32")]
extern "system" {
    fn CreateJobObjectW(attributes: *const SECURITY_ATTRIBUTES, name: *const u16) -> HANDLE;
    fn SetInformationJobObject(job: HANDLE, class: i32, info: *const c_void, len: u32) -> i32;
    fn QueryInformationJobObject(job: HANDLE, class: i32, info: *mut c_void, len: u32, written: *mut u32) -> i32;
    fn GetLastError() -> u32;
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
    fn GetCurrentProcess() -> HANDLE;
    fn CloseHandle(handle: HANDLE) -> i32;
    fn GetActiveProcessorGroupCount() -> u16;
    fn CreateBoundaryDescriptorW(name: *const u16, flags: u32) -> HANDLE;
    fn AddSIDToBoundaryDescriptor(boundary: *mut HANDLE, sid: *mut c_void) -> i32;
    fn AddIntegrityLabelToBoundaryDescriptor(boundary: *mut HANDLE, label: *mut c_void) -> i32;
    fn DeleteBoundaryDescriptor(boundary: HANDLE);
    fn CreatePrivateNamespaceW(attributes: *const SECURITY_ATTRIBUTES, boundary: *const c_void, alias: *const u16) -> HANDLE;
    fn OpenPrivateNamespaceW(boundary: *const c_void, alias: *const u16) -> HANDLE;
    fn GetActiveProcessorCount(group: u16) -> u32;
    fn Sleep(milliseconds: u32);
    fn CreateMutexW(attributes: *const SECURITY_ATTRIBUTES, owned: i32, name: *const u16) -> HANDLE;
    fn WaitForSingleObject(handle: HANDLE, milliseconds: u32) -> u32;
    fn ReleaseMutex(mutex: HANDLE) -> i32;
    fn CreateFileMappingW(file: HANDLE, attributes: *const SECURITY_ATTRIBUTES, protect: u32, high: u32, low: u32, name: *const u16) -> HANDLE;
    fn OpenFileMappingW(access: u32, inherit: i32, name: *const u16) -> HANDLE;
    fn MapViewOfFile(section: HANDLE, access: u32, high: u32, low: u32, bytes: usize) -> *mut c_void;
    fn UnmapViewOfFile(address: *const c_void) -> i32;
    fn OpenJobObjectW(access: u32, inherit: i32, name: *const u16) -> HANDLE;
    fn GetModuleHandleW(name: *const u16) -> HANDLE;
    fn GetProcAddress(module: HANDLE, name: *const u8) -> *const c_void;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> i32;
    fn GetTokenInformation(token: HANDLE, class: i32, info: *mut c_void, len: u32, needed: *mut u32) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
    fn ConvertStringSidToSidW(text: *const u16, sid: *mut *mut c_void) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        len: *mut u32,
    ) -> i32;
    fn GetSecurityInfo(
        handle: HANDLE,
        kind: i32,
        info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last() -> String {
    format!("Windows error {}", unsafe { GetLastError() })
}

/// `sid` as text (`S-1-...`).
fn sid_string(sid: *mut c_void) -> Result<String, String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: a valid SID and an out-pointer; the text is freed below.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut text) == 0 {
            return Err(format!("ConvertSidToStringSid: {}", last()));
        }
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        Ok(s)
    }
}

/// The SID a token information class of this process starts with
/// (`TOKEN_USER`, `TOKEN_OWNER`: a pointer to it first), as text.
fn token_sid(class: i32) -> Result<String, String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: our own token; a buffer of the size passed.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(format!("OpenProcessToken: {}", last()));
        }
        let mut buf = [0u64; 32];
        let mut needed = 0u32;
        let ok = GetTokenInformation(token, class, buf.as_mut_ptr().cast(), 256, &mut needed);
        let result = if ok == 0 { Err(format!("GetTokenInformation: {}", last())) } else { sid_string(buf[0] as *mut c_void) };
        CloseHandle(token);
        result
    }
}

/// The job's owner and the integrity level of its label, if it has one.
fn owner_and_label(job: HANDLE) -> Result<(String, Option<u32>), String> {
    let (mut owner, mut sacl, mut sd) = (std::ptr::null_mut(), std::ptr::null_mut::<c_void>(), std::ptr::null_mut());
    // SAFETY: a handle with READ_CONTROL and out-pointers into `sd`, freed
    // below; the ACL is its 8-byte header, then entries of a 4-byte header
    // (type, flags, size) and, for a mandatory label, a mask and a SID.
    unsafe {
        let rc = GetSecurityInfo(
            job,
            SE_KERNEL_OBJECT,
            OWNER_AND_LABEL,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sacl,
            &mut sd,
        );
        if rc != 0 {
            return Err(format!("GetSecurityInfo: Windows error {rc}"));
        }
        let mut label = None;
        let mut result = sid_string(owner);
        if !sacl.is_null() {
            let acl = sacl.cast::<u8>();
            let count = acl.add(4).cast::<u16>().read_unaligned();
            let mut ace = acl.add(8);
            for _ in 0..count {
                if *ace == MANDATORY_LABEL_ACE {
                    match sid_string(ace.add(8).cast()) {
                        Ok(sid) => label = sid.rsplit('-').next().and_then(|level| level.parse().ok()),
                        Err(e) => result = Err(e),
                    }
                }
                ace = ace.add(usize::from(ace.add(2).cast::<u16>().read_unaligned()));
            }
        }
        LocalFree(sd);
        result.map(|owner| (owner, label))
    }
}

fn query<T: Default>(job: HANDLE, class: i32, what: &str) -> Result<T, String> {
    let mut info = T::default();
    // SAFETY: a structure of the size passed, for this class.
    let ok = unsafe {
        QueryInformationJobObject(job, class, (&mut info as *mut T).cast(), std::mem::size_of::<T>() as u32, std::ptr::null_mut())
    };
    if ok == 0 { Err(format!("reading {what}: {}", last())) } else { Ok(info) }
}

fn set<T>(job: HANDLE, class: i32, info: &T, len: usize, what: &str) -> Result<(), String> {
    // SAFETY: a structure, or an array, of the size passed, for this class.
    if unsafe { SetInformationJobObject(job, class, (info as *const T).cast(), len as u32) } == 0 {
        return Err(format!("setting {what}: {}", last()));
    }
    Ok(())
}

/// The limits the command line names, as a job takes them.
#[derive(Default, Debug, PartialEq)]
struct Wanted {
    /// `Some(None)`: no limit, written as such.
    memory: Option<Option<usize>>,
    quota: Option<Option<u64>>,
    period: Option<u64>,
    cpus: Option<Vec<u32>>,
}

fn parse(version: u8, cgroups: &[String]) -> Result<Wanted, String> {
    let mut asked = Wanted::default();
    for cg in cgroups {
        let (file, value) = cg.split_once('=').ok_or_else(|| format!("--cgroup {cg}: expected <file>=<value>"))?;
        let bad = |why: &str| format!("--cgroup {cg}: {why}");
        let none = if version == 2 { "max" } else { "-1" };
        match (version, file) {
            (2, "memory.max") | (1, "memory.limit_in_bytes") => {
                let value = strstrip(value);
                asked.memory = Some(if value == none {
                    None
                } else {
                    match value.parse::<usize>() {
                        Ok(bytes) if bytes > 0 => Some(bytes),
                        _ => return Err(bad("not a number of bytes above 0")),
                    }
                });
            }
            (2, "cpu.max") => {
                let mut parts = value.split_whitespace();
                let quota = parts.next().unwrap_or("");
                if let Some(period) = parts.next() {
                    asked.period = Some(period.parse().map_err(|_| bad("not a period in microseconds"))?);
                }
                if parts.next().is_some() {
                    return Err(bad("expected <quota> [<period>]"));
                }
                asked.quota =
                    Some(if quota == "max" { None } else { Some(quota.parse().map_err(|_| bad("not a quota in microseconds"))?) });
            }
            (1, "cpu.cfs_quota_us") => {
                asked.quota =
                    Some(if value == "-1" { None } else { Some(value.parse().map_err(|_| bad("not a quota in microseconds"))?) });
            }
            (1, "cpu.cfs_period_us") => {
                asked.period = Some(value.parse().map_err(|_| bad("not a period in microseconds"))?);
            }
            (_, "cpuset.cpus") => asked.cpus = Some(parse_list(value).map_err(bad)?),
            _ => {
                return Err(bad(
                    "not a limit a parent takes on Windows (memory, a CPU cap and processors are: see --help); nothing \
                     is accepted without effect",
                ));
            }
        }
    }
    Ok(asked)
}

/// A level's own CPU hard cap, if it has one.
fn hard_cap(job: HANDLE) -> Result<Option<u32>, String> {
    let cpu: CPU_RATE = query(job, CPU_RATE_CONTROL, "the job's CPU rate")?;
    let capped = RATE_ENABLE | RATE_HARD_CAP;
    Ok((cpu.ControlFlags & capped == capped).then_some(cpu.CpuRate))
}

/// A level's own processors, `(group, mask)` each, sorted by group: its
/// affinity when it has one, else what Windows reports for it by group.
fn processors(job: HANDLE) -> Result<Option<Vec<(u16, u64)>>, String> {
    let info: EXTENDED = query(job, EXTENDED_LIMIT, "the job's limits")?;
    if info.Basic.LimitFlags & LIMIT_AFFINITY != 0 {
        return Ok(Some(vec![(0, info.Basic.Affinity as u64)]));
    }
    let mut groups = [GROUP_AFFINITY::default(); 64];
    let mut len = 0u32;
    // SAFETY: an array of the size passed; the size written comes back.
    let ok = unsafe {
        QueryInformationJobObject(job, GROUP_INFORMATION_EX, groups.as_mut_ptr().cast(), std::mem::size_of_val(&groups) as u32, &mut len)
    };
    if ok == 0 {
        return Err(format!("reading the job's processors: {}", last()));
    }
    let count = (len as usize / std::mem::size_of::<GROUP_AFFINITY>()).min(groups.len());
    let mut found: Vec<(u16, u64)> = groups[..count].iter().map(|g| (g.Group, g.Mask as u64)).collect();
    found.sort_unstable();
    Ok((!found.is_empty()).then_some(found))
}

/// The parent cgroups' private namespace, made or opened once in this
/// process, which keeps it until it ends, as the jailer does
/// (`platform::parent`, `namespace`). A process has a namespace under its
/// alias one time: a second `OpenPrivateNamespaceW` by a process that has
/// it answers `ERROR_DUP_NAME` (52; CI run 43385227122, where this file's
/// test, which writes several times in one process, failed so at its
/// second write). The tool itself writes once in a process.
fn namespace(user: &str) -> Result<HANDLE, String> {
    static HELD: std::sync::Mutex<Option<usize>> = std::sync::Mutex::new(None);
    let mut held = HELD.lock().unwrap();
    if held.is_none() {
        *held = Some(enter_namespace(user)? as usize);
    }
    Ok(held.unwrap() as HANDLE)
}

/// Makes the parent cgroups' private namespace, or opens it if it is
/// there, as the jailer does (`platform::parent`, `enter_namespace`): the
/// boundary is this account's SID at medium integrity, which a jailed
/// process, below medium, is not within. Called once ([`namespace`]).
fn enter_namespace(user: &str) -> Result<HANDLE, String> {
    let (alias, sddl) = (wide(PARENT_NAMESPACE), wide(&parent_namespace_sddl(user)));
    let (mut user_sid, mut medium, mut sd) = (std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: NUL-terminated strings and out-pointers; what the calls
    // allocate is freed below. The descriptor is made, the two SIDs added
    // (the calls may move it), and the namespace made unless it exists,
    // opened unless it has just gone, a few times over.
    unsafe {
        if ConvertStringSidToSidW(wide(user).as_ptr(), &mut user_sid) == 0
            || ConvertStringSidToSidW(wide("S-1-16-8192").as_ptr(), &mut medium) == 0
            || ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) == 0
        {
            return Err(format!("the namespace's SIDs and security descriptor: {}", last()));
        }
        let mut boundary = CreateBoundaryDescriptorW(alias.as_ptr(), 0);
        if boundary.is_null()
            || AddSIDToBoundaryDescriptor(&mut boundary, user_sid) == 0
            || AddIntegrityLabelToBoundaryDescriptor(&mut boundary, medium) == 0
        {
            return Err(format!("the namespace's boundary: {}", last()));
        }
        let attributes = SECURITY_ATTRIBUTES { nLength: 24, lpSecurityDescriptor: sd, bInheritHandle: 0 };
        let mut result = Err(String::new());
        for _ in 0..8 {
            let made = CreatePrivateNamespaceW(&attributes, boundary, alias.as_ptr());
            let err = GetLastError();
            if !made.is_null() {
                result = Ok(made);
                break;
            }
            if err != ERROR_ALREADY_EXISTS {
                result = Err(format!("making the parent cgroups' namespace: Windows error {err}"));
                break;
            }
            let opened = OpenPrivateNamespaceW(boundary, alias.as_ptr());
            if !opened.is_null() {
                result = Ok(opened);
                break;
            }
            result = Err(format!("opening the parent cgroups' namespace: {}", last()));
        }
        DeleteBoundaryDescriptor(boundary);
        LocalFree(sd);
        LocalFree(user_sid);
        LocalFree(medium);
        result
    }
}

/// The job of one level: made, or opened if it is there and one to trust.
/// Whether it was made.
fn level(job_name: &str, user: &str) -> Result<(HANDLE, bool), String> {
    let path = job_name.strip_prefix(PARENT_JOB_PREFIX).unwrap_or(job_name);
    let sddl = wide(&parent_namespace_sddl(user));
    let mut sd = std::ptr::null_mut();
    // SAFETY: NUL-terminated strings; the descriptor is freed after the call
    // that reads it. An existing job is opened and the last error says so.
    let (job, existed) = unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) == 0 {
            return Err(format!("the job's security descriptor: {}", last()));
        }
        let attributes = SECURITY_ATTRIBUTES { nLength: 24, lpSecurityDescriptor: sd, bInheritHandle: 0 };
        let job = CreateJobObjectW(&attributes, wide(job_name).as_ptr());
        let err = GetLastError();
        LocalFree(sd);
        if job.is_null() {
            return Err(format!("the job {job_name}: Windows error {err}"));
        }
        (job, err == ERROR_ALREADY_EXISTS)
    };
    if existed {
        let (owner, label) = owner_and_label(job)?;
        let mine = [user.to_string(), token_sid(TOKEN_OWNER_CLASS)?];
        trusted_parent(&owner, label, &mine).map_err(|why| format!("{path}: {why}"))?;
    }
    let active = query::<ACCOUNTING>(job, BASIC_ACCOUNTING, "the job's processes")?.ActiveProcesses;
    println!("jail-parent: {path}: {} ({job_name}), {active} processes in it", if existed { "opened" } else { "made" });
    Ok((job, !existed))
}

/// `JOB_OBJECT_SET_ATTRIBUTES | JOB_OBJECT_QUERY | READ_CONTROL`: what
/// writing a job below a level again needs of it.
const JOB_WRITE: u32 = 0x2 | 0x4 | 0x0002_0000;
const PAGE_READWRITE: u32 = 4;
const FILE_MAP_ALL: u32 = 0x2 | 0x4;
const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;

/// Security attributes for an object of the namespace, for one call.
fn with_security<T>(user: &str, call: impl FnOnce(&SECURITY_ATTRIBUTES) -> T) -> Result<T, String> {
    let sddl = wide(&parent_namespace_sddl(user));
    let mut sd = std::ptr::null_mut();
    // SAFETY: a NUL-terminated string and an out-pointer; freed below.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) == 0 {
            return Err(format!("the security descriptor: {}", last()));
        }
        let result = call(&SECURITY_ATTRIBUTES { nLength: 24, lpSecurityDescriptor: sd, bInheritHandle: 0 });
        LocalFree(sd);
        Ok(result)
    }
}

/// The namespace's mutex, held: the jailers take it to read the levels and
/// make a jail's job, this tool to write a level and the jobs below it.
struct Lock(HANDLE);

impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: the mutex this thread holds, and its handle.
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

fn lock(user: &str) -> Result<Lock, String> {
    let name = wide(&parent_lock_name());
    // SAFETY: the attributes of the call and a NUL-terminated name. A
    // holder that died gives the mutex up (WAIT_ABANDONED).
    let mutex = with_security(user, |attributes| unsafe { CreateMutexW(attributes, 0, name.as_ptr()) })?;
    if mutex.is_null() {
        return Err(format!("the parent cgroups' mutex: {}", last()));
    }
    // SAFETY: the handle made above.
    unsafe { WaitForSingleObject(mutex, u32::MAX) };
    Ok(Lock(mutex))
}

/// The section beside the job `job_name`, which keeps what the job was
/// asked for: made, or opened.
fn asked_section(job_name: &str, user: &str, make: bool) -> Result<HANDLE, String> {
    let name = wide(&asked_name(job_name));
    // SAFETY: the attributes of the call and a NUL-terminated name; a
    // section of the paging file (no file).
    let section = if make {
        with_security(user, |attributes| unsafe {
            CreateFileMappingW(usize::MAX as HANDLE, attributes, PAGE_READWRITE, 0, ASKED_BYTES as u32, name.as_ptr())
        })?
    } else {
        unsafe { OpenFileMappingW(FILE_MAP_ALL, 0, name.as_ptr()) }
    };
    if section.is_null() {
        return Err(format!("what the job {job_name} was asked for, kept beside it, could not be {}: {}", if make { "made" } else { "opened" }, last()));
    }
    Ok(section)
}

fn read_asked(section: HANDLE, job_name: &str) -> Result<Asked, String> {
    let mut bytes = vec![0u8; ASKED_BYTES];
    // SAFETY: a view of the whole section, copied and unmapped.
    unsafe {
        let view = MapViewOfFile(section, FILE_MAP_ALL, 0, 0, ASKED_BYTES);
        if view.is_null() {
            return Err(format!("reading what the job {job_name} was asked for: {}", last()));
        }
        std::ptr::copy_nonoverlapping(view.cast::<u8>(), bytes.as_mut_ptr(), ASKED_BYTES);
        UnmapViewOfFile(view);
    }
    Asked::decode(&bytes).map_err(|why| format!("{job_name}: {why}"))
}

fn write_asked(section: HANDLE, asked: &Asked, job_name: &str) -> Result<(), String> {
    let bytes = asked.encode();
    // SAFETY: a view of the whole section, longer than the bytes, unmapped.
    unsafe {
        let view = MapViewOfFile(section, FILE_MAP_ALL, 0, 0, ASKED_BYTES);
        if view.is_null() {
            return Err(format!("writing what the job {job_name} was asked for: {}", last()));
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), view.cast::<u8>(), bytes.len());
        UnmapViewOfFile(view);
    }
    Ok(())
}

#[repr(C)]
struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *const u16,
}

/// `OBJECT_DIRECTORY_INFORMATION` (Microsoft Learn, "NtQueryDirectoryObject
/// function").
#[repr(C)]
struct DIRECTORY_ENTRY {
    Name: UNICODE_STRING,
    TypeName: UNICODE_STRING,
}

const _: () = assert!(std::mem::size_of::<DIRECTORY_ENTRY>() == 32);

/// The names, as the namespace has them, of the jobs below the level
/// `path`: the levels under it and the jails under it and them. The
/// namespace is a directory of the object manager, and its handle lists it,
/// one entry a call ("This function has no associated import library or
/// header file; you must call it using the LoadLibrary and GetProcAddress
/// functions": Microsoft Learn). A status that is not success ends in an
/// error, never in a shorter list.
fn jobs_below(namespace: HANDLE, path: &str) -> Result<Vec<String>, String> {
    type Query = unsafe extern "system" fn(HANDLE, *mut c_void, u32, u8, u8, *mut u32, *mut u32) -> i32;
    let under = format!("{path}/");
    let mut names = Vec::new();
    // SAFETY: ntdll is in every process; the function is called as
    // Microsoft declares it, with a buffer of the size passed, which the
    // entry and its strings are in.
    unsafe {
        let function = GetProcAddress(GetModuleHandleW(wide("ntdll.dll").as_ptr()), b"NtQueryDirectoryObject\0".as_ptr());
        if function.is_null() {
            return Err("this Windows has no NtQueryDirectoryObject: the jobs below a level cannot be listed".to_string());
        }
        let query: Query = std::mem::transmute(function);
        let mut buffer = [0u64; 1024];
        let (mut context, mut restart) = (0u32, 1u8);
        loop {
            let status = query(namespace, buffer.as_mut_ptr().cast(), 8192, 1, restart, &mut context, std::ptr::null_mut());
            restart = 0;
            if status as u32 == STATUS_NO_MORE_ENTRIES {
                break;
            }
            if status < 0 {
                return Err(format!(
                    "the jobs below {path} could not be listed (NtQueryDirectoryObject: status {:#x}): nothing was written",
                    status as u32
                ));
            }
            let entry = &*buffer.as_ptr().cast::<DIRECTORY_ENTRY>();
            let text = |s: &UNICODE_STRING| String::from_utf16_lossy(std::slice::from_raw_parts(s.Buffer, usize::from(s.Length) / 2));
            let name = text(&entry.Name);
            if text(&entry.TypeName) == "Job" && name.starts_with(&under) {
                names.push(name);
            }
        }
    }
    Ok(names)
}

/// What a job holds, read from it: its hard cap, and its processors if it
/// was asked for any (a job that was not has those of the job above).
fn holds(job: HANDLE, asked: &Asked) -> Result<Held, String> {
    Ok(Held { rate: hard_cap(job)?, cpus: if asked.cpus.is_some() { processors(job)? } else { None } })
}

fn set_rate(job: HANDLE, rate: Option<u32>) -> Result<(), String> {
    let cpu = match rate {
        Some(rate) => CPU_RATE { ControlFlags: RATE_ENABLE | RATE_HARD_CAP, CpuRate: rate },
        None => CPU_RATE::default(),
    };
    set(job, CPU_RATE_CONTROL, &cpu, std::mem::size_of::<CPU_RATE>(), "the CPU rate")
}

fn set_cpus(job: HANDLE, groups: &[(u16, u64)]) -> Result<(), String> {
    if let [(0, mask)] = groups {
        let mut info: EXTENDED = query(job, EXTENDED_LIMIT, "the job's limits")?;
        info.Basic.LimitFlags |= LIMIT_AFFINITY;
        info.Basic.Affinity = *mask as usize;
        return set(job, EXTENDED_LIMIT, &info, std::mem::size_of::<EXTENDED>(), "the processors");
    }
    let list: Vec<GROUP_AFFINITY> = groups.iter().map(|&(group, mask)| GROUP_AFFINITY { Mask: mask as usize, Group: group, Reserved: [0; 3] }).collect();
    if list.is_empty() {
        return Err("no processors".to_string());
    }
    set(job, GROUP_INFORMATION_EX, &list[0], std::mem::size_of_val(list.as_slice()), "the processors")
}

/// Makes or opens every level of `name` and writes the limits to the last,
/// and with them every job below it (the module's description). The
/// handles, which hold the namespace, the levels and what they were asked
/// for while this process runs.
fn run(name: &str, version: u8, cgroups: &[String]) -> Result<Vec<HANDLE>, String> {
    let names = parent_job_names(name).map_err(|why| format!("--name {name}: {why}"))?;
    let wanted = parse(version, cgroups)?;
    let user = token_sid(TOKEN_USER_CLASS)?;
    let namespace = namespace(&user)?;
    let _lock = lock(&user)?;
    let mut kept = vec![namespace];
    let mut jobs = Vec::new();
    let (mut made, mut section) = (false, std::ptr::null_mut());
    for job_name in &names {
        let (job, new) = level(job_name, &user)?;
        section = asked_section(job_name, &user, new)?;
        if new {
            // Asked for nothing yet, as a directory Linux makes has no limit.
            write_asked(section, &Asked { version, rate: None, cpus: None }, job_name)?;
        }
        jobs.push(job);
        kept.extend([job, section]);
        made = new;
    }
    let (job, above) = (jobs[jobs.len() - 1], &jobs[..jobs.len() - 1]);
    let job_name = &names[names.len() - 1];
    let path = job_name.strip_prefix(PARENT_JOB_PREFIX).unwrap_or(job_name);

    if let Some(memory) = wanted.memory {
        let mut info: EXTENDED = query(job, EXTENDED_LIMIT, "the job's limits")?;
        match memory {
            Some(bytes) => {
                info.Basic.LimitFlags |= LIMIT_JOB_MEMORY;
                info.JobMemoryLimit = bytes;
            }
            None => info.Basic.LimitFlags &= !LIMIT_JOB_MEMORY,
        }
        set(job, EXTENDED_LIMIT, &info, std::mem::size_of::<EXTENDED>(), "the memory limit")?;
        println!("jail-parent: {name}: memory limit {memory:?} bytes (commit, of all its jails together)");
    }
    if wanted.quota.is_none() && wanted.period.is_some() {
        return Err("a CPU period without a quota".to_string());
    }
    if wanted.quota.is_none() && wanted.cpus.is_none() {
        return Ok(kept);
    }

    // What the level is asked for now: what it was, with what is named.
    let was = read_asked(section, job_name)?;
    let mut asked = Asked { version, rate: was.rate, cpus: was.cpus.clone() };
    if let Some(quota) = wanted.quota {
        asked.rate = match quota {
            None => None,
            Some(quota) => {
                // SAFETY: a plain query.
                let cpus = u64::from(unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) });
                Some(cpu_rate(quota, wanted.period.unwrap_or(DEFAULT_PERIOD_US), cpus).map_err(|why| format!("the CPU quota: {why}"))?)
            }
        };
    }
    if let Some(cpus) = &wanted.cpus {
        // SAFETY: plain queries.
        let sizes: Vec<u32> = unsafe { (0..GetActiveProcessorGroupCount()).map(|g| GetActiveProcessorCount(g)).collect() };
        let mut groups = cpu_groups(cpus, &sizes).map_err(|why| format!("cpuset.cpus: {why}"))?;
        groups.sort_unstable();
        asked.cpus = Some(groups);
    }
    // What the levels above come to, and the jobs below with what each was
    // asked for and holds.
    let caps = above.iter().map(|&job| hard_cap(job)).collect::<Result<Vec<_>, _>>()?;
    let sets = above.iter().map(|&job| processors(job)).collect::<Result<Vec<_>, _>>()?;
    let up = Above { caps, cpus: if above.is_empty() { None } else { cpus_of_levels(&sets) } };
    let up_rate = rate_of_levels(&up.caps).map_err(|why| format!("--name {name}: {why}"))?;
    let now = if made { Held::default() } else { holds(job, &was)? };
    let mut below = Vec::new();
    let mut below_jobs = Vec::new();
    if !made {
        for found in jobs_below(namespace, path)? {
            let full = format!("{PARENT_JOB_PREFIX}{found}");
            let unreached = |what: &str, why: String| format!("{found}, a job below {path}, {what}: {why}; nothing was written");
            // SAFETY: a NUL-terminated name.
            let below_job = unsafe { OpenJobObjectW(JOB_WRITE, 0, wide(&full).as_ptr()) };
            if below_job.is_null() {
                return Err(unreached("could not be opened", last()));
            }
            below_jobs.push(below_job);
            let kept_beside = asked_section(&full, &user, false).map_err(|why| unreached("cannot be written again", why))?;
            let its = read_asked(kept_beside, &full);
            // SAFETY: the section opened above.
            unsafe { CloseHandle(kept_beside) };
            let its = its.map_err(|why| unreached("cannot be written again", why))?;
            below.push(Below { name: found.clone(), now: holds(below_job, &its)?, asked: its });
        }
    }
    let (steps, _) = rewrite(&up, path, &asked, &now, &below).map_err(|why| format!("--name {name}: {why}; nothing was written"))?;
    for (done, step) in steps.iter().enumerate() {
        let (index, written) = match step {
            Step::Rate(index, rate) => (*index, set_rate(if *index == 0 { job } else { below_jobs[index - 1] }, *rate)),
            Step::Cpus(index, cpus) => (*index, set_cpus(if *index == 0 { job } else { below_jobs[index - 1] }, cpus)),
        };
        written.map_err(|why| {
            let which = if index == 0 { path } else { below[index - 1].name.as_str() };
            format!(
                "{which}: {why}. The write stopped after {done} of {} writes: no job has more than it had or is to have, and \
                 running this again completes it",
                steps.len()
            )
        })?;
    }
    write_asked(section, &asked, job_name)?;
    for below_job in below_jobs {
        // SAFETY: the handles opened above.
        unsafe { CloseHandle(below_job) };
    }
    match (asked.rate, up_rate) {
        (None, _) => println!("jail-parent: {name}: no CPU cap of its own"),
        (Some(rate), None) => println!("jail-parent: {name}: CPU rate {rate} of 10000 of the host's processors"),
        (Some(rate), Some(up)) => {
            println!("jail-parent: {name}: CPU rate {rate} of 10000 of the host's processors, under levels that come to {up}")
        }
    }
    if let Some(cpus) = &asked.cpus {
        println!("jail-parent: {name}: processors {cpus:x?} (group, mask)");
    }
    println!("jail-parent: {name}: {} jobs below it, {} writes", below.len(), steps.len());
    Ok(kept)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut name, mut version, mut cgroups, mut forever) = (None, 2u8, Vec::new(), false);
    let mut it = args.iter();
    let usage = "usage: jail-parent --name <parent>[/<level>]... [--cgroup-version 1|2] [--cgroup <file>=<value>]... [--forever]";
    while let Some(arg) = it.next() {
        match (arg.as_str(), it.clone().next()) {
            ("--forever", _) => forever = true,
            ("--name", Some(value)) => name = Some(value.clone()),
            ("--cgroup", Some(value)) => cgroups.push(value.clone()),
            ("--cgroup-version", Some(value)) if value == "1" || value == "2" => version = value.parse().unwrap(),
            _ => {
                eprintln!("jail-parent: {arg}: not understood\n{usage}");
                std::process::exit(2);
            }
        }
        if arg != "--forever" {
            it.next();
        }
    }
    let Some(name) = name else {
        eprintln!("{usage}");
        std::process::exit(2);
    };
    match run(&name, version, &cgroups) {
        Ok(_jobs) => {
            println!("jail-parent: {name}: held until {}", if forever { "this process is ended" } else { "standard input ends" });
            if forever {
                loop {
                    // SAFETY: plain call.
                    unsafe { Sleep(u32::MAX) };
                }
            }
            let mut sink = [0u8; 256];
            while matches!(std::io::stdin().read(&mut sink), Ok(n) if n > 0) {}
        }
        Err(why) => {
            eprintln!("jail-parent: {why}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgroup_values::{CPUS_OUTSIDE_PARENT, RATE_ABOVE_PARENT, jail_job_name, rate_under_levels, rate_under_parent};

    /// A job below a level as a jailer makes a jail's: named, with what it
    /// was asked for beside it (`None`: without), and no values yet, which
    /// the next write of a level above gives it.
    fn jail(level: &str, id: &str, asked: Option<&Asked>) -> HANDLE {
        let user = token_sid(TOKEN_USER_CLASS).unwrap();
        let name = jail_job_name(&parent_job_names(level).unwrap().pop().unwrap(), id);
        // SAFETY: the attributes of the call and a NUL-terminated name.
        let job = with_security(&user, |attributes| unsafe { CreateJobObjectW(attributes, wide(&name).as_ptr()) }).unwrap();
        assert!(!job.is_null(), "{}", last());
        if let Some(asked) = asked {
            write_asked(asked_section(&name, &user, true).unwrap(), asked, &name).unwrap();
        }
        job
    }

    /// `cpu.max` for a rate of the host's processors.
    fn quota(rate: u64) -> String {
        // SAFETY: a plain query.
        let cpus = u64::from(unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) });
        format!("cpu.max={} 100000", rate * 10 * cpus)
    }

    // A write to a level that is there, on the host: the tool's own steps
    // against real jobs. A level, a level under it, a jail under each;
    // every write of the top level's CPU cap or processors is read back
    // from each job below as Linux's rule gives it; cgroup v1 fails the
    // write a jail below cannot follow and nothing changes; a job below
    // without what it was asked for stops the write.
    #[test]
    #[ignore = "makes named jobs: run alone by CI's windows job, with --nocapture"]
    fn test_a_write_to_a_level_that_is_there_reaches_the_jobs_below() {
        let top = format!("wjp-test-{}", std::process::id());
        let inner = format!("{top}/in");
        let write = |name: &str, cgroups: &[String]| run(name, 2, cgroups);
        let top_job = *write(&top, &[quota(5000)]).unwrap().get(1).unwrap();
        let inner_job = *write(&inner, &[quota(2500)]).unwrap().get(3).unwrap();
        let cpus = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
        let on = |mask: u64| (cpus >= 2).then(|| vec![(0u16, mask)]);
        let vm1 = jail(&inner, "vm-1", Some(&Asked { version: 2, rate: Some(1250), cpus: on(0b10) }));
        let vm2 = jail(&top, "vm-2", Some(&Asked { version: 1, rate: Some(4000), cpus: None }));
        let caps = || [hard_cap(top_job), hard_cap(inner_job), hard_cap(vm1), hard_cap(vm2)];
        println!("TOOLTEST a level at 5000, a level under it at 2500 of the host, jails made under each: {:?}", caps());
        assert_eq!(hard_cap(inner_job).unwrap(), Some(5000), "a quarter of the host is half of a level of half");

        // Lowered: every job below is written again.
        write(&top, &[quota(4000)]).unwrap();
        println!("TOOLTEST the top lowered to 4000: {:?}", caps());
        let share = |asked, of| Some(rate_under_parent(2, asked, of).unwrap());
        assert_eq!(caps().map(Result::unwrap), [Some(4000), share(2500, 4000), share(1250, 2500), share(4000, 4000)]);

        // cgroup v1: the jail that asked for 4000 cannot follow 3000.
        let refused = write(&top, &[quota(3000)]).unwrap_err();
        println!("TOOLTEST the top to 3000, under which a cgroup v1 jail asked for 4000: {refused}; then {:?}", caps());
        assert!(refused.contains(RATE_ABOVE_PARENT) && refused.contains("vm-2, below") && refused.ends_with("nothing was written"), "{refused}");
        assert_eq!(caps().map(Result::unwrap), [Some(4000), share(2500, 4000), share(1250, 2500), share(4000, 4000)]);

        if cpus >= 2 {
            write(&top, &["cpuset.cpus=0-1".to_string()]).unwrap();
            let first = processors(vm1);
            write(&top, &["cpuset.cpus=0".to_string()]).unwrap();
            let moved = processors(vm1);
            write(&top, &["cpuset.cpus=0-1".to_string()]).unwrap();
            let back = processors(vm1);
            println!("TOOLTEST a jail that asked for processor 1, the top on 0-1, then 0, then 0-1 again: {first:x?}, {moved:x?}, {back:x?}");
            assert_eq!(first.unwrap(), Some(vec![(0, 0b10)]));
            assert_eq!(moved.unwrap(), Some(vec![(0, 0b01)]), "cgroup v2: none in common, the level's");
            assert_eq!(back.unwrap(), Some(vec![(0, 0b10)]));
            // cgroup v1 fails a level's write that leaves a jail below
            // processors outside it.
            let vm3 = jail(&top, "vm-3", Some(&Asked { version: 1, rate: None, cpus: on(0b10) }));
            let outside = write(&top, &["cpuset.cpus=0".to_string()]).unwrap_err();
            println!("TOOLTEST the top to processor 0, under which a cgroup v1 jail asked for 1: {outside}");
            assert!(outside.contains(CPUS_OUTSIDE_PARENT) && outside.contains("vm-3, below"), "{outside}");
            // SAFETY: the test's own handle; the job goes with it.
            unsafe { CloseHandle(vm3) };
        } else {
            println!("TOOLTEST processors: one processor, not run");
        }

        // Raised, and the cap taken off: each job has its own again.
        write(&top, &["cpu.max=max".to_string()]).unwrap();
        println!("TOOLTEST the top's cap taken off: {:?}", caps());
        assert_eq!(caps().map(Result::unwrap), [None, Some(2500), share(1250, 2500), Some(4000)]);

        // A job below that nobody wrote what it was asked for beside.
        let _ghost = jail(&top, "ghost", None);
        let unreached = write(&top, &[quota(5000)]).unwrap_err();
        println!("TOOLTEST a job below without what it was asked for: {unreached}; then {:?}", caps());
        assert!(unreached.contains("ghost, a job below") && unreached.ends_with("nothing was written"), "{unreached}");
        assert_eq!(hard_cap(top_job).unwrap(), None);
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn AssignProcessToJobObject(job: HANDLE, process: HANDLE) -> i32;
        fn GetProcessAffinityMask(process: HANDLE, process_mask: *mut usize, system_mask: *mut usize) -> i32;
        fn GetProcessTimes(process: HANDLE, creation: *mut u64, exit: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
    }

    /// The variable that makes this test program the process of a jail in
    /// `test_a_write_to_a_level_reaches_the_processes_running_below`.
    const SPIN: &str = "WICK_TEST_SPIN";

    /// A jail's process for the test below: a thread for every processor of
    /// the host, each in a loop, until its standard input ends. Nothing
    /// without the variable.
    #[test]
    fn spins_for_another_process() {
        if std::env::var_os(SPIN).is_none() {
            return;
        }
        // SAFETY: a plain query.
        for _ in 0..unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) } {
            std::thread::spawn(|| loop {
                std::hint::spin_loop();
            });
        }
        println!("SPINNING");
        let mut rest = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut rest);
        std::process::exit(0);
    }

    /// A process that spins (`spins_for_another_process`), put in `jobs`
    /// in their order, as the jailer puts a jail's process in its parent's
    /// levels from the top down and then in the jail's own job
    /// (`platform::parent`, `enter`). With what Windows answered each.
    fn spinning_in(jobs: &[HANDLE]) -> (std::process::Child, Vec<Result<(), String>>) {
        use std::os::windows::io::AsRawHandle;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::spins_for_another_process", "--nocapture"])
            .env(SPIN, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let said = std::io::BufRead::lines(std::io::BufReader::new(child.stdout.take().unwrap()));
        assert!(said.map_while(Result::ok).any(|line| line.contains("SPINNING")), "the process did not start");
        let assigned = jobs
            .iter()
            // SAFETY: the test's job and the child's handle.
            .map(|&job| if unsafe { AssignProcessToJobObject(job, child.as_raw_handle().cast()) } == 0 { Err(last()) } else { Ok(()) })
            .collect();
        (child, assigned)
    }

    /// The processors a process may run on, as Windows says (group 0's).
    fn mask_of(child: &std::process::Child) -> Result<usize, String> {
        use std::os::windows::io::AsRawHandle;
        let (mut process, mut system) = (0usize, 0usize);
        // SAFETY: the child's handle and two out values.
        if unsafe { GetProcessAffinityMask(child.as_raw_handle().cast(), &mut process, &mut system) } == 0 {
            return Err(last());
        }
        Ok(process)
    }

    /// The CPU time of each process over half a second, in the units of a
    /// job's rate: 10000 is every processor of the host for all of it. A
    /// measurement on a host that runs other things: printed, never
    /// asserted.
    fn measured(children: &[&std::process::Child]) -> Vec<u64> {
        use std::os::windows::io::AsRawHandle;
        let used = |child: &std::process::Child| {
            let (mut creation, mut exit, mut kernel, mut user) = (0u64, 0u64, 0u64, 0u64);
            // SAFETY: the child's handle and four out values of a FILETIME's size.
            unsafe { GetProcessTimes(child.as_raw_handle().cast(), &mut creation, &mut exit, &mut kernel, &mut user) };
            kernel + user
        };
        let before: Vec<u64> = children.iter().map(|c| used(c)).collect();
        let started = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(500));
        // A FILETIME counts 100 ns.
        let wall = started.elapsed().as_nanos() as u64 / 100;
        // SAFETY: a plain query.
        let cpus = u64::from(unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) });
        children.iter().zip(before).map(|(c, before)| (used(c) - before) * 10_000 / (wall * cpus)).collect()
    }

    // The writes of the test above while processes run in the jobs: a
    // level, a level under it, and two jails whose jobs each hold a
    // process that spins on every processor, put in its jobs from the top
    // down as the jailer puts a jail's. Windows forms its job hierarchy
    // from processes (Microsoft Learn, "Nested Jobs"), so only now are the
    // jobs nested for it, and only now can it refuse a rate or a set of
    // processors for a job with jobs nested under it or a job nested under
    // another. Each write is printed with what Windows answered, each
    // job's cap read back, the processors each process has
    // (`GetProcessAffinityMask`) and the CPU time each took over half a
    // second (a measurement, not asserted). Asserted: every job's cap is
    // Linux's rule for it, and a jail's process has the processors its job
    // was given.
    #[test]
    #[ignore = "makes named jobs: run alone by CI's windows job, with --nocapture"]
    fn test_a_write_to_a_level_reaches_the_processes_running_below() {
        let top = format!("wjp-live-{}", std::process::id());
        let inner = format!("{top}/in");
        let write = |name: &str, cgroups: &[String]| run(name, 2, cgroups);
        let top_job = *write(&top, &[quota(5000)]).unwrap().get(1).unwrap();
        let inner_job = *write(&inner, &[quota(2500)]).unwrap().get(3).unwrap();
        // SAFETY: a plain query.
        let cpus = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
        let on = |mask: u64| (cpus >= 2).then(|| vec![(0u16, mask)]);
        let vm1 = jail(&inner, "vm-1", Some(&Asked { version: 2, rate: Some(1250), cpus: on(0b10) }));
        let vm2 = jail(&top, "vm-2", Some(&Asked { version: 1, rate: Some(4000), cpus: None }));
        let (mut p1, in1) = spinning_in(&[top_job, inner_job, vm1]);
        let (mut p2, in2) = spinning_in(&[top_job, vm2]);
        let caps = || [hard_cap(top_job), hard_cap(inner_job), hard_cap(vm1), hard_cap(vm2)];
        let active = |job| query::<ACCOUNTING>(job, BASIC_ACCOUNTING, "the job's processes").map(|a| a.ActiveProcesses);
        println!(
            "TOOLTEST live: a level at 5000, a level under it at 2500 of the host, {cpus} processors; a process put in the top, the \
             level and its jail's job: {in1:?}; a process put in the top and its jail's job: {in2:?}; processes in each job: {:?}",
            [active(top_job), active(inner_job), active(vm1), active(vm2)]
        );
        let state = |p1: &std::process::Child, p2: &std::process::Child| {
            format!(
                "caps of the top, the level, its jail, the top's jail {:?}; the two processes' processors {:x?}, CPU taken {:?} of 10000",
                caps(),
                [mask_of(p1), mask_of(p2)],
                measured(&[p1, p2])
            )
        };
        println!("TOOLTEST live: before any write with them running: {}", state(&p1, &p2));
        let share = |asked, of| Some(rate_under_parent(2, asked, of).unwrap());
        let failures = std::cell::RefCell::new(Vec::new());
        let expect = |what: &str, wanted: [Option<u32>; 4]| {
            let got = caps();
            if got.iter().map(|c| c.as_ref().ok().copied()).collect::<Vec<_>>() != wanted.iter().map(|w| Some(*w)).collect::<Vec<_>>() {
                failures.borrow_mut().push(format!("{what}: the caps are {got:?}, not {wanted:?}"));
            }
        };

        // Lowered, raised: every job below is written again while it runs.
        let lowered = write(&top, &[quota(4000)]).map(|_| ());
        println!("TOOLTEST live: the top lowered to 4000: {lowered:?}; {}", state(&p1, &p2));
        expect("lowered to 4000", [Some(4000), share(2500, 4000), share(1250, 2500), share(4000, 4000)]);
        let raised = write(&top, &[quota(6000)]).map(|_| ());
        println!("TOOLTEST live: the top raised to 6000: {raised:?}; {}", state(&p1, &p2));
        // The level is given 4166 of 6000 for its 2500, and the two come
        // to 2499.6 of the host, not 2500: the jail's share is of that
        // (`rate_under_levels`), 5000, where one of 2500 is 5000 too and
        // one of the levels' 2499 rounded down was 5002, above the 1250
        // asked for (CI run 43403250054).
        let level = share(2500, 6000);
        let jail = Some(rate_under_levels(2, 1250, &[Some(6000), level]).unwrap());
        assert_eq!(jail, Some(5000));
        expect("raised to 6000", [Some(6000), level, jail, share(4000, 6000)]);

        // cgroup v1: the jail that asked for 4000 cannot follow 3000.
        let refused = write(&top, &[quota(3000)]).map(|_| ());
        println!("TOOLTEST live: the top to 3000, under which a cgroup v1 jail asked for 4000: {refused:?}; {}", state(&p1, &p2));
        expect("refused at 3000", [Some(6000), level, jail, share(4000, 6000)]);
        if !refused.as_ref().is_err_and(|why| why.contains(RATE_ABOVE_PARENT) && why.ends_with("nothing was written")) {
            failures.borrow_mut().push(format!("the top to 3000 over a v1 jail that asked for 4000: {refused:?}"));
        }

        // Processors: the jail that asked for processor 1 has it, then the
        // level's when the level leaves it none, then its own again.
        if cpus >= 2 {
            for (set, wanted) in [("0-1", 0b10usize), ("0", 0b01), ("0-1", 0b10)] {
                let moved = write(&top, &[format!("cpuset.cpus={set}")]).map(|_| ());
                let (job, process) = (processors(vm1), mask_of(&p1));
                println!(
                    "TOOLTEST live: the top on processors {set}: {moved:?}; the jail that asked for processor 1: its job {job:x?}, its \
                     process {process:x?}; the top's other jail's process {:x?}; the top's job {:x?}",
                    mask_of(&p2),
                    processors(top_job)
                );
                if job != Ok(Some(vec![(0, wanted as u64)])) || process != Ok(wanted) {
                    failures.borrow_mut().push(format!("the top on {set}: the jail's job has {job:x?} and its process {process:x?}, not {wanted:#x}"));
                }
            }
        } else {
            println!("TOOLTEST live: processors: one processor, not run");
        }

        // The cap taken off: each job has its own again.
        let off = write(&top, &["cpu.max=max".to_string()]).map(|_| ());
        println!("TOOLTEST live: the top's cap taken off: {off:?}; {}", state(&p1, &p2));
        expect("the cap taken off", [None, Some(2500), share(1250, 2500), Some(4000)]);

        // The processes end when their standard input does.
        drop((p1.stdin.take(), p2.stdin.take()));
        let ended = (p1.wait().map(|s| s.success()), p2.wait().map(|s| s.success()));
        println!("TOOLTEST live: the processes ended: {ended:?}");
        assert!(in1.iter().chain(&in2).all(Result::is_ok), "a process was not put in its jobs: {in1:?}, {in2:?}");
        let failures = failures.into_inner();
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn test_parse() {
        let of = |version, list: &[&str]| parse(version, &list.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        assert_eq!(
            of(2, &["memory.max=67108864", "cpu.max=50000 100000", "cpuset.cpus=0-1,3"]).unwrap(),
            Wanted { memory: Some(Some(64 << 20)), quota: Some(Some(50_000)), period: Some(100_000), cpus: Some(vec![0, 1, 3]) }
        );
        assert_eq!(of(2, &["memory.max=max", "cpu.max=max"]).unwrap(), Wanted { memory: Some(None), quota: Some(None), ..Wanted::default() });
        assert_eq!(
            of(1, &["memory.limit_in_bytes=-1", "cpu.cfs_quota_us=25000", "cpu.cfs_period_us=50000"]).unwrap(),
            Wanted { memory: Some(None), quota: Some(Some(25_000)), period: Some(50_000), cpus: None }
        );
        // Another version's file, a limit a parent does not take, a value
        // that is none: refused, not accepted without effect.
        for (version, cg) in [(1, "memory.max=1"), (2, "memory.limit_in_bytes=1"), (2, "pids.max=5"), (2, "memory.max=0"), (2, "cpu.max")] {
            assert!(of(version, &[cg]).is_err(), "{cg}");
        }
    }
}
