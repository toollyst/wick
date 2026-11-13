// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! A parent cgroup for jails on Windows: what `mkdir` and `echo` into the
//! parent's directory are on Linux.
//!
//! The jailer's `--parent-cgroup <name>` is on Windows the Job Object
//! `Local\wick-cgroup-<name>`, in which every jail of that parent has its
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
//! limits. Run again, it changes the memory limit of the parent that is
//! there. The CPU cap and the processors of a level are written when the
//! level is made and not changed while it is there (refused, with the
//! reason; the same values again are accepted): a job under another holds
//! its rate as a share of that one's, worked out once, where Linux works
//! the hierarchy out again at every write.
//!
//! Run in the session the jailers run in, as the account they run as: the
//! job grants the system and that account, and a jailer joins only a job of
//! its own account, the administrators or the system.
//!
//! No dependencies: `rustc --edition 2021 -O jail-parent.rs` builds it.

#![allow(non_snake_case, clippy::upper_case_acronyms)]

#[path = "../../overlay/jailer/platform/windows/cgroup_values.rs"]
#[allow(dead_code)]
mod cgroup_values;

use std::ffi::c_void;
use std::io::Read;

use cgroup_values::{
    DEFAULT_PERIOD_US, PARENT_JOB_PREFIX, cpu_groups, cpu_rate, cpus_of_levels, cpus_under_parent, level_write, parent_job_names,
    parse_list, rate_of_levels, rate_under_parent, strstrip, trusted_parent,
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
    fn GetActiveProcessorCount(group: u16) -> u32;
    fn Sleep(milliseconds: u32);
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> i32;
    fn GetTokenInformation(token: HANDLE, class: i32, info: *mut c_void, len: u32, needed: *mut u32) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
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
struct Asked {
    /// `Some(None)`: no limit, written as such.
    memory: Option<Option<usize>>,
    quota: Option<Option<u64>>,
    period: Option<u64>,
    cpus: Option<Vec<u32>>,
}

fn parse(version: u8, cgroups: &[String]) -> Result<Asked, String> {
    let mut asked = Asked::default();
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

/// The job of one level: made, or opened if it is there and one to trust.
/// Whether it was made.
fn level(job_name: &str, user: &str) -> Result<(HANDLE, bool), String> {
    let path = job_name.strip_prefix(PARENT_JOB_PREFIX).unwrap_or(job_name);
    let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{user})"));
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

/// Makes or opens every level of `name` and writes the limits to the last.
/// The handles, which hold the levels while this process runs.
fn run(name: &str, version: u8, cgroups: &[String]) -> Result<Vec<HANDLE>, String> {
    let names = parent_job_names(name).map_err(|why| format!("--name {name}: {why}"))?;
    let asked = parse(version, cgroups)?;
    let user = token_sid(TOKEN_USER_CLASS)?;
    let mut jobs = Vec::new();
    let mut made = false;
    for job_name in &names {
        let (job, new) = level(job_name, &user)?;
        jobs.push(job);
        made = new;
    }
    let (job, above) = (jobs[jobs.len() - 1], &jobs[..jobs.len() - 1]);

    if let Some(memory) = asked.memory {
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
    if let Some(quota) = asked.quota {
        let caps = above.iter().map(|&job| hard_cap(job)).collect::<Result<Vec<_>, _>>()?;
        let of_above = rate_of_levels(&caps);
        let wanted = match quota {
            None => None,
            Some(quota) => {
                // SAFETY: plain queries.
                let cpus = u64::from(unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) });
                let host = cpu_rate(quota, asked.period.unwrap_or(DEFAULT_PERIOD_US), cpus).map_err(|why| format!("the CPU quota: {why}"))?;
                Some(match of_above {
                    Some(parent) => rate_under_parent(version, host, parent).map_err(|why| format!("--name {name}: {why}"))?,
                    None => host,
                })
            }
        };
        let write = level_write(made, &hard_cap(job)?, &wanted).map_err(|why| format!("--name {name}: the CPU cap: {why}"))?;
        if let Some(Some(rate)) = write {
            let cpu = CPU_RATE { ControlFlags: RATE_ENABLE | RATE_HARD_CAP, CpuRate: rate };
            set(job, CPU_RATE_CONTROL, &cpu, std::mem::size_of::<CPU_RATE>(), "the CPU rate")?;
        }
        match (wanted, of_above) {
            (None, _) => println!("jail-parent: {name}: no CPU cap of its own"),
            (Some(rate), None) => println!("jail-parent: {name}: CPU rate {rate} of 10000 of the host's processors"),
            (Some(rate), Some(parent)) => println!(
                "jail-parent: {name}: CPU rate {rate} of 10000 of what the levels above have, which is {parent} of 10000 of the \
                 host's processors"
            ),
        }
    } else if asked.period.is_some() {
        return Err("a CPU period without a quota".to_string());
    }
    if let Some(cpus) = &asked.cpus {
        // SAFETY: plain queries.
        let sizes: Vec<u32> = unsafe { (0..GetActiveProcessorGroupCount()).map(|g| GetActiveProcessorCount(g)).collect() };
        let mut groups = cpu_groups(cpus, &sizes).map_err(|why| format!("cpuset.cpus: {why}"))?;
        let levels = above.iter().map(|&job| processors(job)).collect::<Result<Vec<_>, _>>()?;
        if let Some(parent) = cpus_of_levels(&levels) {
            groups = cpus_under_parent(version, &groups, &parent).map_err(|why| format!("--name {name}: cpuset.cpus: {why}"))?;
        }
        groups.sort_unstable();
        let now = processors(job)?.unwrap_or_default();
        let write = level_write(made, &now, &groups).map_err(|why| format!("--name {name}: cpuset.cpus: {why}"))?;
        if write.is_some() {
            if let [(0, mask)] = groups.as_slice() {
                let mut info: EXTENDED = query(job, EXTENDED_LIMIT, "the job's limits")?;
                info.Basic.LimitFlags |= LIMIT_AFFINITY;
                info.Basic.Affinity = *mask as usize;
                set(job, EXTENDED_LIMIT, &info, std::mem::size_of::<EXTENDED>(), "the processors")?;
            } else {
                let list: Vec<GROUP_AFFINITY> =
                    groups.iter().map(|&(group, mask)| GROUP_AFFINITY { Mask: mask as usize, Group: group, Reserved: [0; 3] }).collect();
                set(job, GROUP_INFORMATION_EX, &list[0], std::mem::size_of_val(list.as_slice()), "the processors")?;
            }
        }
        println!("jail-parent: {name}: processors {groups:x?} (group, mask)");
    }
    Ok(jobs)
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

    #[test]
    fn test_parse() {
        let of = |version, list: &[&str]| parse(version, &list.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        assert_eq!(
            of(2, &["memory.max=67108864", "cpu.max=50000 100000", "cpuset.cpus=0-1,3"]).unwrap(),
            Asked { memory: Some(Some(64 << 20)), quota: Some(Some(50_000)), period: Some(100_000), cpus: Some(vec![0, 1, 3]) }
        );
        assert_eq!(of(2, &["memory.max=max", "cpu.max=max"]).unwrap(), Asked { memory: Some(None), quota: Some(None), ..Asked::default() });
        assert_eq!(
            of(1, &["memory.limit_in_bytes=-1", "cpu.cfs_quota_us=25000", "cpu.cfs_period_us=50000"]).unwrap(),
            Asked { memory: Some(None), quota: Some(Some(25_000)), period: Some(50_000), cpus: None }
        );
        // Another version's file, a limit a parent does not take, a value
        // that is none: refused, not accepted without effect.
        for (version, cg) in [(1, "memory.max=1"), (2, "memory.limit_in_bytes=1"), (2, "pids.max=5"), (2, "memory.max=0"), (2, "cpu.max")] {
            assert!(of(version, &[cg]).is_err(), "{cg}");
        }
    }
}
