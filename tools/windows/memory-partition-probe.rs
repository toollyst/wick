// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Measures whether a memory partition can bound everything a jailed process
//! takes, the candidate fix for `memory.max` (docs/COMPATIBILITY.md,
//! "cgroup controllers": a Job Object's limit charges private memory only,
//! sections escape it; `jailer-test.ps1 sections`).
//!
//! Needs an elevated prompt and an account holding "Lock pages in memory"
//! (SeLockMemoryPrivilege; the hugepages stage needs it too) for everything
//! past step 1. It says so and stops if the privilege is missing. CI's kit has it built
//! (`tools\windows\memory-partition-probe.exe`); otherwise, with no
//! dependencies:
//!
//! ```text
//! rustc -O memory-partition-probe.rs
//! memory-partition-probe.exe [partition MiB, default 256] > partition.txt
//! ```
//!
//! The calls are undocumented. Their prototypes and layouts are phnt's
//! (winsiderss/phnt ntmmapi.h and ntpsapi.h, read 2026-11-13; NtTrace.cfg
//! agrees on the prototypes), with three points measured on Windows Server
//! 2022 build 20348, where phnt says nothing or names a field otherwise:
//! - SystemMemoryPartitionInformation takes its structure (240 bytes; any
//!   other length is STATUS_INFO_LENGTH_MISMATCH) as input too: `Channel`
//!   must be 0xFFFFFFFF and `NumaNode` 0xFFFFFFFF for all nodes, or it fails
//!   with STATUS_INVALID_PARAMETER (what every query of the first version
//!   returned);
//! - SystemMemoryPartitionMoveMemory needs the source partition's handle with
//!   modify access: a NULL source is STATUS_INVALID_HANDLE (what the first
//!   version's move returned), a query-only handle STATUS_ACCESS_DENIED. The
//!   system partition is opened by name, `\KernelObjects\MemoryPartition0`;
//! - JobObjectMemoryPartitionInformation (43) takes a partition HANDLE,
//!   although phnt names its field `PartitionId`: the id 0 is
//!   STATUS_INVALID_HANDLE, the system partition's handle
//!   STATUS_NOT_SUPPORTED.
//!
//! What it does, in order, each step on one line:
//! 1. Prints the Windows build, the host's memory and the system partition's
//!    information (needs no privilege).
//! 2. Enables SeLockMemoryPrivilege.
//! 3. For each kind, creates a partition of its own (NtCreatePartition),
//!    moves the size's pages into it from the system partition (NtManagePartition,
//!    SystemMemoryPartitionMoveMemory), and reads its information before and
//!    after, with the host's free memory, to see whether the pages leave the
//!    host up front. A partition of its own per kind, so that no kind runs in
//!    what another left.
//! 4. Makes a kill-on-close job and associates it with the partition
//!    (JobObjectMemoryPartitionInformation, 43) while it is empty, then
//!    creates the child IN the job (PROC_THREAD_ATTRIBUTE_JOB_LIST), so that
//!    the child is the partition's from its first page: a process made
//!    outside and assigned later (what the first version did) did not join
//!    the job. The child enables no privilege, except for large pages, and
//!    takes twice the partition's size of its kind:
//!    - private memory (VirtualAlloc, written);
//!    - pagefile-backed sections, mapped and written, and created only;
//!    - temporary-file sections (wick's memfd), mapped and written;
//!    - large pages;
//!    - events (kernel pool).
//!    Records where the child stopped and with what error, or that it was
//!    killed (its exit code), and the partition's and the host's memory.
//! 5. The same for private memory with a job memory limit of half the
//!    partition as well (nesting).
//! 6. Closes each partition after its kind and reads the host's memory
//!    again (cleanup).

#![allow(non_snake_case, clippy::upper_case_acronyms)]

use std::ffi::c_void;

type H = *mut c_void;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PerfInfo {
    cb: u32,
    commit_total: usize,
    commit_limit: usize,
    commit_peak: usize,
    phys_total: usize,
    phys_avail: usize,
    system_cache: usize,
    kernel_total: usize,
    kernel_paged: usize,
    kernel_nonpaged: usize,
    page_size: usize,
    handles: u32,
    processes: u32,
    threads: u32,
}

/// MEMORY_PARTITION_CONFIGURATION_INFORMATION (phnt).
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
struct PartitionInfo {
    flags: u32,
    numa_node: u32,
    channel: u32,
    numa_nodes: u32,
    resident_available: usize,
    committed: usize,
    commit_limit: usize,
    peak_commitment: usize,
    total_pages: usize,
    available: usize,
    zero: usize,
    free: usize,
    standby: usize,
    standby_by_priority: [usize; 8],
    repurposed_by_priority: [usize; 8],
    maximum_commit_limit: usize,
    reserved: usize,
    id: u32,
}

#[repr(C)]
struct StartupInfo {
    cb: u32,
    reserved: [*mut u16; 3],
    dims: [u32; 7],
    flags: u32,
    show: u16,
    cb_reserved2: u16,
    reserved2: *mut u8,
    stdin: H,
    stdout: H,
    stderr: H,
}

#[repr(C)]
struct StartupInfoEx {
    si: StartupInfo,
    attributes: *mut c_void,
}

#[repr(C)]
struct UnicodeString {
    len: u16,
    max: u16,
    buf: *const u16,
}

#[repr(C)]
struct ObjectAttributes {
    len: u32,
    root: H,
    name: *const UnicodeString,
    attributes: u32,
    sd: *const c_void,
    sqos: *const c_void,
}

#[repr(C)]
#[derive(Default)]
struct ProcessInfo {
    process: usize,
    thread: usize,
    pid: u32,
    tid: u32,
}

#[repr(C)]
#[derive(Default)]
struct ExtendedLimit {
    per_process_time: i64,
    per_job_time: i64,
    flags: u32,
    min_ws: usize,
    max_ws: usize,
    active: u32,
    affinity: usize,
    priority: u32,
    scheduling: u32,
    io: [u64; 6],
    process_memory: usize,
    job_memory: usize,
    peak_process: usize,
    peak_job: usize,
}

#[repr(C)]
struct TokenPrivileges {
    count: u32,
    luid: [u32; 2],
    attributes: u32,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreatePartition(parent: H, out: *mut H, access: u32, oa: *const ObjectAttributes) -> i32;
    fn NtOpenPartition(out: *mut H, access: u32, oa: *const ObjectAttributes) -> i32;
    fn NtManagePartition(target: H, source: H, class: u32, info: *mut c_void, len: u32) -> i32;
    fn NtSetInformationJobObject(j: H, class: u32, info: *const c_void, len: u32) -> i32;
    fn NtQueryInformationJobObject(j: H, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn RtlGetVersion(v: *mut u32) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> H;
    fn GetLastError() -> u32;
    fn K32GetPerformanceInfo(p: *mut PerfInfo, cb: u32) -> i32;
    fn CreateJobObjectW(a: *const c_void, name: *const u16) -> H;
    fn SetInformationJobObject(j: H, class: u32, info: *const c_void, len: u32) -> i32;
    fn InitializeProcThreadAttributeList(list: *mut c_void, count: u32, flags: u32, size: *mut usize) -> i32;
    fn UpdateProcThreadAttribute(list: *mut c_void, flags: u32, attr: usize, value: *const c_void, size: usize, prev: *mut c_void, ret: *mut usize) -> i32;
    fn DeleteProcThreadAttributeList(list: *mut c_void);
    fn IsProcessInJob(p: H, j: H, result: *mut i32) -> i32;
    fn CreateProcessW(app: *const u16, cmd: *mut u16, pa: *const c_void, ta: *const c_void, inherit: i32, flags: u32, env: *const c_void, cwd: *const u16, si: *mut StartupInfo, pi: *mut ProcessInfo) -> i32;
    fn ResumeThread(t: H) -> u32;
    fn WaitForSingleObject(h: H, ms: u32) -> u32;
    fn GetExitCodeProcess(p: H, code: *mut u32) -> i32;
    fn TerminateProcess(p: H, code: u32) -> i32;
    fn CloseHandle(h: H) -> i32;
    fn GetStdHandle(n: u32) -> H;
    fn SetHandleInformation(h: H, mask: u32, flags: u32) -> i32;
    fn VirtualAlloc(p: *mut c_void, size: usize, ty: u32, prot: u32) -> *mut u8;
    fn CreateFileMappingW(f: H, a: *const c_void, prot: u32, hi: u32, lo: u32, name: *const u16) -> H;
    fn MapViewOfFile(h: H, access: u32, hi: u32, lo: u32, size: usize) -> *mut u8;
    fn CreateFileW(name: *const u16, access: u32, share: u32, sa: *const c_void, disp: u32, flags: u32, tmpl: H) -> H;
    fn CreateEventW(a: *const c_void, manual: i32, initial: i32, name: *const u16) -> H;
    fn GetLargePageMinimum() -> usize;
}
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(p: H, access: u32, t: *mut H) -> i32;
    fn LookupPrivilegeValueW(sys: *const u16, name: *const u16, luid: *mut [u32; 2]) -> i32;
    fn AdjustTokenPrivileges(t: H, disable: i32, new: *const TokenPrivileges, len: u32, prev: *mut c_void, ret: *mut u32) -> i32;
}

const MIB: usize = 1 << 20;
/// MEMORY_PARTITION_ALL_ACCESS (phnt).
const PARTITION_ALL_ACCESS: u32 = 0x001F_0003;

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn host() -> String {
    let mut p = PerfInfo { cb: size_of::<PerfInfo>() as u32, ..Default::default() };
    // SAFETY: an output structure of the size given.
    unsafe { K32GetPerformanceInfo(&mut p, p.cb) };
    let m = |v: usize| v * p.page_size / MIB;
    format!(
        "host: available {} MiB of {} MiB, commit {} of {} MiB, pool paged {} MiB nonpaged {} MiB",
        m(p.phys_avail), m(p.phys_total), m(p.commit_total), m(p.commit_limit), m(p.kernel_paged), m(p.kernel_nonpaged)
    )
}

fn partition_info(p: H) -> String {
    // Input as well as output: all NUMA nodes, and a Channel of 0xFFFFFFFF
    // (anything else is STATUS_INVALID_PARAMETER; measured).
    let mut i = PartitionInfo { numa_node: u32::MAX, channel: u32::MAX, ..Default::default() };
    // SAFETY: an in/out structure of the size given; class 0 is the information.
    let st = unsafe { NtManagePartition(p, std::ptr::null_mut(), 0, (&raw mut i).cast(), size_of::<PartitionInfo>() as u32) };
    let m = |v: usize| v * 4096 / MIB;
    format!(
        "partition (status {st:#x}): id {} total {} MiB, available {} MiB, free {} MiB, committed {} MiB, commit limit {} MiB (max {} MiB), resident available {} MiB",
        i.id, m(i.total_pages), m(i.available), m(i.free), m(i.committed), m(i.commit_limit), m(i.maximum_commit_limit), m(i.resident_available)
    )
}

/// The system partition, opened by name with modify access (the source of a
/// move).
fn system_partition() -> Result<H, i32> {
    let name: Vec<u16> = "\\KernelObjects\\MemoryPartition0".encode_utf16().collect();
    let bytes = (name.len() * 2) as u16;
    let us = UnicodeString { len: bytes, max: bytes, buf: name.as_ptr() };
    let oa = ObjectAttributes {
        len: size_of::<ObjectAttributes>() as u32,
        root: std::ptr::null_mut(),
        name: &us,
        attributes: 0x40, // OBJ_CASE_INSENSITIVE
        sd: std::ptr::null(),
        sqos: std::ptr::null(),
    };
    let mut p = std::ptr::null_mut();
    // SAFETY: an output handle and attributes that live through the call.
    let st = unsafe { NtOpenPartition(&mut p, PARTITION_ALL_ACCESS, &oa) };
    if st < 0 { Err(st) } else { Ok(p) }
}

/// A new partition with `size` MiB moved into it from `system`; None (said)
/// if either step fails.
fn new_partition(system: H, size: usize) -> Option<H> {
    let mut p = std::ptr::null_mut();
    // SAFETY: an output handle; no parent (the system partition), no name.
    let st = unsafe { NtCreatePartition(std::ptr::null_mut(), &mut p, PARTITION_ALL_ACCESS, std::ptr::null()) };
    println!("NtCreatePartition: {st:#x}");
    if st < 0 {
        return None;
    }
    println!("  created: {}", partition_info(p));
    // MEMORY_PARTITION_TRANSFER_INFORMATION: pages, NUMA node, flags.
    #[repr(C)]
    struct Transfer {
        pages: usize,
        node: u32,
        flags: u32,
    }
    let mut t = Transfer { pages: size * MIB / 4096, node: 0, flags: 0 };
    // SAFETY: class 1, SystemMemoryPartitionMoveMemory, from the system partition's handle.
    let st = unsafe { NtManagePartition(p, system, 1, (&raw mut t).cast(), size_of::<Transfer>() as u32) };
    println!("  move {size} MiB into it from the system partition: {st:#x}");
    println!("  sized: {}", partition_info(p));
    println!("  sized: {}", host());
    if st < 0 {
        // SAFETY: our handle.
        unsafe { CloseHandle(p) };
        return None;
    }
    Some(p)
}

/// Enables a privilege of this process's token; Err if the token does not hold it.
fn enable(name: &str) -> Result<(), String> {
    // SAFETY: plain calls on our own token, results checked.
    unsafe {
        let mut t = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), 0x20 | 0x8, &mut t) == 0 {
            return Err(format!("OpenProcessToken error {}", GetLastError()));
        }
        let mut luid = [0u32; 2];
        if LookupPrivilegeValueW(std::ptr::null(), w(name).as_ptr(), &mut luid) == 0 {
            return Err(format!("LookupPrivilegeValue error {}", GetLastError()));
        }
        let tp = TokenPrivileges { count: 1, luid, attributes: 2 };
        let ok = AdjustTokenPrivileges(t, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut());
        let e = GetLastError();
        CloseHandle(t);
        // ERROR_NOT_ALL_ASSIGNED: the token does not hold it.
        if ok == 0 || e == 1300 {
            return Err(format!("the account does not hold {name} (error {e})"));
        }
    }
    Ok(())
}

/// The child: takes `mib` MiB (or `mib` * 1000 events) of `kind`, 1 MiB at a
/// time, and prints how far it got.
fn child(kind: &str, mib: usize) {
    if kind == "largepages" {
        if let Err(e) = enable("SeLockMemoryPrivilege") {
            println!("  child {kind}: {e}");
            return;
        }
    }
    let invalid = usize::MAX as H;
    let large = unsafe { GetLargePageMinimum() }.max(MIB);
    let step = if kind == "largepages" { large } else { MIB };
    let mut taken = 0usize;
    let mut why = String::from("none (took it all)");
    'outer: while taken < mib * MIB {
        // SAFETY: new allocations and mappings of our own, written within their size.
        unsafe {
            let p: *mut u8 = match kind {
                "private" => VirtualAlloc(std::ptr::null_mut(), step, 0x3000, 4),
                "largepages" => VirtualAlloc(std::ptr::null_mut(), step, 0x2000_3000, 4),
                "events" => {
                    for _ in 0..1000 {
                        if CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()).is_null() {
                            why = format!("CreateEventW error {}", GetLastError());
                            break 'outer;
                        }
                    }
                    taken += step;
                    continue;
                }
                "sections-created" => {
                    if CreateFileMappingW(invalid, std::ptr::null(), 4, 0, step as u32, std::ptr::null()).is_null() {
                        why = format!("CreateFileMappingW error {}", GetLastError());
                        break 'outer;
                    }
                    taken += step;
                    continue;
                }
                "sections" | "filesections" => {
                    let f = if kind == "filesections" {
                        let path = std::env::temp_dir().join(format!("partition-probe-{}-{taken}", std::process::id()));
                        let f = CreateFileW(w(&path.to_string_lossy()).as_ptr(), 0xC000_0000, 0, std::ptr::null(), 1, 0x0400_0100, std::ptr::null_mut());
                        if f == invalid {
                            why = format!("CreateFileW error {}", GetLastError());
                            break 'outer;
                        }
                        f
                    } else {
                        invalid
                    };
                    let s = CreateFileMappingW(f, std::ptr::null(), 4, 0, step as u32, std::ptr::null());
                    if s.is_null() {
                        why = format!("CreateFileMappingW error {}", GetLastError());
                        break 'outer;
                    }
                    MapViewOfFile(s, 0xF001F, 0, 0, step)
                }
                k => {
                    why = format!("unknown kind {k}");
                    break 'outer;
                }
            };
            if p.is_null() {
                why = format!("allocation error {}", GetLastError());
                break;
            }
            for o in (0..step).step_by(4096) {
                p.add(o).write_volatile(1);
            }
        }
        taken += step;
    }
    let unit = if kind == "events" { format!("{} events", taken / MIB * 1000) } else { format!("{} MiB", taken / MIB) };
    println!("  child {kind}: took {unit} of {} asked; stopped by: {why}", if kind == "events" { format!("{} events", mib * 1000) } else { format!("{mib} MiB") });
}

/// Runs `child <kind> <mib>` in a new job tied to `partition` (and with a job
/// memory limit if `job_mib` > 0), the job set up before the child runs.
fn run(partition: H, kind: &str, mib: usize, job_mib: usize) {
    // SAFETY: plain calls; handles checked and closed.
    unsafe {
        let j = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        let mut l = ExtendedLimit { flags: 0x2000, ..Default::default() };
        if job_mib > 0 {
            l.flags |= 0x200;
            l.job_memory = job_mib * MIB;
        }
        SetInformationJobObject(j, 9, (&raw const l).cast(), size_of::<ExtendedLimit>() as u32);
        // The partition's handle (not its id, whatever phnt calls the field), while the job is empty.
        let hv = partition as usize;
        let st = NtSetInformationJobObject(j, 43, (&raw const hv).cast(), size_of::<usize>() as u32);
        let mut back = 0u8;
        let mut n = 0u32;
        let qst = NtQueryInformationJobObject(j, 43, (&raw mut back).cast(), 1, &mut n);
        // The child is made in the job, so it is the partition's from its first page.
        let mut size = 0usize;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
        let mut list = vec![0u8; size];
        let mut jobs = [j];
        if InitializeProcThreadAttributeList(list.as_mut_ptr().cast(), 1, 0, &mut size) == 0
            // PROC_THREAD_ATTRIBUTE_JOB_LIST
            || UpdateProcThreadAttribute(list.as_mut_ptr().cast(), 0, 0x0002_000D, jobs.as_mut_ptr().cast(), size_of::<H>(), std::ptr::null_mut(), std::ptr::null_mut()) == 0
        {
            println!("{kind}: the job attribute: error {}", GetLastError());
            CloseHandle(j);
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let mut cmd = w(&format!("\"{}\" child {kind} {mib}", exe.display()));
        let out = GetStdHandle(-11i32 as u32);
        SetHandleInformation(out, 1, 1);
        let mut si = StartupInfoEx {
            si: StartupInfo {
                cb: size_of::<StartupInfoEx>() as u32,
                reserved: [std::ptr::null_mut(); 3],
                dims: [0; 7],
                flags: 0x100,
                show: 0,
                cb_reserved2: 0,
                reserved2: std::ptr::null_mut(),
                stdin: std::ptr::null_mut(),
                stdout: out,
                stderr: out,
            },
            attributes: list.as_mut_ptr().cast(),
        };
        let mut pi = ProcessInfo::default();
        // CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT.
        let created = CreateProcessW(std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 1, 4 | 0x0008_0000, std::ptr::null(), std::ptr::null(), &mut si.si, &mut pi);
        let created_error = GetLastError();
        DeleteProcThreadAttributeList(list.as_mut_ptr().cast());
        println!(
            "{kind}{}: job tied to the partition: status {st:#x} (read back {qst:#x}: {back}); child made in the job: {}",
            if job_mib > 0 { format!(" (and a job memory limit of {job_mib} MiB)") } else { String::new() },
            if created == 0 { format!("no, CreateProcessW error {created_error}") } else { String::from("yes") }
        );
        if created == 0 {
            CloseHandle(j);
            return;
        }
        let mut inside = 0;
        IsProcessInJob(pi.process as H, j, &mut inside);
        println!("  {kind}: child in the job: {inside}");
        ResumeThread(pi.thread as H);
        if WaitForSingleObject(pi.process as H, 120_000) != 0 {
            TerminateProcess(pi.process as H, 1);
            println!("  {kind}: still running after 120 s, ended");
        }
        let mut code = 0;
        GetExitCodeProcess(pi.process as H, &mut code);
        println!("  {kind}: child exit code {code:#x}");
        println!("  {}", partition_info(partition));
        println!("  {}", host());
        CloseHandle(pi.thread as H);
        CloseHandle(pi.process as H);
        CloseHandle(j);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("child") {
        child(&args[2], args[3].parse().unwrap_or(0));
        return;
    }
    let size: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(256);
    let mut v = [0u32; 70];
    v[0] = 284;
    // SAFETY: an RTL_OSVERSIONINFOW of the size in its first word.
    unsafe { RtlGetVersion(v.as_mut_ptr()) };
    println!("windows {}.{} build {}", v[1], v[2], v[3]);
    println!("{}", host());
    let system = match system_partition() {
        Ok(h) => h,
        Err(st) => {
            println!("FAIL: NtOpenPartition(\\KernelObjects\\MemoryPartition0): {st:#x}");
            std::process::exit(3);
        }
    };
    println!("system {}", partition_info(system));
    if let Err(e) = enable("SeLockMemoryPrivilege") {
        println!("FAIL: {e}: give the account \"Lock pages in memory\" (secpol.msc, Local Policies, User Rights Assignment), sign out and in, and run this again elevated");
        std::process::exit(2);
    }
    println!("SeLockMemoryPrivilege enabled");
    let runs = [("private", 0), ("sections", 0), ("sections-created", 0), ("filesections", 0), ("largepages", 0), ("events", 0), ("private", size / 2)];
    for (kind, job_mib) in runs {
        let Some(p) = new_partition(system, size) else {
            println!("FAIL {kind}: no partition of {size} MiB");
            continue;
        };
        run(p, kind, size * 2, job_mib);
        // SAFETY: our handle.
        unsafe { CloseHandle(p) };
        println!("  partition closed: {}", host());
    }
}
