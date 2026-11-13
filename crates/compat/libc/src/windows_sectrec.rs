// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! SECTREC: the records for section memory charged against `memory.max`
//! (SECURITY.md's W2; the plan's step S0). No WHP in them; the guest's side
//! (a WHP exit on a section's page) is kvm-ioctls' `SECTREC-a WHP` lines.
//!
//! One test, [`test_section_memory_and_a_charge_for_it_on_record`], runs a
//! child copy of the test binary ([`sectrec_child`]) in a job of its own,
//! as the jailer runs Firecracker, with a job memory limit of 1 GiB, and is
//! the jailer's side of it. Lines start `SECTREC-a` to `SECTREC-d`:
//! - a: what a pagefile-backed section takes of the host's commit, the
//!   job's and the process's, made `SEC_COMMIT` (wick's today) and
//!   `SEC_RESERVE` (Layer 1's), mapped, committed (`VirtualAlloc` on a
//!   view) and written; what a second view of the same section shows as
//!   committed; a 4 KiB commit's time on a view;
//! - b: a charge page (a private page committed and never touched): its
//!   time, what it takes of the commit, the job and the working set, and
//!   where the job's limit refuses charge pages (the error);
//! - c: a file section (wick's memfd: a temporary file deleted on close)
//!   with a view mapped no-access and opened a page at a time at its first
//!   access by an exception handler: each such access's time, the
//!   `VirtualProtect` alone, what another view sees, and what another
//!   process (the jailer's side, through a duplicated handle) sees and
//!   writes;
//! - d: the jailer's poll of a jail laid out as a Firecracker with
//!   vhost-user and a uffd restore would be (private guest RAM, a memfd
//!   guest view, a pagefile section mapped twice, 40 eventfds' pages, and
//!   a section whose handle was closed and whose view stays): the time of
//!   each part (the handle list, the sections' sizes, deduplicated with
//!   `CompareObjectHandles`, the views by `VirtualQueryEx`, the resident
//!   pages by `QueryWorkingSetEx`) and the whole, its share of a CPU at a
//!   poll a millisecond, and what it counts against what the child made;
//!   whether the kernel's object addresses are given to this process
//!   (`SystemExtendedHandleInformation`), and whether this process is
//!   elevated. The elevated case is the user's to start on the PC;
//! - e: what the poll could miss between two polls and what a cheaper poll
//!   would cost: the time a SEC_COMMIT section of 1 and 4 GiB takes to
//!   make, with the host's commit it takes; 256 MiB committed on a
//!   SEC_RESERVE view in one call and then written (how much RAM a
//!   millisecond takes); and, on the jailer's side, each cheap sign of new
//!   section memory (the child's handle count, its virtual size, the host's
//!   commit, its `SharedCommitUsage`) and `GetMappedFileNameW` of each view
//!   (a file's view or the pagefile's); then whether a section's commit is
//!   charged to a process: `PROCESS_MEMORY_COUNTERS_EX2.SharedCommitUsage`
//!   (Learn: "The current shared commit usage, in bytes"; Windows 10 or 11
//!   22H2 with the September 2023 update and later) of the child as a 1
//!   GiB SEC_COMMIT section is made, mapped, its handle closed with the view
//!   kept, unmapped; a SEC_RESERVE section committed on a view; a section
//!   whose handle the jailer's side duplicates and holds while the child
//!   closes its own (both processes' values); and the pagefile quota
//!   (`QUOTA_LIMITS.PagefileLimit`, `ProcessQuotaLimits`): whether the
//!   jailer's side and the child itself can set it, and whether a SEC_COMMIT
//!   section, and private memory, are refused past it.
//!
//! Printed, not asserted, but for each step running and the child ending
//! well.

use std::prelude::rust_2021::*;
use std::{eprintln, format, println, vec};

use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::io::{BufRead, Write};
use std::time::Instant;

use windows_sys::Win32::Foundation::{CloseHandle, CompareObjectHandles, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, VirtualAlloc, VirtualFree, VirtualProtect, VirtualQuery, VirtualQueryEx,
    FILE_MAP_ALL_ACCESS, MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS, MEM_COMMIT, MEM_MAPPED, MEM_RELEASE, MEM_RESERVE,
    PAGE_NOACCESS, PAGE_READWRITE, SEC_COMMIT, SEC_RESERVE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const PAGE: usize = 4096;
const MIB: usize = 1 << 20;
const CHILD: &str = "WICK_SECTREC_CHILD";
/// The job's memory limit the child runs under.
const JOB_LIMIT: usize = 1 << 30;

#[repr(C)]
#[derive(Default)]
struct PerformanceInformation {
    cb: u32,
    commit_total: usize,
    commit_limit: usize,
    commit_peak: usize,
    physical_total: usize,
    physical_available: usize,
    system_cache: usize,
    kernel_total: usize,
    kernel_paged: usize,
    kernel_nonpaged: usize,
    page_size: usize,
    handle_count: u32,
    process_count: u32,
    thread_count: u32,
}

#[repr(C)]
#[derive(Default)]
struct Counters {
    cb: u32,
    page_faults: u32,
    peak_working_set: usize,
    working_set: usize,
    quota_peak_paged: usize,
    quota_paged: usize,
    quota_peak_non_paged: usize,
    quota_non_paged: usize,
    pagefile: usize,
    peak_pagefile: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct WorkingSetEntry {
    address: usize,
    attributes: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HandleEntry {
    handle: usize,
    handle_count: usize,
    pointer_count: usize,
    granted_access: u32,
    type_index: u32,
    attributes: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemHandleEntry {
    object: usize,
    pid: usize,
    handle: usize,
    granted_access: u32,
    back_trace: u16,
    type_index: u16,
    attributes: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Default)]
struct SectionBasicInformation {
    base: usize,
    attributes: u32,
    size: i64,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn K32GetPerformanceInfo(info: *mut PerformanceInformation, cb: u32) -> i32;
    fn K32GetProcessMemoryInfo(process: HANDLE, counters: *mut Counters, cb: u32) -> i32;
    fn K32QueryWorkingSetEx(process: HANDLE, info: *mut c_void, cb: u32) -> i32;
    fn K32GetMappedFileNameW(process: HANDLE, address: *const c_void, name: *mut u16, len: u32) -> u32;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(process: HANDLE, class: u32, info: *mut c_void, len: u32, returned: *mut u32) -> i32;
    fn NtQueryObject(handle: HANDLE, class: u32, info: *mut c_void, len: u32, returned: *mut u32) -> i32;
    fn NtQuerySection(section: HANDLE, class: u32, info: *mut c_void, len: usize, returned: *mut usize) -> i32;
    fn NtQuerySystemInformation(class: u32, info: *mut c_void, len: u32, returned: *mut u32) -> i32;
    fn NtSetInformationProcess(process: HANDLE, class: u32, info: *const c_void, len: u32) -> i32;
}

const PROCESS_HANDLE_INFORMATION: u32 = 51;
const OBJECT_TYPE_INFORMATION: u32 = 2;
const SECTION_BASIC_INFORMATION: u32 = 0;
const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const JOB_OBJECT_MEMORY_USAGE_INFORMATION: i32 = 28;

const PROCESS_QUOTA_LIMITS: u32 = 1;

/// `PROCESS_MEMORY_COUNTERS_EX2` (Learn: Windows 10 22H2 or Windows 11
/// 22H2 with the September 2023 update and later).
#[repr(C)]
#[derive(Default)]
struct CountersEx2 {
    cb: u32,
    page_faults: u32,
    sizes: [usize; 10],
    shared_commit: u64,
}

/// A process's `SharedCommitUsage`, or none where `GetProcessMemoryInfo`
/// refuses the structure's size.
fn shared_commit(process: HANDLE) -> Option<u64> {
    let mut c = CountersEx2 { cb: core::mem::size_of::<CountersEx2>() as u32, ..Default::default() };
    // SAFETY: a structure of the size given.
    (unsafe { K32GetProcessMemoryInfo(process, (&raw mut c).cast(), c.cb) } != 0).then_some(c.shared_commit)
}

/// `QUOTA_LIMITS`: paged pool, nonpaged pool, the working set's least and
/// most, the pagefile limit, the time limit.
fn quota_limits(process: HANDLE) -> Result<[usize; 6], i32> {
    let mut q = [0usize; 6];
    // SAFETY: a buffer of QUOTA_LIMITS' size.
    let status = unsafe { NtQueryInformationProcess(process, PROCESS_QUOTA_LIMITS, q.as_mut_ptr().cast(), 48, core::ptr::null_mut()) };
    if status < 0 { Err(status) } else { Ok(q) }
}

/// Sets a process's pagefile quota to `limit` bytes, the rest left at zero
/// (unchanged): the NTSTATUS.
fn set_pagefile_limit(process: HANDLE, limit: usize) -> i32 {
    let q = [0, 0, 0, 0, limit, 0usize];
    // SAFETY: a QUOTA_LIMITS of the size given.
    unsafe { NtSetInformationProcess(process, PROCESS_QUOTA_LIMITS, q.as_ptr().cast(), 48) }
}

fn us(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1e6
}

fn spread(t: &[f64]) -> String {
    let mut t = t.to_vec();
    t.sort_by(f64::total_cmp);
    match t.len() {
        0 => "none".to_string(),
        n => format!("median {:.2} us (least {:.2}, most {:.2})", t[n / 2], t[0], t[n - 1]),
    }
}

/// The host's commit, the job's memory (its current use where Windows
/// gives it, else its peak), the process's private commit and working set,
/// in bytes.
#[derive(Clone, Copy)]
struct Charge {
    host_commit: usize,
    job: Option<usize>,
    job_is_peak: bool,
    private: usize,
    working_set: usize,
}

fn charge() -> Charge {
    let mut perf = PerformanceInformation { cb: core::mem::size_of::<PerformanceInformation>() as u32, ..Default::default() };
    // SAFETY: an output structure of the size given.
    let host_commit = if unsafe { K32GetPerformanceInfo(&mut perf, perf.cb) } != 0 { perf.commit_total * perf.page_size } else { 0 };
    let mut c = Counters { cb: core::mem::size_of::<Counters>() as u32, ..Default::default() };
    // SAFETY: as above.
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) } != 0;
    let (job, job_is_peak) = job_memory();
    Charge {
        host_commit,
        job,
        job_is_peak,
        private: if ok { c.pagefile } else { 0 },
        working_set: if ok { c.working_set } else { 0 },
    }
}

/// The job's memory use (`JobObjectMemoryUsageInformation`, phnt's class
/// 28: JobMemory, PeakJobMemoryUsed), else its peak (documented).
fn job_memory() -> (Option<usize>, bool) {
    use windows_sys::Win32::System::JobObjects::{JobObjectExtendedLimitInformation, QueryInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION};
    let mut usage = [0u64; 2];
    // SAFETY: the calling process's job (a null handle); a buffer of the size given.
    if unsafe { QueryInformationJobObject(core::ptr::null_mut(), JOB_OBJECT_MEMORY_USAGE_INFORMATION, usage.as_mut_ptr().cast(), 16, core::ptr::null_mut()) } != 0 {
        return (Some(usage[0] as usize), false);
    }
    // SAFETY: plain data.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { core::mem::zeroed() };
    // SAFETY: as above.
    let ok = unsafe {
        QueryInformationJobObject(
            core::ptr::null_mut(),
            JobObjectExtendedLimitInformation,
            (&raw mut info).cast(),
            core::mem::size_of_val(&info) as u32,
            core::ptr::null_mut(),
        )
    } != 0;
    (ok.then_some(info.PeakJobMemoryUsed), true)
}

/// What changed from `a` to `b`, in KiB.
fn delta(a: Charge, b: Charge) -> String {
    let kib = |x: usize, y: usize| (y as i64 - x as i64) / 1024;
    let job = match (a.job, b.job) {
        (Some(x), Some(y)) => format!("{:+} KiB{}", kib(x, y), if b.job_is_peak { " (its peak)" } else { "" }),
        _ => "not read".to_string(),
    };
    format!(
        "the host's commit {:+} KiB, the job's {job}, the process's private commit {:+} KiB, working set {:+} KiB",
        kib(a.host_commit, b.host_commit),
        kib(a.private, b.private),
        kib(a.working_set, b.working_set)
    )
}

/// A pagefile-backed section of `len` bytes, `SEC_COMMIT` or `SEC_RESERVE`.
fn pagefile_section(len: usize, reserve: bool) -> HANDLE {
    // SAFETY: an unnamed section; checked.
    let s = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            core::ptr::null(),
            PAGE_READWRITE | if reserve { SEC_RESERVE } else { SEC_COMMIT },
            (len as u64 >> 32) as u32,
            len as u32,
            core::ptr::null(),
        )
    };
    assert!(!s.is_null(), "CreateFileMappingW: {}", std::io::Error::last_os_error());
    s
}

fn view(section: HANDLE, len: usize) -> usize {
    // SAFETY: maps the section anywhere; checked.
    let v = unsafe { MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, len) }.Value as usize;
    assert_ne!(v, 0, "MapViewOfFile: {}", std::io::Error::last_os_error());
    v
}

fn unmap(at: usize) {
    // SAFETY: a view this file mapped.
    unsafe { UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: at as *mut c_void }) };
}

fn write_pages(at: usize, len: usize, byte: impl Fn(usize) -> u8) {
    for i in 0..len / PAGE {
        // SAFETY: a page of a view this file mapped read-write.
        unsafe { ((at + i * PAGE) as *mut u8).write_volatile(byte(i)) };
    }
}

/// The state of the first region at `at` (`VirtualQuery`): committed or
/// reserved, and how far.
fn state(at: usize) -> String {
    // SAFETY: plain data, and a query of this process's memory.
    let mut m: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { VirtualQuery(at as *const c_void, &mut m, core::mem::size_of_val(&m)) } == 0 {
        return "not queried".to_string();
    }
    let kind = match m.State {
        MEM_COMMIT => "committed",
        MEM_RESERVE => "reserved",
        _ => "free",
    };
    format!("{kind} for {} KiB", m.RegionSize / 1024)
}

/// A temporary file of `len` bytes deleted at its last close, as wick's
/// memfd, and a section of it.
fn memfd(len: usize) -> (std::fs::File, HANDLE) {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    static N: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!("wick-sectrec-{}-{}.tmp", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .attributes(0x100) // FILE_ATTRIBUTE_TEMPORARY
        .custom_flags(0x0400_0000) // FILE_FLAG_DELETE_ON_CLOSE
        .open(&path)
        .unwrap();
    file.set_len(len as u64).unwrap();
    // SAFETY: a section of the whole file; checked.
    let s = unsafe { CreateFileMappingW(file.as_raw_handle(), core::ptr::null(), PAGE_READWRITE, 0, 0, core::ptr::null()) };
    assert!(!s.is_null(), "CreateFileMappingW of a file: {}", std::io::Error::last_os_error());
    (file, s)
}

/// The no-access view [`opener`] opens a page at a time: its start, its
/// length, and the accesses it opened.
static NOACCESS_AT: AtomicUsize = AtomicUsize::new(0);
static NOACCESS_LEN: AtomicUsize = AtomicUsize::new(0);
static OPENED: AtomicU64 = AtomicU64::new(0);

/// Opens the page of an access violation in the no-access view
/// (read-write) and has the access run again; leaves any other exception
/// to the handlers after it.
unsafe extern "system" fn opener(info: *mut EXCEPTION_POINTERS) -> i32 {
    // SAFETY: the system passes a valid record.
    let r = unsafe { &*(*info).ExceptionRecord };
    if r.ExceptionCode != 0xC000_0005_u32 as i32 || r.NumberParameters < 2 {
        return 0;
    }
    let addr = r.ExceptionInformation[1];
    let (at, len) = (NOACCESS_AT.load(Ordering::Acquire), NOACCESS_LEN.load(Ordering::Acquire));
    if addr < at || addr >= at + len {
        return 0;
    }
    let mut old = 0;
    // SAFETY: a page of the test's own view.
    if unsafe { VirtualProtect((addr & !(PAGE - 1)) as *const c_void, PAGE, PAGE_READWRITE, &mut old) } == 0 {
        return 0;
    }
    OPENED.fetch_add(1, Ordering::Relaxed);
    -1 // EXCEPTION_CONTINUE_EXECUTION
}

/// Waits for the jailer's side's line on standard input.
fn wait_for_the_parent() -> String {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
    line.trim().to_string()
}

#[test]
#[ignore = "run by test_section_memory_and_a_charge_for_it_on_record in a job of its own"]
fn sectrec_child() {
    if std::env::var_os(CHILD).is_none() {
        return;
    }
    let say = |l: String| println!("{l}");
    assert_eq!(wait_for_the_parent(), "go");

    // a: pagefile-backed sections.
    let len = 64 * MIB;
    for reserve in [false, true] {
        let kind = if reserve { "SEC_RESERVE" } else { "SEC_COMMIT" };
        let c0 = charge();
        let s = pagefile_section(len, reserve);
        let c1 = charge();
        say(format!("SECTREC-a a {kind} pagefile-backed section of 64 MiB made: {}", delta(c0, c1)));
        let v = view(s, len);
        let w = view(s, len);
        let c2 = charge();
        say(format!("SECTREC-a {kind}: two views of it mapped: {}; the first view {}", delta(c1, c2), state(v)));
        let written = if reserve {
            // SAFETY: the first 16 MiB of our view.
            let p = unsafe { VirtualAlloc(v as *const c_void, 16 * MIB, MEM_COMMIT, PAGE_READWRITE) };
            let c3 = charge();
            say(format!(
                "SECTREC-a {kind}: 16 MiB of the first view committed (VirtualAlloc): {}, error {}; {}; the first view {}, \
                 the second view {}",
                if p.is_null() { "refused" } else { "done" },
                if p.is_null() { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { 0 },
                delta(c2, c3),
                state(v),
                state(w)
            ));
            16 * MIB
        } else {
            len
        };
        let c4 = charge();
        write_pages(v, written, |i| (i % 251) as u8 + 1);
        let c5 = charge();
        say(format!("SECTREC-a {kind}: {} MiB of it written through the first view: {}", written / MIB, delta(c4, c5)));
        if reserve {
            // A 4 KiB commit's time on a view, 1024 times.
            let mut t = Vec::with_capacity(1024);
            let mut refused = 0;
            for i in 0..1024 {
                let at = v + 16 * MIB + i * PAGE;
                let start = Instant::now();
                // SAFETY: a page of our view.
                let p = unsafe { VirtualAlloc(at as *const c_void, PAGE, MEM_COMMIT, PAGE_READWRITE) };
                t.push(us(start));
                refused += usize::from(p.is_null());
            }
            let c6 = charge();
            say(format!(
                "SECTREC-a {kind}: 1024 commits of 4 KiB on the view, one at a time: {} each, {refused} refused; {}",
                spread(&t),
                delta(c5, c6)
            ));
        }
        unmap(v);
        unmap(w);
        // SAFETY: our section.
        unsafe { CloseHandle(s) };
        let c7 = charge();
        say(format!("SECTREC-a {kind}: unmapped and closed: {} since it was made", delta(c0, c7)));
    }

    // b: charge pages.
    let reserved = 1usize << 31;
    // SAFETY: a reservation of our own, released below.
    let base = unsafe { VirtualAlloc(core::ptr::null(), reserved, MEM_RESERVE, PAGE_READWRITE) } as usize;
    assert_ne!(base, 0);
    let c0 = charge();
    let mut t = Vec::with_capacity(4096);
    for i in 0..4096 {
        let start = Instant::now();
        // SAFETY: a page of our reservation.
        let p = unsafe { VirtualAlloc((base + i * PAGE) as *const c_void, PAGE, MEM_COMMIT, PAGE_READWRITE) };
        t.push(us(start));
        assert!(!p.is_null());
    }
    let c1 = charge();
    say(format!(
        "SECTREC-b 4096 charge pages (committed one at a time, never touched): {} each; {}",
        spread(&t),
        delta(c0, c1)
    ));
    let mut at = base + 16 * MIB;
    let refusal = loop {
        if at + MIB > base + reserved {
            break None;
        }
        // SAFETY: as above.
        let p = unsafe { VirtualAlloc(at as *const c_void, MIB, MEM_COMMIT, PAGE_READWRITE) };
        if p.is_null() {
            break std::io::Error::last_os_error().raw_os_error();
        }
        at += MIB;
    };
    let c2 = charge();
    say(format!(
        "SECTREC-b charge pages committed a MiB at a time under the job's limit of {} MiB: refused at {} MiB of them with error \
         {refusal:?} (1455 ERROR_COMMITMENT_LIMIT is the job's limit, as private memory's); the process's private commit then \
         {} MiB, the job's {}",
        JOB_LIMIT / MIB,
        (at - base) / MIB,
        c2.private / MIB,
        c2.job.map_or("not read".to_string(), |j| format!("{} MiB", j / MIB))
    ));
    // SAFETY: our reservation.
    unsafe { VirtualFree(base as *mut c_void, 0, MEM_RELEASE) };

    // c: a memfd's view mapped no-access, opened a page at a time.
    let len = 16 * MIB;
    let (file, s) = memfd(len);
    let c0 = charge();
    let a = view(s, len);
    let b = view(s, len);
    let mut old = 0;
    // SAFETY: our view.
    let protected = unsafe { VirtualProtect(a as *const c_void, len, PAGE_NOACCESS, &mut old) } != 0;
    NOACCESS_AT.store(a, Ordering::Release);
    NOACCESS_LEN.store(len, Ordering::Release);
    // SAFETY: a handler that only opens the test's view; removed below.
    let handler = unsafe { AddVectoredExceptionHandler(1, Some(opener)) };
    assert!(!handler.is_null());
    let start = Instant::now();
    write_pages(a, len, |i| (i % 251) as u8 + 1);
    let took = us(start);
    let c1 = charge();
    let opened = OPENED.swap(0, Ordering::Relaxed);
    let seen = (0..len / PAGE)
        // SAFETY: a page of our other view, read-write.
        .filter(|&i| unsafe { ((b + i * PAGE) as *const u8).read_volatile() } == (i % 251) as u8 + 1)
        .count();
    say(format!(
        "SECTREC-c a memfd (a temporary file deleted on close) of 16 MiB, a view of it no-access ({}) and opened a page at a \
         time at its first access: 4096 writes {:.2} us each, {opened} pages opened; the other view sees {seen} of the 4096 \
         writes; {}",
        if protected { "VirtualProtect done" } else { "VirtualProtect refused" },
        took / 4096.0,
        delta(c0, c1)
    ));
    // The open alone: the view made no-access again, 1024 pages opened by
    // VirtualProtect with no access.
    // SAFETY: our view.
    unsafe { VirtualProtect(a as *const c_void, len, PAGE_NOACCESS, &mut old) };
    let mut t = Vec::with_capacity(1024);
    for i in 0..1024 {
        let start = Instant::now();
        // SAFETY: a page of our view.
        unsafe { VirtualProtect((a + i * PAGE) as *const c_void, PAGE, PAGE_READWRITE, &mut old) };
        t.push(us(start));
    }
    say(format!("SECTREC-c the open alone, VirtualProtect of a page of the view to read-write: {} each", spread(&t)));
    // The jailer's side maps the section through a handle it duplicates,
    // reads what was written, and writes page 2000's second byte, which
    // this process then reads through the no-access view.
    say(format!("SECTREC-SECTION {} {len}", s as usize));
    let answer = wait_for_the_parent();
    let opened_before = OPENED.load(Ordering::Relaxed);
    // SAFETY: page 2000 of our no-access view (opened by the handler) and of the other.
    let (through_a, through_b) = unsafe { (((a + 2000 * PAGE + 1) as *const u8).read_volatile(), ((b + 2000 * PAGE + 1) as *const u8).read_volatile()) };
    say(format!(
        "SECTREC-c the jailer's side said \"{answer}\"; its write of 0x5a to page 2000 read here: {through_a:#x} through the \
         view opened at the access ({} opened), {through_b:#x} through the other",
        OPENED.load(Ordering::Relaxed) - opened_before
    ));
    // SAFETY: our handler.
    unsafe { RemoveVectoredExceptionHandler(handler) };
    NOACCESS_LEN.store(0, Ordering::Release);
    unmap(a);
    unmap(b);
    // SAFETY: our section.
    unsafe { CloseHandle(s) };
    drop(file);

    // e: how fast a process takes section memory: what the jailer's poll
    // could miss between two polls.
    for size in [1usize << 30, 4 << 30] {
        let c0 = charge();
        let start = Instant::now();
        // SAFETY: an unnamed section; closed below.
        let s = unsafe {
            CreateFileMappingW(INVALID_HANDLE_VALUE, core::ptr::null(), PAGE_READWRITE | SEC_COMMIT, (size as u64 >> 32) as u32, size as u32, core::ptr::null())
        };
        let took = us(start);
        let c1 = charge();
        say(format!(
            "SECTREC-e a SEC_COMMIT section of {} GiB made in {took:.1} us: {}; {}",
            size >> 30,
            if s.is_null() { format!("refused, error {}", std::io::Error::last_os_error().raw_os_error().unwrap_or(0)) } else { "made".to_string() },
            delta(c0, c1)
        ));
        if !s.is_null() {
            // SAFETY: ours.
            unsafe { CloseHandle(s) };
        }
    }
    let s = pagefile_section(1 << 30, true);
    let v = view(s, 1 << 30);
    let start = Instant::now();
    // SAFETY: the first 256 MiB of our view.
    let p = unsafe { VirtualAlloc(v as *const c_void, 256 * MIB, MEM_COMMIT, PAGE_READWRITE) };
    let took = us(start);
    let start = Instant::now();
    if !p.is_null() {
        write_pages(v, 256 * MIB, |_| 1);
    }
    let wrote = us(start);
    say(format!(
        "SECTREC-e a SEC_RESERVE section's view: 256 MiB committed in one VirtualAlloc in {took:.1} us ({}); its 65536 pages \
         then written in {:.1} ms, {:.0} MiB a second, {:.0} MiB in a millisecond",
        if p.is_null() { "refused" } else { "done" },
        wrote / 1000.0,
        256.0 / (wrote / 1e6),
        256.0 / (wrote / 1000.0)
    ));
    unmap(v);
    // SAFETY: ours.
    unsafe { CloseHandle(s) };

    // e: SharedCommitUsage, whether a section's commit is charged to the
    // process that made it, held it, or mapped it.
    let me = unsafe { GetCurrentProcess() };
    let shared = || shared_commit(me).map_or("not read (the structure's size refused)".to_string(), |v| format!("{} KiB", v / 1024));
    say(format!("SECTREC-e shared: this process's SharedCommitUsage at the start {}", shared()));
    let s = pagefile_section(1 << 30, false);
    say(format!("SECTREC-e shared: a SEC_COMMIT section of 1 GiB made: {}", shared()));
    let v = view(s, 1 << 30);
    say(format!("SECTREC-e shared: mapped: {}", shared()));
    // SAFETY: ours; the view stays.
    unsafe { CloseHandle(s) };
    say(format!("SECTREC-e shared: its handle closed, the view kept: {}", shared()));
    unmap(v);
    say(format!("SECTREC-e shared: unmapped (the section gone): {}", shared()));
    let s = pagefile_section(256 * MIB, true);
    let v = view(s, 256 * MIB);
    say(format!("SECTREC-e shared: a SEC_RESERVE section of 256 MiB made and mapped: {}", shared()));
    // SAFETY: the first 64 MiB of our view.
    let p = unsafe { VirtualAlloc(v as *const c_void, 64 * MIB, MEM_COMMIT, PAGE_READWRITE) };
    say(format!("SECTREC-e shared: 64 MiB of it committed on the view ({}): {}", if p.is_null() { "refused" } else { "done" }, shared()));
    unmap(v);
    // SAFETY: ours.
    unsafe { CloseHandle(s) };
    say(format!("SECTREC-e shared: unmapped and closed: {}", shared()));
    // A section made here whose handle the jailer's side duplicates and
    // holds while this process closes its own.
    let s = pagefile_section(1 << 30, false);
    say(format!("SECTREC-e shared: a second SEC_COMMIT section of 1 GiB made: {}", shared()));
    say(format!("SECTREC-SHARED {}", s as usize));
    assert_eq!(wait_for_the_parent(), "held");
    // SAFETY: ours; the jailer's side holds its own.
    unsafe { CloseHandle(s) };
    say(format!("SECTREC-e shared: its handle closed here, the jailer's side holding a duplicate: {}", shared()));
    say("SECTREC-SHARED-CLOSED".to_string());
    assert_eq!(wait_for_the_parent(), "released");
    say(format!("SECTREC-e shared: the jailer's side's duplicate closed: {}", shared()));

    // d: a jail as Firecracker's with vhost-user and a uffd restore.
    const GUEST: usize = 1 << 30;
    const TOUCHED: usize = 64 * MIB;
    // SAFETY: a reservation of our own, released at the end.
    let ram = unsafe { VirtualAlloc(core::ptr::null(), GUEST, MEM_RESERVE, PAGE_READWRITE) } as usize;
    // SAFETY: its first 64 MiB.
    assert!(!unsafe { VirtualAlloc(ram as *const c_void, TOUCHED, MEM_COMMIT, PAGE_READWRITE) }.is_null());
    write_pages(ram, TOUCHED, |_| 1);
    let (memfd_file, memfd_section) = memfd(GUEST);
    let memfd_view = view(memfd_section, GUEST);
    write_pages(memfd_view, TOUCHED, |_| 2);
    let alias = pagefile_section(GUEST, false);
    let (guest_view, alias_view) = (view(alias, GUEST), view(alias, GUEST));
    write_pages(alias_view, TOUCHED, |_| 3);
    let eventfds: Vec<(HANDLE, usize)> = (0..40)
        .map(|_| {
            let s = pagefile_section(PAGE, false);
            let v = view(s, PAGE);
            write_pages(v, PAGE, |_| 4);
            (s, v)
        })
        .collect();
    let hidden = pagefile_section(TOUCHED, false);
    let hidden_view = view(hidden, TOUCHED);
    write_pages(hidden_view, TOUCHED, |_| 5);
    // SAFETY: the handle; its view stays.
    unsafe { CloseHandle(hidden) };
    say(format!(
        "SECTREC-JAIL made: private guest RAM 1 GiB reserved, 64 MiB written; a memfd of 1 GiB, one view, 64 MiB written; a \
         pagefile section of 1 GiB (SEC_COMMIT), two views (the guest's and a uffd alias), 64 MiB written; 40 eventfd \
         sections of 4 KiB, each mapped and written; a pagefile section of 64 MiB (SEC_COMMIT), mapped, written, its handle \
         closed. Sections' memory in truth: commit {} MiB (the two pagefile sections and the eventfds'), the memfd's 64 MiB \
         resident in its file's pages",
        (GUEST + TOUCHED + 40 * PAGE) / MIB
    ));
    assert_eq!(wait_for_the_parent(), "done");
    for (s, v) in eventfds {
        unmap(v);
        // SAFETY: our section.
        unsafe { CloseHandle(s) };
    }
    for v in [memfd_view, guest_view, alias_view, hidden_view] {
        unmap(v);
    }
    // SAFETY: our sections and reservation.
    unsafe {
        CloseHandle(memfd_section);
        CloseHandle(alias);
        VirtualFree(ram as *mut c_void, 0, MEM_RELEASE);
    }
    drop(memfd_file);
    // e: the pagefile quota (QUOTA_LIMITS.PagefileLimit), whether the
    // jailer's side or this process can set it, and whether a section's
    // creation is then refused at it.
    say(format!("SECTREC-e quota: this process's QUOTA_LIMITS {:?}; private commit {} MiB", quota_limits(me), charge().private / MIB));
    let limit = charge().private + 64 * MIB;
    say(format!("SECTREC-QUOTA {limit}"));
    let answer = wait_for_the_parent();
    let own = set_pagefile_limit(me, limit);
    say(format!(
        "SECTREC-e quota: the jailer's side's set of a pagefile limit of {} MiB: {answer}; this process's own set: NTSTATUS {own:#010x}; \
         its QUOTA_LIMITS now {:?}",
        limit / MIB,
        quota_limits(me)
    ));
    // SAFETY: an unnamed section; closed below.
    let s = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, core::ptr::null(), PAGE_READWRITE | SEC_COMMIT, 0, 256 * MIB as u32, core::ptr::null()) };
    let section = if s.is_null() { format!("refused, error {}", std::io::Error::last_os_error().raw_os_error().unwrap_or(0)) } else { "made".to_string() };
    if !s.is_null() {
        // SAFETY: ours.
        unsafe { CloseHandle(s) };
    }
    // SAFETY: a private reservation, committed, released below.
    let p = unsafe { VirtualAlloc(core::ptr::null(), 128 * MIB, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
    let private = if p.is_null() { format!("refused, error {}", std::io::Error::last_os_error().raw_os_error().unwrap_or(0)) } else { "done".to_string() };
    if !p.is_null() {
        // SAFETY: ours.
        unsafe { VirtualFree(p, 0, MEM_RELEASE) };
    }
    say(format!(
        "SECTREC-e quota: past that limit, a SEC_COMMIT section of 256 MiB: {section}; 128 MiB of private memory committed: {private}"
    ));
    say("SECTREC-END".to_string());
}

/// Whether this process's token is elevated (`TokenElevation`).
fn elevated() -> Option<bool> {
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    let mut token: HANDLE = core::ptr::null_mut();
    // SAFETY: our own token, closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let mut is = 0u32;
    let mut n = 0u32;
    // SAFETY: a u32 TOKEN_ELEVATION of the size given.
    let ok = unsafe { GetTokenInformation(token, TokenElevation, (&raw mut is).cast(), 4, &mut n) } != 0;
    // SAFETY: as above.
    unsafe { CloseHandle(token) };
    ok.then_some(is != 0)
}

/// The child's handle list (`ProcessHandleInformation`).
fn handles_of(process: HANDLE) -> Vec<HandleEntry> {
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let mut got = 0u32;
        // SAFETY: a buffer of the size given.
        let status = unsafe { NtQueryInformationProcess(process, PROCESS_HANDLE_INFORMATION, buf.as_mut_ptr().cast(), buf.len() as u32, &mut got) };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            buf.resize((got as usize).max(buf.len() * 2), 0);
            continue;
        }
        if status < 0 {
            return Vec::new();
        }
        // SAFETY: the snapshot's header (two usize) then its entries.
        let n = unsafe { *buf.as_ptr().cast::<usize>() };
        let entries = buf[16..].as_ptr().cast::<HandleEntry>();
        // SAFETY: n entries follow the header.
        return (0..n).map(|i| unsafe { entries.add(i).read_unaligned() }).collect();
    }
}

/// A handle of the child's, duplicated into this process.
fn duplicated(process: HANDLE, handle: usize) -> Option<HANDLE> {
    let mut out: HANDLE = core::ptr::null_mut();
    // SAFETY: the child's handle value; ours is closed by the caller.
    let ok = unsafe { DuplicateHandle(process, handle as HANDLE, GetCurrentProcess(), &mut out, 0, 0, DUPLICATE_SAME_ACCESS) } != 0;
    ok.then_some(out)
}

/// The type name of an object (`ObjectTypeInformation`).
fn type_name(h: HANDLE) -> String {
    let mut buf = vec![0u64; 512];
    let mut got = 0u32;
    // SAFETY: a buffer of the size given.
    if unsafe { NtQueryObject(h, OBJECT_TYPE_INFORMATION, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut got) } < 0 {
        return String::new();
    }
    // SAFETY: OBJECT_TYPE_INFORMATION starts with its UNICODE_STRING name.
    let (len, ptr) = unsafe { (*buf.as_ptr().cast::<u16>(), *buf.as_ptr().add(1).cast::<*const u16>()) };
    // SAFETY: the name's characters, in the buffer.
    String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(ptr, usize::from(len) / 2) })
}

/// One poll's numbers and its parts' times.
#[derive(Default)]
struct Poll {
    handles: usize,
    sections: usize,
    distinct: usize,
    distinct_bytes: u64,
    views: usize,
    view_bytes: usize,
    view_committed: usize,
    resident: usize,
    times: [f64; 4],
}

fn poll(process: HANDLE, section_type: u32, resident: bool) -> Poll {
    let mut p = Poll::default();
    let t = Instant::now();
    let list = handles_of(process);
    p.times[0] = us(t);
    p.handles = list.len();
    let t = Instant::now();
    let mut kept: Vec<HANDLE> = Vec::new();
    for e in list.iter().filter(|e| e.type_index == section_type) {
        p.sections += 1;
        let Some(h) = duplicated(process, e.handle) else { continue };
        // SAFETY: two handles of ours.
        if kept.iter().any(|&k| unsafe { CompareObjectHandles(k, h) } != 0) {
            // SAFETY: ours.
            unsafe { CloseHandle(h) };
            continue;
        }
        let mut info = SectionBasicInformation::default();
        let mut got = 0usize;
        // SAFETY: a structure of the size given.
        if unsafe { NtQuerySection(h, SECTION_BASIC_INFORMATION, (&raw mut info).cast(), core::mem::size_of_val(&info), &mut got) } >= 0 {
            p.distinct_bytes += info.size as u64;
        }
        p.distinct += 1;
        kept.push(h);
    }
    for h in kept {
        // SAFETY: ours.
        unsafe { CloseHandle(h) };
    }
    p.times[1] = us(t);
    let t = Instant::now();
    let mut regions = Vec::new();
    let mut at = 0usize;
    let mut last_base = usize::MAX;
    loop {
        // SAFETY: plain data; a query of the child's memory.
        let mut m: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQueryEx(process, at as *const c_void, &mut m, core::mem::size_of_val(&m)) } == 0 {
            break;
        }
        if m.Type == MEM_MAPPED {
            if m.AllocationBase as usize != last_base {
                p.views += 1;
                last_base = m.AllocationBase as usize;
            }
            p.view_bytes += m.RegionSize;
            if m.State == MEM_COMMIT {
                p.view_committed += m.RegionSize;
                regions.push((m.BaseAddress as usize, m.RegionSize));
            }
        }
        at = m.BaseAddress as usize + m.RegionSize;
    }
    p.times[2] = us(t);
    if resident {
        let t = Instant::now();
        let mut entries: Vec<WorkingSetEntry> = Vec::new();
        for (base, len) in regions {
            entries.extend((0..len / PAGE).map(|i| WorkingSetEntry { address: base + i * PAGE, attributes: 0 }));
        }
        // SAFETY: entries with their addresses set, of the size given.
        let ok = unsafe { K32QueryWorkingSetEx(process, entries.as_mut_ptr().cast(), core::mem::size_of_val(entries.as_slice()) as u32) } != 0;
        if ok {
            p.resident = entries.iter().filter(|e| e.attributes & 1 != 0).count() * PAGE;
        }
        p.times[3] = us(t);
    }
    p
}

/// Whether this process is given the kernel's object addresses of the
/// child's handles (`SystemExtendedHandleInformation`): the child's
/// entries, and those with an address.
fn object_addresses(pid: usize) -> String {
    let mut buf = vec![0u8; 4 << 20];
    loop {
        let mut got = 0u32;
        // SAFETY: a buffer of the size given.
        let status = unsafe { NtQuerySystemInformation(SYSTEM_EXTENDED_HANDLE_INFORMATION, buf.as_mut_ptr().cast(), buf.len() as u32, &mut got) };
        if status == STATUS_INFO_LENGTH_MISMATCH && buf.len() < 512 << 20 {
            let len = (got as usize).max(buf.len() * 2);
            buf.resize(len, 0);
            continue;
        }
        if status < 0 {
            return format!("SystemExtendedHandleInformation refused: NTSTATUS {:#010x}", status as u32);
        }
        // SAFETY: the header (two usize) then its entries.
        let n = unsafe { *buf.as_ptr().cast::<usize>() };
        let entries = buf[16..].as_ptr().cast::<SystemHandleEntry>();
        let (mut mine, mut with) = (0, 0);
        for i in 0..n {
            // SAFETY: n entries follow the header.
            let e = unsafe { entries.add(i).read_unaligned() };
            if e.pid == pid {
                mine += 1;
                with += usize::from(e.object != 0);
            }
        }
        return format!("SystemExtendedHandleInformation: the child's {mine} handles, {with} of them with the object's address");
    }
}

/// SECTREC-e, the jailer's side: what each cheap sign of new section memory
/// costs a poll (the child's handle count, its virtual size, the host's
/// commit), 1000 times each, and what telling a view of a file from one of
/// the pagefile costs (`GetMappedFileNameW`, which names a file view's file
/// and fails for a pagefile-backed one), for each of the child's views.
fn triggers(process: HANDLE) -> String {
    const PROCESS_HANDLE_COUNT: u32 = 20;
    const PROCESS_VM_COUNTERS: u32 = 3;
    let timed = |f: &mut dyn FnMut() -> bool| {
        let mut t = Vec::with_capacity(1000);
        let mut failed = 0;
        for _ in 0..1000 {
            let start = Instant::now();
            failed += usize::from(!f());
            t.push(us(start));
        }
        format!("{}{}", spread(&t), if failed > 0 { format!(", {failed} failed") } else { String::new() })
    };
    let handles = timed(&mut || {
        let mut n = 0u32;
        // SAFETY: a u32 of the size given.
        unsafe { NtQueryInformationProcess(process, PROCESS_HANDLE_COUNT, (&raw mut n).cast(), 4, core::ptr::null_mut()) >= 0 }
    });
    let virtual_size = timed(&mut || {
        // VM_COUNTERS: PeakVirtualSize, VirtualSize, then the rest.
        let mut counters = [0usize; 16];
        // SAFETY: a buffer larger than VM_COUNTERS.
        unsafe { NtQueryInformationProcess(process, PROCESS_VM_COUNTERS, counters.as_mut_ptr().cast(), 88, core::ptr::null_mut()) >= 0 }
    });
    let host = timed(&mut || {
        let mut perf = PerformanceInformation { cb: core::mem::size_of::<PerformanceInformation>() as u32, ..Default::default() };
        // SAFETY: an output structure of the size given.
        unsafe { K32GetPerformanceInfo(&mut perf, perf.cb) != 0 }
    });
    let list = timed(&mut || !handles_of(process).is_empty());
    let shared = timed(&mut || shared_commit(process).is_some());
    let shared_now = shared_commit(process).map_or("not read".to_string(), |v| format!("{} MiB", v >> 20));
    // Each view's base, by a walk; then its file's name, or none.
    let mut views = Vec::new();
    let mut at = 0usize;
    let mut last = usize::MAX;
    loop {
        // SAFETY: plain data; a query of the child's memory.
        let mut m: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQueryEx(process, at as *const c_void, &mut m, core::mem::size_of_val(&m)) } == 0 {
            break;
        }
        if m.Type == MEM_MAPPED && m.AllocationBase as usize != last {
            last = m.AllocationBase as usize;
            views.push(last);
        }
        at = m.BaseAddress as usize + m.RegionSize;
    }
    let mut named = 0;
    let mut t = Vec::new();
    for &v in &views {
        let mut name = [0u16; 512];
        let start = Instant::now();
        // SAFETY: a buffer of the length given.
        let n = unsafe { K32GetMappedFileNameW(process, v as *const c_void, name.as_mut_ptr(), 512) };
        t.push(us(start));
        named += usize::from(n > 0);
    }
    format!(
        "SECTREC-e the jailer's cheap signs, 1000 times each: the child's handle count {handles}; its virtual size \
         (VM_COUNTERS) {virtual_size}; the host's commit (GetPerformanceInfo) {host}; the whole handle list {list}; its \
         SharedCommitUsage (PROCESS_MEMORY_COUNTERS_EX2) {shared}, {shared_now} with the jail made. \
         GetMappedFileNameW of each of the {} views: {}, {named} named a file (the rest pagefile-backed)",
        views.len(),
        spread(&t)
    )
}

/// The jailer's side: the child in a job, its lines relayed, the
/// cross-process step and the polls.
#[test]
#[ignore = "a record: run on Windows with --ignored --nocapture"]
fn test_section_memory_and_a_charge_for_it_on_record() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    };
    let exe = std::env::current_exe().unwrap();
    let mut child = std::process::Command::new(exe)
        .args(["--exact", "windows_sectrec::sectrec_child", "--ignored", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // SAFETY: a new unnamed job.
    let job = unsafe { CreateJobObjectW(core::ptr::null(), core::ptr::null()) };
    assert!(!job.is_null());
    // SAFETY: plain data.
    let mut limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { core::mem::zeroed() };
    limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY;
    limit.JobMemoryLimit = JOB_LIMIT;
    let process = child.as_raw_handle() as HANDLE;
    // SAFETY: a structure of the size given; the child's handle.
    unsafe {
        assert_ne!(SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&raw const limit).cast(), core::mem::size_of_val(&limit) as u32), 0);
        assert_ne!(AssignProcessToJobObject(job, process), 0, "{}", std::io::Error::last_os_error());
    }
    let mut to_child = child.stdin.take().unwrap();
    writeln!(to_child, "go").unwrap();
    let say = |l: String| eprintln!("{l}");
    let mut ended = false;
    let mut held: Option<HANDLE> = None;
    for line in std::io::BufReader::new(child.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        if let Some(rest) = line.strip_prefix("SECTREC-SECTION ") {
            let mut parts = rest.split(' ');
            let (handle, len) = (parts.next().unwrap().parse::<usize>().unwrap(), parts.next().unwrap().parse::<usize>().unwrap());
            let answer = match duplicated(process, handle) {
                None => format!("the section's handle not duplicated: {}", std::io::Error::last_os_error()),
                Some(h) => {
                    let v = view(h, len);
                    let seen = (0..len / PAGE)
                        // SAFETY: a page of our view of the child's section.
                        .filter(|&i| unsafe { ((v + i * PAGE) as *const u8).read_volatile() } == (i % 251) as u8 + 1)
                        .count();
                    // SAFETY: as above.
                    unsafe { ((v + 2000 * PAGE + 1) as *mut u8).write_volatile(0x5A) };
                    unmap(v);
                    // SAFETY: ours.
                    unsafe { CloseHandle(h) };
                    format!("another process's view of the section sees {seen} of the 4096 writes; it wrote page 2000")
                }
            };
            say(format!("SECTREC-c the jailer's side: {answer}"));
            writeln!(to_child, "{answer}").unwrap();
            continue;
        }
        if line.starts_with("SECTREC-JAIL ") {
            say(line.clone());
            let section_type = handles_of(process)
                .iter()
                .find_map(|e| {
                    let h = duplicated(process, e.handle)?;
                    let name = type_name(h);
                    // SAFETY: ours.
                    unsafe { CloseHandle(h) };
                    (name == "Section").then_some(e.type_index)
                })
                .unwrap_or(u32::MAX);
            say(format!(
                "SECTREC-d this process (the jailer's side) elevated: {:?}; {}",
                elevated(),
                object_addresses(child.id() as usize)
            ));
            for resident in [false, true] {
                let mut polls = Vec::new();
                for _ in 0..20 {
                    polls.push(poll(process, section_type, resident));
                }
                let part = |i: usize| spread(&polls.iter().map(|p| p.times[i]).collect::<Vec<_>>());
                let totals: Vec<f64> = polls.iter().map(|p| p.times.iter().sum()).collect();
                let mut sorted = totals.clone();
                sorted.sort_by(f64::total_cmp);
                let p = &polls[polls.len() - 1];
                say(format!(
                    "SECTREC-d a poll {} the resident pages, 20 times: the handle list {}; the sections' sizes {}; the views {}; \
                     the resident pages {}; the whole {}, {:.2} % of a CPU at a poll a millisecond",
                    if resident { "with" } else { "without" },
                    part(0),
                    part(1),
                    part(2),
                    if resident { part(3) } else { "not read".to_string() },
                    spread(&totals),
                    sorted[sorted.len() / 2] / 10.0
                ));
                say(format!(
                    "SECTREC-d what it counts: {} handles, {} of them sections, {} distinct by CompareObjectHandles, {} MiB of \
                     sections by their handles; {} views, {} MiB mapped, {} MiB of it committed{}",
                    p.handles,
                    p.sections,
                    p.distinct,
                    p.distinct_bytes >> 20,
                    p.views,
                    p.view_bytes / MIB,
                    p.view_committed / MIB,
                    if resident { format!(", {} MiB resident", p.resident / MIB) } else { String::new() }
                ));
            }
            say(triggers(process));
            writeln!(to_child, "done").unwrap();
            continue;
        }
        if let Some(rest) = line.strip_prefix("SECTREC-SHARED ") {
            let handle = rest.parse::<usize>().unwrap();
            let own = || shared_commit(unsafe { GetCurrentProcess() }).map_or("not read".to_string(), |v| format!("{} KiB", v / 1024));
            let before = own();
            held = duplicated(process, handle);
            say(format!(
                "SECTREC-e shared: the jailer's side duplicated the child's section handle ({}): its own SharedCommitUsage {before} \
                 before, {} after",
                if held.is_some() { "done" } else { "refused" },
                own()
            ));
            writeln!(to_child, "held").unwrap();
            continue;
        }
        if line == "SECTREC-SHARED-CLOSED" {
            let own = || shared_commit(unsafe { GetCurrentProcess() }).map_or("not read".to_string(), |v| format!("{} KiB", v / 1024));
            let child_now = shared_commit(process).map_or("not read".to_string(), |v| format!("{} KiB", v / 1024));
            let mine = own();
            if let Some(h) = held.take() {
                // SAFETY: ours.
                unsafe { CloseHandle(h) };
            }
            say(format!(
                "SECTREC-e shared: the child's own handle closed: the child's SharedCommitUsage read by the jailer's side \
                 {child_now}, the jailer's side's own {mine} while it held the duplicate, {} once it closed it",
                own()
            ));
            writeln!(to_child, "released").unwrap();
            continue;
        }
        if let Some(rest) = line.strip_prefix("SECTREC-QUOTA ") {
            let limit = rest.parse::<usize>().unwrap();
            let status = set_pagefile_limit(process, limit);
            let answer = format!("NTSTATUS {status:#010x}, the child's QUOTA_LIMITS read here {:?}", quota_limits(process));
            say(format!("SECTREC-e quota: the jailer's side (elevated {:?}) set the child's pagefile limit: {answer}", elevated()));
            writeln!(to_child, "{answer}").unwrap();
            continue;
        }
        if line == "SECTREC-END" {
            ended = true;
        }
        if line.starts_with("SECTREC") {
            say(line);
        }
    }
    let status = child.wait().unwrap();
    // SAFETY: our job handle.
    unsafe { CloseHandle(job) };
    assert!(ended && status.success(), "the child ended {status:?} before its end");
}

/// SECTREC-h, for S1's second part: the userfaultfd restore's section made
/// `SEC_RESERVE`, whose missing pages must stay inaccessible through the
/// guest's view until the handler has filled them through the alias (today
/// the section is `SEC_COMMIT` and the guest's view is made `PAGE_NOACCESS`
/// page by page, `windows_uffd`). Two views of a `SEC_RESERVE` section, A
/// (the guest's) and B (the alias), both mapped read-write. Printed, from
/// `VirtualQuery` (state and protection) and reads made only where the
/// page reads:
/// - a page committed through A with `PAGE_NOACCESS`: what A and B show;
///   B written, then A made read-write: what A reads;
/// - a page committed through B (read-write): what A shows, so whether a
///   fill through the alias opens the guest's view at once (a race: a
///   vCPU could read the page before the fill ends);
/// - a committed page decommitted through a view (`MEM_DECOMMIT`): the
///   result, for `MADV_DONTNEED` of registered memory;
/// - A's committed page made `PAGE_NOACCESS` again: what B shows.
#[test]
#[ignore = "a record: run on Windows with --ignored --nocapture"]
fn test_a_reserved_section_committed_through_one_view_on_record() {
    let say = |l: String| eprintln!("SECTREC-h {l}");
    let len = MIB;
    // SAFETY: a pagefile-backed SEC_RESERVE section of our own.
    let s = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, core::ptr::null(), PAGE_READWRITE | SEC_RESERVE, 0, len as u32, core::ptr::null()) };
    assert!(!s.is_null());
    // SAFETY: two views of it.
    let (a, b) = unsafe {
        (
            MapViewOfFile(s, FILE_MAP_ALL_ACCESS, 0, 0, len).Value as usize,
            MapViewOfFile(s, FILE_MAP_ALL_ACCESS, 0, 0, len).Value as usize,
        )
    };
    assert!(a != 0 && b != 0);
    let q = |at: usize| {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        unsafe { VirtualQuery(at as *const c_void, &mut mbi, core::mem::size_of_val(&mbi)) };
        (mbi.State, mbi.Protect)
    };
    let shows = |what: &str, at: usize| {
        let (state, protect) = q(at);
        format!("{what}: state {state:#x} ({}), protection {protect:#x}", if state == MEM_COMMIT { "committed" } else if state == MEM_RESERVE { "reserved" } else { "other" })
    };
    let readable = |at: usize| {
        let (state, protect) = q(at);
        state == MEM_COMMIT && matches!(protect, PAGE_READWRITE | 0x02 | 0x40 | 0x20)
    };
    let err = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

    // A page committed through A, no access.
    // SAFETY: commits a page of our view.
    let p = unsafe { VirtualAlloc(a as *const c_void, PAGE, MEM_COMMIT, PAGE_NOACCESS) };
    let e = err();
    say(format!(
        "page 0 committed through A with PAGE_NOACCESS: {}; {}; {}",
        if p.is_null() { format!("refused, error {e}") } else { "done".into() },
        shows("A", a),
        shows("B", b)
    ));
    if readable(b) {
        // SAFETY: B's page reads and writes (checked above).
        unsafe { *(b as *mut u8) = 0x5a };
        let mut old = 0;
        // SAFETY: our view's page.
        let ok = unsafe { VirtualProtect(a as *const c_void, PAGE, PAGE_READWRITE, &mut old) } != 0;
        let e = err();
        let read = if readable(a) {
            // SAFETY: A's page reads (checked).
            format!("{:#x}", unsafe { *(a as *const u8) })
        } else {
            "not readable".into()
        };
        say(format!(
            "B written 0x5a; A made read-write: {} (old {old:#x}); A reads {read}; {}",
            if ok { "done".into() } else { format!("refused, error {e}") },
            shows("A", a)
        ));
    } else {
        say("B's page does not read: not written".into());
    }

    // A page committed through B.
    // SAFETY: commits a page of our view.
    let p = unsafe { VirtualAlloc((b + PAGE) as *const c_void, PAGE, MEM_COMMIT, PAGE_READWRITE) };
    let e = err();
    say(format!(
        "page 1 committed through B with PAGE_READWRITE: {}; {}; {}",
        if p.is_null() { format!("refused, error {e}") } else { "done".into() },
        shows("A", a + PAGE),
        shows("B", b + PAGE)
    ));

    // Decommit through a view.
    // SAFETY: our view's committed page.
    let ok = unsafe { VirtualFree(a as *mut c_void, PAGE, 0x4000) } != 0;
    let e = err();
    say(format!(
        "page 0 decommitted through A (MEM_DECOMMIT): {}; {}; {}",
        if ok { "done".into() } else { format!("refused, error {e}") },
        shows("A", a),
        shows("B", b)
    ));

    // A's page made inaccessible again.
    let mut old = 0;
    // SAFETY: our view's page.
    let ok = unsafe { VirtualProtect((a + PAGE) as *const c_void, PAGE, PAGE_NOACCESS, &mut old) } != 0;
    let e = err();
    say(format!(
        "page 1 made PAGE_NOACCESS through A: {}; {}; {}",
        if ok { "done".into() } else { format!("refused, error {e}") },
        shows("A", a + PAGE),
        shows("B", b + PAGE)
    ));
    // SAFETY: our views and section.
    unsafe {
        UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: a as *mut c_void });
        UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: b as *mut c_void });
        CloseHandle(s);
    }
}

/// UFFDCHUNK (b) to (d), the host's side of the W2 plan's "Discarded
/// userfaultfd pages" (the guest's side, (a), is kvm-ioctls'
/// `test_a_replaced_backing_under_mapped_guest_ram_on_record`):
/// - c: a charge page's decommit: 2 MiB of private memory committed
///   `PAGE_NOACCESS` (512 charge pages), then one page decommitted
///   (`VirtualFree(MEM_DECOMMIT)`), then the other 511: each step's time
///   and what it moves of the process's private commit, the job's memory
///   and the host's commit, for part (1) of the plan;
/// - d: a SEC_RESERVE section of 2 MiB mapped twice (A, the guest's view;
///   B, the alias), committed through A with no access and written through
///   B, then `DiscardVirtualMemory` of B: its result and time, and the
///   section's pages in the working set (`QueryWorkingSetEx`) through each
///   view, with the host's commit, before and after;
/// - b: the price of part (2): 1 GiB made as one SEC_RESERVE section mapped
///   twice, against 512 sections of 2 MiB, each mapped into a placeholder
///   of the guest's run and of the alias's (`VirtualAlloc2`
///   `MEM_RESERVE_PLACEHOLDER`, split by `VirtualFree(MEM_RELEASE |
///   MEM_PRESERVE_PLACEHOLDER)`, `MapViewOfFile3(MEM_REPLACE_PLACEHOLDER)`)
///   with its handle closed: each one's time, and the host's commit, the
///   kernel's paged and nonpaged pool and this process's handle count it
///   moves; then 100 swaps of one chunk (both views back to placeholders
///   with `UnmapViewOfFile2(MEM_PRESERVE_PLACEHOLDER)`, a new section made
///   and mapped into both, its handle closed).
///
/// Run alone (its own process), as the readings are the whole process's.
/// Printed, not asserted, but for each step running.
#[test]
#[ignore = "a record: run on Windows with --ignored --nocapture"]
fn test_chunked_sections_and_a_charge_decommit_on_record() {
    use windows_sys::Win32::System::Memory::{
        DiscardVirtualMemory, MapViewOfFile3, UnmapViewOfFile2, VirtualAlloc2, MEM_DECOMMIT, MEM_PRESERVE_PLACEHOLDER,
        MEM_REPLACE_PLACEHOLDER, MEM_RESERVE_PLACEHOLDER,
    };
    use windows_sys::Win32::System::Threading::GetProcessHandleCount;
    let say = |l: String| eprintln!("UFFDCHUNK {l}");
    const CHUNK: usize = 2 * MIB;
    // SAFETY: plain call.
    let me = unsafe { GetCurrentProcess() };
    let err = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

    // c: the charge pages' decommit.
    // SAFETY: reserves and commits memory of our own.
    let charge_base = unsafe { VirtualAlloc(core::ptr::null(), CHUNK, MEM_RESERVE, PAGE_NOACCESS) } as usize;
    assert_ne!(charge_base, 0);
    let before = charge();
    // SAFETY: commits our reservation, no access.
    assert!(!unsafe { VirtualAlloc(charge_base as *const c_void, CHUNK, MEM_COMMIT, PAGE_NOACCESS) }.is_null());
    let committed = charge();
    let t = Instant::now();
    // SAFETY: decommits a page of our reservation.
    let one = unsafe { VirtualFree(charge_base as *mut c_void, PAGE, MEM_DECOMMIT) } != 0;
    let one_us = us(t);
    let after_one = charge();
    let t = Instant::now();
    // SAFETY: as above.
    let rest = unsafe { VirtualFree((charge_base + PAGE) as *mut c_void, CHUNK - PAGE, MEM_DECOMMIT) } != 0;
    let rest_us = us(t);
    let after_rest = charge();
    say(format!("c: 512 charge pages committed PAGE_NOACCESS: {}", delta(before, committed)));
    say(format!("c: one decommitted: {} in {one_us:.2} us: {}", if one { "done" } else { "refused" }, delta(committed, after_one)));
    say(format!("c: the other 511 decommitted in one call: {} in {rest_us:.2} us: {}", if rest { "done" } else { "refused" }, delta(after_one, after_rest)));
    // SAFETY: our reservation.
    unsafe { VirtualFree(charge_base as *mut c_void, 0, MEM_RELEASE) };

    // d: DiscardVirtualMemory through the alias.
    // SAFETY: a pagefile-backed SEC_RESERVE section of our own, mapped twice.
    let s = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, core::ptr::null(), PAGE_READWRITE | SEC_RESERVE, 0, CHUNK as u32, core::ptr::null()) };
    assert!(!s.is_null());
    // SAFETY: as above.
    let (a, b) = unsafe { (MapViewOfFile(s, FILE_MAP_ALL_ACCESS, 0, 0, CHUNK).Value as usize, MapViewOfFile(s, FILE_MAP_ALL_ACCESS, 0, 0, CHUNK).Value as usize) };
    assert!(a != 0 && b != 0);
    let resident = |base: usize| {
        let mut entries: Vec<WorkingSetEntry> = (0..CHUNK / PAGE).map(|i| WorkingSetEntry { address: base + i * PAGE, attributes: 0 }).collect();
        // SAFETY: entries with their addresses set, of the size given.
        let ok = unsafe { K32QueryWorkingSetEx(me, entries.as_mut_ptr().cast(), core::mem::size_of_val(entries.as_slice()) as u32) } != 0;
        if ok { format!("{} of 512", entries.iter().filter(|e| e.attributes & 1 != 0).count()) } else { "not read".into() }
    };
    let shared = || shared_commit(me).map_or_else(|| "not read".to_string(), |v| format!("{} KiB", v / 1024));
    // SAFETY: commits the section's pages through A, no access, and writes them through B.
    let ok = unsafe { !VirtualAlloc(a as *const c_void, CHUNK, MEM_COMMIT, PAGE_NOACCESS).is_null() };
    if ok {
        // SAFETY: B is read-write and the pages are committed.
        unsafe { core::ptr::write_bytes(b as *mut u8, 0x5a, CHUNK) };
    }
    let filled = charge();
    say(format!(
        "d: 2 MiB committed through A with no access ({}) and written through B: resident through A {}, through B {}; SharedCommitUsage {}",
        if ok { "done".to_string() } else { format!("refused, error {}", err()) },
        resident(a),
        resident(b),
        shared()
    ));
    let t = Instant::now();
    // SAFETY: discards the alias's pages, read-write.
    let r = unsafe { DiscardVirtualMemory(b as *mut c_void, CHUNK) };
    let discard_us = us(t);
    say(format!(
        "d: DiscardVirtualMemory of B: result {r} in {discard_us:.2} us; resident through A {}, through B {}; SharedCommitUsage {}; {}",
        resident(a),
        resident(b),
        shared(),
        delta(filled, charge())
    ));
    // SAFETY: our views and section.
    unsafe {
        UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: a as *mut c_void });
        UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: b as *mut c_void });
        CloseHandle(s);
    }

    // b: one section of 1 GiB against 512 of 2 MiB.
    const GIB: usize = 1 << 30;
    const CHUNKS: usize = GIB / CHUNK;
    let handles = || {
        let mut n = 0u32;
        // SAFETY: an output count.
        unsafe { GetProcessHandleCount(me, &mut n) };
        n
    };
    let pool = || {
        let mut perf = PerformanceInformation { cb: core::mem::size_of::<PerformanceInformation>() as u32, ..Default::default() };
        // SAFETY: an output structure of the size given.
        unsafe { K32GetPerformanceInfo(&mut perf, perf.cb) };
        (perf.commit_total * perf.page_size, perf.kernel_paged * perf.page_size, perf.kernel_nonpaged * perf.page_size)
    };
    let moved = |x: (usize, usize, usize), y: (usize, usize, usize), hx: u32, hy: u32| {
        let kib = |p: usize, q: usize| (q as i64 - p as i64) / 1024;
        format!(
            "the host's commit {:+} KiB, paged pool {:+} KiB, nonpaged pool {:+} KiB, handles {:+}",
            kib(x.0, y.0),
            kib(x.1, y.1),
            kib(x.2, y.2),
            i64::from(hy) - i64::from(hx)
        )
    };
    let (p0, h0) = (pool(), handles());
    let t = Instant::now();
    // SAFETY: a section of our own, mapped twice.
    let s = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, core::ptr::null(), PAGE_READWRITE | SEC_RESERVE, 0, GIB as u32, core::ptr::null()) };
    assert!(!s.is_null());
    // SAFETY: as above.
    let (a, b) = unsafe { (MapViewOfFile(s, FILE_MAP_ALL_ACCESS, 0, 0, GIB).Value as usize, MapViewOfFile(s, FILE_MAP_ALL_ACCESS, 0, 0, GIB).Value as usize) };
    // SAFETY: our handle; the views keep the section.
    unsafe { CloseHandle(s) };
    let one_section = us(t);
    let (p1, h1) = (pool(), handles());
    say(format!("b: 1 GiB as one SEC_RESERVE section, mapped twice, its handle closed: {one_section:.1} us; {}", moved(p0, p1, h0, h1)));
    // SAFETY: our views.
    unsafe {
        UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: a as *mut c_void });
        UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: b as *mut c_void });
    }
    let (p0, h0) = (pool(), handles());
    let t = Instant::now();
    let placeholder = || {
        // SAFETY: reserves a placeholder of our own.
        let p = unsafe { VirtualAlloc2(me, core::ptr::null(), GIB, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, core::ptr::null_mut(), 0) } as usize;
        assert_ne!(p, 0, "error {}", err());
        for i in 0..CHUNKS - 1 {
            // SAFETY: splits our placeholder at the chunk's end.
            assert_ne!(unsafe { VirtualFree((p + i * CHUNK) as *mut c_void, CHUNK, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) }, 0, "split {i}: error {}", err());
        }
        p
    };
    let (guest, alias) = (placeholder(), placeholder());
    let split = us(t);
    let map_chunk = |i: usize| {
        // SAFETY: a section of our own, mapped into our placeholders.
        unsafe {
            let s = CreateFileMappingW(INVALID_HANDLE_VALUE, core::ptr::null(), PAGE_READWRITE | SEC_RESERVE, 0, CHUNK as u32, core::ptr::null());
            assert!(!s.is_null());
            for base in [guest, alias] {
                let at = base + i * CHUNK;
                let v = MapViewOfFile3(s, me, at as *const c_void, 0, CHUNK, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, core::ptr::null_mut(), 0);
                assert_eq!(v.Value as usize, at, "chunk {i}: error {}", err());
            }
            CloseHandle(s);
        }
    };
    let t = Instant::now();
    for i in 0..CHUNKS {
        map_chunk(i);
    }
    let mapped = us(t);
    let (p1, h1) = (pool(), handles());
    say(format!(
        "b: 1 GiB as {CHUNKS} sections of 2 MiB: two placeholders of 1 GiB split into {CHUNKS} each in {split:.1} us; the sections \
         made and mapped into both, their handles closed, in {mapped:.1} us ({:.2} us a chunk); {}",
        mapped / CHUNKS as f64,
        moved(p0, p1, h0, h1)
    ));
    // A chunk written through the guest's run reads through the alias's.
    // SAFETY: commits the first chunk through the guest's view and writes it.
    let ok = unsafe { !VirtualAlloc(guest as *const c_void, CHUNK, MEM_COMMIT, PAGE_READWRITE).is_null() };
    if ok {
        // SAFETY: committed above.
        unsafe { *(guest as *mut u8) = 0x77 };
    }
    // SAFETY: the alias's view of the same section, committed through the guest's.
    let read = if ok { format!("{:#x}", unsafe { *(alias as *const u8) }) } else { format!("not committed, error {}", err()) };
    say(format!("b: chunk 0 committed and written 0x77 through the guest's run: the alias's run reads {read}"));
    let mut swaps = Vec::new();
    for _ in 0..100 {
        let t = Instant::now();
        for base in [guest, alias] {
            // SAFETY: our view, back to its placeholder.
            assert_ne!(unsafe { UnmapViewOfFile2(me, MEMORY_MAPPED_VIEW_ADDRESS { Value: base as *mut c_void }, MEM_PRESERVE_PLACEHOLDER) }, 0, "error {}", err());
        }
        map_chunk(0);
        swaps.push(us(t));
    }
    let q = || {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        unsafe { VirtualQuery(guest as *const c_void, &mut mbi, core::mem::size_of_val(&mbi)) };
        mbi.State
    };
    say(format!(
        "b: 100 swaps of chunk 0 (both views back to placeholders, a new section mapped into both, its handle closed): {}; \
         chunk 0 after: {}",
        spread(&swaps),
        if q() == MEM_COMMIT { "committed (the old section's page?)" } else { "reserved, as a new section's" }
    ));
    let (p2, h2) = (pool(), handles());
    say(format!("b: after the swaps, against the chunks just mapped: {}", moved(p1, p2, h1, h2)));
    for base in [guest, alias] {
        for i in 0..CHUNKS {
            // SAFETY: our views; their address space is released.
            unsafe { UnmapViewOfFile2(me, MEMORY_MAPPED_VIEW_ADDRESS { Value: (base + i * CHUNK) as *mut c_void }, 0) };
        }
    }
}
