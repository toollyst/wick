// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `memory.max` for the memory a Job Object does not charge: the jailer's
//! count of the jail's section commit (SECURITY.md, "Windows jailer:
//! `memory.max` bounds memory in sections at the jailer's next count").
//!
//! The job's memory limit charges private commit only. A pagefile-backed
//! section's commit is charged to no job and no quota: a jailed process under
//! a job limit of 32 MiB maps and writes 256 MiB of sections
//! (`jailer-test.ps1 sections`; SECTREC-a and SECTREC-e,
//! `test_section_memory_and_a_charge_for_it_on_record` in crates/compat/libc).
//! Wick charges the sections it makes itself a page of private commit per
//! touched page (crates/compat/libc, `windows_mm`, `Charge`), so the job
//! refuses them; a compromised Firecracker makes sections around wick. So
//! the jailer counts them, and ends the jail as the memory cgroup's OOM kill
//! ends a cgroup's process, with 137:
//!
//! - **The count**, every millisecond (a high-resolution waitable timer):
//!   over the job's processes (`JobObjectBasicProcessIdList`), private commit
//!   plus section commit (`PROCESS_MEMORY_COUNTERS_EX2`: `PrivateUsage`,
//!   `SharedCommitUsage`, "the current shared commit usage", Microsoft Learn),
//!   less what pays for section commit already. `SharedCommitUsage` follows
//!   whoever holds a handle or a view of the section: charged at the
//!   section's creation, kept while a handle or a view keeps it, gone with it
//!   (SECTREC-e shared, PC b4717ec). Neither a closed handle nor a second
//!   view hides one or counts one twice.
//! - **Wick's charge pages** are committed `PAGE_NOACCESS` private memory
//!   (commit and no memory), counted in `PrivateUsage`; the section page each
//!   pays for is in `SharedCommitUsage` as well. So committed, private,
//!   `PAGE_NOACCESS` regions (the *cover*, read with `VirtualQueryEx`) are
//!   taken off the section commit, no more than it, per process. A process
//!   can only claim cover it has paid for in the job's private commit and
//!   cannot use, so the count holds memory a process can use (private commit
//!   that is not cover, and section commit) to `memory.max`, and host commit
//!   to twice it (the cover and the section commit it covers).
//! - **The cover is read** at a process's first poll, every 100 ms, whenever
//!   a process's private commit falls below what it was at its last read (a
//!   charge page given back, or a region freed), and once more before any
//!   kill, so that no jail is ended on a cover read before new charge pages
//!   were committed.
//! - **Large pages** the jailer gave (`large_pages`, bounded by the jail's
//!   `hugetlb.2MB.max`, as hugetlb pages are not charged to `memory.max` on
//!   Linux) are taken off the section commit that the cover leaves, up to the
//!   bytes given.
//! - **The kill**: `TerminateJobObject` with 137, the line below on the
//!   jailer's standard error naming the count, its parts and the poll before.
//! - **A process of the job that the jailer cannot open or read** ends the
//!   jail the same way: the count cannot be taken, so the jail does not run
//!   uncounted.
//!
//! What remains, against Linux (memcontrol.c, `try_charge_memcg`, charges
//! each page before it is mapped): a time window. Between two polls a
//! jailed process can take host commit beyond `memory.max` (a 4 GiB section
//! in 27.8 us, SECTREC-e c) and is ended at the next poll, about 1 ms (the timer's median interval,
//! `test_the_poll_timer_ticks_about_every_millisecond`, COMMITTIMER). A
//! process that swaps its cover for usable private commit between two reads
//! of the cover holds up to twice `memory.max` of usable memory until the
//! next read, within 100 ms. Windows tells no user-mode process of a
//! section's creation (`ObRegisterCallbacks` takes process, thread and
//! desktop handles only: Learn, `OB_OPERATION_REGISTRATION`).
//!
//! Hosts without `SharedCommitUsage` (Learn: Windows 10 22H2 or Windows 11
//! 22H2, each with the September 2023 cumulative update, and later; no server
//! is listed): `memory.max` is refused when the jailer reads it
//! (`cgroup`, [`sections_counted`]), before any jail is made, as a limit the
//! jailer cannot enforce. The count is proved on the host ([`self_check`]),
//! not inferred from its build.

use std::collections::HashMap;
use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, STILL_ACTIVE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JOBOBJECT_BASIC_PROCESS_ID_LIST, JobObjectBasicProcessIdList, QueryInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, CreateWaitableTimerExW, GetCurrentProcess, GetExitCodeProcess, INFINITE,
    OpenProcess, PROCESS_QUERY_INFORMATION, SetWaitableTimer, TIMER_ALL_ACCESS, TerminateProcess, WaitForMultipleObjects,
};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn K32GetProcessMemoryInfo(process: HANDLE, counters: *mut Counters, cb: u32) -> i32;
    fn VirtualQueryEx(process: HANDLE, address: *const c_void, info: *mut Region, len: usize) -> usize;
    fn CreateFileMappingW(
        file: HANDLE,
        attributes: *const SECURITY_ATTRIBUTES,
        protect: u32,
        high: u32,
        low: u32,
        name: *const u16,
    ) -> HANDLE;
}

/// The exit code of a jail ended at its memory limit: 128 + SIGKILL, as a
/// shell reports a process the OOM killer ended.
pub(super) const KILLED: u32 = 137;
/// How often the count is taken.
const POLL: Duration = Duration::from_millis(1);
/// How often the cover is read whatever the counts say.
const WALK: Duration = Duration::from_millis(100);

const MEM_COMMIT: u32 = 0x1000;
const MEM_PRIVATE: u32 = 0x2_0000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READWRITE: u32 = 0x04;
const SEC_COMMIT: u32 = 0x0800_0000;

/// `PROCESS_MEMORY_COUNTERS_EX2` (psapi.h): `sizes` from
/// `PeakWorkingSetSize` to `PrivateWorkingSetSize`, `PrivateUsage` at 8.
#[repr(C)]
#[derive(Default)]
struct Counters {
    cb: u32,
    page_faults: u32,
    sizes: [usize; 10],
    shared_commit: u64,
}

/// `MEMORY_BASIC_INFORMATION` (winnt.h, 64-bit).
#[repr(C)]
#[derive(Default)]
struct Region {
    base: usize,
    allocation_base: usize,
    allocation_protect: u32,
    partition_id: u16,
    size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}

/// A process's private commit and section commit, or none if they cannot be
/// read (a host without `PROCESS_MEMORY_COUNTERS_EX2` refuses its size).
fn counters(process: HANDLE) -> Option<(u64, u64)> {
    let mut c = Counters { cb: u32::try_from(std::mem::size_of::<Counters>()).unwrap(), ..Counters::default() };
    // SAFETY: a structure of the size given.
    (unsafe { K32GetProcessMemoryInfo(process, &raw mut c, c.cb) } != 0).then_some((c.sizes[8] as u64, c.shared_commit))
}

/// A process's committed, private, `PAGE_NOACCESS` bytes: the commit that
/// pays for section pages (wick's charge pages) and can pay for nothing else.
fn cover(process: HANDLE) -> u64 {
    let mut at = 0usize;
    let mut sum = 0u64;
    loop {
        let mut r = Region::default();
        // SAFETY: a structure of the size given; any address may be asked
        // about (past the last one the call fails).
        if unsafe { VirtualQueryEx(process, at as *const c_void, &raw mut r, std::mem::size_of::<Region>()) } == 0 {
            return sum;
        }
        if r.state == MEM_COMMIT && r.kind == MEM_PRIVATE && r.protect == PAGE_NOACCESS {
            sum += r.size as u64;
        }
        match r.base.checked_add(r.size) {
            Some(next) if next > at => at = next,
            _ => return sum,
        }
    }
}

/// The ids of the job's processes.
fn pids(job: HANDLE) -> Result<Vec<u32>, String> {
    let mut room = 16usize;
    loop {
        // The list's two counts take the first word, the ids one word each.
        let mut buf = vec![0usize; 1 + room];
        let len = u32::try_from(std::mem::size_of_val(buf.as_slice())).unwrap();
        // SAFETY: a buffer of the size given, for this class.
        let ok = unsafe {
            QueryInformationJobObject(job, JobObjectBasicProcessIdList, buf.as_mut_ptr().cast(), len, std::ptr::null_mut())
        };
        // SAFETY: the buffer begins with the list's header.
        let head = unsafe { &*buf.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
        let (assigned, listed) = (head.NumberOfAssignedProcesses as usize, head.NumberOfProcessIdsInList as usize);
        // SAFETY: plain call.
        if ok == 0 && unsafe { GetLastError() } != ERROR_MORE_DATA {
            return Err(format!("the job's processes cannot be listed: {}", io::Error::last_os_error()));
        }
        if ok != 0 && listed >= assigned {
            return Ok(buf[1..=listed].iter().map(|&id| u32::try_from(id).unwrap_or(u32::MAX)).collect());
        }
        room = assigned.max(room * 2);
    }
}

/// The process `pid` of the job, opened to be counted; none if it has ended
/// (its id may be another process's by now).
fn open(pid: u32, job: HANDLE) -> Result<Option<OwnedHandle>, String> {
    // SAFETY: plain call.
    let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
    if h.is_null() {
        // SAFETY: plain call.
        let e = unsafe { GetLastError() };
        if e == ERROR_INVALID_PARAMETER {
            return Ok(None);
        }
        return Err(format!(
            "process {pid} of the jail cannot be opened to be counted: {}",
            io::Error::from_raw_os_error(e.cast_signed())
        ));
    }
    // SAFETY: a handle we own.
    let h = unsafe { OwnedHandle::from_raw_handle(h) };
    let mut inside = 0;
    // SAFETY: handles we hold, an out-parameter.
    if unsafe { IsProcessInJob(h.as_raw_handle(), job, &mut inside) } == 0 {
        return Err(format!("process {pid} of the jail: IsProcessInJob: {}", io::Error::last_os_error()));
    }
    Ok((inside != 0).then_some(h))
}

fn ended(process: HANDLE) -> bool {
    let mut code = 0u32;
    // SAFETY: a process handle we hold.
    unsafe { GetExitCodeProcess(process, &mut code) != 0 && code != STILL_ACTIVE.cast_unsigned() }
}

/// Proves the count on this host: a 1 MiB pagefile-backed section made here
/// moves this process's `SharedCommitUsage` by its size at least.
pub(super) fn self_check() -> Result<(), String> {
    // SAFETY: the pseudo-handle of this process.
    let me = unsafe { GetCurrentProcess() };
    let size = 1u64 << 20;
    let Some((_, before)) = counters(me) else {
        return Err(format!("GetProcessMemoryInfo refuses PROCESS_MEMORY_COUNTERS_EX2: {}", io::Error::last_os_error()));
    };
    // SAFETY: a new pagefile-backed section, no name.
    let s = unsafe {
        CreateFileMappingW(INVALID_HANDLE_VALUE, std::ptr::null(), PAGE_READWRITE | SEC_COMMIT, 0, 1 << 20, std::ptr::null())
    };
    if s.is_null() {
        return Err(format!("a 1 MiB section for the check: {}", io::Error::last_os_error()));
    }
    // SAFETY: the section just made, ours.
    let s = unsafe { OwnedHandle::from_raw_handle(s) };
    let after = counters(me).map_or(0, |(_, shared)| shared);
    drop(s);
    if after < before + size {
        return Err(format!(
            "SharedCommitUsage moved from {before} to {after} bytes for a 1 MiB section, not by its size"
        ));
    }
    Ok(())
}

/// Whether this host can count sections ([`self_check`], once a process).
pub(crate) fn sections_counted() -> Result<(), String> {
    static CHECKED: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    CHECKED.get_or_init(self_check).clone()
}

#[derive(Debug, Default, Clone, Copy)]
struct Count {
    private: u64,
    shared: u64,
    covered: u64,
    large: u64,
}

impl Count {
    fn total(&self) -> u64 {
        self.private + self.shared - self.covered - self.large
    }
}

struct Process {
    handle: OwnedHandle,
    cover: u64,
    /// The private commit when the cover was last read.
    read_at: Option<u64>,
}

/// When a jail past its limit was ended, the parts of the window for the
/// record (COMMITPOLL): the poll that counted it past the limit began
/// (`seen`), its count again with the cover read (`counted`), and
/// `TerminateJobObject` came back (`terminated`); with the polls made from
/// the first (`first`) to the last.
#[derive(Debug, Clone, Copy)]
pub(super) struct Ended {
    pub first: Option<Instant>,
    pub seen: Instant,
    pub counted: Instant,
    pub terminated: Instant,
    pub polls: u64,
}

struct Jail {
    job: OwnedHandle,
    limit: u64,
    large: Option<Arc<AtomicU64>>,
    processes: HashMap<u32, Process>,
    walked: Option<Instant>,
    polls: u64,
    walks: u64,
    longest_walk: Duration,
    before: Option<(Instant, u64)>,
    first: Option<Instant>,
    /// The poll past the limit: its start, and the end of its count.
    past: Option<(Instant, Instant)>,
}

impl Jail {
    /// The jail's count; the cover of every process read again with `walk`.
    fn count(&mut self, walk: bool) -> Result<Count, String> {
        let job = self.job.as_raw_handle();
        let pids = pids(job)?;
        self.processes.retain(|pid, _| pids.contains(pid));
        let mut c = Count::default();
        for pid in pids {
            let p = match self.processes.entry(pid) {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(e) => match open(pid, job)? {
                    Some(handle) => e.insert(Process { handle, cover: 0, read_at: None }),
                    None => continue,
                },
            };
            let h = p.handle.as_raw_handle();
            let Some((private, shared)) = counters(h) else {
                if ended(h) {
                    continue;
                }
                return Err(format!("the memory counters of process {pid} of the jail: {}", io::Error::last_os_error()));
            };
            if walk || p.read_at.is_none_or(|at| private < at) {
                let t = Instant::now();
                p.cover = cover(h);
                p.read_at = Some(private);
                self.walks += 1;
                self.longest_walk = self.longest_walk.max(t.elapsed());
            }
            c.private += private;
            c.shared += shared;
            c.covered += p.cover.min(shared);
        }
        if walk {
            self.walked = Some(Instant::now());
        }
        let given = self.large.as_ref().map_or(0, |g| g.load(Ordering::Acquire));
        c.large = given.min(c.shared - c.covered);
        Ok(c)
    }

    /// One poll: `Err` with the line to end the jail with.
    fn poll(&mut self) -> Result<(), String> {
        let now = Instant::now();
        self.first.get_or_insert(now);
        self.polls += 1;
        let walk = self.walked.is_none_or(|t| now.duration_since(t) >= WALK);
        let mut c = self.count(walk)?;
        if c.total() > self.limit && !walk {
            // The cover read again before any kill.
            c = self.count(true)?;
        }
        if c.total() > self.limit {
            self.past = Some((now, Instant::now()));
            let before = self.before.map_or_else(
                || "no poll before it".to_string(),
                |(t, n)| format!("the poll before, {} us earlier, counted {n}", now.duration_since(t).as_micros()),
            );
            return Err(format!(
                "the jail's memory, {} bytes (private commit {}, section commit {}, of which {} paid by charge pages and {} \
                 large pages), is past the memory limit (memory.max {}): the jail is ended with {KILLED}; {before}; {} polls, \
                 {} reads of the cover, the longest {} us",
                c.total(),
                c.private,
                c.shared,
                c.covered,
                c.large,
                self.limit,
                self.polls,
                self.walks,
                self.longest_walk.as_micros(),
            ));
        }
        self.before = Some((now, c.total()));
        Ok(())
    }
}

/// Duplicates a handle we hold, with the same access.
fn duplicate(h: HANDLE) -> io::Result<OwnedHandle> {
    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a handle we hold into this process.
    if unsafe { DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &mut out, 0, 0, DUPLICATE_SAME_ACCESS) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the handle just made.
    Ok(unsafe { OwnedHandle::from_raw_handle(out) })
}

/// The poll's timer: a high-resolution waitable timer, due in [`POLL`] and
/// then every [`POLL`].
fn poll_timer() -> io::Result<OwnedHandle> {
    // SAFETY: no attributes, no name.
    let timer = unsafe {
        CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS)
    };
    if timer.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the timer just made.
    let timer = unsafe { OwnedHandle::from_raw_handle(timer) };
    let period = i32::try_from(POLL.as_millis()).unwrap();
    let due = -i64::from(period) * 10_000;
    // SAFETY: our timer; relative due time, then every period, no routine.
    if unsafe { SetWaitableTimer(timer.as_raw_handle(), &due, period, None, std::ptr::null(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(timer)
}

/// Counts the jail of `job` against `limit` bytes until `firecracker` ends,
/// and ends the jail with 137 past it. `large`: the bytes of large pages the
/// jailer gave (`large_pages`). `Err` if the count cannot be taken or
/// started: the caller ends the jail. A host that cannot count sections had
/// `memory.max` refused before (`cgroup`, [`sections_counted`]). The thread
/// gives the window's parts ([`Ended`]) when it ended the jail past the
/// limit.
pub(super) fn watch(
    job: HANDLE,
    firecracker: HANDLE,
    limit: u64,
    large: Option<Arc<AtomicU64>>,
) -> io::Result<JoinHandle<Option<Ended>>> {
    sections_counted().map_err(io::Error::other)?;
    let job = duplicate(job)?;
    let firecracker = duplicate(firecracker)?;
    let timer = poll_timer()?;
    let mut jail = Jail {
        job,
        limit,
        large,
        processes: HashMap::new(),
        walked: None,
        polls: 0,
        walks: 0,
        longest_walk: Duration::ZERO,
        before: None,
        first: None,
        past: None,
    };
    std::thread::Builder::new().name("memory.max".into()).spawn(move || {
        let waits = [timer.as_raw_handle(), firecracker.as_raw_handle()];
        loop {
            // SAFETY: two handles this thread holds.
            let r = unsafe { WaitForMultipleObjects(2, waits.as_ptr(), 0, INFINITE) };
            let result = match r.wrapping_sub(WAIT_OBJECT_0) {
                0 => jail.poll(),
                1 => return None,
                _ => Err(format!("waiting for the next poll: {}", io::Error::last_os_error())),
            };
            if let Err(line) = result {
                eprintln!("jailer: memory.max: {line}");
                // SAFETY: the jail's job, our duplicate.
                if unsafe { TerminateJobObject(jail.job.as_raw_handle(), KILLED) } == 0 {
                    // Firecracker at least: the job's other processes end
                    // with it when the jailer closes the job.
                    eprintln!("jailer: memory.max: TerminateJobObject: {}", io::Error::last_os_error());
                    // SAFETY: our duplicate of Firecracker's handle.
                    unsafe { TerminateProcess(firecracker.as_raw_handle(), KILLED) };
                }
                let terminated = Instant::now();
                return jail.past.map(|(seen, counted)| Ended {
                    first: jail.first,
                    seen,
                    counted,
                    terminated,
                    polls: jail.polls,
                });
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Foundation::DUPLICATE_CLOSE_SOURCE;
    use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    use super::super::tests::{Held, held_process};
    use super::*;

    const MIB: u64 = 1 << 20;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualAllocEx(process: HANDLE, address: *const c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
    }

    /// A job holding a suspended process of ours.
    fn jail() -> (OwnedHandle, Held) {
        // SAFETY: an unnamed job.
        let job = unsafe { OwnedHandle::from_raw_handle(CreateJobObjectW(std::ptr::null(), std::ptr::null())) };
        let p = held_process();
        // SAFETY: handles we own.
        assert_ne!(unsafe { AssignProcessToJobObject(job.as_raw_handle(), p.process.as_raw_handle()) }, 0);
        (job, p)
    }

    /// The process's private commit and section commit.
    fn of(p: &Held) -> u64 {
        let (private, shared) = counters(p.process.as_raw_handle()).unwrap();
        private + shared
    }

    /// Gives the process a pagefile-backed section of `bytes` and closes
    /// ours: its commit is the holder's (SECTREC-e shared).
    fn give_section(p: &Held, bytes: u64) {
        // SAFETY: a new pagefile-backed section, no name.
        let s = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE | SEC_COMMIT,
                u32::try_from(bytes >> 32).unwrap(),
                u32::try_from(bytes & 0xffff_ffff).unwrap(),
                std::ptr::null(),
            )
        };
        assert!(!s.is_null(), "{}", io::Error::last_os_error());
        let mut there: HANDLE = std::ptr::null_mut();
        // SAFETY: moves our section handle into our child.
        let ok = unsafe {
            DuplicateHandle(GetCurrentProcess(), s, p.process.as_raw_handle(), &mut there, 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
    }

    /// Whether the process ends within `ms`, and its exit code then.
    fn ends_within(p: &Held, ms: u32) -> Option<u32> {
        // SAFETY: our child's handle.
        if unsafe { WaitForSingleObject(p.process.as_raw_handle(), ms) } != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 0;
        // SAFETY: our child's handle.
        unsafe { GetExitCodeProcess(p.process.as_raw_handle(), &mut code) };
        Some(code)
    }

    // The count stands on this: the host's SharedCommitUsage moves with a
    // section (CI's Windows Server 2025 and the PC's Windows 11 are in
    // Learn's range).
    #[test]
    fn test_shared_commit_is_counted_on_this_host() {
        self_check().unwrap();
    }

    // The poll's timer ticks about every POLL on this host: 500 ticks of
    // `poll_timer`, their intervals' least, median, 99th percentile and
    // greatest printed (COMMITTIMER), the median asserted within 2 ms, the
    // window the docs give ("about 1 ms"). A timer that fell back to the
    // system's default tick would be about 15.6 ms.
    #[test]
    fn test_the_poll_timer_ticks_about_every_millisecond() {
        let timer = poll_timer().unwrap();
        let mut last = Instant::now();
        let mut gaps = Vec::with_capacity(500);
        for _ in 0..500 {
            // SAFETY: our timer.
            assert_eq!(unsafe { WaitForSingleObject(timer.as_raw_handle(), 1000) }, WAIT_OBJECT_0);
            let now = Instant::now();
            gaps.push(now.duration_since(last).as_micros());
            last = now;
        }
        gaps.sort_unstable();
        let (least, median, p99, most) = (gaps[0], gaps[250], gaps[495], gaps[499]);
        println!("COMMITTIMER 500 ticks of the poll's timer: least {least} us, median {median} us, 99th percentile {p99} us, greatest {most} us");
        assert!(median <= 2000, "the poll's timer ticks every {median} us (median), not about every 1 ms");
    }

    // A section given to a process of the jail is counted, and one past the
    // limit ends the jail with 137 at the next poll; a section within it does
    // not. Printed (COMMITPOLL): the window from the section given to the
    // process's end, in its parts: making and giving the section, to the
    // poll that counted it past the limit, that poll's count with the cover
    // read again before the kill, TerminateJobObject, and the process's end
    // as this test sees it; with the polls' mean interval.
    #[test]
    fn test_a_section_past_the_limit_ends_the_jail_with_137() {
        let (job, p) = jail();
        let limit = of(&p) + 32 * MIB;
        let w = watch(job.as_raw_handle(), p.process.as_raw_handle(), limit, None).unwrap();
        give_section(&p, 16 * MIB);
        assert_eq!(ends_within(&p, 250), None, "16 MiB of sections under a limit 32 MiB above the process ended it");
        let t = Instant::now();
        give_section(&p, 32 * MIB);
        let given = Instant::now();
        let code = ends_within(&p, 1000);
        let observed = Instant::now();
        let ended = w.join().unwrap();
        let us = |a: Instant, b: Instant| b.saturating_duration_since(a).as_micros();
        match ended {
            Some(e) => {
                let mean = e.first.map_or(0, |f| us(f, e.seen) / u128::from(e.polls.saturating_sub(1).max(1)));
                println!(
                    "COMMITPOLL a section past the limit: the jail ended {} us after it was given: the section made and \
                     given {} us; to the poll that counted it past the limit {} us; that poll's count, the cover read \
                     again, {} us; TerminateJobObject {} us; to the process's end as the test saw it {} us; {} polls, \
                     {mean} us apart on average",
                    us(t, observed),
                    us(t, given),
                    us(given, e.seen),
                    us(e.seen, e.counted),
                    us(e.counted, e.terminated),
                    us(e.terminated, observed),
                    e.polls,
                );
            }
            None => println!("COMMITPOLL a section past the limit: the count did not end the jail ({} us)", us(t, observed)),
        }
        assert_eq!(code, Some(KILLED), "48 MiB of sections under a limit 32 MiB above the process");
        assert!(ended.is_some(), "the jail ended, not by the count");
    }

    // Charge pages (committed PAGE_NOACCESS private memory) pay for section
    // commit: covered sections are not counted twice, uncovered ones are.
    #[test]
    fn test_charge_pages_pay_for_the_sections_they_cover() {
        let (job, p) = jail();
        // SAFETY: our suspended child; the system chooses the address.
        let at = unsafe {
            VirtualAllocEx(p.process.as_raw_handle(), std::ptr::null(), usize::try_from(48 * MIB).unwrap(), 0x3000, PAGE_NOACCESS)
        };
        assert!(!at.is_null(), "{}", io::Error::last_os_error());
        assert!(cover(p.process.as_raw_handle()) >= 48 * MIB);
        let limit = of(&p) + 16 * MIB;
        let w = watch(job.as_raw_handle(), p.process.as_raw_handle(), limit, None).unwrap();
        give_section(&p, 48 * MIB);
        assert_eq!(ends_within(&p, 250), None, "48 MiB of sections paid by 48 MiB of charge pages were counted");
        give_section(&p, 32 * MIB);
        assert_eq!(ends_within(&p, 1000), Some(KILLED), "32 MiB of sections past the cover, 16 MiB of room");
        w.join().unwrap();
    }

    // Large pages the jailer gave are hugetlb's, not memory.max's.
    #[test]
    fn test_large_pages_given_are_not_counted() {
        let (job, p) = jail();
        let limit = of(&p) + 16 * MIB;
        let given = Arc::new(AtomicU64::new(48 * MIB));
        let w = watch(job.as_raw_handle(), p.process.as_raw_handle(), limit, Some(given)).unwrap();
        give_section(&p, 48 * MIB);
        assert_eq!(ends_within(&p, 250), None, "48 MiB given as large pages were counted");
        give_section(&p, 32 * MIB);
        assert_eq!(ends_within(&p, 1000), Some(KILLED), "32 MiB of sections past the large pages, 16 MiB of room");
        w.join().unwrap();
    }
}
