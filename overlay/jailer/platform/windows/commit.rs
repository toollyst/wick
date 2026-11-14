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
//! - **The count**, every millisecond (a high-resolution waitable timer on
//!   a 1 ms schedule, [`PollTimer`]):
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
//! each page before it is mapped): a time window. Between two polls a jailed
//! process can take host commit beyond `memory.max` (a 4 GiB section in 27.8
//! us, SECTREC-e c) and is ended after the next poll: the window from a
//! section's creation to a jail that can take no more: to the next poll
//! (every 1 ms on a schedule: COMMITTIMER, not yet run with it), that poll's
//! count with the cover read again (160-185 us), `TerminateJobObject` (265 us
//! in one run, 7740 us in another) and the processes' end after it (876-979
//! us): 1374 us and 9830 us in all on the PC at df0bf87 (COMMITPOLL, debug
//! and release, one run each); what a process commits during the call and
//! after it, and the call's own time over 50 rounds, alone and after a freeze
//! of the job, is TERMREC's (`test_terminating_a_jail_on_record`, not yet
//! run). A process that swaps its cover for usable private commit between two
//! reads of the cover holds up to twice `memory.max` of usable memory until
//! the next read, within 100 ms. Windows tells no user-mode process of a
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

/// The poll's timer: a high-resolution waitable timer, due at a schedule
/// of one tick every [`POLL`] from its start, each tick set once the one
/// before was taken ([`PollTimer::arm`]) as a relative wait to its due
/// time. Windows' periodic timer, due every [`POLL`] by itself, ticked
/// 1.5 ms apart (median; least 1.02 ms, greatest 2.0 ms: COMMITTIMER on the
/// PC at df0bf87, debug and release), as a period counted from each tick's
/// late expiry would; the schedule makes up for a late tick with a shorter
/// wait to the next. A tick missed while a poll ran long is not made up:
/// the next poll is at once, and the schedule goes on from it.
struct PollTimer {
    timer: OwnedHandle,
    next: Instant,
}

impl PollTimer {
    fn new() -> io::Result<PollTimer> {
        // SAFETY: no attributes, no name.
        let timer = unsafe {
            CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS)
        };
        if timer.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the timer just made.
        let timer = unsafe { OwnedHandle::from_raw_handle(timer) };
        let mut t = PollTimer { timer, next: Instant::now() };
        t.arm()?;
        Ok(t)
    }

    /// Sets the timer due at the schedule's next tick: [`POLL`] after the
    /// last one's due time, or at once if that is past.
    fn arm(&mut self) -> io::Result<()> {
        let now = Instant::now();
        self.next += POLL;
        if self.next < now {
            self.next = now;
        }
        // Relative, in 100 ns units, negative; at least one.
        let due = -i64::try_from((self.next - now).as_nanos() / 100).unwrap_or(i64::MAX).max(1);
        // SAFETY: our timer; once, no routine.
        if unsafe { SetWaitableTimer(self.timer.as_raw_handle(), &due, 0, None, std::ptr::null(), 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
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
    let mut timer = PollTimer::new()?;
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
        let waits = [timer.timer.as_raw_handle(), firecracker.as_raw_handle()];
        loop {
            // SAFETY: two handles this thread holds.
            let r = unsafe { WaitForMultipleObjects(2, waits.as_ptr(), 0, INFINITE) };
            let result = match r.wrapping_sub(WAIT_OBJECT_0) {
                // The next tick is set before the poll, so that the poll's
                // time is in the wait.
                0 => timer.arm().map_err(|e| format!("setting the next poll: {e}")).and_then(|()| jail.poll()),
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

    // The poll's timer ticks every POLL on this host: 500 ticks of
    // `PollTimer`, armed after each as the poll arms it; their intervals'
    // least, median, 99th percentile and greatest printed (COMMITTIMER), with
    // Windows' periodic timer of the same period beside them (the control:
    // 1.5 ms median on the PC at df0bf87). Asserted: the 500 ticks take at
    // most 550 ms (a mean interval within 10% of POLL), the window the docs
    // give ("every 1 ms"). A timer that fell back to the system's default
    // tick would be about 15.6 ms.
    #[test]
    fn test_the_poll_timer_ticks_about_every_millisecond() {
        let ticks = |wait: &mut dyn FnMut()| {
            let start = Instant::now();
            let mut last = start;
            let mut gaps = Vec::with_capacity(500);
            for _ in 0..500 {
                wait();
                let now = Instant::now();
                gaps.push(now.duration_since(last).as_micros());
                last = now;
            }
            let total = last.duration_since(start).as_millis();
            gaps.sort_unstable();
            (total, gaps[0], gaps[250], gaps[495], gaps[499])
        };
        let mut timer = PollTimer::new().unwrap();
        let (total, least, median, p99, most) = ticks(&mut || {
            // SAFETY: our timer.
            assert_eq!(unsafe { WaitForSingleObject(timer.timer.as_raw_handle(), 1000) }, WAIT_OBJECT_0);
            timer.arm().unwrap();
        });
        // The control: one periodic timer, due every POLL by itself.
        // SAFETY: no attributes, no name.
        let periodic = unsafe {
            OwnedHandle::from_raw_handle(CreateWaitableTimerExW(
                std::ptr::null(),
                std::ptr::null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_ALL_ACCESS,
            ))
        };
        let period = i32::try_from(POLL.as_millis()).unwrap();
        let due = -i64::from(period) * 10_000;
        // SAFETY: our timer; relative due time, then every period.
        assert_ne!(unsafe { SetWaitableTimer(periodic.as_raw_handle(), &due, period, None, std::ptr::null(), 0) }, 0);
        let control = ticks(&mut || {
            // SAFETY: our timer.
            assert_eq!(unsafe { WaitForSingleObject(periodic.as_raw_handle(), 1000) }, WAIT_OBJECT_0);
        });
        println!(
            "COMMITTIMER 500 ticks of the poll's timer in {total} ms: least {least} us, median {median} us, 99th percentile \
             {p99} us, greatest {most} us; Windows' periodic timer of {period} ms, the control: 500 ticks in {} ms, least {} us, \
             median {} us, 99th percentile {} us, greatest {} us",
            control.0, control.1, control.2, control.3, control.4
        );
        assert!(total <= 550, "500 ticks of the poll's timer took {total} ms, not about 500 (every 1 ms)");
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

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MapViewOfFile(section: HANDLE, access: u32, high: u32, low: u32, bytes: usize) -> *mut c_void;
        fn VirtualAlloc(address: *const c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
        fn QueryThreadCycleTime(thread: HANDLE, cycles: *mut u64) -> i32;
        fn GetCurrentThread() -> HANDLE;
    }

    /// The environment variable that gives [`commits_until_ended`] its
    /// shared page's section handle (hexadecimal; the test's child only).
    const TERMREC_PAGE: &str = "WICK_TEST_TERMREC_PAGE";

    /// The child of [`test_terminating_a_jail_on_record`]: commits 64 KiB at a
    /// time, as fast as it can, up to 1 GiB, writing the bytes committed so
    /// far to the shared page after each, then spins until it is ended.
    /// Without the page (any other run of the tests) it returns at once.
    #[test]
    #[ignore = "run by test_terminating_a_jail_on_record, in a job of its own"]
    fn commits_until_ended() {
        let Some(h) = std::env::var(TERMREC_PAGE).ok().and_then(|v| usize::from_str_radix(&v, 16).ok()) else {
            return;
        };
        // SAFETY: the inherited section of a page; FILE_MAP_ALL_ACCESS.
        let page = unsafe { MapViewOfFile(h as HANDLE, 0xf001f, 0, 0, 4096) };
        assert!(!page.is_null());
        // SAFETY: the view is a page, aligned; the parent reads it the same way.
        let done = unsafe { &*page.cast::<AtomicU64>() };
        let mut total = 0u64;
        while total < 1 << 30 {
            // SAFETY: new memory, the system chooses where.
            if unsafe { VirtualAlloc(std::ptr::null(), 64 << 10, 0x3000, PAGE_READWRITE) }.is_null() {
                break;
            }
            total += 64 << 10;
            done.store(total, Ordering::Release);
        }
        loop {
            std::hint::spin_loop();
        }
    }

    /// This thread's cycles.
    fn cycles() -> u64 {
        let mut c = 0;
        // SAFETY: this thread's pseudo-handle and an out-parameter.
        unsafe { QueryThreadCycleTime(GetCurrentThread(), &mut c) };
        c
    }

    // What ending a jail costs and lets through (TERMREC lines), for the
    // window memory.max's count leaves: the time from a poll's decision to a
    // jail that can take no more commit. COMMITPOLL on the PC at df0bf87
    // gave TerminateJobObject 265 us in one run and 7740 us in another. 50
    // rounds of each kind, a job of its own each:
    // - held: a suspended process holding a 48 MiB section (COMMITPOLL's);
    // - committing: a process committing 64 KiB at a time as fast as it can
    //   (commits_until_ended), ended once it committed 16 MiB;
    // each ended by TerminateJobObject alone, and by a freeze of the job
    // (the freezer's JobFreeze) and then TerminateJobObject. Printed per
    // kind: each call's wall time and this thread's cycles in it (the call
    // working, against waiting or preempted: the cycles given as time at
    // this thread's rate, measured first), the commit the process made
    // during the freeze, during TerminateJobObject and from its return to
    // the process's end, and the time from its return to the end; least,
    // median and greatest. A record: nothing is asserted but that every
    // process ended with 137.
    #[test]
    #[ignore = "a record of 200 terminations (TERMREC); CI's jailer loop and the PC run it"]
    fn test_terminating_a_jail_on_record() {
        use super::super::freezer::{Job, JobFreeze};
        use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        // This thread's cycles per microsecond, from a 20 ms spin.
        let (t, c) = (Instant::now(), cycles());
        while t.elapsed() < Duration::from_millis(20) {
            std::hint::spin_loop();
        }
        // Cycles per millisecond.
        let rate = (cycles() - c) * 1000 / u64::try_from(t.elapsed().as_micros()).unwrap().max(1);
        let us = |d: Duration| u64::try_from(d.as_micros()).unwrap();
        // The shared page: an inheritable section.
        let sa = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        // SAFETY: a pagefile-backed section of a page, no name.
        let section = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE | SEC_COMMIT, 0, 4096, std::ptr::null()) };
        assert!(!section.is_null(), "{}", io::Error::last_os_error());
        // SAFETY: our section; FILE_MAP_ALL_ACCESS.
        let page = unsafe { MapViewOfFile(section, 0xf001f, 0, 0, 4096) };
        assert!(!page.is_null());
        // SAFETY: as the child's.
        let done = unsafe { &*page.cast::<AtomicU64>() };
        let median = |v: &mut Vec<u64>| {
            v.sort_unstable();
            (v[0], v[v.len() / 2], v[v.len() - 1])
        };
        for kind in ["held", "committing"] {
            for freeze in [false, true] {
                let (mut call, mut cpu, mut frozen, mut during_freeze, mut during, mut after, mut to_end) =
                    (vec![], vec![], vec![], vec![], vec![], vec![], vec![]);
                for _ in 0..50 {
                    // SAFETY: an unnamed job.
                    let job = unsafe { OwnedHandle::from_raw_handle(CreateJobObjectW(std::ptr::null(), std::ptr::null())) };
                    let (process, _held, _child) = if kind == "held" {
                        let p = held_process();
                        // SAFETY: handles we own.
                        assert_ne!(unsafe { AssignProcessToJobObject(job.as_raw_handle(), p.process.as_raw_handle()) }, 0);
                        give_section(&p, 48 * MIB);
                        (duplicate(p.process.as_raw_handle()).unwrap(), Some(p), None)
                    } else {
                        done.store(0, Ordering::Release);
                        let child = std::process::Command::new(std::env::current_exe().unwrap())
                            .args(["--exact", "platform::windows::commit::tests::commits_until_ended", "--ignored", "--nocapture"])
                            .env(TERMREC_PAGE, format!("{:x}", section as usize))
                            .stdout(std::process::Stdio::null())
                            .spawn()
                            .unwrap();
                        let h = child.as_raw_handle();
                        // SAFETY: handles we own.
                        assert_ne!(unsafe { AssignProcessToJobObject(job.as_raw_handle(), h) }, 0);
                        let t = Instant::now();
                        while done.load(Ordering::Acquire) < 16 * MIB {
                            assert!(t.elapsed() < Duration::from_secs(10), "the child did not commit 16 MiB");
                            std::hint::spin_loop();
                        }
                        (duplicate(h).unwrap(), None, Some(child))
                    };
                    let at = done.load(Ordering::Acquire);
                    if freeze {
                        let t = Instant::now();
                        Job(job.as_raw_handle()).set(true).unwrap();
                        frozen.push(us(t.elapsed()));
                    }
                    let at_freeze = done.load(Ordering::Acquire);
                    let (t, c) = (Instant::now(), cycles());
                    // SAFETY: our job.
                    assert_ne!(unsafe { TerminateJobObject(job.as_raw_handle(), KILLED) }, 0, "{}", io::Error::last_os_error());
                    let (returned, c2) = (Instant::now(), cycles());
                    let at_return = done.load(Ordering::Acquire);
                    // SAFETY: our handle of the process.
                    assert_eq!(unsafe { WaitForSingleObject(process.as_raw_handle(), 10_000) }, WAIT_OBJECT_0);
                    let end = Instant::now();
                    let mut code = 0;
                    // SAFETY: as above.
                    unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) };
                    assert_eq!(code, KILLED);
                    let at_end = done.load(Ordering::Acquire);
                    call.push(us(returned.duration_since(t)));
                    cpu.push((c2 - c) * 1000 / rate.max(1));
                    during_freeze.push((at_freeze - at) >> 10);
                    during.push((at_return - at_freeze) >> 10);
                    after.push((at_end - at_return) >> 10);
                    to_end.push(us(end.duration_since(returned)));
                }
                let f = if freeze {
                    let (a, b, c) = median(&mut frozen);
                    let (d, e, g) = median(&mut during_freeze);
                    format!("the freeze {a}/{b}/{c} us, committed during it {d}/{e}/{g} KiB; ")
                } else {
                    String::new()
                };
                let (a, b, c) = median(&mut call);
                let (d, e, g) = median(&mut cpu);
                let (h, i, j) = median(&mut during);
                let (k, l, m) = median(&mut after);
                let (n, o, q) = median(&mut to_end);
                println!(
                    "TERMREC {kind}, {}: 50 rounds, least/median/greatest: {f}TerminateJobObject {a}/{b}/{c} us, this \
                     thread's cycles in it as time {d}/{e}/{g} us; committed during it {h}/{i}/{j} KiB, from its return to \
                     the end {k}/{l}/{m} KiB; from its return to the process's end {n}/{o}/{q} us",
                    if freeze { "frozen first" } else { "TerminateJobObject alone" }
                );
            }
        }
        println!("TERMREC this thread's rate: {} cycles per us", rate / 1000);
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
