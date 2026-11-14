// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! NOFILEREC: the record for the jailer's no-file bound (the
//! `--resource-limit` row of docs/COMPATIBILITY.md; the wick POSIX layer's
//! `EMFILE` is `libc::wick_nofile`). Linux's `RLIMIT_NOFILE` counts
//! descriptors (v6.12 fs/file.c, `alloc_fd`); Windows counts handles, of
//! which a descriptor is one or more and Windows keeps others of its own.
//! A bound the jailer enforces from outside the jail could count every
//! handle (`GetProcessHandleCount`, then `no-file` plus a margin for the
//! handles that are no descriptor), or only the object types that back
//! descriptors, read per handle with `NtQueryInformationProcess`'s
//! ProcessHandleInformation (class 51). This prints, for each kind of
//! descriptor wick's POSIX layer makes, the handles it adds by object type;
//! what the class-51 read costs at a process's count, 10,000 and 100,000
//! handles more; whether it and ProcessHandleCount (class 20, the count and
//! the most the process held) read another process with the jailer's access
//! (`PROCESS_QUERY_INFORMATION`, with and without `PROCESS_DUP_HANDLE`);
//! and whether this process is elevated (CI's runner is; a PC runs it
//! unelevated).
//!
//! Neither class is on Microsoft Learn: their layouts are System Informer's
//! phnt (ntpsapi.h: `PROCESS_HANDLE_INFORMATION`, two `ULONG`s;
//! `PROCESS_HANDLE_SNAPSHOT_INFORMATION`, two `ULONG_PTR`s then entries of
//! 40 bytes whose `ObjectTypeIndex` is at 28). A status other than 0 is
//! printed, not read past. A type's name is `NtQueryObject`'s
//! ObjectTypeInformation (2) of a duplicate of one of its handles, Learn's
//! `PUBLIC_OBJECT_TYPE_INFORMATION` (a `UNICODE_STRING` first).

use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::io::Write;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetProcessHandleCount, OpenProcess, OpenProcessToken, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_INFORMATION,
};

use crate::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use crate::eventfd::EventFd;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(process: HANDLE, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryObject(handle: HANDLE, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
}

const PROCESS_HANDLE_COUNT: u32 = 20;
const PROCESS_HANDLE_INFORMATION: u32 = 51;
const OBJECT_TYPE_INFORMATION: u32 = 2;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32.cast_signed();
/// Which child scenario runs ([`nofilerec_hold`]).
const HOLD: &str = "WICK_NOFILEREC_HOLD";

/// The process's handle count and the most it held (class 20), or the
/// status.
fn count_and_most(process: HANDLE) -> Result<(u32, u32), i32> {
    let mut two = [0u32; 2];
    let mut ret = 0u32;
    // SAFETY: a buffer of the size given.
    let st = unsafe { NtQueryInformationProcess(process, PROCESS_HANDLE_COUNT, two.as_mut_ptr().cast(), 8, &mut ret) };
    if st == 0 { Ok((two[0], two[1])) } else { Err(st) }
}

/// Each handle's value and object type index (class 51), with the read's
/// time, or the status.
fn snapshot(process: HANDLE) -> Result<(Vec<(u32, usize)>, Duration), i32> {
    let mut words = 1usize << 13;
    let start = Instant::now();
    loop {
        let mut buf = vec![0u64; words];
        let len = u32::try_from(words * 8).unwrap_or(u32::MAX);
        let mut got = 0u32;
        // SAFETY: a buffer of the size given.
        let st = unsafe { NtQueryInformationProcess(process, PROCESS_HANDLE_INFORMATION, buf.as_mut_ptr().cast(), len, &mut got) };
        if st == STATUS_INFO_LENGTH_MISMATCH {
            words = (words * 2).max(got as usize / 8 + 512);
            continue;
        }
        let took = start.elapsed();
        if st != 0 {
            return Err(st);
        }
        let n = usize::try_from(buf[0]).unwrap_or(0);
        let bytes = (got as usize).min(words * 8);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let at = 16 + i * 40;
            if at + 40 > bytes {
                break;
            }
            // Entries of 40 bytes, 8-aligned: the handle at 0, the type
            // index the low half of the word at 24 (GrantedAccess, then
            // ObjectTypeIndex).
            let handle = usize::try_from(buf[at / 8]).unwrap_or(0);
            let type_index = u32::try_from(buf[at / 8 + 3] >> 32).unwrap_or(u32::MAX);
            out.push((type_index, handle));
        }
        return Ok((out, took));
    }
}

/// The name of the type of `handle`, a handle of `process`.
fn type_name(process: HANDLE, handle: usize) -> Option<String> {
    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a handle of a process we hold into this one.
    if unsafe { DuplicateHandle(process, handle as HANDLE, GetCurrentProcess(), &mut dup, 0, 0, DUPLICATE_SAME_ACCESS) } == 0 {
        return None;
    }
    // SAFETY: the duplicate just made, ours.
    let dup = unsafe { OwnedHandle::from_raw_handle(dup) };
    let mut buf = vec![0u64; 512];
    let mut ret = 0u32;
    // SAFETY: a buffer of the size given.
    let st = unsafe { NtQueryObject(dup.as_raw_handle(), OBJECT_TYPE_INFORMATION, buf.as_mut_ptr().cast(), 4096, &mut ret) };
    if st != 0 {
        return None;
    }
    let bytes = usize::from(u16::try_from(buf[0] & 0xffff).unwrap_or(0));
    let ptr = buf[1] as *const u16;
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the UNICODE_STRING NtQueryObject wrote, pointing into `buf`.
    Some(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, bytes / 2) }))
}

/// Type names by index, found once each (the system's for its boot).
#[derive(Default)]
struct Names(HashMap<u32, String>);

impl Names {
    /// The handles of `process` by type name.
    fn by_type(&mut self, process: HANDLE) -> BTreeMap<String, i64> {
        let (handles, _) = snapshot(process).unwrap_or_else(|st| panic!("ProcessHandleInformation: status {st:#x}"));
        let mut out = BTreeMap::new();
        for &(t, _) in &handles {
            let name = self.0.entry(t).or_insert_with(|| {
                // A handle of the type that duplicates; some never do.
                handles
                    .iter()
                    .filter(|&&(u, _)| u == t)
                    .take(4)
                    .find_map(|&(_, h)| type_name(process, h))
                    .unwrap_or_else(|| format!("type {t}"))
            });
            *out.entry(name.clone()).or_insert(0) += 1;
        }
        out
    }
}

/// What the types gained (and lost) from `before` to `after`.
fn delta(before: &BTreeMap<String, i64>, after: &BTreeMap<String, i64>) -> String {
    let mut parts = Vec::new();
    for name in before.keys().chain(after.keys()).collect::<std::collections::BTreeSet<_>>() {
        let d = after.get(name).copied().unwrap_or(0) - before.get(name).copied().unwrap_or(0);
        if d != 0 {
            parts.push(format!("{name} {d:+}"));
        }
    }
    if parts.is_empty() { "nothing".to_string() } else { parts.join(", ") }
}

/// Descriptors of wick's POSIX layer, closed when dropped.
struct Fds(Vec<libc::c_int>);

impl Drop for Fds {
    fn drop(&mut self) {
        for &fd in &self.0 {
            // SAFETY: descriptors this record made.
            unsafe { libc::close(fd) };
        }
    }
}

fn fd(what: &str, fd: libc::c_int) -> Fds {
    assert!(fd >= 0, "{what}: {}", std::io::Error::last_os_error());
    Fds(vec![fd])
}

fn elevated() -> Option<bool> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: this process's pseudo handle and an out-parameter.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    // SAFETY: the token just opened, ours.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret = 0u32;
    // SAFETY: a structure of the size given.
    let ok = unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenElevation, (&raw mut e).cast(), 4, &mut ret)
    };
    (ok != 0).then_some(e.TokenIsElevated != 0)
}

fn handle_count() -> u32 {
    let mut n = 0u32;
    // SAFETY: this process's pseudo handle and an out-parameter.
    assert_ne!(unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut n) }, 0);
    n
}

/// The class-51 read's least and median time over 9 reads, and the
/// count's (`GetProcessHandleCount`) median over 1000.
fn costs(process: HANDLE) -> (Duration, Duration, Duration) {
    let mut t: Vec<Duration> = (0..9).map(|_| snapshot(process).map(|(_, d)| d).unwrap_or(Duration::MAX)).collect();
    t.sort_unstable();
    let mut c: Vec<Duration> = (0..1000)
        .map(|_| {
            let s = Instant::now();
            std::hint::black_box(handle_count());
            s.elapsed()
        })
        .collect();
    c.sort_unstable();
    (t[0], t[4], c[500])
}

/// Prints the handles each kind of descriptor adds, by type, the class-51
/// read's cost, and the classes' reads of another process (NOFILEREC
/// lines). Asserts only that the classes can be read in this process.
#[test]
#[ignore = "a record: run alone on Windows with --ignored --nocapture (CI's WHP step)"]
fn test_the_handles_each_descriptor_makes_on_record() {
    // SAFETY: this process's pseudo handle.
    let me = unsafe { GetCurrentProcess() };
    println!("NOFILEREC elevated: {:?}", elevated());
    let (n, most) = count_and_most(me).unwrap_or_else(|st| panic!("ProcessHandleCount (20): status {st:#x}"));
    println!("NOFILEREC ProcessHandleCount (20) of this process: {n} handles, the most {most} (GetProcessHandleCount {})", handle_count());
    let mut names = Names::default();

    // Each kind made once to warm its first-use handles up (Winsock's,
    // the thread pool's), then measured.
    let dir = std::env::temp_dir().join(format!("nofilerec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let held_socket = fd("socket", unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) });
    let held_event = EventFd::new(0).unwrap();
    let held_epoll = Epoll::new().unwrap();
    let held_fd = held_socket.0[0];
    let event_fd = wick_os::fd::AsRawFd::as_raw_fd(&held_event);
    let mut serial = 0u32;
    // SAFETY (the calls below): wick's POSIX layer making descriptors, each
    // closed when what holds it drops.
    #[allow(clippy::type_complexity)]
    let kinds: Vec<(&str, Box<dyn Fn() -> Box<dyn std::any::Any> + '_>)> = vec![
        ("socket(AF_INET, SOCK_STREAM)", Box::new(|| Box::new(fd("socket", unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) })))),
        ("socket(AF_UNIX, SOCK_STREAM)", Box::new(|| Box::new(fd("socket", unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) })))),
        (
            "pipe (two)",
            Box::new(|| {
                let mut ends = [0; 2];
                assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
                Box::new(Fds(ends.to_vec()))
            }),
        ),
        ("dup of a socket", Box::new(move || Box::new(fd("dup", unsafe { libc::dup(held_fd) })))),
        ("memfd_create", Box::new(|| Box::new(fd("memfd_create", unsafe { libc::memfd_create(c"r".as_ptr(), 0) })))),
        (
            "timerfd_create(CLOCK_MONOTONIC)",
            Box::new(|| Box::new(fd("timerfd_create", unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) }))),
        ),
        ("EventFd::new", Box::new(|| Box::new(EventFd::new(0).unwrap()))),
        ("EventFd::try_clone", Box::new(|| Box::new(held_event.try_clone().unwrap()))),
        ("Epoll::new", Box::new(|| Box::new(Epoll::new().unwrap()))),
        ("std::fs::File::open (CreateFileW)", Box::new(|| Box::new(std::fs::File::open(std::env::current_exe().unwrap()).unwrap()))),
        ("UnixStream::pair (wick-os, two)", Box::new(|| Box::new(wick_os::unix::net::UnixStream::pair().unwrap()))),
        ("a thread (no descriptor; parked)", Box::new(|| {
            let t = std::thread::spawn(std::thread::park);
            struct Join(Option<std::thread::JoinHandle<()>>);
            impl Drop for Join {
                fn drop(&mut self) {
                    if let Some(t) = self.0.take() {
                        t.thread().unpark();
                        let _ = t.join();
                    }
                }
            }
            Box::new(Join(Some(t)))
        })),
    ];
    for (what, make) in &kinds {
        drop(make());
        let before = names.by_type(me);
        let made = make();
        let after = names.by_type(me);
        drop(made);
        serial += 1;
        println!("NOFILEREC {serial:2} {what}: {}", delta(&before, &after));
    }
    // An eventfd added to an epoll and removed again (the epoll's helpers).
    let add = || held_epoll.ctl(ControlOperation::Add, event_fd, EpollEvent::new(EventSet::IN, 0)).unwrap();
    let del = || held_epoll.ctl(ControlOperation::Delete, event_fd, EpollEvent::default()).unwrap();
    add();
    del();
    let before = names.by_type(me);
    add();
    let after = names.by_type(me);
    del();
    println!("NOFILEREC {:2} Epoll::ctl ADD of an eventfd: {}", serial + 1, delta(&before, &after));
    let _ = std::io::stdout().flush();
    let (least, median, count) = costs(me);
    println!(
        "NOFILEREC class 51 at {} handles: least {} us, median {} us; GetProcessHandleCount median {} ns",
        handle_count(),
        least.as_micros(),
        median.as_micros(),
        count.as_nanos()
    );
    for more in [10_000usize, 100_000] {
        let events: Vec<OwnedHandle> = (0..more)
            .map(|_| {
                // SAFETY: an unnamed event, ours.
                let h = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
                assert!(!h.is_null(), "{}", std::io::Error::last_os_error());
                // SAFETY: the event just made.
                unsafe { OwnedHandle::from_raw_handle(h) }
            })
            .collect();
        let (least, median, count) = costs(me);
        println!(
            "NOFILEREC class 51 at {} handles ({more} events more): least {} us, median {} us; GetProcessHandleCount median {} ns",
            handle_count(),
            least.as_micros(),
            median.as_micros(),
            count.as_nanos()
        );
        drop(events);
    }

    // Another process, opened with the access the jailer's poll has
    // (commit.rs: PROCESS_QUERY_INFORMATION), and with PROCESS_DUP_HANDLE
    // too, which a type's name needs.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "windows::nofilerec::nofilerec_hold", "--ignored", "--nocapture", "--test-threads=1"])
        .env(HOLD, "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    for (label, access) in [
        ("PROCESS_QUERY_INFORMATION", PROCESS_QUERY_INFORMATION),
        ("PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE", PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE),
    ] {
        // SAFETY: opens our child.
        let h = unsafe { OpenProcess(access, 0, child.id()) };
        if h.is_null() {
            println!("NOFILEREC another process with {label}: OpenProcess: {}", std::io::Error::last_os_error());
            continue;
        }
        // SAFETY: the handle just opened, ours.
        let h = unsafe { OwnedHandle::from_raw_handle(h) };
        let counted = match count_and_most(h.as_raw_handle()) {
            Ok((n, most)) => format!("{n} handles, the most {most}"),
            Err(st) => format!("class 20 status {st:#x}"),
        };
        let typed = match snapshot(h.as_raw_handle()) {
            Ok((v, took)) => {
                let named = if access & PROCESS_DUP_HANDLE != 0 {
                    let by = Names::default().by_type(h.as_raw_handle());
                    by.iter().map(|(k, v)| format!("{k} {v}")).collect::<Vec<_>>().join(", ")
                } else {
                    "(no names without PROCESS_DUP_HANDLE)".to_string()
                };
                format!("class 51: {} entries in {} us: {named}", v.len(), took.as_micros())
            }
            Err(st) => format!("class 51 status {st:#x}"),
        };
        println!("NOFILEREC another process with {label}: {counted}; {typed}");
    }
    drop(child.stdin.take());
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    drop((held_socket, held_epoll));
}

/// The other process of the record: holds until its standard input ends.
#[test]
#[ignore = "run by test_the_handles_each_descriptor_makes_on_record, in a process of its own"]
fn nofilerec_hold() {
    if std::env::var_os(HOLD).is_none() {
        return;
    }
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}
