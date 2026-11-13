// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The named pipe behind [`super::Queue`], and the relay.
//!
//! [`OutPipe`] is the client end of the pipe a path names, made
//! non-blocking, with the overflow: the reader made the pipe
//! (`CreateNamedPipe`) and Firecracker opened it by its name (`CreateFile`).
//! The relay thread waits for two things, and Windows gives a pipe's client
//! nothing to wait on for either (Microsoft Learn, read 2026-11-13):
//!
//! - A pipe of the name made again. `WaitNamedPipe` waits for a free
//!   instance of a pipe that exists: "If no instances of the specified
//!   named pipe exist, the WaitNamedPipe function returns immediately,
//!   regardless of the time-out value" (WaitNamedPipeA). The connection
//!   that can be waited for, an overlapped `ConnectNamedPipe`, is the
//!   server's, the reader's here.
//! - Room in the reader's pipe. Nothing signals it. The one wait there is
//!   is a write itself, on a blocking-wait handle: it "cannot succeed until
//!   sufficient space is created in the buffer by a thread reading from the
//!   other end of the pipe" (Named Pipe Type, Read, and Wait Modes), and
//!   with overlapped I/O its completion sets an event (Synchronous and
//!   Overlapped Pipe I/O). The relay cannot use it. The wait mode is the
//!   pipe end's, shared by every handle to it (libc's
//!   `test_pipe_wait_mode_is_shared_by_duplicated_handles`), and a client
//!   has one end ("after it is opened, the named pipe instance cannot be
//!   opened by another client", CreateFileW), so the writers' writes, whose
//!   results as non-blocking ones are measured ([`super::Pipe`]), would
//!   wait as well. And a write that waits must be cancelled when the
//!   `OutPipe` is dropped or the process ends: CancelIoEx's page gives a
//!   cancelled operation's status (`ERROR_OPERATION_ABORTED`) and not how
//!   many of its bytes the reader had taken, so a byte could reach the
//!   reader twice or never.
//!
//! So the relay thread looks: every [`PERIOD`] while bytes wait and
//! nothing moves, every millisecond while they move. It sleeps, on a
//! condition variable a write signals, while nothing waits. A write moves
//! what waits too, before it queues behind it.
//!
//! A new reader is a pipe of the same name whose owner is the first pipe's
//! owner ([`owner_of`]): on Linux the next reader opens the same FIFO,
//! which the file system's permissions guard; a Windows pipe name is free
//! for any process once its pipe has ended, so the name alone would hand
//! what waits to whoever makes it first. A pipe of the name that is not
//! taken (another owner's, or one that cannot be opened or asked) is
//! reported once, through [`set_report`]'s function (Firecracker's logger)
//! or on standard error, and again only after a reader's pipe was taken in
//! between. The owner is known only once the pipe is open, so the pipe is
//! opened at the anonymous impersonation level (`SECURITY_SQOS_PRESENT`
//! with `SECURITY_ANONYMOUS`, CreateFileW; "The server cannot impersonate
//! or identify the client", Impersonation Levels): whoever made it learns
//! that a client came, and nothing of Firecracker's identity.
//!
//! Differences from Linux that Windows leaves: bytes a reader left unread
//! in its pipe end with that pipe (Linux keeps them for the next reader);
//! and at an abrupt end of the process the overflow is lost (on Linux the
//! bytes are the kernel's). An orderly end moves it first ([`drain`]: the
//! C runtime's `atexit`, which a return from `main` runs, and whoever
//! calls it before another end).

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, IntoRawHandle};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED,
    GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{GetLengthSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_PIPE, GetFileType, OPEN_EXISTING, SECURITY_ANONYMOUS,
    SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::Pipes::{PIPE_NOWAIT, PIPE_READMODE_BYTE, SetNamedPipeHandleState};

use super::{Fault, Pipe, Queue};

/// How often the relay looks for room in a full pipe, and for a new
/// reader's pipe, while bytes wait and none move: the most a reader that
/// comes back, or that reads again, waits for the bytes held for it.
pub const PERIOD: Duration = Duration::from_millis(50);

/// How long the orderly drain waits for a reader that holds its pipe and
/// takes nothing (Linux's end does not wait: its bytes stay in the FIFO).
pub const DRAIN_STALL: Duration = Duration::from_secs(1);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Where a pipe that is not taken for a reader's is reported.
static REPORT: OnceLock<fn(&str)> = OnceLock::new();

/// Names the function that gets the line about a pipe of a path's name
/// that was not taken for its reader's (Firecracker: its logger). The first
/// call's stays; with none, the line goes to standard error. It is called
/// by the relay thread, or by the thread of a drain, with no lock of this
/// module held, so it may write to an [`OutPipe`] itself.
pub fn set_report(report: fn(&str)) {
    let _ = REPORT.set(report);
}

fn report(line: &str) {
    match REPORT.get() {
        Some(report) => report(line),
        None => eprintln!("{line}"),
    }
}

/// The client end of a reader's pipe.
#[derive(Debug)]
struct Client {
    h: HANDLE,
    quota: usize,
}

// SAFETY: a handle is a value any thread may use.
unsafe impl Send for Client {}

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: our handle, closed once.
        unsafe { CloseHandle(self.h) };
    }
}

impl Client {
    /// Takes `h`, the client end of a named pipe, and makes it
    /// non-blocking (`PIPE_NOWAIT`: "ReadFile, WriteFile, and
    /// ConnectNamedPipe always return immediately", SetNamedPipeHandleState).
    fn adopt(h: HANDLE) -> io::Result<Client> {
        // From here the handle is closed on every path.
        let mut client = Client { h, quota: 0 };
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        // SAFETY: a pipe handle and a mode that outlives the call.
        if unsafe { SetNamedPipeHandleState(h, &mode, std::ptr::null(), std::ptr::null()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        client.quota = crate::windows::stdio::pipe_quota(h)
            .ok_or_else(|| io::Error::other("the pipe does not say how many bytes it holds (FilePipeLocalInformation)"))?;
        Ok(client)
    }
}

impl Pipe for Client {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Fault> {
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let mut n = 0u32;
        // SAFETY: the buffer is valid for `len` bytes; a synchronous write.
        if unsafe { WriteFile(self.h, buf.as_ptr(), len, &mut n, std::ptr::null_mut()) } == 0 {
            // SAFETY: plain call.
            return Err(match unsafe { GetLastError() } {
                ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED => Fault::Gone,
                e => Fault::Other(io::Error::from_raw_os_error(e.cast_signed())),
            });
        }
        Ok(usize::try_from(n).unwrap_or(usize::MAX))
    }

    fn quota(&self) -> usize {
        self.quota
    }
}

/// The owner of the pipe `h` is an end of, as the bytes of its SID
/// (`GetSecurityInfo` with `SE_KERNEL_OBJECT`: "To retrieve a named pipe's
/// security descriptor, call the GetSecurityInfo function", Named Pipe
/// Security and Access Rights; the handle's `GENERIC_READ` or
/// `GENERIC_WRITE` carries the right to read it).
fn owner_of(h: HANDLE) -> io::Result<Vec<u8>> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: out-pointers for the owner and for the descriptor it points
    // into, which is freed below.
    let e = unsafe {
        GetSecurityInfo(
            h,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if e != 0 {
        return Err(io::Error::from_raw_os_error(e.cast_signed()));
    }
    let bytes = if owner.is_null() {
        Err(io::Error::other("the pipe has no owner"))
    } else {
        // SAFETY: a valid SID inside `sd`, of the length it states.
        Ok(unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), GetLengthSid(owner) as usize) }.to_vec())
    };
    // SAFETY: allocated by GetSecurityInfo for us to free.
    unsafe { LocalFree(sd.cast()) };
    bytes
}

struct Shared {
    queue: Mutex<Queue<Client>>,
    /// The overflow's length, for the relay to read without the lock.
    queued: AtomicUsize,
    /// The path, NUL-terminated, for the next reader's pipe.
    path: Vec<u16>,
    /// The first pipe's owner: a later pipe of the name is the reader's
    /// only if it has the same.
    owner: Vec<u8>,
    /// A pipe of the name was not taken and that was reported: not again
    /// until a reader's pipe is.
    refused: AtomicBool,
}

impl Shared {
    /// The pipe of the path's name, if there is one now with a free
    /// instance (`ERROR_FILE_NOT_FOUND` without a pipe of the name,
    /// `ERROR_PIPE_BUSY` when "all pipe instances are currently connected",
    /// CreateFileW) and it is the first reader's owner's. The error: why a
    /// pipe that is there was not taken.
    fn reopen(&self) -> Result<Option<Client>, String> {
        // SAFETY: a NUL-terminated path; no security attributes or template.
        let h = unsafe {
            CreateFileW(
                self.path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                // Whoever made this pipe is not known yet: it gets nothing
                // of the client's identity (see the module's comment).
                SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            // SAFETY: plain call.
            return match unsafe { GetLastError() } {
                ERROR_FILE_NOT_FOUND | ERROR_PIPE_BUSY => Ok(None),
                e => Err(format!("it cannot be opened: {}", io::Error::from_raw_os_error(e.cast_signed()))),
            };
        }
        // SAFETY: plain call.
        if unsafe { GetFileType(h) } != FILE_TYPE_PIPE {
            // SAFETY: our handle.
            unsafe { CloseHandle(h) };
            return Err("it is no pipe".into());
        }
        let client = Client::adopt(h).map_err(|e| format!("it cannot be made non-blocking or asked its size: {e}"))?;
        let owner = owner_of(client.h).map_err(|e| format!("its owner cannot be read: {e}"))?;
        if owner != self.owner {
            return Err("its owner is not the owner of the pipe Firecracker opened first".into());
        }
        Ok(Some(client))
    }

    /// One pass of the relay: a new reader's pipe taken if the last one
    /// ended, and the overflow's front moved. The bytes moved, and whether
    /// a reader's pipe is held. Nothing once the writer has gone.
    fn step(&self) -> (usize, bool) {
        let mut refusal = None;
        let mut q = lock(&self.queue);
        if q.closed() {
            return (0, false);
        }
        if !q.connected() {
            match self.reopen() {
                Ok(Some(client)) => {
                    q.connect(client);
                    self.refused.store(false, Ordering::Release);
                }
                Ok(None) => {}
                Err(why) => {
                    if !self.refused.swap(true, Ordering::AcqRel) {
                        refusal = Some(why);
                    }
                }
            }
        }
        let moved = q.relay();
        let (queued, connected) = (q.queued(), q.connected());
        self.queued.store(queued, Ordering::Release);
        drop(q);
        if let Some(why) = refusal {
            // With no lock held: the line may be written to this very pipe.
            let path = OsString::from_wide(&self.path[..self.path.len() - 1]);
            report(&format!(
                "The pipe {} was made again and is not taken for its reader's: {why}. The {queued} bytes that wait \
                 for a reader of it stay in Firecracker.",
                path.to_string_lossy()
            ));
        }
        (moved, connected)
    }

    /// The orderly end's drain: the overflow moved while a reader takes
    /// it; over when none holds a pipe of the name (as Linux frees a
    /// FIFO's bytes when its last holder goes) or the reader has taken
    /// nothing for [`DRAIN_STALL`].
    fn drain(&self) {
        let mut deadline = Instant::now() + DRAIN_STALL;
        while self.queued.load(Ordering::Acquire) > 0 {
            let (moved, connected) = self.step();
            if !connected {
                return;
            }
            if moved > 0 {
                deadline = Instant::now() + DRAIN_STALL;
            } else if Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// A named pipe Firecracker writes its log, its metrics or a serial
/// device's output to, with a Linux FIFO's results ([`super`]).
pub struct OutPipe(Arc<Shared>);

impl OutPipe {
    /// `file`, opened from `path` for reading and writing, as an
    /// [`OutPipe`] if it is a pipe; the file back if it is not.
    pub fn from_file(file: File, path: &Path) -> io::Result<Result<OutPipe, File>> {
        // SAFETY: plain call on an open handle.
        if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_PIPE {
            return Ok(Err(file));
        }
        let client = Client::adopt(file.into_raw_handle())?;
        let owner = owner_of(client.h)?;
        Ok(Ok(Self::with_owner(client, path, owner)?))
    }

    /// The `OutPipe` of `client`, the pipe `path` names, whose later
    /// readers' pipes are those `owner` owns.
    fn with_owner(client: Client, path: &Path, owner: Vec<u8>) -> io::Result<OutPipe> {
        let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue::new(client)),
            queued: AtomicUsize::new(0),
            path,
            owner,
            refused: AtomicBool::new(false),
        });
        relay::register(&shared)?;
        Ok(OutPipe(shared))
    }

    /// A write with a Linux FIFO's results ([`Queue::write`]). What waits
    /// is moved first, as far as the reader's pipe takes it now.
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut q = lock(&self.0.queue);
        if q.queued() > 0 {
            q.relay();
        }
        let result = q.write(buf);
        let queued = q.queued();
        self.0.queued.store(queued, Ordering::Release);
        drop(q);
        if queued > 0 {
            relay::wake();
        }
        result
    }

    /// The bytes in the overflow.
    pub fn queued(&self) -> usize {
        self.0.queued.load(Ordering::Acquire)
    }

    /// One pass of the relay, now (tests).
    #[cfg(test)]
    fn relay_now(&self) -> usize {
        self.0.step().0
    }
}

impl Drop for OutPipe {
    /// An `OutPipe` dropped (a serial device's, with its VM) is drained
    /// first: on Linux its bytes are in the FIFO already. Then its end of
    /// the reader's pipe is closed, here and now, as `close` closes a
    /// descriptor: the relay thread may hold the rest a moment longer, and
    /// the reader must see the pipe's end when the drop returns.
    fn drop(&mut self) {
        self.0.drain();
        let mut q = lock(&self.0.queue);
        q.close();
        self.0.queued.store(0, Ordering::Release);
    }
}

impl std::fmt::Debug for OutPipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = OsString::from_wide(&self.0.path[..self.0.path.len() - 1]);
        f.debug_struct("OutPipe").field("path", &path).field("queued", &self.queued()).finish()
    }
}

/// Moves what Firecracker still holds for each pipe's reader into its pipe
/// before an orderly end.
pub fn drain() {
    for shared in relay::all() {
        shared.drain();
    }
}

/// The thread that moves overflows into their readers' pipes.
mod relay {
    use super::*;

    struct Relay {
        pipes: Mutex<Vec<Weak<Shared>>>,
        /// Set by a write that left bytes waiting.
        pending: Mutex<bool>,
        wake: Condvar,
        /// The thread runs and the drain is registered with `atexit`.
        started: Mutex<bool>,
    }

    static RELAY: OnceLock<Relay> = OnceLock::new();

    unsafe extern "C" {
        /// The C runtime's `atexit`: run by `exit`, which a return from
        /// `main` calls.
        fn atexit(f: extern "C" fn()) -> i32;
    }

    extern "C" fn at_exit() {
        super::drain();
    }

    pub(super) fn register(shared: &Arc<Shared>) -> io::Result<()> {
        let relay = RELAY.get_or_init(|| Relay {
            pipes: Mutex::new(Vec::new()),
            pending: Mutex::new(false),
            wake: Condvar::new(),
            started: Mutex::new(false),
        });
        // A pipe is opened only with the drain registered and the thread
        // running: an open that could make neither fails, and the next one
        // tries again.
        let mut started = lock(&relay.started);
        if !*started {
            // SAFETY: a plain extern "C" fn.
            if unsafe { atexit(at_exit) } != 0 {
                return Err(io::Error::other("atexit refused the pipe drain"));
            }
            std::thread::Builder::new().name("fc_fifo".into()).spawn(move || run(relay))?;
            *started = true;
        }
        drop(started);
        let mut pipes = lock(&relay.pipes);
        pipes.retain(|p| p.strong_count() > 0);
        pipes.push(Arc::downgrade(shared));
        Ok(())
    }

    /// Every open pipe.
    pub(super) fn all() -> Vec<Arc<Shared>> {
        RELAY.get().map_or_else(Vec::new, |r| lock(&r.pipes).iter().filter_map(Weak::upgrade).collect())
    }

    pub(super) fn wake() {
        if let Some(relay) = RELAY.get() {
            *lock(&relay.pending) = true;
            relay.wake.notify_one();
        }
    }

    fn run(relay: &'static Relay) {
        loop {
            let mut moved = 0;
            let mut waiting = false;
            for shared in all() {
                if shared.queued.load(Ordering::Acquire) > 0 {
                    moved += shared.step().0;
                    waiting |= shared.queued.load(Ordering::Acquire) > 0;
                }
            }
            if waiting {
                // No handle to wait on for room or for a new pipe: look
                // again, soon while the reader is taking bytes.
                std::thread::sleep(if moved > 0 { Duration::from_millis(1) } else { PERIOD });
                continue;
            }
            let mut pending = lock(&relay.pending);
            while !*pending {
                pending = relay.wake.wait(pending).unwrap_or_else(PoisonError::into_inner);
            }
            *pending = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::path::PathBuf;

    use windows_sys::Win32::Storage::FileSystem::{PIPE_ACCESS_DUPLEX, ReadFile};
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe};

    use super::*;

    /// A reader: the server end of a named pipe that holds `size` bytes.
    struct Server(HANDLE);

    // SAFETY: a handle is a value any thread may use.
    unsafe impl Send for Server {}

    impl Drop for Server {
        fn drop(&mut self) {
            // SAFETY: our handle, closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    fn path(name: &str) -> PathBuf {
        PathBuf::from(format!(r"\\.\pipe\wick-fifo-test-{}-{name}", std::process::id()))
    }

    fn server(path: &Path, size: u32) -> Server {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: a NUL-terminated name; one instance, default security.
        let h = unsafe {
            CreateNamedPipeW(wide.as_ptr(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 0, size, 0, std::ptr::null())
        };
        assert_ne!(h, INVALID_HANDLE_VALUE, "{}", io::Error::last_os_error());
        Server(h)
    }

    impl Server {
        /// The bytes the pipe holds now; `None` once the writer has closed
        /// its end and nothing is left.
        fn available(&self) -> Option<usize> {
            let mut n = 0u32;
            // SAFETY: only the count is asked for.
            let ok = unsafe {
                PeekNamedPipe(self.0, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut n, std::ptr::null_mut())
            };
            (ok != 0).then_some(n as usize)
        }

        /// Reads what the pipe holds now, at most `max` bytes.
        fn read_available(&self, max: usize) -> Vec<u8> {
            let n = self.available().unwrap_or(0).min(max);
            let mut out = vec![0u8; n];
            if n > 0 {
                let mut got = 0u32;
                // SAFETY: a buffer of `n` bytes, which the pipe holds.
                let ok = unsafe {
                    ReadFile(self.0, out.as_mut_ptr(), u32::try_from(n).unwrap(), &mut got, std::ptr::null_mut())
                };
                assert!(ok != 0 && got as usize == n, "{}", io::Error::last_os_error());
            }
            out
        }

        /// Reads `n` bytes, or fails after 10 s.
        fn read_exactly(&self, n: usize) -> Vec<u8> {
            let mut out = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            while out.len() < n {
                let part = self.read_available(n - out.len());
                if part.is_empty() {
                    assert!(Instant::now() < deadline, "{} of {n} bytes in 10 s", out.len());
                    std::thread::sleep(Duration::from_millis(1));
                }
                out.extend(part);
            }
            out
        }
    }

    /// The path opened as Firecracker opens it (`utils::open_file_nonblock`).
    fn open(path: &Path) -> OutPipe {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
        OutPipe::from_file(file, path).unwrap().expect("a pipe")
    }

    /// As [`open`], had the pipe opened first been `owner`'s (a SID's
    /// bytes).
    fn open_as_if_owned_by(path: &Path, owner: Vec<u8>) -> OutPipe {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
        let client = Client::adopt(file.into_raw_handle()).unwrap();
        OutPipe::with_owner(client, path, owner).unwrap()
    }

    /// The lines [`set_report`]'s function got in this process.
    static REPORTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

    fn keep_report(line: &str) {
        lock(&REPORTS).push(line.to_owned());
    }

    /// Line `i`: 100 bytes, its number first.
    fn line(i: usize) -> Vec<u8> {
        format!("{i:099}\n").into_bytes()
    }

    fn lines(range: std::ops::Range<usize>) -> Vec<u8> {
        range.flat_map(line).collect()
    }

    /// Writes `buf` until the first error: the bytes taken and the error.
    fn fill(out: &OutPipe, buf: &[u8]) -> (usize, io::Error) {
        let mut taken = 0;
        loop {
            match out.write(buf) {
                Ok(n) => {
                    assert_eq!(n, buf.len(), "a {}-byte write is taken whole or refused (PIPE_BUF)", buf.len());
                    taken += n;
                }
                Err(e) => return (taken, e),
            }
            assert!(taken <= 2 * 65536, "{taken} bytes taken with no reader and no error");
        }
    }

    // A pipe nobody reads takes pipe(7)'s 65536 at most, then the
    // would-block error (EAGAIN), as a Linux FIFO: 64000 to 65536 in
    // 100-byte writes (Linux: 64000), exactly 65536 in 4096-byte writes,
    // whether the reader's pipe holds a page of it or all.
    #[test]
    fn test_a_fifo_nobody_reads_takes_linuxs_capacity() {
        for size in [4096u32, 65536] {
            let p = path(&format!("lines-{size}"));
            let _reader = server(&p, size);
            let out = open(&p);
            let (taken, err) = fill(&out, &line(0));
            assert_eq!(err.kind(), ErrorKind::WouldBlock, "{err}");
            assert!((64000..=65536).contains(&taken), "a pipe of {size}: {taken} bytes before the would-block error");
            let p = path(&format!("pages-{size}"));
            let _reader = server(&p, size);
            let out = open(&p);
            let (taken, err) = fill(&out, &[b'p'; 4096]);
            assert_eq!((taken, err.kind()), (65536, ErrorKind::WouldBlock), "a pipe of {size}");
        }
    }

    // A write after the reader left succeeds, as on a FIFO, which
    // Firecracker holds read-write (before this: os error 233, and
    // FlushMetrics answered 400); writes go on to 64 KiB, then the
    // would-block error.
    #[test]
    fn test_a_pipe_whose_reader_left_takes_writes_as_a_fifo_does() {
        let p = path("left");
        let reader = server(&p, 65536);
        let out = open(&p);
        assert_eq!(out.write(&line(0)).unwrap(), 100);
        assert_eq!(reader.read_exactly(100), line(0));
        drop(reader);
        assert_eq!(out.write(&line(1)).unwrap(), 100);
        let (taken, err) = fill(&out, &line(2));
        assert_eq!(err.kind(), ErrorKind::WouldBlock, "{err}");
        // Lines 1 to 655: 65500 bytes; one more does not fit 65536.
        assert_eq!((taken, out.queued()), (65400, 65500));
    }

    // A reader that makes the pipe again gets what was written meanwhile,
    // every line in order, once each; then writes go into its pipe
    // directly.
    #[test]
    fn test_a_new_reader_of_the_name_gets_what_was_written_meanwhile() {
        let p = path("again");
        let reader = server(&p, 65536);
        let out = open(&p);
        drop(reader);
        for i in 0..300 {
            out.write(&line(i)).unwrap();
        }
        assert_eq!(out.queued(), 30000);
        // A pipe smaller than what waits: the relay follows the reader.
        let reader = server(&p, 4096);
        assert!(reader.read_exactly(30000) == lines(0..300), "the lines came back otherwise");
        // The reader has the last byte before the relay has counted it out.
        let deadline = Instant::now() + Duration::from_secs(10);
        while out.queued() > 0 {
            assert!(Instant::now() < deadline, "{} bytes still wait", out.queued());
            std::thread::sleep(Duration::from_millis(1));
        }
        out.write(&line(9999)).unwrap();
        assert_eq!(out.queued(), 0, "into the reader's pipe directly");
        assert_eq!(reader.read_exactly(100), line(9999));
    }

    // A pipe made under the name by another owner than the first pipe's is
    // not taken: nothing is written to it, what waits stays, and one line
    // says so, however often the relay looks.
    #[test]
    fn test_a_pipe_of_another_owner_is_not_taken_and_is_reported_once() {
        set_report(keep_report);
        let p = path("owner");
        let name = p.to_string_lossy().into_owned();
        let reports = || lock(&REPORTS).iter().filter(|l| l.contains(&name)).cloned().collect::<Vec<_>>();
        // The first pipe as if Everyone's (S-1-1-0): the pipes this test
        // makes are its account's, another owner's.
        let everyone = vec![1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let reader = server(&p, 65536);
        let out = open_as_if_owned_by(&p, everyone);
        drop(reader);
        out.write(&line(0)).unwrap();
        assert_eq!(out.queued(), 100);
        // No pipe of the name: nothing to report.
        assert_eq!((out.relay_now(), reports().len()), (0, 0));
        let other = server(&p, 65536);
        for _ in 0..5 {
            assert_eq!(out.relay_now(), 0);
        }
        let said = reports();
        assert_eq!((out.queued(), said.len()), (100, 1), "{said:?}");
        assert!(said[0].contains("its owner is not the owner of the pipe Firecracker opened first"), "{said:?}");
        assert!(other.read_available(usize::MAX).is_empty(), "bytes went into another owner's pipe");
    }

    // The relay fills the reader's pipe to its last byte, whatever room
    // the reader made: every byte written so far is there to read, as in a
    // FIFO, while more waits than fits.
    #[test]
    fn test_the_relay_fills_the_pipe_to_the_byte() {
        let p = path("fill");
        let reader = server(&p, 4096);
        let out = open(&p);
        for i in 0..100 {
            out.write(&line(i)).unwrap();
        }
        // 40 lines went in directly and left 96 bytes of room, less than a
        // line: the front of the 41st is there too (a write moves what
        // waits before it queues behind it).
        assert_eq!((reader.available(), out.queued()), (Some(4096), 5904));
        assert_eq!(reader.read_exactly(1001), lines(0..100)[..1001]);
        out.relay_now();
        assert_eq!((reader.available(), out.queued()), (Some(4096), 5904 - 1001));
    }

    // A write of at most 4096 bytes (PIPE_BUF) is taken whole or refused,
    // a refused one leaving no byte; a longer one takes what fits.
    #[test]
    fn test_a_small_write_is_all_or_nothing() {
        let p = path("atomic");
        let reader = server(&p, 4096);
        let out = open(&p);
        fill(&out, &line(0));
        assert_eq!(out.write(&[b'a'; 3000]).unwrap_err().kind(), ErrorKind::WouldBlock);
        reader.read_exactly(5000);
        out.relay_now();
        let n = out.write(&[b'b'; 9000]).unwrap();
        assert!(0 < n && n < 9000, "{n} of a 9000-byte write");
        assert_eq!(out.write(&[b'a'; 3000]).unwrap_err().kind(), ErrorKind::WouldBlock);
        let mut rest = Vec::new();
        loop {
            let part = reader.read_available(usize::MAX);
            if part.is_empty() && out.relay_now() == 0 && out.queued() == 0 {
                break;
            }
            rest.extend(part);
        }
        rest.extend(reader.read_available(usize::MAX));
        assert!(!rest.contains(&b'a'), "a refused write left bytes");
        assert_eq!(rest.iter().filter(|b| **b == b'b').count(), n);
    }

    // A path that is no pipe is the file itself, written directly.
    #[test]
    fn test_a_regular_file_is_written_directly() {
        let p = std::env::temp_dir().join(format!("wick-fifo-test-{}.txt", std::process::id()));
        let file = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&p).unwrap();
        assert!(OutPipe::from_file(file, &p).unwrap().is_err(), "a disk file taken for a pipe");
        std::fs::remove_file(&p).unwrap();
    }

    // A line written while the reader's pipe has room is in it when the
    // write returns: the writer's end closed at once (as its process's end
    // closes it), the reader reads the line, and then the pipe's end.
    #[test]
    fn test_a_line_is_in_the_readers_pipe_when_the_write_returns() {
        let p = path("killed");
        let reader = server(&p, 65536);
        let out = open(&p);
        out.write(&line(7)).unwrap();
        assert_eq!(out.queued(), 0);
        drop(out);
        assert_eq!(reader.read_exactly(100), line(7));
        assert_eq!(reader.available(), None, "the pipe's end after the line");
    }

    // Lines written while a reader takes them, through full and empty
    // spells, arrive in order, once each.
    #[test]
    fn test_order_is_kept_across_a_full_pipe() {
        const N: usize = 1500;
        let p = path("order");
        let reader = server(&p, 4096);
        let out = open(&p);
        let reading = std::thread::spawn(move || reader.read_exactly(N * 100));
        for i in 0..N {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match out.write(&line(i)) {
                    Ok(n) => {
                        assert_eq!(n, 100);
                        break;
                    }
                    Err(e) => {
                        assert_eq!(e.kind(), ErrorKind::WouldBlock, "{e}");
                        assert!(Instant::now() < deadline, "line {i} refused for 10 s");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
        assert!(reading.join().unwrap() == lines(0..N), "the lines came back otherwise");
    }

    // What waits for a reader reaches it with no other write: the relay
    // moves it as the reader makes room.
    #[test]
    fn test_the_overflow_reaches_the_reader_without_another_write() {
        let p = path("relay");
        let reader = server(&p, 4096);
        let out = open(&p);
        for i in 0..200 {
            out.write(&line(i)).unwrap();
        }
        assert!(out.queued() > 0);
        assert!(reader.read_exactly(20000) == lines(0..200), "the lines came back otherwise");
    }

    // An `OutPipe` dropped, and an orderly end, move the overflow to a
    // reader that takes it.
    #[test]
    fn test_a_dropped_out_file_drains_to_the_reader() {
        let p = path("drop");
        let reader = server(&p, 4096);
        let out = open(&p);
        for i in 0..100 {
            out.write(&line(i)).unwrap();
        }
        assert!(out.queued() > 0);
        let reading = std::thread::spawn(move || reader.read_exactly(10000));
        drop(out);
        assert!(reading.join().unwrap() == lines(0..100), "the lines came back otherwise");
    }

    // Without a reader of the name the drain does not wait: what waits is
    // lost with the process, as Linux frees a FIFO nobody else holds.
    #[test]
    fn test_a_drain_without_a_reader_does_not_wait() {
        let p = path("nobody");
        let reader = server(&p, 4096);
        let out = open(&p);
        drop(reader);
        out.write(&line(0)).unwrap();
        let start = Instant::now();
        drop(out);
        assert!(start.elapsed() < DRAIN_STALL, "{:?}", start.elapsed());
    }
}
