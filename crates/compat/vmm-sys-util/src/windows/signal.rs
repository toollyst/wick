// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `signal` for Windows: the same API, with signals delivered by Windows
//! mechanisms that have their semantics.
//!
//! - Thread-directed signals ([`Killable::kill`], `pthread_kill`) are special
//!   user APCs (`QueueUserAPC2`, or `NtQueueApcThreadEx` before Windows 11):
//!   they interrupt the target thread wherever it runs, without it waiting
//!   alertably, and run the handler on that thread, as a signal does.
//! - Faults are delivered from the unhandled-exception filter, so exceptions
//!   that structured exception handling catches stay with it, as they never
//!   become signals on Linux either: access violations are `SIGSEGV`
//!   (`SEGV_MAPERR` for addresses with no committed memory, `SEGV_ACCERR`
//!   otherwise), in-page errors and misaligned accesses `SIGBUS`, illegal and
//!   privileged instructions `SIGILL`, arithmetic exceptions `SIGFPE`,
//!   breakpoints `SIGTRAP`. `si_addr` is the faulting address; the third
//!   handler argument is the `CONTEXT`. When the handler returns, the
//!   instruction runs again, as on Linux.
//! - Console events: Ctrl+C is `SIGINT`, Ctrl+Break `SIGQUIT`, closing the
//!   console, logoff and shutdown `SIGHUP`. Windows ends the process after a
//!   `SIGHUP` handler returns, as it does for every console-close handler.
//!
//! A thread runs handlers once Windows has set up its thread-local storage,
//! as a Linux thread runs no code before that: a signal sent to a thread
//! that is still starting is queued when its storage is ready (`EAGAIN` if
//! it does not start, as a suspended thread), and one that reaches a thread
//! whose storage is already freed, at its very end, is dropped with it.
//!
//! Each thread has a signal mask: a blocked signal stays pending and its
//! handler runs when the signal is unblocked. Blocked faults take the default
//! action, as Linux does.
//!
//! - A write to a Unix stream socket whose peer is gone (wick-os's
//!   `UnixStream`) raises `SIGPIPE` on the writing thread, as Linux does for
//!   a `write(2)` without `MSG_NOSIGNAL`; the write still fails.
//!
//! Real-time signals are numbered 34..=64 as with glibc. Windows raises no
//! `SIGXCPU`, `SIGXFSZ` or `SIGSYS`; handlers for them can be registered and
//! are called when the signal is sent to a thread.

use std::fmt::{self, Display};
use std::io;
use std::os::windows::io::AsRawHandle;
use std::result;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Once;
use std::thread::JoinHandle;

use libc::{
    BUS_OBJERR, FPE_FLTDIV, FPE_FLTINV, FPE_FLTOVF, FPE_FLTRES, FPE_FLTUND, FPE_INTDIV,
    FPE_INTOVF, ILL_ILLOPC, ILL_PRVOPC, SEGV_ACCERR, SEGV_MAPERR, SI_TKILL, SIGBUS, SIGFPE,
    SIGHUP, SIGILL, SIGINT, SIGQUIT, SIGSEGV, SIGTRAP, TRAP_BRKPT, c_int, c_void, pthread_t,
    siginfo_t, sigset_t,
};
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT, EXCEPTION_DATATYPE_MISALIGNMENT, EXCEPTION_FLT_DIVIDE_BY_ZERO,
    EXCEPTION_FLT_INEXACT_RESULT, EXCEPTION_FLT_INVALID_OPERATION, EXCEPTION_FLT_OVERFLOW,
    EXCEPTION_FLT_UNDERFLOW, EXCEPTION_ILLEGAL_INSTRUCTION, EXCEPTION_IN_PAGE_ERROR,
    EXCEPTION_INT_DIVIDE_BY_ZERO, EXCEPTION_INT_OVERFLOW, EXCEPTION_PRIV_INSTRUCTION,
    EXCEPTION_STACK_OVERFLOW, HANDLE, NTSTATUS,
};
use windows_sys::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
    LPTOP_LEVEL_EXCEPTION_FILTER, SetUnhandledExceptionFilter,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, VirtualQuery};

use crate::errno;

/// The error cases enumeration for signal handling.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Couldn't create a sigset.
    CreateSigset(errno::Error),
    /// The wrapped signal has already been blocked.
    SignalAlreadyBlocked(c_int),
    /// Failed to check if the requested signal is in the blocked set already.
    CompareBlockedSignals(errno::Error),
    /// The signal could not be blocked.
    BlockSignal(errno::Error),
    /// The signal mask could not be retrieved.
    RetrieveSignalMask(c_int),
    /// The signal could not be unblocked.
    UnblockSignal(errno::Error),
    /// Failed to wait for given signal.
    ClearWaitPending(errno::Error),
    /// Failed to get pending signals.
    ClearGetPending(errno::Error),
    /// Failed to check if given signal is in the set of pending signals.
    ClearCheckPending(errno::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            CreateSigset(e) => write!(f, "couldn't create a sigset: {}", e),
            SignalAlreadyBlocked(num) => write!(f, "signal {} already blocked", num),
            CompareBlockedSignals(e) => write!(
                f,
                "failed to check whether requested signal is in the blocked set: {}",
                e,
            ),
            BlockSignal(e) => write!(f, "signal could not be blocked: {}", e),
            RetrieveSignalMask(errno) => write!(
                f,
                "failed to retrieve signal mask: {}",
                io::Error::from_raw_os_error(*errno),
            ),
            UnblockSignal(e) => write!(f, "signal could not be unblocked: {}", e),
            ClearWaitPending(e) => write!(f, "failed to wait for given signal: {}", e),
            ClearGetPending(e) => write!(f, "failed to get pending signals: {}", e),
            ClearCheckPending(e) => write!(
                f,
                "failed to check whether given signal is in the pending set: {}",
                e,
            ),
        }
    }
}

/// A simplified [Result](https://doc.rust-lang.org/std/result/enum.Result.html) type
/// for operations that can return [`Error`](Enum.error.html).
pub type SignalResult<T> = result::Result<T, Error>;

/// Public alias for a signal handler.
pub type SignalHandler =
    extern "C" fn(num: c_int, info: *mut siginfo_t, _unused: *mut c_void) -> ();

/// Return the minimum (inclusive) real-time signal number.
#[allow(non_snake_case)]
pub fn SIGRTMIN() -> c_int {
    34
}

/// Return the maximum (inclusive) real-time signal number.
#[allow(non_snake_case)]
pub fn SIGRTMAX() -> c_int {
    64
}

#[allow(clippy::cast_possible_wrap)]
fn einval() -> errno::Error {
    errno::Error::new(ERROR_INVALID_PARAMETER as i32)
}

/// Verify that a signal number is valid.
///
/// Supported signals range from `SIGHUP` to `SIGSYS` and from `SIGRTMIN` to `SIGRTMAX`.
pub fn validate_signal_num(num: c_int) -> errno::Result<()> {
    if (libc::SIGHUP..=libc::SIGSYS).contains(&num) || (SIGRTMIN() <= num && num <= SIGRTMAX()) {
        Ok(())
    } else {
        Err(einval())
    }
}

/// Registered handlers, by signal number.
static HANDLERS: [AtomicUsize; 65] = [const { AtomicUsize::new(0) }; 65];

fn handler(num: c_int) -> Option<SignalHandler> {
    let f = HANDLERS.get(usize::try_from(num).ok()?)?.load(Ordering::Acquire);
    // SAFETY: only `SignalHandler` values are stored, as `usize`.
    (f != 0).then(|| unsafe { std::mem::transmute::<usize, SignalHandler>(f) })
}

fn bit(num: c_int) -> u64 {
    1u64 << (num - 1)
}

thread_local! {
    /// Blocked signals of this thread, bit `n - 1` for signal `n`.
    static MASK: AtomicU64 = const { AtomicU64::new(0) };
    /// Signals sent to this thread while blocked.
    static PENDING: AtomicU64 = const { AtomicU64::new(0) };
}

/// Runs the handler of `num` on this thread, or keeps it pending if blocked.
fn deliver(num: c_int) {
    if MASK.with(|m| m.load(Ordering::SeqCst)) & bit(num) != 0 {
        PENDING.with(|p| p.fetch_or(bit(num), Ordering::SeqCst));
        return;
    }
    if let Some(f) = handler(num) {
        let mut info = siginfo_t::new(num, SI_TKILL, std::ptr::null_mut());
        f(num, &mut info, std::ptr::null_mut());
    }
}

/// Raises `num` on this thread as a synchronous signal, the way Linux forces
/// a seccomp trap's `SIGSYS` on the thread that made the call: the handler
/// runs now, on this thread, whether or not the signal is blocked, with
/// `si_code` `code`. Returns `false` if no handler is registered (the
/// caller then takes the default action).
pub fn raise_synchronous(num: c_int, code: c_int) -> bool {
    let Some(f) = handler(num) else { return false };
    let mut info = siginfo_t::new(num, code, std::ptr::null_mut());
    f(num, &mut info, std::ptr::null_mut());
    true
}

/// Where faults come from: the unhandled-exception filter.
static PREVIOUS_FILTER: AtomicUsize = AtomicUsize::new(0);

fn fault_signal(rec: &windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_RECORD) -> Option<(c_int, c_int, *mut c_void)> {
    let at = rec.ExceptionAddress;
    // For access violations and in-page errors, the second parameter is the
    // data address.
    let data = (rec.NumberParameters >= 2).then(|| rec.ExceptionInformation[1] as *mut c_void);
    let code: NTSTATUS = rec.ExceptionCode;
    Some(match code {
        EXCEPTION_ACCESS_VIOLATION | EXCEPTION_STACK_OVERFLOW => {
            let addr = data.unwrap_or(at);
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: queries an address; the buffer is ours.
            let n = unsafe { VirtualQuery(addr, &mut mbi, std::mem::size_of_val(&mbi)) };
            let si = if n != 0 && mbi.State == MEM_COMMIT {
                SEGV_ACCERR
            } else {
                SEGV_MAPERR
            };
            (SIGSEGV, si, addr)
        }
        EXCEPTION_IN_PAGE_ERROR => (SIGBUS, BUS_OBJERR, data.unwrap_or(at)),
        EXCEPTION_DATATYPE_MISALIGNMENT => (SIGBUS, 1 /* BUS_ADRALN */, at),
        EXCEPTION_ILLEGAL_INSTRUCTION => (SIGILL, ILL_ILLOPC, at),
        EXCEPTION_PRIV_INSTRUCTION => (SIGILL, ILL_PRVOPC, at),
        EXCEPTION_INT_DIVIDE_BY_ZERO => (SIGFPE, FPE_INTDIV, at),
        EXCEPTION_INT_OVERFLOW => (SIGFPE, FPE_INTOVF, at),
        EXCEPTION_FLT_DIVIDE_BY_ZERO => (SIGFPE, FPE_FLTDIV, at),
        EXCEPTION_FLT_OVERFLOW => (SIGFPE, FPE_FLTOVF, at),
        EXCEPTION_FLT_UNDERFLOW => (SIGFPE, FPE_FLTUND, at),
        EXCEPTION_FLT_INEXACT_RESULT => (SIGFPE, FPE_FLTRES, at),
        EXCEPTION_FLT_INVALID_OPERATION => (SIGFPE, FPE_FLTINV, at),
        EXCEPTION_BREAKPOINT => (SIGTRAP, TRAP_BRKPT, at),
        _ => return None,
    })
}

unsafe extern "system" fn unhandled(info: *const EXCEPTION_POINTERS) -> i32 {
    // SAFETY: Windows passes valid exception pointers.
    let (rec, ctx) = unsafe { (&*(*info).ExceptionRecord, (*info).ContextRecord) };
    if let Some((num, code, addr)) = fault_signal(rec) {
        let blocked = MASK.with(|m| m.load(Ordering::SeqCst)) & bit(num) != 0;
        if let (false, Some(f)) = (blocked, handler(num)) {
            let mut si = siginfo_t::new(num, code, addr);
            f(num, &mut si, ctx.cast());
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    let prev = PREVIOUS_FILTER.load(Ordering::Acquire);
    if prev != 0 {
        // SAFETY: the value is the filter that was installed before ours.
        let prev: LPTOP_LEVEL_EXCEPTION_FILTER = unsafe { std::mem::transmute(prev) };
        if let Some(prev) = prev {
            // SAFETY: calls the previous filter with the same arguments.
            return unsafe { prev(info) };
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}

unsafe extern "system" fn console_event(ctrl: u32) -> i32 {
    let num = match ctrl {
        CTRL_C_EVENT => SIGINT,
        CTRL_BREAK_EVENT => SIGQUIT,
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => SIGHUP,
        _ => return 0,
    };
    match handler(num) {
        Some(f) => {
            let mut info = siginfo_t::new(num, 0 /* SI_USER */, std::ptr::null_mut());
            f(num, &mut info, std::ptr::null_mut());
            1
        }
        None => 0,
    }
}

/// Register the signal handler of `signum`.
///
/// The handler runs asynchronously, interrupting whatever the thread was
/// doing, and must only do async-signal-safe operations.
pub fn register_signal_handler(num: c_int, handler: SignalHandler) -> errno::Result<()> {
    validate_signal_num(num)?;
    if num == libc::SIGKILL || num == libc::SIGSTOP {
        return Err(einval());
    }
    HANDLERS[usize::try_from(num).unwrap()].store(handler as usize, Ordering::Release);
    match num {
        SIGSEGV | SIGBUS | SIGILL | SIGFPE | SIGTRAP => {
            static FILTER: Once = Once::new();
            FILTER.call_once(|| {
                // SAFETY: installs our filter; the previous one is chained.
                let prev = unsafe { SetUnhandledExceptionFilter(Some(unhandled)) };
                PREVIOUS_FILTER.store(
                    prev.map_or(0, |p| p as usize),
                    Ordering::Release,
                );
            });
        }
        SIGINT | SIGQUIT | SIGHUP => {
            static CONSOLE: Once = Once::new();
            let mut result = Ok(());
            CONSOLE.call_once(|| {
                // SAFETY: adds a handler routine; checked.
                if unsafe { SetConsoleCtrlHandler(Some(console_event), 1) } == 0 {
                    result = Err(errno::Error::last());
                }
            });
            result?;
        }
        // A write to a stream whose peer is gone, which Linux answers with
        // SIGPIPE to the writing thread (wick-os's UnixStream calls this).
        // libc's write(2) on a pipe or socket, wick-os's UnixStream.
        libc::SIGPIPE => {
            libc::wick_signal::set_broken_pipe_hook(|| deliver(libc::SIGPIPE));
            wick_os::windows::set_broken_pipe_hook(|| deliver(libc::SIGPIPE));
        }
        _ => {}
    }
    Ok(())
}

/// Creates a `sigset` from a list of signals.
pub fn create_sigset(signals: &[c_int]) -> errno::Result<sigset_t> {
    let mut sigset = sigset_t::default();
    for &signal in signals {
        // SAFETY: the set is ours.
        if unsafe { libc::sigaddset(&mut sigset, signal) } < 0 {
            return Err(einval());
        }
    }
    Ok(sigset)
}

/// Retrieves the signal mask of the current thread as a vector of `c_int`s.
pub fn get_blocked_signals() -> SignalResult<Vec<c_int>> {
    let mask = MASK.with(|m| m.load(Ordering::SeqCst));
    Ok((1..=SIGRTMAX()).filter(|&n| mask & bit(n) != 0).collect())
}

/// Masks given signal on the current thread.
pub fn block_signal(num: c_int) -> SignalResult<()> {
    validate_signal_num(num).map_err(Error::CreateSigset)?;
    let old = MASK.with(|m| m.fetch_or(bit(num), Ordering::SeqCst));
    if old & bit(num) != 0 {
        return Err(Error::SignalAlreadyBlocked(num));
    }
    Ok(())
}

/// Unmasks given signal on the current thread; a pending one is delivered.
pub fn unblock_signal(num: c_int) -> SignalResult<()> {
    validate_signal_num(num).map_err(Error::CreateSigset)?;
    MASK.with(|m| m.fetch_and(!bit(num), Ordering::SeqCst));
    if PENDING.with(|p| p.fetch_and(!bit(num), Ordering::SeqCst)) & bit(num) != 0 {
        deliver(num);
    }
    Ok(())
}

/// Clears a pending signal of the current thread.
pub fn clear_signal(num: c_int) -> SignalResult<()> {
    validate_signal_num(num).map_err(Error::CreateSigset)?;
    PENDING.with(|p| p.fetch_and(!bit(num), Ordering::SeqCst));
    Ok(())
}

type QueueUserApc2 = unsafe extern "system" fn(
    Option<unsafe extern "system" fn(usize)>,
    HANDLE,
    usize,
    i32,
) -> i32;
type NtQueueApcThreadEx = unsafe extern "system" fn(
    HANDLE,
    usize,
    unsafe extern "system" fn(usize, usize, usize),
    usize,
    usize,
    usize,
) -> NTSTATUS;

/// What `GetProcAddress` returns.
type RawProc = unsafe extern "system" fn() -> isize;

/// `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC`, also the reserve-handle value
/// that asks `NtQueueApcThreadEx` for a special user APC.
const SPECIAL_USER_APC: usize = 1;

/// Offset of `ThreadLocalStoragePointer` in the 64-bit TEB.
const TEB_TLS_POINTER: usize = 0x58;

/// Whether this thread's thread-local storage exists (it does not yet while
/// the loader starts the thread, nor after it freed it as the thread ends).
fn own_tls_ready() -> bool {
    let p: usize;
    // SAFETY: reads a field of this thread's TEB.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::asm!("mov {}, gs:[0x58]", out(reg) p, options(nostack, readonly, preserves_flags));
    }
    // SAFETY: as above; x18 holds the TEB address.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        std::arch::asm!("ldr {}, [x18, #0x58]", out(reg) p, options(nostack, readonly, preserves_flags));
    }
    p != 0
}

unsafe extern "system" fn apc(num: usize) {
    // Handlers and the signal mask live in thread-local storage.
    if !own_tls_ready() {
        return;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    deliver(num as c_int);
}

/// `THREAD_BASIC_INFORMATION`.
#[repr(C)]
struct ThreadBasicInformation {
    exit_status: NTSTATUS,
    teb: usize,
    client_id: [usize; 2],
    affinity: usize,
    priority: i32,
    base_priority: i32,
}

type NtQueryInformationThread =
    unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> NTSTATUS;

/// Waits until `thread` has its thread-local storage. `false` if it does not
/// get it in time (a suspended thread).
fn wait_tls_ready(thread: HANDLE) -> bool {
    static QUERY: std::sync::OnceLock<Option<NtQueryInformationThread>> =
        std::sync::OnceLock::new();
    let query = QUERY.get_or_init(|| {
        find("ntdll.dll", b"NtQueryInformationThread\0")
            // SAFETY: the export has this signature.
            .map(|f| unsafe { std::mem::transmute::<RawProc, NtQueryInformationThread>(f) })
    });
    let Some(query) = query else {
        return true;
    };
    // SAFETY: an all-zero THREAD_BASIC_INFORMATION is valid.
    let mut info: ThreadBasicInformation = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    let size = std::mem::size_of::<ThreadBasicInformation>() as u32;
    // SAFETY: ThreadBasicInformation (0) into a buffer of its size.
    let status = unsafe { query(thread, 0, (&raw mut info).cast(), size, std::ptr::null_mut()) };
    if status < 0 || info.teb == 0 {
        // Not a thread of ours to inspect: queue as is.
        return true;
    }
    let field = (info.teb + TEB_TLS_POINTER) as *const c_void;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        // The field is written by the loader. Read with ReadProcessMemory,
        // which fails where a plain read would fault: the thread may exit
        // and its TEB go between the caller's check and this read.
        let mut value = 0usize;
        // SAFETY: reads one word of this process into `value`.
        let read = unsafe {
            windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                field,
                (&raw mut value).cast(),
                std::mem::size_of::<usize>(),
                std::ptr::null_mut(),
            )
        };
        if read == 0 || value != 0 {
            // Ready, or the TEB is gone: queue, and send judges the result.
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::yield_now();
    }
}

unsafe extern "system" fn nt_apc(num: usize, _: usize, _: usize) {
    // SAFETY: same routine.
    unsafe { apc(num) };
}

enum Queue {
    Kernel32(QueueUserApc2),
    Ntdll(NtQueueApcThreadEx),
    None,
}

/// An export of kernel32 or ntdll (always loaded); `name` ends with NUL.
fn find(module: &str, name: &[u8]) -> Option<RawProc> {
    let wide: Vec<u16> = module.encode_utf16().chain([0]).collect();
    // SAFETY: the module name is NUL-terminated, and so is `name`.
    unsafe {
        let m = GetModuleHandleW(wide.as_ptr());
        if m.is_null() {
            None
        } else {
            GetProcAddress(m, name.as_ptr())
        }
    }
}

fn queue() -> &'static Queue {
    static QUEUE: std::sync::OnceLock<Queue> = std::sync::OnceLock::new();
    QUEUE.get_or_init(|| {
        if let Some(f) = find("kernel32.dll", b"QueueUserAPC2\0") {
            // SAFETY: the export has this signature.
            return Queue::Kernel32(unsafe { std::mem::transmute::<RawProc, QueueUserApc2>(f) });
        }
        if let Some(f) = find("ntdll.dll", b"NtQueueApcThreadEx\0") {
            // SAFETY: the export has this signature.
            return Queue::Ntdll(unsafe { std::mem::transmute::<RawProc, NtQueueApcThreadEx>(f) });
        }
        Queue::None
    })
}

/// How long a thread whose APC could not be queued is given to finish
/// exiting before the failure is the caller's.
const EXITING_MS: u32 = 100;

/// Whether `thread` has exited (its handle is signalled), waiting up to
/// `ms` for it.
fn exited(thread: HANDLE, ms: u32) -> bool {
    // SAFETY: waits on a thread handle the caller holds.
    unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(thread, ms)
            == windows_sys::Win32::Foundation::WAIT_OBJECT_0
    }
}

/// Sends `num` to the thread `thread` (`pthread_kill`).
fn send(thread: HANDLE, num: c_int) -> errno::Result<()> {
    validate_signal_num(num)?;
    let arg = usize::try_from(num).unwrap();
    // A thread that has exited, not yet joined, is sent nothing, and the
    // call succeeds, as Linux's pthread_kill: musl's pthread_kill.c returns
    // 0 for a valid signal once the thread's tid is 0, which __pthread_exit
    // sets before the kernel thread exits (glibc 2.34+ likewise, for an
    // exiting thread). Queueing an APC to one fails with ERROR_GEN_FAILURE
    // (31: KILLTEST, CI run 43306073982), which vmm's kick of a vCPU thread
    // that had finished returned (test_vcpu_dump_cpu_config, run 43292883636).
    if exited(thread, 0) {
        return Ok(());
    }
    if !wait_tls_ready(thread) {
        return Err(errno::Error::new(libc::EAGAIN));
    }
    match queue() {
        // SAFETY: queues an APC on a thread handle the caller holds.
        Queue::Kernel32(f) => {
            if unsafe { f(Some(apc), thread, arg, SPECIAL_USER_APC as i32) } == 0 {
                let e = errno::Error::last();
                // It exited since the check above, or is exiting.
                return if exited(thread, EXITING_MS) { Ok(()) } else { Err(e) };
            }
        }
        // SAFETY: as above.
        Queue::Ntdll(f) => {
            let status = unsafe { f(thread, SPECIAL_USER_APC, nt_apc, arg, 0, 0) };
            if status < 0 {
                if exited(thread, EXITING_MS) {
                    return Ok(());
                }
                #[allow(clippy::cast_possible_wrap)]
                return Err(errno::Error::new(ERROR_NOT_SUPPORTED as i32));
            }
        }
        #[allow(clippy::cast_possible_wrap)]
        Queue::None => return Err(errno::Error::new(ERROR_NOT_SUPPORTED as i32)),
    }
    Ok(())
}

/// Trait for threads that can be signalled via `pthread_kill`.
///
/// # Safety
///
/// The returned `pthread_t` (a thread handle value) must be valid and live
/// at least as long as the trait object.
pub unsafe trait Killable {
    /// Cast this killable thread as `pthread_t`.
    fn pthread_handle(&self) -> pthread_t;

    /// Send a signal to this killable thread.
    fn kill(&self, num: c_int) -> errno::Result<()> {
        send(self.pthread_handle() as HANDLE, num)
    }
}

// SAFETY: the join handle owns the thread handle.
unsafe impl<T> Killable for JoinHandle<T> {
    fn pthread_handle(&self) -> pthread_t {
        self.as_raw_handle() as pthread_t
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    static CALLED: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn count(num: c_int, info: *mut siginfo_t, _: *mut c_void) {
        assert_eq!(unsafe { (*info).si_signo }, num);
        CALLED.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn test_validate() {
        validate_signal_num(SIGRTMIN()).unwrap();
        validate_signal_num(SIGRTMAX()).unwrap();
        validate_signal_num(0).unwrap_err();
        validate_signal_num(65).unwrap_err();
        register_signal_handler(libc::SIGKILL, count).unwrap_err();
    }

    // A write to a stream whose peer closed fails and raises SIGPIPE on the
    // writing thread, as on Linux.
    #[test]
    fn test_write_to_a_closed_peer_raises_sigpipe() {
        use std::io::Write;
        static PIPES: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn on_pipe(num: c_int, info: *mut siginfo_t, _: *mut c_void) {
            assert_eq!(unsafe { (*info).si_signo }, num);
            assert_eq!(num, libc::SIGPIPE);
            PIPES.fetch_add(1, Ordering::SeqCst);
        }
        register_signal_handler(libc::SIGPIPE, on_pipe).unwrap();
        let (mut a, b) = wick_os::unix::net::UnixStream::pair().unwrap();
        drop(b);
        let failed = (0..100).any(|_| {
            let r = a.write(&[0u8; 4096]);
            std::thread::sleep(Duration::from_millis(5));
            r.is_err()
        });
        assert!(failed, "writes to a closed peer kept succeeding");
        assert!(PIPES.load(Ordering::SeqCst) > 0, "no SIGPIPE");
        // And through libc's write(2), as vm-memory writes a socket.
        let before = PIPES.load(Ordering::SeqCst);
        let (a, b) = wick_os::unix::net::UnixStream::pair().unwrap();
        drop(b);
        use wick_os::fd::AsRawFd;
        let failed = (0..100).any(|_| {
            let r = unsafe { libc::write(a.as_raw_fd(), [0u8; 4096].as_ptr().cast(), 4096) };
            std::thread::sleep(Duration::from_millis(5));
            r < 0
        });
        assert!(failed, "libc writes to a closed peer kept succeeding");
        assert!(PIPES.load(Ordering::SeqCst) > before, "no SIGPIPE from libc's write");
    }

    #[test]
    fn test_raise_synchronous() {
        static CODE: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn record(num: c_int, info: *mut siginfo_t, _: *mut c_void) {
            assert_eq!(unsafe { (*info).si_signo }, num);
            CODE.store(unsafe { (*info).si_code } as usize, Ordering::SeqCst);
        }
        let num = SIGRTMIN() + 7;
        assert!(!raise_synchronous(num, 1));
        register_signal_handler(num, record).unwrap();
        // Blocked or not, the handler runs before the call returns.
        block_signal(num).unwrap();
        assert!(raise_synchronous(num, 7));
        assert_eq!(CODE.load(Ordering::SeqCst), 7);
        unblock_signal(num).unwrap();
    }

    #[test]
    fn test_kill_interrupts_busy_thread() {
        let num = SIGRTMIN() + 1;
        register_signal_handler(num, count).unwrap();
        static STOP: AtomicBool = AtomicBool::new(false);
        let before = CALLED.load(Ordering::SeqCst);
        // A thread that never waits: the APC must still interrupt it.
        let t = std::thread::spawn(|| {
            while !STOP.load(Ordering::SeqCst) {
                std::hint::spin_loop();
            }
        });
        t.kill(num).unwrap();
        for _ in 0..200 {
            if CALLED.load(Ordering::SeqCst) > before {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        STOP.store(true, Ordering::SeqCst);
        t.join().unwrap();
        assert!(CALLED.load(Ordering::SeqCst) > before);
    }

    // pthread_kill of a thread that has returned but is not joined: Linux
    // sends nothing and returns 0 (musl pthread_kill.c: `r = t->tid ?
    // -__syscall(SYS_tkill, t->tid, sig) : ... 0`, and __pthread_exit sets
    // tid to 0 before the kernel thread exits; glibc 2.34+ likewise for an
    // exiting thread). Before send checked for it, the last kill here was
    // Err(Error(31)), ERROR_GEN_FAILURE from QueueUserAPC2 (KILLTEST, CI
    // run 43306073982), and vmm's test_vcpu_dump_cpu_config failed when its
    // last kick came after the vCPU thread had finished. A live thread
    // still gets the signal.
    #[test]
    fn test_kill_of_an_exited_thread_succeeds() {
        let num = SIGRTMIN() + 5;
        register_signal_handler(num, count).unwrap();
        let before = CALLED.load(Ordering::SeqCst);
        let (tx, rx) = mpsc::channel::<()>();
        let live = std::thread::spawn(move || {
            let _ = rx.recv_timeout(Duration::from_secs(10));
        });
        live.kill(num).unwrap();
        let start = std::time::Instant::now();
        while CALLED.load(Ordering::SeqCst) == before {
            assert!(start.elapsed() < Duration::from_secs(5), "not delivered to a live thread");
            std::thread::yield_now();
        }
        tx.send(()).unwrap();
        live.join().unwrap();
        let t = std::thread::spawn(|| {});
        while !t.is_finished() {
            std::thread::yield_now();
        }
        // While it exits, and once it has.
        t.kill(num).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        t.kill(num).unwrap();
        // An invalid signal is still refused, as musl checks it first.
        t.kill(65).unwrap_err();
        t.join().unwrap();
    }

    #[test]
    fn test_kill_right_after_spawn() {
        // Sent while the thread may still be starting: delivered once it can
        // run handlers, every time.
        let num = SIGRTMIN() + 3;
        register_signal_handler(num, count).unwrap();
        for _ in 0..200 {
            let before = CALLED.load(Ordering::SeqCst);
            let (tx, rx) = mpsc::channel::<()>();
            let t = std::thread::spawn(move || {
                let _ = rx.recv_timeout(Duration::from_secs(5));
            });
            t.kill(num).unwrap();
            let start = std::time::Instant::now();
            while CALLED.load(Ordering::SeqCst) == before {
                assert!(start.elapsed() < Duration::from_secs(5), "not delivered");
                std::thread::yield_now();
            }
            tx.send(()).unwrap();
            t.join().unwrap();
        }
    }

    #[test]
    fn test_blocked_signal_is_pending() {
        let num = SIGRTMIN() + 2;
        register_signal_handler(num, count).unwrap();
        let (tx, rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<usize>();
        let t = std::thread::spawn(move || {
            block_signal(num).unwrap();
            assert_eq!(block_signal(num), Err(Error::SignalAlreadyBlocked(num)));
            assert!(get_blocked_signals().unwrap().contains(&num));
            tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            let before = CALLED.load(Ordering::SeqCst);
            unblock_signal(num).unwrap();
            done_tx.send(CALLED.load(Ordering::SeqCst) - before).unwrap();
        });
        rx.recv().unwrap();
        t.kill(num).unwrap();
        assert_eq!(done_rx.recv().unwrap(), 1, "delivered on unblock");
        t.join().unwrap();
    }

    static FAULT_PAGE: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn fix_fault(num: c_int, info: *mut siginfo_t, _: *mut c_void) {
        use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};
        assert_eq!(num, SIGSEGV);
        let addr = unsafe { (*info).si_addr() } as usize;
        assert_eq!(addr & !0xfff, FAULT_PAGE.load(Ordering::SeqCst));
        assert_eq!(unsafe { (*info).si_code }, SEGV_ACCERR);
        let mut old = 0;
        unsafe { VirtualProtect(addr as *const c_void, 1, PAGE_READWRITE, &mut old) };
    }

    #[test]
    fn test_fault_handler_retries_instruction() {
        use windows_sys::Win32::System::Memory::{MEM_RESERVE, PAGE_NOACCESS, VirtualAlloc};
        let page =
            unsafe { VirtualAlloc(std::ptr::null(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS) };
        assert!(!page.is_null());
        FAULT_PAGE.store(page as usize, Ordering::SeqCst);
        register_signal_handler(SIGSEGV, fix_fault).unwrap();
        let p = page.cast::<u8>();
        unsafe { p.add(8).write_volatile(42) };
        assert_eq!(unsafe { p.add(8).read_volatile() }, 42);
    }
}
