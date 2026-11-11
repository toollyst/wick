// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The POSIX items Firecracker and its dependencies use that `libc` has no
//! Windows version of, with their Linux layout. Descriptors are handle values
//! (see `wick-os`); functions here call Win32.

use crate::{c_void, size_t};

/// `struct iovec`: one buffer of a vectored I/O call. Compared and hashed by
/// its fields with the `extra_traits` feature, as libc's own.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "extra_traits", derive(PartialEq, Eq, Hash))]
pub struct iovec {
    /// Start of the buffer.
    pub iov_base: *mut c_void,
    /// Length of the buffer.
    pub iov_len: size_t,
}

// Signals. Windows has none; `vmm-sys-util`'s Windows `signal` module
// delivers them (thread-directed signals as special user APCs, faults from
// the unhandled-exception filter, console events as SIGINT/SIGHUP). The
// numbers are Linux's. `SIGINT`, `SIGILL`, `SIGFPE`, `SIGSEGV` and `SIGTERM`
// come from the CRT with the same values; the CRT's `SIGABRT` (22) is kept,
// as `abort()` raises it.

/// Hangup (console closed, logoff, shutdown).
pub const SIGHUP: crate::c_int = 1;
/// Quit (Ctrl+Break).
pub const SIGQUIT: crate::c_int = 3;
/// Breakpoint.
pub const SIGTRAP: crate::c_int = 5;
/// Bus error (in-page I/O error).
pub const SIGBUS: crate::c_int = 7;
/// Kill.
pub const SIGKILL: crate::c_int = 9;
/// User signal 1.
pub const SIGUSR1: crate::c_int = 10;
/// User signal 2.
pub const SIGUSR2: crate::c_int = 12;
/// Broken pipe. Windows returns the error instead and never raises it.
pub const SIGPIPE: crate::c_int = 13;
/// Alarm.
pub const SIGALRM: crate::c_int = 14;
/// Child stopped or exited.
pub const SIGCHLD: crate::c_int = 17;
/// Continue.
pub const SIGCONT: crate::c_int = 18;
/// Stop.
pub const SIGSTOP: crate::c_int = 19;
/// CPU time limit exceeded.
pub const SIGXCPU: crate::c_int = 24;
/// File size limit exceeded.
pub const SIGXFSZ: crate::c_int = 25;
/// Bad system call (seccomp). Windows has no seccomp and never raises it.
pub const SIGSYS: crate::c_int = 31;

/// `si_code`: sent by `tkill`/`pthread_kill`.
pub const SI_TKILL: crate::c_int = -6;
/// `si_code` of `SIGSEGV`: address not mapped.
pub const SEGV_MAPERR: crate::c_int = 1;
/// `si_code` of `SIGSEGV`: no permission for the access.
pub const SEGV_ACCERR: crate::c_int = 2;
/// `si_code` of `SIGBUS`: object-specific hardware error (in-page error).
pub const BUS_OBJERR: crate::c_int = 3;
/// `si_code` of `SIGILL`: illegal opcode.
pub const ILL_ILLOPC: crate::c_int = 1;
/// `si_code` of `SIGILL`: privileged opcode.
pub const ILL_PRVOPC: crate::c_int = 5;
/// `si_code` of `SIGFPE`: integer divide by zero.
pub const FPE_INTDIV: crate::c_int = 1;
/// `si_code` of `SIGFPE`: integer overflow.
pub const FPE_INTOVF: crate::c_int = 2;
/// `si_code` of `SIGFPE`: floating-point divide by zero.
pub const FPE_FLTDIV: crate::c_int = 3;
/// `si_code` of `SIGFPE`: floating-point overflow.
pub const FPE_FLTOVF: crate::c_int = 4;
/// `si_code` of `SIGFPE`: floating-point underflow.
pub const FPE_FLTUND: crate::c_int = 5;
/// `si_code` of `SIGFPE`: floating-point inexact result.
pub const FPE_FLTRES: crate::c_int = 6;
/// `si_code` of `SIGFPE`: floating-point invalid operation.
pub const FPE_FLTINV: crate::c_int = 7;
/// `si_code` of `SIGTRAP`: breakpoint.
pub const TRAP_BRKPT: crate::c_int = 1;

/// `siginfo_t` with the Linux x86_64 layout (128 bytes): `si_signo`,
/// `si_errno`, `si_code`, then the union, whose first field for faults is
/// `si_addr`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct siginfo_t {
    /// Signal number.
    pub si_signo: crate::c_int,
    /// Error number (unused, 0).
    pub si_errno: crate::c_int,
    /// Signal code.
    pub si_code: crate::c_int,
    _pad0: crate::c_int,
    _fields: [u64; 14],
}

impl siginfo_t {
    /// A `siginfo_t` for `signo` and `code`, and the fault address.
    pub fn new(signo: crate::c_int, code: crate::c_int, addr: *mut c_void) -> siginfo_t {
        let mut fields = [0u64; 14];
        fields[0] = addr as usize as u64;
        siginfo_t {
            si_signo: signo,
            si_errno: 0,
            si_code: code,
            _pad0: 0,
            _fields: fields,
        }
    }

    /// The fault address.
    ///
    /// # Safety
    /// Meaningful for `SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE` and `SIGTRAP`.
    pub unsafe fn si_addr(&self) -> *mut c_void {
        self._fields[0] as usize as *mut c_void
    }
}

/// `sigset_t` with glibc's size: one bit per signal, 1024 bits.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct sigset_t {
    __val: [u64; 16],
}

/// `sigemptyset`.
///
/// # Safety
/// `set` must be valid for writes.
pub unsafe fn sigemptyset(set: *mut sigset_t) -> crate::c_int {
    // SAFETY: the caller's contract.
    unsafe { *set = sigset_t::default() };
    0
}

/// `sigfillset`.
///
/// # Safety
/// `set` must be valid for writes.
pub unsafe fn sigfillset(set: *mut sigset_t) -> crate::c_int {
    // SAFETY: the caller's contract.
    unsafe { (*set).__val = [u64::MAX; 16] };
    0
}

fn sig_bit(signum: crate::c_int) -> Option<(usize, u64)> {
    let n = usize::try_from(signum).ok()?.checked_sub(1)?;
    (n < 1024).then(|| (n / 64, 1u64 << (n % 64)))
}

/// `sigaddset`; -1 for an invalid signal number (`errno` is not set).
///
/// # Safety
/// `set` must be valid for reads and writes.
pub unsafe fn sigaddset(set: *mut sigset_t, signum: crate::c_int) -> crate::c_int {
    match sig_bit(signum) {
        // SAFETY: the caller's contract.
        Some((w, b)) => unsafe {
            (*set).__val[w] |= b;
            0
        },
        None => -1,
    }
}

/// `sigdelset`; -1 for an invalid signal number.
///
/// # Safety
/// `set` must be valid for reads and writes.
pub unsafe fn sigdelset(set: *mut sigset_t, signum: crate::c_int) -> crate::c_int {
    match sig_bit(signum) {
        // SAFETY: the caller's contract.
        Some((w, b)) => unsafe {
            (*set).__val[w] &= !b;
            0
        },
        None => -1,
    }
}

/// `sigismember`: 1, 0, or -1 for an invalid signal number.
///
/// # Safety
/// `set` must be valid for reads.
pub unsafe fn sigismember(set: *const sigset_t, signum: crate::c_int) -> crate::c_int {
    match sig_bit(signum) {
        // SAFETY: the caller's contract.
        Some((w, b)) => crate::c_int::from(unsafe { (*set).__val[w] } & b != 0),
        None => -1,
    }
}

/// `pthread_t`: the value of a thread handle.
pub type pthread_t = usize;

/// Process ids (Windows process ids fit).
pub type pid_t = i32;
/// User ids (no Windows equivalent; 0 where one is reported).
pub type uid_t = u32;
/// Group ids (no Windows equivalent; 0 where one is reported).
pub type gid_t = u32;

/// `kill`: `SIGKILL` and `SIGTERM` end process `pid` with exit status
/// 128 + the signal, as the shell reports a process killed by it; signal 0
/// checks that it exists. Windows cannot deliver other signals to another
/// process, nor signal process groups: those fail with `EINVAL`. `ESRCH` if
/// there is no such process, `EPERM` if this one may not end it.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn kill(pid: pid_t, sig: crate::c_int) -> crate::c_int {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
    };
    let terminate = sig == SIGKILL || sig == crate::SIGTERM;
    if pid <= 0 || !(terminate || sig == 0) {
        crate::windows_fd::set_errno(crate::EINVAL);
        return -1;
    }
    let access = if terminate { PROCESS_TERMINATE } else { PROCESS_QUERY_LIMITED_INFORMATION };
    // SAFETY: plain call.
    let h = unsafe { OpenProcess(access, 0, pid.cast_unsigned()) };
    if h.is_null() {
        // SAFETY: plain call.
        let e = unsafe { GetLastError() };
        crate::windows_fd::set_errno(if e == ERROR_ACCESS_DENIED { crate::EPERM } else { crate::ESRCH });
        return -1;
    }
    // SAFETY: a process handle opened above.
    let ok = !terminate || unsafe { TerminateProcess(h, (128 + sig).cast_unsigned()) } != 0;
    // SAFETY: as above.
    unsafe { CloseHandle(h) };
    if ok {
        0
    } else {
        crate::windows_fd::set_errno(crate::EPERM);
        -1
    }
}
