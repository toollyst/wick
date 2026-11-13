// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Process sandbox for hosts without seccomp-BPF.
//!
//! On Linux Firecracker restricts each thread with seccomp-BPF filters. Other
//! hosts have no seccomp, so wick installs the host's own sandbox instead,
//! with the same command line meaning:
//!
//! | Firecracker flag        | Linux                 | macOS                                   | Windows                                   |
//! |-------------------------|-----------------------|-----------------------------------------|-------------------------------------------|
//! | (default)               | built-in BPF filters  | built-in Seatbelt profile ([`PROFILE`]) | process mitigation profile ([`windows`])  |
//! | `--no-seccomp`          | no filters            | no sandbox                              | no sandbox                                |
//! | `--seccomp-filter FILE` | the given BPF filters | refused (BPF cannot be enforced)        | refused (BPF cannot be enforced)          |
//!
//! Each host sandbox is process-wide and permanent: the first thread that would
//! install its seccomp filter installs it for the whole process; later calls do
//! nothing.
//!
//! The macOS sandbox restricts what the process can ask the kernel for: no
//! program execution, no fork, no IP networking, no Mach service lookups (but
//! the one a vmnet interface's start makes while the microVM is built), no
//! IOKit, no sysctl writes. Started by the jailer ([`super::jail`]), it also
//! limits files to the jail directory; without the jailer, files are not
//! limited, as on Linux without the jailer (guest images, snapshots and
//! sockets are chosen by the operator at run time).
//!
//! The Windows sandbox is a process mitigation profile, each mitigation tied
//! to the seccomp rule it stands for: no child processes, no win32k, no
//! dynamic code, Microsoft-signed images only, none from the network or
//! labelled low, no extension points, strict handle checks. Files are the
//! jail's token's and ACLs' ([`super::jail`]).

/// The sandbox the process should install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// No sandbox (`--no-seccomp`).
    None,
    /// The built-in default.
    Default,
}

/// Errors installing the sandbox.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SandboxError {
    /// Failed to install the process sandbox: {0}
    Install(String),
    /// Failed to narrow the process sandbox: {0}
    Narrow(String),
    /// Custom seccomp-BPF filters can only be enforced on Linux
    CustomFilterUnsupported,
    /// The jail's CPU limit of {0}% holds only with the sandbox: without it Firecracker could lift the limit itself (unlike a cgroup's). Drop --no-seccomp or the CPU cgroup
    CpuLimitNeedsSandbox(u8),
}

#[cfg(target_os = "macos")]
pub use macos::{
    API_FCNTL_COMMANDS, API_MACH_TRAPS, API_MIG_ROUTINES, API_SYSCALLS, FCNTL_COMMANDS,
    ABSENT, EXCEPTION_MIG_ROUTINES, FILES_ANYWHERE, Limit, MACH_TRAPS, MACH_TRAPS_IF_DEFINED, MEASURED_MAJORS, MIG_ROUTINES,
    PROFILE, RUN_DENIED_OPERATIONS, SETUP_MIG_ROUTINES_IF_DEFINED, SYSCALLS, Skip,
    SigsysHandler, UNFILTERED_SYSCALLS, api_profile, apply, apply_api, narrowed,
    denied_elsewhere, denied_syscall, files_in_jail, narrow, prepare, profile, profile_for, select,
    selected, set_sigsys_handler,
};

/// Narrows the sandbox to what a running microVM needs, for good. Called
/// where upstream installs the VMM thread's seccomp filter, after the microVM
/// is built (on Linux that thread runs unfiltered until then). On Linux each
/// thread's seccomp filter does this.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn narrow() -> Result<(), SandboxError> {
    Ok(())
}

/// Whether a SIGSYS is the host sandbox denying a system call (upstream's
/// handler then exits as for a seccomp violation). Async-signal-safe.
///
/// # Safety
/// `info` is the siginfo the kernel passed to a SIGSYS handler.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub unsafe fn denied_syscall(_si_code: libc::c_int, _info: *mut libc::siginfo_t) -> bool {
    false
}

#[cfg(target_os = "windows")]
pub use windows::{
    MITIGATIONS, Mitigation, Phase, apply, apply_api, denied_syscall, narrow, select, selected,
};

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
/// Selects the sandbox policy (no effect on Linux, where seccomp is used).
pub fn select(_policy: Policy) {}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
/// Installs the selected sandbox (no effect on Linux, where seccomp is used).
pub fn apply() -> Result<(), SandboxError> {
    Ok(())
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CStr, c_char};
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::{Policy, SandboxError};

    /// Seatbelt profile installed by default on macOS, after the file rule
    /// ([`FILES_ANYWHERE`], or [`files_in_jail`] when the jailer started
    /// Firecracker).
    pub const PROFILE: &str = r#"(version 1)
; Whatever no rule below allows is a denial, except what DENIED_WITH_ERROR
; lists (default_rule): the kernel kills the process inside the denied call
; (the action SIGKILL), where upstream's filters trap the call and its SIGSYS
; handler exits with the bad-syscall code. Seatbelt has no action that stops
; the calling thread alone, and a signal to the process (as SIGSYS was) let
; that thread run on with the call failed (docs/COMPATIBILITY.md).
(deny default)
; Unix sockets only: API server, vsock backends, console. Binding one is
; setup's (RUN_DENIED_OPERATIONS), as on Linux the VMM thread's filter has no
; bind, but for a hot-plugged network device's endpoint (run_rule).
(allow network-inbound (local unix-socket))
(allow network-outbound (remote unix-socket))
; Guest memory backed by POSIX shared memory (memfd_create): only the
; objects this process names for its memfds (shm_rule), as on Linux a memfd
; has no name another process could open.
; Own process only. Information about other processes is not covered by the
; default rule (measured: under (deny default), proc_pidinfo, proc_pidpath and
; proc_listallpids of another process succeed), so it is denied here: it
; fails with an error, as /proc/<pid> of another process is not there in a
; Linux jail (no /proc in the chroot, nor the pid in its PID namespace). A
; signal to another process is a denial (the default rule), as kill is in
; none of upstream's filters. Firecracker's children, the API process, are
; its own: it reads how the API process ended (its exit reason, which only
; the parent may read: xnu bsd/kern/proc_info.c `proc_pidexitreasoninfo`),
; as on Linux the API thread is Firecracker's own.
(allow signal (target self))
(deny process-info*)
(allow process-info* (target self))
(allow process-info-pidinfo (target children))
; No code mapped in: upstream's filters trap mmap and mprotect asking for
; PROT_EXEC. A file mapped executable and a MAP_JIT mapping are denials here
; (without the explicit rule Seatbelt lets a file under /usr/lib be mapped
; executable); an anonymous mapping is the compatibility libc's check
; (libc::wick_mm), turned on by narrow(), which ends the process by a denied
; call (DENIED_CALL_RULE).
(deny file-map-executable (with send-signal SIGKILL))
(deny dynamic-code-generation (with send-signal SIGKILL))
; System calls: only those in SYSCALLS, Mach traps: only those in MACH_TRAPS,
; kernel MIG routines: only those in MIG_ROUTINES, and the kernel's own
; message for a thread's fault (EXCEPTION_MIG_ROUTINES). Any other one is a
; denial, a number the kernel has no call for too (xnu bsd/dev/arm/
; systemcalls.c `unix_syscall` checks such a number as SYS_invalid, which no
; list has), as upstream's filters trap a number they do not list.
(deny syscall-unix (with send-signal SIGKILL))
(deny syscall-mach (with send-signal SIGKILL))
(deny syscall-mig (with send-signal SIGKILL))
; Two phases, as upstream's filters have: setup, until the microVM is built
; (on Linux the VMM thread runs unfiltered until then), and run. What only
; setup needs is allowed until the process holds the narrowed extension,
; which narrow() takes. Then it cannot be undone: no extension can be issued,
; and the Sandbox call that takes one (mac-syscall 6) and every other
; mac-syscall are denials; none releases one.
(deny generic-issue-extension)
(deny system-mac-syscall (with send-signal SIGKILL))
(allow system-mac-syscall (require-all (mac-policy-name "Sandbox") (mac-syscall-number 6)
    (require-not (extension "com.toollyst.wick.narrowed"))))
"#;

    /// The extension that ends the setup phase for good (see [`PROFILE`]).
    const NARROWED: &CStr = c"com.toollyst.wick.narrowed";

    /// The system calls a running microVM may make (`SYS_<name>`,
    /// <sys/syscall.h>): after [`narrow`], where upstream's VMM thread gets
    /// its filter. Each line stands for the rules of upstream's filters
    /// (`resources/seccomp/aarch64-unknown-linux-musl.json`, the union of the
    /// vmm, vcpu and api threads, as one process holds them all here) named in
    /// its comment, and holds what a Firecracker process was measured to call
    /// after narrowing, over every stage of `tools/macos/boot-test.sh`
    /// (`tools/macos/sandbox-discovery.sh`), with each call's
    /// cancellation-point twin (`_nocancel`) and what a panic or a thread's
    /// exit takes.
    ///
    /// Seatbelt skips the rule on the number of the calls of
    /// [`UNFILTERED_SYSCALLS`] (`write`, `open`, `socket`, `ioctl`, ...) when
    /// a rule allows the operation they make, on the macOS majors each says;
    /// for those, that table names the rule that decides each one.
    pub const SYSCALLS: &[&str] = &[
        // mmap, munmap, mprotect, madvise, mincore.
        "mmap", "munmap", "mprotect", "madvise", "mincore",
        // futex.
        "psynch_mutexwait", "psynch_mutexdrop", "psynch_cvbroad", "psynch_cvsignal",
        "psynch_cvwait", "psynch_cvclrprepost", "ulock_wait", "ulock_wake", "ulock_wait2",
        "__semwait_signal", "__semwait_signal_nocancel",
        // futex: the priority a contended lock's owner is lent (libpthread's
        // QoS override), measured after narrowing on a loaded host.
        "bsdthread_ctl",
        // epoll_ctl, epoll_pwait.
        "kevent", "kevent_qos", "kevent_id", "poll", "poll_nocancel",
        // read, readv, write, writev, recvfrom, recvmsg, sendmsg, sendto, lseek.
        "read", "read_nocancel", "readv", "readv_nocancel", "write", "write_nocancel", "writev",
        "writev_nocancel", "pread", "pread_nocancel", "pwrite", "pwrite_nocancel", "recvmsg",
        "recvmsg_nocancel", "recvfrom", "recvfrom_nocancel", "sendmsg", "sendmsg_nocancel",
        "sendto", "sendto_nocancel", "recvmsg_x", "sendmsg_x", "lseek",
        // sendto's address in the jail's network, a path resolved against its
        // directory, which this thread enters for the call (platform::net).
        "__pthread_fchdir",
        // accept4, socket, connect (domains: the network rules); the socket
        // options macOS sets where Linux has MSG_NOSIGNAL and accept4's flags.
        "accept", "accept_nocancel", "socket", "connect", "connect_nocancel", "setsockopt",
        "getsockopt",
        // fstat, newfstatat.
        "fstat64", "stat64", "lstat64", "fstatat64", "fstatfs64",
        // openat, close, fcntl, ioctl (paths and drivers: the file rules).
        "open", "open_nocancel", "openat", "openat_nocancel", "close", "close_nocancel", "fcntl",
        "fcntl_nocancel", "ioctl",
        // eventfd2: an eventfd is an unnamed FIFO here (vmm-sys-util's
        // anonymous_fifo: made, opened, its name removed).
        "mkfifo", "unlink",
        // ftruncate, fallocate, fsync.
        "ftruncate", "fsync", "fsync_nocancel", "fdatasync",
        // msync (MS_SYNC): the pmem device writes its guest's flush to the
        // file (test_pmem.py: denied, the microVM stopped with SIGSYS).
        "msync", "msync_nocancel",
        // What macOS 27 lets through by an operation's rule, not by number
        // (UNFILTERED_SYSCALLS), where an older major's Seatbelt checks the
        // number (15; 26 for getumask and proc_info_extended_id): listed so
        // that every major behaves as 27 does. pwritev (write); the
        // process's own ids and file mode mask, which nothing in Seatbelt
        // limits (getpid names a hot-plugged device's eventfd and timer
        // FIFOs); proc_info_extended_id and terminate_with_payload, which
        // their rules (process-info*, signal) still hold to this process.
        // By reasoning, not discovery: on 27 the number rule is not
        // consulted for them, so a discovery run cannot show who calls them.
        "pwritev", "pwritev_nocancel", "getpid", "getuid", "getgid", "umask", "getumask",
        "issetugid", "proc_info_extended_id", "terminate_with_payload",
        // getrandom, clock_gettime, gettid.
        "getentropy", "gettimeofday", "thread_selfid",
        // clock_gettime(CLOCK_PROCESS_CPUTIME_ID): libc reads the process's
        // CPU clock with getrusage(RUSAGE_SELF) (utils::time's ProcessCpu; the
        // boot timer reads it on a vCPU thread when the guest writes to it,
        // measured: denied, the microVM stopped with SIGSYS). getrusage
        // reports on the process itself or its children only.
        "getrusage",
        // rt_sigaction, rt_sigprocmask, rt_sigreturn, sigaltstack, tkill.
        "sigaction", "sigprocmask", "__pthread_sigmask", "sigreturn", "sigaltstack",
        "__pthread_kill",
        // exit, exit_group: a thread's exit, a worker thread parking, a panic.
        "exit", "bsdthread_terminate", "__disable_threadsignal", "workq_open", "workq_kernreturn",
        "abort_with_payload", "os_fault_with_payload",
        // A cancellation point's EINTR (read, nanosleep, ... interrupted by a
        // handled signal, the vCPU kick's included): libsystem's stub asks
        // whether the calling thread was cancelled before it returns the
        // error (Libsyscall custom/errno.c `cerror`, libpthread
        // `_pthread_exit_if_canceled`). The call reads or sets the calling
        // thread's own cancellation state only (XNU bsd/kern/kern_sig.c
        // `__pthread_canceled`); no thread is ever marked cancelled here
        // (__pthread_markcancel is in no list), so the answer is always no.
        // Never seen in discovery: only a signal landing inside a blocking
        // call takes that path (test_a_handled_signal_interrupts_a_blocking_call).
        "__pthread_canceled",
    ];

    /// What decides a system call of [`UNFILTERED_SYSCALLS`] in this
    /// profile, after [`narrow`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Limit {
        /// No rule allows the operation the call makes, so the rule on its
        /// number decides: it is in none of the lists, and is a denial.
        Number,
        /// The rule of this operation (or these, space separated): a call
        /// it denies is a denial (the kernel's kill).
        Signal(&'static str),
        /// The rule of this operation: a call it denies fails with `EPERM`,
        /// as a path outside the chroot or another process's `/proc` entry
        /// does on Linux.
        Error(&'static str),
        /// No rule allows what it asks for, and the default rule denies it;
        /// no single operation's rule lifts it (measured for `link`: with
        /// files, and every other class of operation, allowed, it is still
        /// denied; only `(allow default)` lets it run).
        Default,
        /// Allowed after narrowing, as the rule of upstream's filters named
        /// allows it, with no argument checked there (descriptors are opened
        /// under the file rule).
        Upstream(&'static str),
        /// Nothing in Seatbelt decides it, for the reason given: the call
        /// runs (or the kernel itself refuses it, as said).
        Impossible(&'static str),
    }

    /// The macOS majors where [`UNFILTERED_SYSCALLS`] was measured
    /// (`test_seatbelt_skips_the_number_of_these` on each, which the CI
    /// macOS matrix runs: .github/workflows/ci.yml). On another major that
    /// test and `test_unfiltered_syscalls_are_limited_by_their_rule` fail,
    /// naming it, the first with what it measured there.
    pub const MEASURED_MAJORS: &[u32] = &[15, 26, 27];

    /// The calls of [`UNFILTERED_SYSCALLS`] a measured major's kernel does
    /// not have: their number is `nosys`, which raises SIGSYS itself, with
    /// or without a sandbox, and their libsandbox has no `SYS_` name for
    /// them. Measured on each major by running the call with no sandbox
    /// (`test_seatbelt_skips_the_number_of_these`).
    pub const ABSENT: &[(&str, &[u32])] = &[("getumask", &[15, 26])];

    /// On which of [`MEASURED_MAJORS`] Seatbelt skips the rule on a call's
    /// number.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Skip {
        /// On every measured major.
        All,
        /// On these majors only: on the other measured ones the rule on its
        /// number decides, as for a call outside the table.
        On(&'static [u32]),
    }

    impl Skip {
        /// Whether Seatbelt skips the rule on the number on macOS `major`.
        pub fn on(self, major: u32) -> bool {
            match self {
                Skip::All => true,
                Skip::On(majors) => majors.contains(&major),
            }
        }
    }

    /// The system calls whose number Seatbelt does not check when a rule
    /// allows the operation they make (measured on each of
    /// [`MEASURED_MAJORS`]: under `(allow default)` each one runs with a rule
    /// denying its number, `test_seatbelt_skips_the_number_of_these`), on
    /// which majors ([`Skip`]), with the rule of this profile that decides
    /// each one after [`narrow`]
    /// (`test_unfiltered_syscalls_are_limited_by_their_rule`). For the others,
    /// and for these on a major where the number is checked, the rule on the
    /// number decides ([`SYSCALLS`]).
    #[rustfmt::skip]
    pub const UNFILTERED_SYSCALLS: &[(&str, u16, Limit, Skip)] = &[
        ("exit", 1, Limit::Upstream("exit"), Skip::All),
        ("fork", 2, Limit::Signal("process-fork"), Skip::All),
        ("write", 4, Limit::Upstream("write"), Skip::All),
        ("open", 5, Limit::Error("file-read* file-write*"), Skip::All),
        ("close", 6, Limit::Upstream("close"), Skip::All),
        ("link", 9, Limit::Default, Skip::All),
        ("unlink", 10, Limit::Signal("file-write-unlink"), Skip::All),
        ("mknod", 14, Limit::Number, Skip::All),
        ("chmod", 15, Limit::Signal("file-write-mode"), Skip::All),
        ("chown", 16, Limit::Signal("file-write-owner"), Skip::All),
        ("getpid", 20, Limit::Impossible(NO_OPERATION), Skip::On(&[26, 27])),
        ("getuid", 24, Limit::Impossible(NO_OPERATION), Skip::On(&[26, 27])),
        ("ptrace", 26, Limit::Signal("system-debug"), Skip::All),
        ("chflags", 34, Limit::Signal("file-write-flags"), Skip::All),
        ("fchflags", 35, Limit::Signal("file-write-flags"), Skip::All),
        ("kill", 37, Limit::Signal("signal"), Skip::All),
        ("getgid", 47, Limit::Impossible(NO_OPERATION), Skip::On(&[26, 27])),
        ("acct", 51, Limit::Signal("system-acct"), Skip::All),
        ("ioctl", 54, Limit::Signal("file-ioctl"), Skip::All),
        ("reboot", 55, Limit::Signal("system-reboot"), Skip::All),
        ("revoke", 56, Limit::Signal("file-revoke"), Skip::All),
        ("umask", 60, Limit::Impossible(NO_OPERATION), Skip::On(&[26, 27])),
        ("chroot", 61, Limit::Signal("file-chroot"), Skip::All),
        ("swapon", 85, Limit::Signal("system-swap"), Skip::All),
        ("setpriority", 96, Limit::Signal("system-sched"), Skip::All),
        ("socket", 97, Limit::Signal("system-socket"), Skip::All),
        ("connect", 98, Limit::Signal("network-outbound"), Skip::All),
        ("getpriority", 100, Limit::Signal("system-sched"), Skip::All),
        ("bind", 104, Limit::Signal("network-bind"), Skip::All),
        ("writev", 121, Limit::Upstream("writev"), Skip::All),
        ("fchown", 123, Limit::Signal("file-write-owner"), Skip::All),
        ("fchmod", 124, Limit::Signal("file-write-mode"), Skip::All),
        ("utimes", 138, Limit::Signal("file-write-times"), Skip::All),
        ("futimes", 139, Limit::Signal("file-write-times"), Skip::All),
        ("pwrite", 154, Limit::Upstream("write"), Skip::All),
        ("nfssvc", 155, Limit::Signal("system-nfssvc"), Skip::All),
        ("unmount", 159, Limit::Signal("file-unmount"), Skip::All),
        ("quotactl", 165, Limit::Impossible(QUOTAS), Skip::All),
        ("mount", 167, Limit::Signal("file-mount"), Skip::All),
        ("csops", 169, Limit::Signal("process-codesigning*"), Skip::All),
        ("csops_audittoken", 170, Limit::Signal("process-codesigning*"), Skip::All),
        ("sysctl", 202, Limit::Signal("sysctl-read"), Skip::All),
        ("undelete", 205, Limit::Impossible(WHITEOUTS), Skip::All),
        ("getumask", 215, Limit::Impossible(NO_OPERATION), Skip::On(&[27])),
        ("searchfs", 225, Limit::Signal("file-search"), Skip::All),
        ("setxattr", 236, Limit::Signal("file-write-xattr"), Skip::All),
        ("fsetxattr", 237, Limit::Signal("file-write-xattr"), Skip::All),
        ("removexattr", 238, Limit::Signal("file-write-xattr"), Skip::All),
        ("fremovexattr", 239, Limit::Signal("file-write-xattr"), Skip::All),
        ("fsctl", 242, Limit::Signal("system-fsctl file-fsctl"), Skip::All),
        ("ffsctl", 245, Limit::Signal("system-fsctl file-fsctl"), Skip::All),
        ("semctl", 254, Limit::Signal("ipc-sysv*"), Skip::All),
        ("semget", 255, Limit::Signal("ipc-sysv*"), Skip::All),
        ("semop", 256, Limit::Signal("ipc-sysv*"), Skip::All),
        ("msgctl", 258, Limit::Signal("ipc-sysv*"), Skip::All),
        ("msgget", 259, Limit::Signal("ipc-sysv*"), Skip::All),
        ("msgsnd", 260, Limit::Signal("ipc-sysv*"), Skip::All),
        ("msgrcv", 261, Limit::Signal("ipc-sysv*"), Skip::All),
        ("shmat", 262, Limit::Signal("ipc-sysv*"), Skip::All),
        ("shmctl", 263, Limit::Signal("ipc-sysv*"), Skip::All),
        ("shmdt", 264, Limit::Signal("ipc-sysv*"), Skip::All),
        ("shmget", 265, Limit::Signal("ipc-sysv*"), Skip::All),
        ("shm_open", 266, Limit::Signal("ipc-posix-shm*"), Skip::All),
        ("shm_unlink", 267, Limit::Signal("ipc-posix-shm*"), Skip::All),
        ("sem_open", 268, Limit::Signal("ipc-posix-sem*"), Skip::All),
        ("sem_close", 269, Limit::Number, Skip::All),
        ("sem_unlink", 270, Limit::Signal("ipc-posix-sem*"), Skip::All),
        ("sem_wait", 271, Limit::Number, Skip::All),
        ("sem_trywait", 272, Limit::Number, Skip::All),
        ("sem_post", 273, Limit::Number, Skip::All),
        ("sysctlbyname", 274, Limit::Signal("sysctl-read"), Skip::All),
        ("chmod_extended", 282, Limit::Signal("file-write-mode file-write-acl"), Skip::All),
        ("fchmod_extended", 283, Limit::Signal("file-write-mode file-write-acl"), Skip::All),
        ("issetugid", 327, Limit::Impossible(NO_OPERATION), Skip::On(&[26, 27])),
        ("__pthread_kill", 328, Limit::Upstream("tkill"), Skip::On(&[26, 27])),
        ("proc_info", 336, Limit::Error("process-info*"), Skip::All),
        ("lchown", 364, Limit::Signal("file-write-owner"), Skip::All),
        ("write_nocancel", 397, Limit::Upstream("write"), Skip::All),
        ("open_nocancel", 398, Limit::Error("file-read* file-write*"), Skip::All),
        ("close_nocancel", 399, Limit::Upstream("close"), Skip::All),
        ("connect_nocancel", 409, Limit::Signal("network-outbound"), Skip::All),
        ("writev_nocancel", 412, Limit::Upstream("writev"), Skip::All),
        ("pwrite_nocancel", 415, Limit::Upstream("write"), Skip::All),
        ("msgsnd_nocancel", 418, Limit::Signal("ipc-sysv*"), Skip::All),
        ("msgrcv_nocancel", 419, Limit::Signal("ipc-sysv*"), Skip::All),
        ("sem_wait_nocancel", 420, Limit::Number, Skip::All),
        ("pid_suspend", 433, Limit::Signal("system-suspend-resume"), Skip::All),
        ("pid_resume", 434, Limit::Signal("system-suspend-resume"), Skip::All),
        ("connectx", 447, Limit::Signal("network-outbound"), Skip::All),
        ("clonefileat", 462, Limit::Signal("file-clone"), Skip::All),
        ("openat", 463, Limit::Error("file-read* file-write*"), Skip::All),
        ("openat_nocancel", 464, Limit::Error("file-read* file-write*"), Skip::All),
        ("fchmodat", 467, Limit::Signal("file-write-mode"), Skip::All),
        ("fchownat", 468, Limit::Signal("file-write-owner"), Skip::All),
        ("linkat", 471, Limit::Default, Skip::All),
        ("unlinkat", 472, Limit::Signal("file-write-unlink"), Skip::All),
        ("fclonefileat", 517, Limit::Signal("file-clone"), Skip::All),
        ("fs_snapshot", 518, Limit::Signal("fs-snapshot*"), Skip::All),
        ("terminate_with_payload", 520, Limit::Signal("signal"), Skip::On(&[26, 27])),
        ("abort_with_payload", 521, Limit::Upstream("exit_group"), Skip::On(&[26, 27])),
        ("fmount", 526, Limit::Signal("file-mount"), Skip::All),
        ("pwritev", 541, Limit::Upstream("writev"), Skip::On(&[26, 27])),
        ("pwritev_nocancel", 543, Limit::Upstream("writev"), Skip::On(&[26, 27])),
        ("proc_info_extended_id", 545, Limit::Error("process-info*"), Skip::On(&[27])),
    ];

    /// Why a call of [`UNFILTERED_SYSCALLS`] has no limit: it asks only
    /// about the process itself, or sets its own file mode mask.
    const NO_OPERATION: &str = "Seatbelt has no operation for it and skips its number: \
        it asks about the process itself (or sets its own file mode mask)";
    /// Why `quotactl` has none.
    const QUOTAS: &str = "Seatbelt has no operation for it; it fails with ENOTSUP here \
        (APFS keeps no quotas)";
    /// Why `undelete` has none.
    const WHITEOUTS: &str = "Seatbelt has no operation for it; it removes a whiteout, which \
        only a union mount has, and fails with EPERM on any other file";

    /// System calls allowed until [`narrow`] only, in addition to
    /// [`SYSCALLS`]: what building the microVM takes (on Linux the VMM thread
    /// runs unfiltered until then), measured as [`SYSCALLS`] are.
    pub const SETUP_SYSCALLS: &[&str] = &[
        "geteuid", "access", "dup", "pipe", "getegid", "dup2", "bind",
        "listen", "socketpair", "csops", "csops_audittoken",
        "kdebug_typefilter", "kdebug_trace_string", "kdebug_trace64", "getrlimit", "sysctl",
        "getattrlist", "shm_open", "shm_unlink", "gettid", "proc_info",
        "getdirentries64", "bsdthread_create", "kqueue", "sigsuspend_nocancel", "fileport_makefd",
        // vmnet.framework's XPC connection reads the process's persona once
        // the process forked (the API process, ext::api_process): measured,
        // syscall-unix 494 in the sandbox's report.
        "persona",
        // The Sandbox call narrow() takes the narrowed extension with
        // (PROFILE's system-mac-syscall rules).
        "__mac_syscall",
        // platform::net::bind: openers of endpoints in one directory take
        // turns under its flock, so that a stale socket file is replaced
        // once and a live one is refused with EBUSY, as a TAP another file
        // holds (test_openers_of_a_stale_name_take_turns). Once narrowed a
        // bind replaces nothing and takes no turn.
        "flock",
    ];

    /// The Mach traps a running microVM may make (`MSC_<name>`, XNU's
    /// osfmk/kern/syscall_sw.c), the other way into the kernel on macOS, each
    /// line for the Linux rules in its comment, measured as [`SYSCALLS`] are.
    /// Not in it: anything reaching another task (`task_for_pid`,
    /// `pid_for_task`, `task_name_for_pid`), IOKit, swap control, debugging.
    pub const MACH_TRAPS: &[&str] = &[
        // mmap, munmap, mprotect.
        "_kernelrpc_mach_vm_allocate_trap", "_kernelrpc_mach_vm_deallocate_trap",
        "_kernelrpc_mach_vm_protect_trap", "_kernelrpc_mach_vm_map_trap",
        // close: port rights of its own task (libdispatch, Hypervisor.framework).
        "_kernelrpc_mach_port_deallocate_trap", "_kernelrpc_mach_port_mod_refs_trap",
        "_kernelrpc_mach_port_construct_trap", "_kernelrpc_mach_port_destruct_trap",
        // futex.
        "semaphore_signal_trap", "semaphore_wait_trap", "semaphore_timedwait_trap",
        // sendmsg, recvmsg: Mach messages, to libdispatch and Hypervisor.framework.
        "mach_msg2_trap", "thread_get_special_reply_port",
        // sched_yield (a contended lock yields).
        "swtch_pri", "syscall_thread_switch",
    ];

    /// Mach traps allowed until [`narrow`] only, in addition to [`MACH_TRAPS`].
    pub const SETUP_MACH_TRAPS: &[&str] = &[
        "_kernelrpc_mach_port_guard_trap", "_kernelrpc_mach_port_type_trap",
        "_kernelrpc_mach_port_insert_right_trap", "_kernelrpc_mach_port_request_notification_trap",
        "host_self_trap", "mach_timebase_info_trap", "mach_generate_activity_id",
        "host_create_mach_voucher_trap", "mach_reply_port", "task_self_trap", "thread_self_trap",
    ];

    /// The kernel's MIG routines a running microVM may call: the services of
    /// kernel objects a Mach message (`mach_msg2_trap`) reaches, by the
    /// kernel's names for them, measured as [`SYSCALLS`] are: the clock
    /// `nanosleep` waits on (clock_nanosleep), semaphores (futex), mapping and
    /// inspecting its own memory (mmap, mremap, mincore), and its own task's
    /// special ports. Not in it: setting special or exception ports, other
    /// tasks' threads or state, host special ports, XPC connections.
    pub const MIG_ROUTINES: &[&str] = &[
        "clock_get_time", "semaphore_create", "semaphore_destroy", "mach_vm_map_external",
        "mach_vm_remap_external", "mach_vm_region", "task_get_special_port_from_user",
    ];

    /// The message by which the kernel turns a thread's fault or trap into
    /// its signal, allowed in every phase and in the API process's profile.
    /// Not a call of Firecracker's: the kernel sends it itself, on the
    /// faulting thread, to the host's exception port (XNU
    /// osfmk/kern/exception.c `exception_triage_thread`, `exception_deliver`:
    /// the port's behaviour is EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, so
    /// the message is `mach_exception_raise`; the port is the kernel object
    /// bsd/uxkern/ux_handler.c `ux_handler_setup` installs), and a message to
    /// a kernel object is served on the sending thread after a check against
    /// its task's MIG filter (osfmk/kern/ipc_kobject.c
    /// `ipc_kobject_server_internal`: `task_get_mach_kobj_filter_mask(curtask)`,
    /// `mac_task_kobj_msg_evaluate`). macOS 15 denies it there when it is not
    /// listed ("deny(1) syscall-mig 53", CI run 43396747298, 15.8.2): the
    /// message fails, the thread goes back to the instruction
    /// (`thread_exception_return`) and faults again (hundreds of reports for
    /// one process), and the process gets the denial's kill in place of
    /// SIGSEGV, SIGBUS or SIGTRAP. macOS 26 and 27 do not consult the filter
    /// for it (the same tests pass without the allowance). On Linux the
    /// kernel raises a fault's signal with no call a filter sees.
    ///
    /// What the allowance gives the process itself (SECURITY.md, the system
    /// call filter): the kernel finds a kernel object's routine by the
    /// message's id alone (ipc_kobject.c `mig_init`, `find_mig_hash_entry`),
    /// so this id passes the filter whichever kernel object the process sends
    /// it to, and runs `catch_mach_exception_raise` (ux_handler.c), which
    /// fails unless the port is the host's exception port. The process holds
    /// no send right to that port and nothing allowed gives it one
    /// (`host_get_exception_ports`, `task_get_exception_ports`,
    /// `thread_get_exception_ports` and the swap routines are in no list; the
    /// host's privileged port is denied, `mach-priv-host-port`, and so are
    /// Mach lookups). With one, it could only raise the exception's signal on
    /// the thread whose port it puts in the message (ux_exception.c
    /// `handle_ux_exception`), and the only thread ports it can name are its
    /// own threads', which it can already signal (`__pthread_kill`). The API
    /// process sends no Mach message at all (no `mach_msg2_trap` in
    /// [`API_MACH_TRAPS`]). `test_an_exception_message_of_its_own_does_nothing`.
    pub const EXCEPTION_MIG_ROUTINES: &[&str] = &["mach_exception_raise"];

    /// The rule for [`EXCEPTION_MIG_ROUTINES`], where Seatbelt knows the
    /// name, as for [`SETUP_MIG_ROUTINES_IF_DEFINED`]: a profile naming a
    /// routine its major's Seatbelt does not know does not compile at all.
    /// Known on macOS 27 (`sandbox-exec`, `defined?`) and on 15, where the
    /// allowance matters: there `test_a_fault_is_its_signal_under_each_profile`
    /// and the fault and trap cases of
    /// `test_the_other_ends_are_unchanged_without_a_denied_call` pass with it
    /// (CI run 43403250054, macos-15, 15.8.2), and would fail if a fault
    /// still ended by the sandbox's kill, the name being unknown or not the
    /// routine denied.
    fn exception_rule() -> String {
        EXCEPTION_MIG_ROUTINES
            .iter()
            .map(|name| {
                format!("(when (defined? '{name}) (allow syscall-mig (kernel-mig-routine {name})))\n")
            })
            .collect()
    }

    /// System calls a running microVM makes only where PV steal time is
    /// offered (macOS 27, `kvm_ioctls::pv_time_offered`; nowhere else is
    /// either list in the profile): a vCPU thread reads its own CPU time,
    /// clock_gettime(CLOCK_THREAD_CPUTIME_ID), which libc makes
    /// thread_selfusage (XNU bsd/kern/kern_resource.c: the calling
    /// thread's runtime, `thread_get_runtime_self`, nothing else; measured:
    /// without it the microVM stopped with SIGSYS at its first run).
    /// Linux's VMM filter has clock_gettime.
    pub const PVTIME_SYSCALLS: &[&str] = &["thread_selfusage"];

    /// MIG routines a running microVM calls only where PV steal time is
    /// offered: the PV time kicker (kvm-ioctls hvf::pvtime::Kicker) reads a
    /// vCPU thread's run state and CPU time with `thread_info`. XNU's
    /// routine takes a thread inspect port (osfmk/mach/thread_act.defs
    /// `thread_info`) and only reads (osfmk/kern/thread.c
    /// `thread_info_internal`: basic, identifier, scheduling and extended
    /// information; the debug flavor only on DEVELOPMENT kernels). The
    /// ports it can name are this process's own threads': no rule lets it
    /// reach another task's (task_for_pid, task_threads and the task name
    /// traps stay denied). On Linux KVM reads the vCPU thread's run delay in
    /// the kernel, with no call of the VMM's: this stands for no rule of
    /// upstream's filter, and gives a compromised VMM only its own threads'
    /// state, which it can already observe.
    pub const PVTIME_MIG_ROUTINES: &[&str] = &["thread_info"];

    /// MIG routines allowed until [`narrow`] only, in addition to
    /// [`MIG_ROUTINES`].
    pub const SETUP_MIG_ROUTINES: &[&str] = &[
        "host_get_clock_service", "_mach_make_memory_entry", "mach_memory_entry_ownership",
        "mach_vm_copy", "host_info", "task_info_from_user",
        "mach_port_set_attributes", "mach_port_request_notification",
        "mach_port_get_context_from_user", "task_restartable_ranges_register",
        "mach_voucher_attr_command",
        // A vCPU thread's latency tier, set by the thread that makes it
        // while the microVM is built (ext::vcpu_thread; Linux's vCPU threads
        // need no counterpart). Setup's only: the routine sets any policy of
        // any thread of the task.
        "thread_policy_set",
    ];

    /// MIG routines of the setup phase that macOS 26 added (measured on
    /// macOS 27: a guest's memory is reallocated by libmalloc through them;
    /// on macOS 15 the names are unbound and a profile naming them does not
    /// compile, measured by CI's macos-15 job), allowed where the kernel
    /// defines them. An explicit list, so that a misspelt name in
    /// [`SETUP_MIG_ROUTINES`] or [`MIG_ROUTINES`] still fails to compile.
    pub const SETUP_MIG_ROUTINES_IF_DEFINED: &[&str] = &["mach_vm_reallocate", "vm_reallocate"];

    /// Mach traps of [`MACH_TRAPS`]' kind that only newer macOS releases have
    /// (allowed where Seatbelt knows them). Measured: libmalloc's deferred
    /// reclamation.
    pub const MACH_TRAPS_IF_DEFINED: &[&str] = &["mach_vm_reclaim_update_kernel_accounting_trap"];

    /// The API process's system calls (`ext::api_process`), each line the
    /// rule of upstream's `api` filter it stands for: an HTTP server on a
    /// socket it already listens on.
    #[rustfmt::skip]
    pub const API_SYSCALLS: &[&str] = &[
        // accept4.
        "accept", "accept_nocancel",
        // read, recvfrom, recvmsg, sendto, write.
        "read", "read_nocancel", "readv", "readv_nocancel", "write", "write_nocancel", "writev",
        "writev_nocancel", "recvfrom", "recvfrom_nocancel", "recvmsg", "recvmsg_nocancel",
        "sendto", "sendto_nocancel", "sendmsg", "sendmsg_nocancel",
        // epoll_ctl, epoll_pwait.
        "kevent", "kevent_qos", "kevent_id",
        // openat (paths: none, the profile has no file rule), close, fcntl,
        // ioctl (FIONBIO), fstat.
        "open", "open_nocancel", "openat", "openat_nocancel", "close", "close_nocancel", "fcntl",
        "fcntl_nocancel", "ioctl", "fstat64",
        // mmap, munmap, madvise (brk, mremap: macOS's allocator maps).
        "mmap", "munmap", "madvise",
        // futex.
        "psynch_mutexwait", "psynch_mutexdrop", "psynch_cvbroad", "psynch_cvsignal",
        "psynch_cvwait", "psynch_cvclrprepost", "ulock_wait", "ulock_wake", "ulock_wait2",
        // getrandom, clock_gettime, gettid.
        "getentropy", "gettimeofday", "thread_selfid",
        // rt_sigaction, rt_sigprocmask, rt_sigreturn, sigaltstack, tkill.
        "sigaction", "sigprocmask", "__pthread_sigmask", "sigreturn", "sigaltstack",
        "__pthread_kill",
        // exit, exit_group: a thread's exit, a panic.
        "exit", "bsdthread_terminate", "__disable_threadsignal", "abort_with_payload",
        "os_fault_with_payload",
        // As in SYSCALLS: a cancellation point's EINTR.
        "__pthread_canceled",
        // As in SYSCALLS: what macOS 27 lets through by an operation's rule
        // where an older major checks the number, so that every major
        // behaves as 27 (the API process's profile has no file rule, so
        // pwritev reaches no file; getpid: api_process's own checks).
        "pwritev", "pwritev_nocancel", "getpid", "getuid", "getgid", "umask", "getumask",
        "issetugid", "proc_info_extended_id", "terminate_with_payload",
    ];

    /// The API process's Mach traps: memory (mmap, munmap), port rights of
    /// its own task (close), futex, sched_yield.
    #[rustfmt::skip]
    pub const API_MACH_TRAPS: &[&str] = &[
        "_kernelrpc_mach_vm_allocate_trap", "_kernelrpc_mach_vm_deallocate_trap",
        "_kernelrpc_mach_vm_map_trap", "_kernelrpc_mach_port_deallocate_trap",
        "_kernelrpc_mach_port_mod_refs_trap", "_kernelrpc_mach_port_construct_trap",
        "_kernelrpc_mach_port_destruct_trap", "semaphore_signal_trap", "semaphore_wait_trap",
        "swtch_pri", "syscall_thread_switch",
    ];

    /// The API process's kernel MIG routines.
    pub const API_MIG_ROUTINES: &[&str] = &["mach_vm_map_external"];

    /// The API process's rules, after [`default_rule`]: as [`PROFILE`]'s,
    /// without shared memory and the setup phase.
    pub const API_PROFILE: &str = r#"(allow network-inbound (local unix-socket))
(allow network-outbound (remote unix-socket))
(allow signal (target self))
(deny process-info*)
(allow process-info* (target self))
(deny file-map-executable (with send-signal SIGKILL))
(deny dynamic-code-generation (with send-signal SIGKILL))
(deny syscall-unix (with send-signal SIGKILL))
(deny syscall-mach (with send-signal SIGKILL))
(deny syscall-mig (with send-signal SIGKILL))
(deny generic-issue-extension)
(deny system-mac-syscall (with send-signal SIGKILL))
"#;

    /// The API process's profile: only its lists, no files, Unix sockets only
    /// (the API socket, the link to Firecracker), no setup phase (on Linux
    /// the API thread's filter is installed before it serves).
    #[allow(unexpected_cfgs)]
    pub fn api_profile() -> String {
        let mut rule = format!("(version 1)\n{}{API_PROFILE}", default_rule());
        rule.push_str(&api_discovery_rule());
        rule.push_str(&allow("syscall-unix", "", "syscall-number", "SYS_", API_SYSCALLS));
        rule.push_str(&allow("syscall-mach", "", "machtrap-number", "MSC_", API_MACH_TRAPS));
        rule.push_str(&allow("syscall-mig", "", "kernel-mig-routine", "", API_MIG_ROUTINES));
        rule.push_str(&exception_rule());
        rule.push_str(&fcntl_rule("", API_FCNTL_COMMANDS));
        rule.push_str(DENIED_CALL_RULE);
        rule
    }

    /// The discovery build's rule for the API process: every call outside
    /// its lists is allowed and reported.
    #[allow(unexpected_cfgs)]
    fn api_discovery_rule() -> String {
        #[cfg(wick_sandbox_discovery)]
        return "(allow syscall-unix syscall-mach syscall-mig (with report))\n".to_owned();
        #[allow(unreachable_code)]
        String::new()
    }

    /// Installs the API process's sandbox ([`api_profile`]) and the check of
    /// executable mappings, unless the sandbox is off (`--no-seccomp`).
    #[allow(unexpected_cfgs)]
    pub fn apply_api() -> Result<(), SandboxError> {
        let mut state = STATE.lock().unwrap();
        if state.policy == Policy::None || state.installed {
            return Ok(());
        }
        install_compiled(&compiled_api_profile()?)?;
        state.installed = true;
        state.narrowed_done = true;
        if !cfg!(wick_sandbox_discovery) {
            libc::wick_mm::deny_exec(exec_denied);
            // Upstream's api filter: madvise with MADV_DONTNEED only.
            libc::wick_mm::allow_only_advice(libc::MADV_DONTNEED, exec_denied);
        }
        Ok(())
    }

    /// File rule without the jailer: guest kernels, disks, snapshots, logs,
    /// metrics and the API socket are chosen by the operator, also after
    /// start-up (hot-plug, snapshots), as on Linux without the jailer.
    pub const FILES_ANYWHERE: &str = "(allow file-read* file-write*)\n";

    /// A path for a profile: absolute, quoted.
    fn quoted(path: &Path, what: &str) -> Result<String, SandboxError> {
        let path = path
            .to_str()
            .filter(|r| r.starts_with('/') && !r.contains(['\0', '\n']))
            .ok_or_else(|| SandboxError::Install(format!("{what} path {path:?}")))?;
        Ok(path.replace('\\', "\\\\").replace('"', "\\\""))
    }

    /// A regular expression for a profile that matches the names directly in
    /// the directory `path` (absolute), and nothing below them.
    fn names_directly_in(path: &Path, what: &str) -> Result<String, SandboxError> {
        let path = path
            .to_str()
            .filter(|r| r.starts_with('/') && !r.contains(['\0', '\n', '"']))
            .ok_or_else(|| SandboxError::Install(format!("{what} path {path:?}")))?;
        let mut regex = String::from("^");
        for c in path.chars() {
            if "\\.^$*+?()[]{}|".contains(c) {
                regex.push('\\');
            }
            regex.push(c);
        }
        Ok(format!("(regex #\"{}/[^/]+$\")", regex.trim_end_matches('/')))
    }

    /// File rule in a jail: only the jail directory, by its path outside the
    /// chroot (Seatbelt matches the real path of a file, and the chroot
    /// already hides everything else; this also covers descriptors opened
    /// before the chroot).
    ///
    /// With the jail's network (`netns`, the jail's own directory in the
    /// network directory `--netns` names, `<network>/<id>`): also the Unix
    /// sockets in that directory and nothing else there, as on Linux a
    /// network namespace gives its interfaces and no file; and the sockets
    /// directly in the network directory, the operator's switch's, to send
    /// to and to look at, not to make, remove or replace; and who owns the
    /// network directory (its metadata: an endpoint takes as peers the
    /// sockets of that owner, `platform::net`'s `Switch`). No other
    /// directory of the network: another jail's endpoints are out of reach
    /// whatever their files' permissions (two jails of one uid are told
    /// apart by this rule alone). The jail's directory is reached through a
    /// descriptor opened before the chroot, from which a relative path
    /// climbs out (`..`), so Unix sockets are then connected to only in the
    /// jail, in the jail's directory and directly in the network: file
    /// rules do not cover `connect` or `sendto` (measured: both reach a
    /// socket elsewhere with only the file rules), `network-outbound` does.
    pub fn files_in_jail(root: &Path, netns: Option<&Path>) -> Result<String, SandboxError> {
        let root = quoted(root, "jail")?;
        let mut rule = format!("(allow file-read* file-write* (subpath \"{root}\"))\n");
        if let Some(netns) = netns {
            let network = netns
                .parent()
                .ok_or_else(|| SandboxError::Install(format!("network path {netns:?}")))?;
            let switch = names_directly_in(network, "network")?;
            let network = quoted(network, "network")?;
            let netns = quoted(netns, "network")?;
            rule.push_str(&format!(
                "(allow file-read* file-write* (require-all (subpath \"{netns}\") (vnode-type SOCKET)))\n\
                 (allow file-read-metadata file-write-data (require-all {switch} (vnode-type SOCKET)))\n\
                 (allow file-read-metadata (literal \"{network}\"))\n\
                 (deny network-outbound (remote unix-socket))\n\
                 (allow network-outbound (remote unix-socket (subpath \"{root}\")) \
                 (remote unix-socket (subpath \"{netns}\")) (remote unix-socket {switch}))\n"
            ));
        }
        Ok(rule)
    }

    /// The profile for this process.
    pub fn profile() -> Result<String, SandboxError> {
        profile_for(crate::ext::jail::root(), crate::ext::jail::netns())
    }

    /// The profile for a process in the jail at `root` (`None`: no jail),
    /// with the jail's network `netns` if it has one.
    pub fn profile_for(root: Option<&Path>, netns: Option<&Path>) -> Result<String, SandboxError> {
        let files = match root {
            Some(root) => files_in_jail(root, netns)?,
            None => FILES_ANYWHERE.to_owned(),
        };
        let profile = PROFILE.replacen("(deny default)\n", &default_rule(), 1);
        Ok(format!(
            "{profile}{}{}{}{files}{}{}{DENIED_CALL_RULE}",
            shm_rule(std::process::id()),
            syscall_rule(),
            operation_rule(),
            run_rule(root, netns)?,
            unlink_rule(root, std::process::id())?
        ))
    }

    /// The system call a check of the compatibility libc's ends the process
    /// by, as a denial ([`exec_denied`]), last in both profiles so that no
    /// rule allows it: SYS_invalid (63), the slot xnu's `unix_syscall`
    /// checks and runs for any number it has no call for (bsd/dev/arm/
    /// systemcalls.c: `syscode = (code < nsysent) ? code : SYS_invalid`).
    /// Its entry is `nosys` (bsd/kern/syscalls.master: "used internally and
    /// reserved"), which does nothing but fail: were it ever let through, it
    /// would change nothing, and [`exec_denied`] ends the process anyway.
    const DENIED_CALL: u16 = 63;
    const DENIED_CALL_RULE: &str = "(deny syscall-unix (syscall-number SYS_invalid) (with send-signal SIGKILL))\n";

    /// The POSIX shared memory objects of the process `pid`: the names the
    /// compatibility memfd gives them (`/fcm.<pid>.<n>`, and
    /// `/fcmH.<pid>.<n>` for a huge page one, `libc::HUGE_MEMFD_PREFIX`;
    /// made and unlinked at once). Another name is a denial (the default
    /// rule): on Linux a memfd has no name another process could
    /// open.
    fn shm_rule(pid: u32) -> String {
        format!(
            "(allow ipc-posix-shm* (ipc-posix-name-prefix \"/fcm.{pid}.\") \
             (ipc-posix-name-prefix \"{}{pid}.\"))\n",
            libc::HUGE_MEMFD_PREFIX
        )
    }

    /// The names a running microVM may remove (`unlink`, `unlinkat`; also
    /// `rmdir` and the old name of `rename`, which Seatbelt decides by the
    /// same operation, `file-write-unlink`), after [`narrow`]: its own
    /// eventfds' and timers' FIFOs only, which vmm-sys-util names
    /// `.eventfd-<pid>-<n>` and the compatibility libc `.timerfd-<pid>-<n>`
    /// in the temporary directory and remove once open (an eventfd made when
    /// the guest activates a device; a timer made for a hot-plugged device's
    /// rate limiter, where Linux's filter allows `timerfd_create`). Any other
    /// name is a denial, as upstream's
    /// filters have no `unlink` (Linux's eventfd and tap have no name): a
    /// network endpoint's socket is left behind when the device goes, as
    /// the API socket is, and the next bind at the path replaces a stale one
    /// (`platform::net::bind`); a running microVM may not remove it or any
    /// other socket (a compromised unjailed VMM would reach the user's other
    /// sockets). The file rule's other operations are unchanged. Seatbelt
    /// matches the real path, so the directory is given by its: in a jail
    /// (`root`), its `/tmp` (the jailer's `TMPDIR`) by its path outside;
    /// outside a jail, the temporary directory.
    ///
    /// Memfds take no name a microVM removes: their shared memory objects
    /// are `shm_rule`'s (`shm_unlink` is decided by `ipc-posix-shm*`), and
    /// the compatibility libc's `memfd_create`, which makes a file, is not
    /// called by Firecracker.
    #[allow(unexpected_cfgs)]
    fn unlink_rule(root: Option<&Path>, pid: u32) -> Result<String, SandboxError> {
        let tmp = std::env::temp_dir();
        let tmp = match root {
            Some(root) => {
                let inside = tmp
                    .strip_prefix("/")
                    .map_err(|_| SandboxError::Install(format!("temporary directory {tmp:?}")))?;
                root.join(inside)
            }
            None => tmp
                .canonicalize()
                .map_err(|err| SandboxError::Install(format!("temporary directory {tmp:?}: {err}")))?,
        };
        let narrowed = format!("(extension \"{}\")", NARROWED.to_str().unwrap());
        let mut rule = format!("(deny file-write-unlink {narrowed} (with send-signal SIGKILL))\n");
        // Discovery build: allowed and reported instead.
        #[cfg(wick_sandbox_discovery)]
        rule.push_str(&format!("(allow file-write-unlink {narrowed} (with report))\n"));
        for prefix in [vmm_sys_util::eventfd::FIFO_PREFIX, libc::TIMERFD_FIFO_PREFIX] {
            let fifo = quoted(&tmp.join(format!("{prefix}{pid}-")), "FIFO")?;
            rule.push_str(&format!(
                "(allow file-write-unlink (require-all {narrowed} (vnode-type FIFO) (prefix \"{fifo}\")))\n"
            ));
        }
        Ok(rule)
    }

    /// Operations a running microVM may not ask for, after the file rule
    /// (which allows them on the files it covers until [`narrow`]):
    /// changing a file's mode, owner, flags, times, extended attributes or
    /// ACL, and cloning one. They are denials, as `chmod`, `fchmod`,
    /// `chown`, `utimensat`, `setxattr` and `copy_file_range` are in none
    /// of upstream's filters. And binding a socket, which the
    /// `network-inbound` rule allows until then (it decides a bind no
    /// `network-bind` rule matches; this one, for the same operation and
    /// with a filter, is the more specific, measured): as Linux's VMM filter
    /// has no `bind`, the sockets Firecracker binds while the microVM is
    /// built or restored (network endpoints, the vsock device's) are bound
    /// then; but for the endpoint of a network device hot-plugged into a
    /// running microVM, which Linux's filter lets open its TAP (`openat`,
    /// `ioctl`): a Unix socket in the jail's network, or outside a jail at
    /// the operator's path, binds after [`narrow`] too (`run_rule`). Seatbelt
    /// decides their system calls by these operations, not by number
    /// ([`UNFILTERED_SYSCALLS`]).
    pub const RUN_DENIED_OPERATIONS: &[&str] = &[
        "file-write-mode", "file-write-owner", "file-write-flags", "file-write-times",
        "file-write-xattr", "file-write-acl", "file-write-setugid", "file-clone",
        "network-bind",
    ];

    /// The `fcntl` commands a running microVM may use (`F_<name>`,
    /// <sys/fcntl.h>), each line for the rule of upstream's filters in its
    /// comment, measured as [`SYSCALLS`] are. Any other command is a
    /// denial after [`narrow`] (Seatbelt's `system-fcntl`, which checks
    /// every command).
    pub const FCNTL_COMMANDS: &[&str] = &[
        // fcntl F_SETFD FD_CLOEXEC.
        "F_GETFD", "F_SETFD",
        // eventfd2 with EFD_NONBLOCK: an eventfd is a FIFO here, made
        // non-blocking once open (vmm-sys-util).
        "F_GETFL", "F_SETFL",
        // fsync (macOS's full flush to the drive: the block device's flush).
        "F_FULLFSYNC",
        // io_uring_setup, io_uring_register: the asynchronous block engine's
        // workers take their own descriptors of the drive and eventfd.
        "F_DUPFD_CLOEXEC",
        // fallocate FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE (the
        // compatibility libc's fallocate).
        "F_PUNCHHOLE",
        // timerfd_create: a timer is a FIFO here (the compatibility libc),
        // whose write end the timer thread sets to raise no SIGPIPE once
        // the timer is closed; made after narrowing for a hot-plugged
        // device's rate limiter (measured: the one call outside the lists
        // when a drive, a net device or a pmem device is hot-plugged, with
        // rate limiters, under the discovery build).
        "F_SETNOSIGPIPE",
    ];

    /// The API process's `fcntl` commands: upstream's `api` filter allows
    /// `F_SETFD`.
    pub const API_FCNTL_COMMANDS: &[&str] = &["F_GETFD", "F_SETFD"];

    /// `(allow system-fcntl ...)` for `commands` after a deny with the kill
    /// under `condition` (none: always).
    #[allow(unexpected_cfgs)]
    fn fcntl_rule(condition: &str, commands: &[&str]) -> String {
        let mut rule = if condition.is_empty() {
            "(deny system-fcntl (with send-signal SIGKILL))\n".to_owned()
        } else {
            format!("(deny system-fcntl {condition} (with send-signal SIGKILL))\n")
        };
        rule.push_str(&allow("system-fcntl", "", "fcntl-command", "", commands));
        // Discovery build: another command is allowed and reported.
        #[cfg(wick_sandbox_discovery)]
        rule.push_str(&format!(
            "(allow system-fcntl (require-all {condition} (require-not (fcntl-command {}))) (with report))\n",
            commands.join(" ")
        ));
        rule
    }

    /// The rules of the run phase that come after the file rule: the
    /// operations of [`RUN_DENIED_OPERATIONS`] and the `fcntl` commands
    /// outside [`FCNTL_COMMANDS`] are denials once the process holds the
    /// narrowed extension; but a Unix socket binds where setup could bind
    /// one, for a hot-plugged network device's endpoint (a rule with a
    /// filter: the more specific one decides): in the jail (`root`) and its
    /// network (`netns`), or anywhere outside a jail (`root` is `None`). An
    /// IP socket never binds after [`narrow`], and a stream socket bound
    /// then cannot listen (`listen` is in [`SETUP_SYSCALLS`]).
    #[allow(unexpected_cfgs)]
    fn run_rule(root: Option<&Path>, netns: Option<&Path>) -> Result<String, SandboxError> {
        let narrowed = format!("(extension \"{}\")", NARROWED.to_str().unwrap());
        let mut rule = format!(
            "(deny {} {narrowed} (with send-signal SIGKILL))\n",
            RUN_DENIED_OPERATIONS.join(" ")
        );
        // Discovery build: allowed and reported instead.
        #[cfg(wick_sandbox_discovery)]
        rule.push_str(&format!(
            "(allow {} {narrowed} (with report))\n",
            RUN_DENIED_OPERATIONS.join(" ")
        ));
        if root.is_none() {
            rule.push_str(&format!("(allow network-bind (require-all {narrowed} (local unix-socket)))\n"));
        }
        for (dir, what) in [(root, "jail"), (netns, "network directory")] {
            if let Some(dir) = dir {
                let dir = quoted(dir, what)?;
                rule.push_str(&format!(
                    "(allow network-bind (require-all {narrowed} (local unix-socket) (subpath \"{dir}\")))\n"
                ));
            }
        }
        rule.push_str(&fcntl_rule(&narrowed, FCNTL_COMMANDS));
        Ok(rule)
    }

    /// What a denied operation does: on Linux a system call outside a
    /// thread's filter traps, so here an operation no rule allows is a
    /// denial, which the kernel ends the process in (see [`PROFILE`]). Except for files, which fail with an error, as on Linux a path
    /// outside the chroot does, and what [`DENIED_WITH_ERROR`] lists.
    #[allow(unexpected_cfgs)]
    fn default_rule() -> String {
        let mut rule = String::from("(deny default (with send-signal SIGKILL))\n(deny file-read* file-write*)\n");
        for (op, why) in DENIED_WITH_ERROR {
            rule.push_str(&format!("; {why}\n(deny {op})\n"));
        }
        // Discovery build: every operation no rule allows is allowed and
        // reported instead.
        #[cfg(wick_sandbox_discovery)]
        rule.push_str("(allow default (with report))\n(deny file-read* file-write*)\n");
        rule
    }

    /// Operations denied with an error rather than the kill: ones the system
    /// libraries make and handle failing, that Firecracker never asks for.
    pub const DENIED_WITH_ERROR: &[(&str, &str)] = &[
        (
            "mach-priv-host-port",
            "libsandbox asks for the host's privileged port right after sandbox_init.",
        ),
        (
            "system-info (info-type \"vfs.disk-space\")",
            "fstatfs (fallocate's hole punching, for the block size: a guest's discard on a \
             drive with discard on; test_run_phase_ioctls_and_holes) then reports no exact free \
             space, and the hole is punched.",
        ),
    ];

    /// Operations of the setup phase only: building the microVM opens the
    /// console's terminal and reads system information; on Linux the VMM
    /// thread's filter allows ioctl only for KVM, the TAP device and the
    /// terminal. Binding a Unix socket is not here: Seatbelt decides it by
    /// the `network-inbound` rule (measured: with `(deny network-bind)` and
    /// that rule, a bind is allowed unless the deny is the more specific
    /// rule), so [`RUN_DENIED_OPERATIONS`] denies it after [`narrow`]; a
    /// stream socket cannot listen then either (`listen` is in
    /// [`SETUP_SYSCALLS`]), as Linux's VMM filter has no `bind` or `listen`.
    pub const SETUP_OPERATIONS: &[&str] = &[
        "file-ioctl",
        "sysctl-read",
        "system-socket",
        // A vmnet interface (vmnet-shared, vmnet-host) is started while
        // the microVM is built, as Linux opens the TAP device then:
        // vmnet.framework connects to NetworkSharing for it (measured: the
        // only service a vmnet-shared start looks up). The sandbox is
        // installed by whichever thread installs its filter first, the API
        // thread's racing the build, so without this rule the lookup raised
        // SIGSYS whenever the sandbox came first (seen in boot-test vmnet
        // once the profile was compiled ahead).
        "mach-lookup (global-name \"com.apple.NetworkSharing\")",
    ];

    /// Operations of the run phase, for the ioctl requests upstream's VMM
    /// filter allows a running microVM that have a macOS counterpart: the
    /// terminal's settings restored on shutdown (TCGETS, TCSETS, TIOCGWINSZ)
    /// and a block device's sizes when a drive is opened (BLKSSZGET,
    /// BLKPBSZGET, BLKIOMIN, BLKIOOPT, mapped by the compatibility libc).
    /// KVM, the TAP device and Nitro Enclaves have none: those requests are
    /// never made here. Generic requests (FIONBIO, FIOCLEX) are not driver
    /// requests and Seatbelt does not filter them. Of sysctls, a running
    /// microVM reads only the one below.
    pub const RUN_OPERATIONS: &[&str] = &[
        concat!(
            "file-ioctl (ioctl-command",
            " #x40487413 #x80487414 #x80487415 #x80487416", // TIOCGETA, TIOCSETA, TIOCSETAW, TIOCSETAF
            " #x40087468",                                    // TIOCGWINSZ
            " #x40046418 #x4004644d",                         // DKIOCGETBLOCKSIZE, DKIOCGETPHYSICALBLOCKSIZE
            // DKIOCGETBLOCKCOUNT: a drive's size when it is opened again
            // (PATCH /drives), the macOS counterpart of Linux's lseek to the
            // end; a read-only query of a descriptor the process holds.
            " #x40086419",
            ")"
        ),
        // Whether the host is itself a virtual machine: read by the system
        // libraries (not wick's code) right after the microVM starts,
        // measured on every boot; information only.
        "sysctl-read (sysctl-name \"kern.hv_vmm_present\")",
    ];

    #[allow(unexpected_cfgs)]
    fn operation_rule() -> String {
        let setup = format!("(require-not (extension \"{}\"))", NARROWED.to_str().unwrap());
        let mut rule = String::new();
        for op in SETUP_OPERATIONS {
            let (name, filter) = op.split_once(' ').unwrap_or((op, ""));
            if filter.is_empty() {
                rule.push_str(&format!("(allow {name} {setup})\n"));
            } else {
                rule.push_str(&format!("(allow {name} (require-all {filter} {setup}))\n"));
            }
        }
        // Discovery build: after narrow(), the setup operations' kinds are
        // allowed and reported (a rule with a filter, so that it takes
        // precedence over the default rule, whose reports miss some of them,
        // sysctl reads among them), but for what the run phase's rules below
        // allow, which come later and so decide.
        #[cfg(wick_sandbox_discovery)]
        {
            let narrowed = format!("(extension \"{}\")", NARROWED.to_str().unwrap());
            for op in SETUP_OPERATIONS {
                let name = op.split_once(' ').map_or(*op, |(name, _)| name);
                rule.push_str(&format!("(allow {name} {narrowed} (with report))\n"));
            }
        }
        for op in RUN_OPERATIONS {
            let (name, filter) = op.split_once(' ').unwrap_or((op, ""));
            rule.push_str(&format!("(allow {name} {filter})\n"));
        }
        rule
    }

    /// `(allow <op> (require-all <condition> (<filter> <prefix><name>...)))`,
    /// or nothing for an empty list.
    ///
    /// A system call whose number `UNFILTERED_SYSCALLS` records is written as
    /// that number, not as its `SYS_` name: libsandbox's names are those of
    /// the major it ships with, and an unknown one fails the whole profile
    /// (macOS 15 and 26 have no `SYS_getumask`), while a system call's number
    /// does not change between majors.
    fn allow(op: &str, condition: &str, filter: &str, prefix: &str, names: &[&str]) -> String {
        if names.is_empty() {
            return String::new();
        }
        let mut list = format!("({filter}");
        for name in names {
            list.push(' ');
            match UNFILTERED_SYSCALLS.iter().find(|(n, ..)| n == name) {
                Some((_, number, ..)) if prefix == "SYS_" => list.push_str(&number.to_string()),
                _ => {
                    list.push_str(prefix);
                    list.push_str(name);
                }
            }
        }
        list.push(')');
        if condition.is_empty() {
            format!("(allow {op} {list})\n")
        } else {
            format!("(allow {op} (require-all {condition} {list}))\n")
        }
    }

    /// The allow rules for the system calls, Mach traps and MIG routines of
    /// each phase.
    fn syscall_rule() -> String {
        let setup = format!("(require-not (extension \"{}\"))", NARROWED.to_str().unwrap());
        // First, so that the allow rules below take precedence over it.
        let mut rule = discovery_rule();
        let run = (SYSCALLS, MACH_TRAPS, MIG_ROUTINES);
        let setup_lists = (SETUP_SYSCALLS, SETUP_MACH_TRAPS, SETUP_MIG_ROUTINES);
        for (cond, (syscalls, traps, migs)) in [("", run), (setup.as_str(), setup_lists)] {
            rule.push_str(&allow("syscall-unix", cond, "syscall-number", "SYS_", syscalls));
            rule.push_str(&allow("syscall-mach", cond, "machtrap-number", "MSC_", traps));
            rule.push_str(&allow("syscall-mig", cond, "kernel-mig-routine", "", migs));
        }
        if kvm_ioctls::pv_time_offered() {
            rule.push_str(&allow("syscall-unix", "", "syscall-number", "SYS_", PVTIME_SYSCALLS));
            rule.push_str(&allow("syscall-mig", "", "kernel-mig-routine", "", PVTIME_MIG_ROUTINES));
        }
        rule.push_str(&exception_rule());
        for name in MACH_TRAPS_IF_DEFINED {
            rule.push_str(&format!(
                "(when (defined? 'MSC_{name}) (allow syscall-mach (machtrap-number MSC_{name})))\n"
            ));
        }
        for name in SETUP_MIG_ROUTINES_IF_DEFINED {
            rule.push_str(&format!(
                "(when (defined? '{name}) (allow syscall-mig (require-all (kernel-mig-routine {name}) {setup})))\n"
            ));
        }
        rule
    }

    /// The discovery build's rule (`tools/macos/sandbox-discovery.sh`, never
    /// released): after narrow(), a call outside the run phase's lists is
    /// allowed and reported instead of denied, so that one run of the
    /// scenario tests lists every call they are missing.
    #[allow(unexpected_cfgs)]
    fn discovery_rule() -> String {
        #[cfg(wick_sandbox_discovery)]
        return format!(
            "(allow syscall-unix syscall-mach syscall-mig (extension \"{}\") (with report))\n",
            NARROWED.to_str().unwrap()
        );
        #[allow(unreachable_code)]
        String::new()
    }

    /// Set by [`denied_elsewhere`]: the SIGSYS it hands upstream's handler
    /// stands for the API process's denied call.
    static DENIED_ELSEWHERE: AtomicBool = AtomicBool::new(false);

    /// Whether a SIGSYS stands for a call a host sandbox denied, on which
    /// upstream's handler exits as for a seccomp violation. The sandbox's own
    /// denials raise no SIGSYS here: the kernel ends the process inside the
    /// denied call (see [`PROFILE`]). The one SIGSYS that stands for a denial
    /// is the one [`denied_elsewhere`] hands upstream's handler, for the API
    /// process's. Any other (another process's `kill`, a thread's own
    /// `raise`) is not one, and upstream's handler exits with its
    /// unexpected-error code, as on Linux for a SIGSYS seccomp did not send.
    /// Async-signal-safe.
    ///
    /// # Safety
    /// `info` is the siginfo passed to a SIGSYS handler.
    pub unsafe fn denied_syscall(si_code: libc::c_int, info: *mut libc::siginfo_t) -> bool {
        if !DENIED_ELSEWHERE.load(Ordering::Acquire) || si_code != 0 || info.is_null() {
            return false;
        }
        // SAFETY: the caller passes the handler's siginfo; getpid has no
        // arguments.
        unsafe { (*info).si_pid == libc::getpid() }
    }

    // SIGSYS.
    //
    // A call the sandbox denies raises none: the kernel kills the process
    // inside the call ([`PROFILE`]). What remains is the kernel's own SIGSYS
    // for a call it has no entry for (xnu bsd/kern/subr_xxx.c `nosys`:
    // `psignal_uthread`, to the calling thread), and a SIGSYS a process
    // sends, which upstream's handler takes as on Linux. `nosys` runs only
    // for a number the sandbox let through: one it has no number for is
    // checked as SYS_invalid and denied ([`PROFILE`]); one it allows that
    // this macOS has no call for ([`ABSENT`]), or any without the sandbox
    // (`--no-seccomp`). There the call fails with ENOSYS and the process goes
    // on, as Linux runs a number its filter allows and has no call for, and
    // any without a filter.

    /// The type of a SIGSYS handler (upstream's `sigsys_handler`).
    pub type SigsysHandler = extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void);

    /// The handler Firecracker registered for SIGSYS ([`set_sigsys_handler`]).
    static SIGSYS_HANDLER: AtomicUsize = AtomicUsize::new(0);

    /// Registers `handler` for SIGSYS, behind [`forward_sigsys`]. Upstream's
    /// `register_signal_handlers` calls this for its `sigsys_handler`.
    pub fn set_sigsys_handler(handler: SigsysHandler) -> vmm_sys_util::errno::Result<()> {
        SIGSYS_HANDLER.store(handler as usize, Ordering::Release);
        // SAFETY: a zeroed sigaction, then its fields; forward_sigsys is
        // async-signal-safe as far as upstream's handler is.
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = forward_sigsys as *const () as usize;
            // As upstream's register_signal_handler: its siginfo, every
            // signal blocked while it runs.
            act.sa_flags = libc::SA_SIGINFO;
            libc::sigfillset(&mut act.sa_mask);
            if libc::sigaction(libc::SIGSYS, &act, std::ptr::null_mut()) != 0 {
                return vmm_sys_util::errno::errno_result();
            }
        }
        Ok(())
    }

    fn errno_location() -> *mut libc::c_int {
        // SAFETY: the calling thread's errno.
        unsafe { libc::__error() }
    }

    /// Whether a SIGSYS with this code and sender is the kernel's (`nosys`):
    /// it signals the calling thread from the process itself, so the sender
    /// is this process and the code 0.
    ///
    /// xnu keeps a caught signal's sender and code in the process, not with
    /// the signal: written when a signal is posted (bsd/kern/kern_sig.c
    /// `psignal_internal`: `sig_proc->si_pid`, `si_code = 0`), and when a
    /// child exits or stops (bsd/kern/kern_exit.c `proc_exit`: the child's
    /// pid, `CLD_EXITED`), and read and zeroed when a signal is delivered
    /// (bsd/dev/arm/unix_signal.c `sendsig`). So the kernel's SIGSYS, posted
    /// with this process as its sender, is delivered with
    /// - no sender, if another signal was delivered first;
    /// - a child's pid and a `CLD_` code, if the API process ended in
    ///   between;
    /// - another process's pid, if that process signalled Firecracker in
    ///   between, which nothing tells from that process sending SIGSYS.
    ///
    /// The first two are no signal another process sent (its pid is never
    /// 0, its code 0), and are taken as the kernel's. So is a SIGSYS the
    /// process sends itself (`raise`), which nothing tells from the kernel's
    /// and nothing in Firecracker sends; on Linux upstream's handler exits on
    /// it with its unexpected-error code.
    fn own_sigsys(code: libc::c_int, pid: libc::pid_t, me: libc::pid_t) -> bool {
        (code == 0 && (pid == me || pid == 0)) || (libc::CLD_EXITED..=libc::CLD_CONTINUED).contains(&code)
    }

    /// The SIGSYS handler: the kernel's own SIGSYS for a call it has none
    /// for is the call's ENOSYS alone (errno kept), and the process goes on
    /// (see above); any other SIGSYS goes to upstream's handler.
    extern "C" fn forward_sigsys(num: libc::c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
        // SAFETY: errno of this thread; the kernel's siginfo, if any.
        let saved = unsafe { *errno_location() };
        let (code, pid) = if info.is_null() {
            (-1, -1)
        } else {
            // SAFETY: as above.
            unsafe { ((*info).si_code, (*info).si_pid) }
        };
        // SAFETY: no arguments.
        let me = unsafe { libc::getpid() };
        if own_sigsys(code, pid, me) {
            // SAFETY: as above.
            unsafe { *errno_location() = saved };
            return;
        }
        // SAFETY: a SigsysHandler stored by set_sigsys_handler, which
        // registered this.
        let handler: SigsysHandler = unsafe { std::mem::transmute(SIGSYS_HANDLER.load(Ordering::Acquire)) };
        handler(num, info, ctx);
    }

    /// Ends Firecracker as for a call its own sandbox denied, for the API
    /// process's, which the kernel ended by SIGKILL and Firecracker, its
    /// parent, knows by its exit reason (`api_process`): upstream's handler,
    /// on this thread, with every signal blocked as a handler runs (its log
    /// line, the fault metric, exit 148), as on Linux the API thread's
    /// trapped call ends Firecracker. Does not return.
    pub fn denied_elsewhere() -> ! {
        // SAFETY: a full set, for this thread.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigfillset(&mut set);
            libc::pthread_sigmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
        }
        DENIED_ELSEWHERE.store(true, Ordering::Release);
        // SAFETY: a zeroed siginfo with a denial's fields (no code, this
        // process: denied_syscall).
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        info.si_signo = libc::SIGSYS;
        // SAFETY: no arguments.
        info.si_pid = unsafe { libc::getpid() };
        if let handler @ 1.. = SIGSYS_HANDLER.load(Ordering::Acquire) {
            // SAFETY: stored by set_sigsys_handler.
            let handler: SigsysHandler = unsafe { std::mem::transmute(handler) };
            handler(libc::SIGSYS, &mut info, std::ptr::null_mut());
        }
        // Upstream's handler exits; without one, its exit code.
        crate::ext::fifo::drain();
        // SAFETY: ends the process.
        unsafe { libc::_exit(crate::FcExitCode::BadSyscall as i32) }
    }

    unsafe extern "C" {
        // libsystem_sandbox (part of libSystem).
        fn sandbox_free_error(errorbuf: *mut c_char);
        fn sandbox_extension_issue_generic(class: *const c_char, flags: u32) -> *mut c_char;
        fn sandbox_extension_consume(token: *const c_char) -> i64;
    }

    struct State {
        policy: Policy,
        installed: bool,
        /// The narrowed extension's token, issued before the sandbox (a
        /// sandboxed process cannot issue one), until narrow() consumes it.
        narrowed: Option<Token>,
        narrowed_done: bool,
    }

    /// An extension token from libsandbox, wiped and freed when dropped.
    struct Token(*mut c_char);

    // SAFETY: the token is a heap string owned by this value alone.
    unsafe impl Send for Token {}

    impl Token {
        fn issue(class: &CStr) -> Result<Self, SandboxError> {
            // SAFETY: a NUL-terminated class name; flags 0.
            let token = unsafe { sandbox_extension_issue_generic(class.as_ptr(), 0) };
            if token.is_null() {
                return Err(SandboxError::Install(format!(
                    "issuing the {class:?} extension: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(Token(token))
        }

        fn consume(&self) -> std::io::Result<i64> {
            // SAFETY: a token sandbox_extension_issue_generic returned.
            let handle = unsafe { sandbox_extension_consume(self.0) };
            if handle < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(handle)
        }
    }

    impl Drop for Token {
        fn drop(&mut self) {
            // SAFETY: a NUL-terminated string libsandbox allocated with malloc;
            // wiped so that the process keeps no copy of it, then freed.
            unsafe {
                let len = libc::strlen(self.0);
                std::ptr::write_bytes(self.0, 0, len);
                libc::free(self.0.cast());
            }
        }
    }

    static STATE: Mutex<State> = Mutex::new(State {
        policy: Policy::None,
        installed: false,
        narrowed: None,
        narrowed_done: false,
    });

    /// Selects the sandbox to install. Called once at start-up from the seccomp configuration.
    pub fn select(policy: Policy) {
        STATE.lock().unwrap().policy = policy;
    }

    /// The selected policy (for the API process made before the selection,
    /// `ext::api_process`).
    pub fn selected() -> Policy {
        STATE.lock().unwrap().policy
    }

    /// Installs the selected sandbox if it is not installed yet.
    pub fn apply() -> Result<(), SandboxError> {
        let mut state = STATE.lock().unwrap();
        if state.installed {
            return Ok(());
        }
        if state.policy == Policy::None {
            // A process may lift its own CPU limit; only the system call
            // allow-list denies it that.
            return match crate::ext::jail::cpu_limit() {
                Some(percent) => Err(SandboxError::CpuLimitNeedsSandbox(percent)),
                None => Ok(()),
            };
        }
        // Issued before the sandbox, which denies issuing; an extension
        // taken before the sandbox is installed would not attach to it.
        let narrowed = Token::issue(NARROWED)?;
        install_compiled(&compiled_profile()?)?;
        state.installed = true;
        state.narrowed = Some(narrowed);
        Ok(())
    }

    /// Whether [`narrow`] has run: what a running microVM may still do
    /// differs from what building it may (`platform::net::bind` replaces a
    /// stale socket only before).
    pub fn narrowed() -> bool {
        STATE.lock().unwrap().narrowed_done
    }

    /// Ends the setup phase for good: takes the narrowed extension, after
    /// which the process can neither release it nor take or issue another
    /// (see [`PROFILE`]). Without the sandbox (`--no-seccomp`), or a second
    /// time, it does nothing.
    #[allow(unexpected_cfgs)]
    pub fn narrow() -> Result<(), SandboxError> {
        let mut state = STATE.lock().unwrap();
        if !state.installed || state.narrowed_done {
            return Ok(());
        }
        let fail = |what: &str, err: std::io::Error| SandboxError::Narrow(format!("{what}: {err}"));
        // The narrowed profile allows no new thread (SETUP_SYSCALLS'
        // bsdthread_create): the Async block engine's workers start now.
        crate::platform::async_io::seal_workers()
            .map_err(|err| fail("starting the async I/O workers", err))?;
        // And the thread that fires the timers (timerfd_create), which a
        // timer made after this would otherwise start.
        libc::timerfd_start_thread();
        let token = state.narrowed.take().expect("the narrowed token is kept until narrow()");
        token.consume().map_err(|err| fail("taking the narrowed extension", err))?;
        drop(token);
        // Upstream's filters trap mmap and mprotect asking for PROT_EXEC. A
        // discovery build lets the call through.
        if !cfg!(wick_sandbox_discovery) {
            libc::wick_mm::deny_exec(exec_denied);
        }
        state.narrowed_done = true;
        Ok(())
    }

    /// Ends the process as a denied call does, for an `mmap` or `mprotect`
    /// asking for `PROT_EXEC` after [`narrow`], or the API process's
    /// `madvise` with advice other than `MADV_DONTNEED`: the compatibility
    /// libc's checks of what upstream's filters trap. It makes the call
    /// [`DENIED_CALL_RULE`] denies, and the kernel kills the process inside
    /// it, with the sandbox's exit reason and a crash report naming this
    /// thread, as for any denial. It does not return: were the call let
    /// through, the process ends by SIGKILL all the same.
    extern "C" fn exec_denied(_prot: libc::c_int) {
        // SAFETY: a system call that reads no argument (`nosys`), then a
        // signal to this process.
        unsafe {
            std::arch::asm!(
                "svc #0x80",
                inout("x16") usize::from(DENIED_CALL) => _,
                inout("x0") 0usize => _,
                out("x1") _,
                out("x17") _,
                options(nostack),
            );
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
        loop {
            std::hint::spin_loop();
        }
    }

    /// Installs `profile` for the whole process, permanently.
    #[cfg(test)]
    fn install(profile: &str) -> Result<(), SandboxError> {
        install_compiled(&Compiled::here(profile)?)
    }

    /// Installs a compiled profile for the whole process, permanently.
    fn install_compiled(compiled: &Compiled) -> Result<(), SandboxError> {
        // libsystem_trace sets itself up on the process's first os_log use,
        // and asks the sandbox then (sandbox_check, the Sandbox mac-syscall
        // 2), which the profile denies: Hypervisor.framework's first log,
        // when the microVM is built, raised SIGSYS. sandbox_init logs before
        // it applies a profile, so libsystem_trace was set up by then; a
        // compiled profile is applied without it, so the log is set up
        // here, as it was.
        // SAFETY: NUL-terminated subsystem and category; the log object is
        // kept for the process's life, as os_log's are.
        unsafe { os_log_create(c"com.toollyst.wick".as_ptr(), c"sandbox".as_ptr()) };
        let profile = SandboxProfile {
            builtin: std::ptr::null(),
            data: compiled.0.as_ptr(),
            size: compiled.0.len(),
        };
        // SAFETY: a profile of libsandbox's bytecode, which it only reads.
        if unsafe { sandbox_apply(&profile) } != 0 {
            return Err(SandboxError::Install(format!(
                "applying the profile: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// A profile compiled to libsandbox's bytecode.
    #[derive(Clone)]
    pub struct Compiled(Vec<u8>);

    impl std::fmt::Debug for Compiled {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Compiled({} bytes)", self.0.len())
        }
    }

    impl Compiled {
        /// Compiles `profile` in this process.
        fn here(profile: &str) -> Result<Self, SandboxError> {
            let profile = std::ffi::CString::new(profile)
                .map_err(|_| SandboxError::Install("profile contains NUL".into()))?;
            let mut err: *mut c_char = std::ptr::null_mut();
            // SAFETY: a NUL-terminated profile, no parameters, an out-pointer.
            let compiled =
                unsafe { sandbox_compile_string(profile.as_ptr(), std::ptr::null_mut(), &mut err) };
            if compiled.is_null() {
                let msg = if err.is_null() {
                    std::io::Error::last_os_error().to_string()
                } else {
                    // SAFETY: libsandbox's NUL-terminated message, freed below.
                    let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
                    // SAFETY: as above.
                    unsafe { sandbox_free_error(err) };
                    msg
                };
                return Err(SandboxError::Install(msg));
            }
            // SAFETY: libsandbox's profile: `size` bytes at `data`, freed
            // once copied.
            let bytes = unsafe {
                let p = &*compiled;
                let bytes = std::slice::from_raw_parts(p.data, p.size).to_vec();
                sandbox_free_profile(compiled);
                bytes
            };
            Ok(Compiled(bytes))
        }

        /// Compiles `profile` in a child process. libsandbox compiles a
        /// profile in the memory of the process that asks (about 3 MiB for
        /// Firecracker's, measured with phys_footprint), which malloc then
        /// keeps resident: Firecracker, which upstream holds to 5 MiB of its
        /// own memory (tests/host_tools/memory.py), would carry that for
        /// good. The child's memory goes with the child.
        ///
        /// # Safety
        /// The process has one thread (the child runs libsandbox's
        /// compiler, which allocates).
        unsafe fn in_child(profile: &str) -> Result<Self, SandboxError> {
            use std::io::Read;
            let fail = |what: &str| {
                SandboxError::Install(format!(
                    "compiling the profile in a child: {what}: {}",
                    std::io::Error::last_os_error()
                ))
            };
            let mut fds = [0; 2];
            // SAFETY: an array of two descriptors.
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                return Err(fail("pipe"));
            }
            // SAFETY: the caller guarantees one thread.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // The child: the bytecode, or an error message, then exit.
                // SAFETY: our own descriptors; _exit ends the child without
                // running the parent's exit handlers.
                unsafe {
                    libc::close(fds[0]);
                    let (status, bytes) = match Compiled::here(profile) {
                        Ok(c) => (0u8, c.0),
                        Err(e) => (1u8, e.to_string().into_bytes()),
                    };
                    let mut out = vec![status];
                    out.extend_from_slice(&bytes);
                    let mut off = 0;
                    while off < out.len() {
                        let n = libc::write(fds[1], out[off..].as_ptr().cast(), out.len() - off);
                        if n <= 0 {
                            libc::_exit(2);
                        }
                        off += n.unsigned_abs();
                    }
                    libc::_exit(0);
                }
            }
            // SAFETY: our own descriptor.
            unsafe { libc::close(fds[1]) };
            if pid < 0 {
                // SAFETY: our own descriptor.
                unsafe { libc::close(fds[0]) };
                return Err(fail("fork"));
            }
            // SAFETY: the pipe's read end, owned here from now on.
            let mut pipe = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fds[0]) };
            let mut out = Vec::new();
            let read = pipe.read_to_end(&mut out);
            let mut status = 0;
            // SAFETY: our child; an out-pointer.
            while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
                if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    return Err(fail("waitpid"));
                }
            }
            read.map_err(|e| SandboxError::Install(format!("compiling the profile in a child: {e}")))?;
            match out.split_first() {
                Some((0, bytes)) if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 => {
                    Ok(Compiled(bytes.to_vec()))
                }
                Some((1, msg)) => Err(SandboxError::Install(String::from_utf8_lossy(msg).into_owned())),
                _ => Err(SandboxError::Install(format!(
                    "compiling the profile in a child: it ended with status {status:#x}"
                ))),
            }
        }
    }

    /// The profiles [`prepare`] compiled: Firecracker's and the API process's.
    static COMPILED: std::sync::OnceLock<(Compiled, Compiled)> = std::sync::OnceLock::new();

    /// Compiles this process's profiles ahead of [`apply`] and
    /// [`apply_api`], in a child ([`Compiled::in_child`]), for the jail at
    /// `root` (`None`: no jail) with the network `netns`.
    ///
    /// # Safety
    /// The process has one thread: `ext::jail::enter` calls it first thing in
    /// main.
    pub unsafe fn prepare(root: Option<&Path>, netns: Option<&Path>) -> Result<(), SandboxError> {
        // SAFETY: one thread, as the caller guarantees.
        let vmm = unsafe { Compiled::in_child(&profile_for(root, netns)?)? };
        // SAFETY: as above.
        let api = unsafe { Compiled::in_child(&api_profile())? };
        COMPILED
            .set((vmm, api))
            .map_err(|_| SandboxError::Install("the profiles are compiled once".into()))
    }

    /// Firecracker's profile, compiled ([`prepare`]) or compiled now.
    fn compiled_profile() -> Result<Compiled, SandboxError> {
        match COMPILED.get() {
            Some((vmm, _)) => Ok(vmm.clone()),
            None => Compiled::here(&profile()?),
        }
    }

    /// The API process's profile, compiled ([`prepare`]) or compiled now.
    fn compiled_api_profile() -> Result<Compiled, SandboxError> {
        match COMPILED.get() {
            Some((_, api)) => Ok(api.clone()),
            None => Compiled::here(&api_profile()),
        }
    }

    /// libsandbox's compiled profile (sandbox_compile_string).
    #[repr(C)]
    struct SandboxProfile {
        builtin: *const c_char,
        data: *const u8,
        size: usize,
    }

    // libsandbox: compiling apart from applying, which sandbox_init does in
    // one call. Not in the SDK's headers, exported by libsandbox (its .tbd
    // lists them); Chromium's Seatbelt sandbox uses the same three calls.
    unsafe extern "C" {
        // <os/log.h> (libSystem).
        fn os_log_create(subsystem: *const c_char, category: *const c_char) -> *mut libc::c_void;
    }

    #[link(name = "sandbox")]
    unsafe extern "C" {
        fn sandbox_compile_string(
            profile: *const c_char,
            params: *mut libc::c_void,
            error: *mut *mut c_char,
        ) -> *mut SandboxProfile;
        fn sandbox_apply(profile: *const SandboxProfile) -> i32;
        fn sandbox_free_profile(profile: *mut SandboxProfile);
    }

    #[cfg(test)]
    mod tests {
        use std::process::Command;

        use super::*;

        /// The end of a stream, as an epoll user meets it after the sandbox
        /// has narrowed: an epoll instance, a socket pair and a pipe, made
        /// before (as Firecracker makes them before its filters), and in
        /// [`EndOfStream::check`] an ADD of each, the peer's close and the
        /// events of a wait. The compatibility epoll reads the end of a
        /// socket's stream with only what the narrowed lists allow (until
        /// it did, a peer's close raised SIGSYS on `kqueue`).
        struct EndOfStream {
            epoll: vmm_sys_util::epoll::Epoll,
            socket: std::os::unix::net::UnixStream,
            peer: std::os::unix::net::UnixStream,
            read_end: std::fs::File,
            write_end: std::fs::File,
        }

        impl EndOfStream {
            fn new() -> Self {
                use std::os::fd::FromRawFd;
                let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
                let mut fds = [0; 2];
                // SAFETY: a two-element output buffer.
                assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
                EndOfStream {
                    epoll: vmm_sys_util::epoll::Epoll::new().unwrap(),
                    socket,
                    peer,
                    // SAFETY: descriptors just made, owned here.
                    read_end: unsafe { std::fs::File::from_raw_fd(fds[0]) },
                    // SAFETY: as above.
                    write_end: unsafe { std::fs::File::from_raw_fd(fds[1]) },
                }
            }

            /// Linux's events for a peer's close (`unix_poll`) and a pipe's
            /// last writer's (`pipe_poll`).
            fn check(self) {
                use std::os::fd::AsRawFd;
                use vmm_sys_util::epoll::{ControlOperation, EpollEvent, EventSet};
                let EndOfStream { epoll, socket, peer, read_end, write_end } = self;
                let socket_events = EventSet::IN | EventSet::READ_HANG_UP;
                epoll
                    .ctl(ControlOperation::Add, socket.as_raw_fd(), EpollEvent::new(socket_events, 1))
                    .unwrap();
                epoll
                    .ctl(ControlOperation::Add, read_end.as_raw_fd(), EpollEvent::new(EventSet::IN, 2))
                    .unwrap();
                drop((peer, write_end));
                let mut got = [EpollEvent::default(); 4];
                let n = epoll.wait(1000, &mut got).unwrap();
                let of = |data| got[..n].iter().find(|e| e.data() == data).map(EpollEvent::event_set);
                assert_eq!(of(1), Some(socket_events | EventSet::HANG_UP));
                assert_eq!(of(2), Some(EventSet::HANG_UP));
            }
        }

        /// Whether macOS `major`'s kernel has no `name` ([`ABSENT`]).
        fn absent(name: &str, major: u32) -> bool {
            ABSENT.iter().any(|(n, majors)| *n == name && majors.contains(&major))
        }

        // The sandbox is permanent, so it is tested in a child process
        // (the test binary itself, filtered to the child test below).
        /// Processes a test started, killed and waited for when it is
        /// dropped: at the test's end, or as a panic unwinds it.
        struct Others(Vec<std::process::Child>);

        impl Drop for Others {
            fn drop(&mut self) {
                for other in &mut self.0 {
                    let _ = other.kill();
                    let _ = other.wait();
                }
            }
        }

        /// How long a child test may run. Its cases take seconds at most
        /// (16 at a time on a loaded host): one still running then is
        /// blocked, and fails here instead of holding its test, and CI's
        /// step, until the job's timeout (run 43442912128's macos-15
        /// seatbelt job, cancelled in its sandbox tests with no log).
        const CHILD_LIMIT: std::time::Duration = std::time::Duration::from_secs(120);

        /// Runs the ignored test `name` in a child process of its own with
        /// `env`, at most [`CHILD_LIMIT`]. A child still running then is
        /// sampled (`sample(1)`: each thread's stack), killed, and its test
        /// fails with the stacks and the output it gave; a child whose
        /// output stays open after its end (a process it started holds it)
        /// fails too, after a short wait.
        fn child(name: &str, env: &[(&str, &str)]) -> std::process::Output {
            child_within(name, env, CHILD_LIMIT)
        }

        /// [`child`], with its limit.
        fn child_within(name: &str, env: &[(&str, &str)], limit: std::time::Duration) -> std::process::Output {
            child_run(name, env, limit).0
        }

        /// [`child`], with the child's exit reason ([`exit_reason`]).
        fn child_reason(name: &str, env: &[(&str, &str)]) -> (std::process::Output, Option<ExitReason>) {
            child_run(name, env, CHILD_LIMIT)
        }

        /// What xnu recorded as a process's reason to exit: its namespace
        /// and code (<sys/proc_info.h> `proc_exitreasonbasicinfo`).
        type ExitReason = (u32, u64);

        /// The namespace of a kill by a Seatbelt action (OS_REASON_SANDBOX,
        /// xnu bsd/sys/reason.h). Its code is Seatbelt's own, by the kind of
        /// operation (measured on 27.2: 0xdd for a system call, 0x1 for a
        /// network operation).
        const OS_REASON_SANDBOX: u32 = 25;

        /// Whether `reason` is the sandbox's kill.
        fn sandbox_kill(reason: Option<ExitReason>) -> bool {
            reason.is_some_and(|(namespace, _)| namespace == OS_REASON_SANDBOX)
        }

        /// The exit reason of `pid`, this process's child, once it has
        /// exited and before it is reaped (`waitid` with `WNOWAIT`): only
        /// the parent may read it (xnu bsd/kern/proc_info.c
        /// `proc_pidexitreasoninfo`), and only while the child is a zombie.
        /// None when it has none (an exit by `exit`).
        fn exit_reason(pid: libc::pid_t) -> Option<ExitReason> {
            loop {
                // SAFETY: a zeroed siginfo for the output; our child.
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                // SAFETY: as above.
                let got = unsafe {
                    libc::waitid(libc::P_PID, libc::id_t::try_from(pid).unwrap(), &mut info, libc::WEXITED | libc::WNOWAIT)
                };
                if got == 0 {
                    break;
                }
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINTR), "waitid {pid}");
            }
            // proc_exitreasonbasicinfo: namespace u32, code u64, flags u64,
            // reason buffer size u32, packed (24 bytes).
            let mut buf = [0u8; 24];
            // SAFETY: an output buffer of the size passed; flavour 25 is
            // PROC_PIDEXITREASONBASICINFO.
            let n = unsafe { libc::proc_pidinfo(pid, 25, 0, buf.as_mut_ptr().cast(), 24) };
            (n == 24).then(|| {
                (
                    u32::from_ne_bytes(buf[0..4].try_into().unwrap()),
                    u64::from_ne_bytes(buf[4..12].try_into().unwrap()),
                )
            })
        }

        /// [`child_within`], with the child's exit reason.
        fn child_run(
            name: &str,
            env: &[(&str, &str)],
            limit: std::time::Duration,
        ) -> (std::process::Output, Option<ExitReason>) {
            use std::io::Read;
            use std::process::Stdio;
            use std::sync::mpsc;
            let exe = std::env::current_exe().unwrap();
            let mut proc = Command::new(exe)
                .args([
                    "--exact",
                    &format!("ext::sandbox::macos::tests::{name}"),
                    "--ignored",
                    "--nocapture",
                ])
                .envs(env.iter().copied())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|e| panic!("{name} {env:?}: spawn: {e}"));
            let pid = proc.id();
            let read = |mut from: Box<dyn Read + Send>| {
                let (tx, rx) = mpsc::channel();
                std::thread::spawn(move || {
                    let mut all = Vec::new();
                    let _ = from.read_to_end(&mut all);
                    let _ = tx.send(all);
                });
                rx
            };
            let stdout = read(Box::new(proc.stdout.take().unwrap()));
            let stderr = read(Box::new(proc.stderr.take().unwrap()));
            let (done_tx, done) = mpsc::channel();
            std::thread::spawn(move || {
                let reason = exit_reason(i32::try_from(proc.id()).unwrap());
                let _ = done_tx.send(proc.wait().map(|status| (status, reason)));
            });
            let (status, reason) = match done.recv_timeout(limit) {
                Ok(status) => status.unwrap(),
                Err(_) => {
                    let sample = Command::new("/usr/bin/sample")
                        .args([&pid.to_string(), "1", "-mayDie"])
                        .output()
                        .map(|o| String::from_utf8_lossy(&o.stdout).split("Binary Images:").next().unwrap_or("").to_owned())
                        .unwrap_or_else(|e| format!("sample: {e}"));
                    // SAFETY: our child, which has not been waited for (the
                    // waiting thread has not returned).
                    unsafe { libc::kill(i32::try_from(pid).unwrap(), libc::SIGKILL) };
                    let _ = done.recv();
                    let out = |rx: mpsc::Receiver<Vec<u8>>| {
                        String::from_utf8_lossy(&rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap_or_default())
                            .into_owned()
                    };
                    panic!(
                        "{name} {env:?}: still running after {limit:?}, killed. Its threads:\n{sample}\n\
                         --- stdout\n{}\n--- stderr\n{}",
                        out(stdout),
                        out(stderr)
                    );
                }
            };
            let end = |rx: mpsc::Receiver<Vec<u8>>, which: &str| {
                rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap_or_else(|_| {
                    panic!("{name} {env:?}: ended ({status:?}) and its {which} is still open 10 s on: a process it started holds it")
                })
            };
            let mut stdout = end(stdout, "stdout");
            let stderr = end(stderr, "stderr");
            // For [`denied`], which reads the output alone.
            if let Some((namespace, code)) = reason {
                stdout.extend(format!("\n{EXIT_REASON_LINE}{namespace} {code:#x}\n").into_bytes());
            }
            (std::process::Output { status, stdout, stderr }, reason)
        }

        /// The line [`child_run`] adds to a child's output with its exit
        /// reason.
        const EXIT_REASON_LINE: &str = "WICK-EXIT-REASON ";

        /// Whether a child ended by a denied call: by SIGKILL, with the
        /// sandbox's exit reason. Where Linux's seccomp traps the call and
        /// upstream's handler exits 148, the kernel kills the process inside
        /// the call ([`PROFILE`]).
        fn denied(out: &std::process::Output) -> bool {
            use std::os::unix::process::ExitStatusExt;
            let want = format!("{EXIT_REASON_LINE}{OS_REASON_SANDBOX} ");
            out.status.signal() == Some(libc::SIGKILL) && String::from_utf8_lossy(&out.stdout).contains(&want)
        }

        /// A panic's message.
        fn panic_text(panic: &Box<dyn std::any::Any + Send>) -> String {
            panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_default()
        }

        // A child that blocks fails its test at the limit, with its
        // threads' stacks, and is killed: it cannot hold the test (and CI's
        // step) until the job's timeout.
        #[test]
        fn test_a_blocked_child_fails_with_its_stacks() {
            let panic = std::panic::catch_unwind(|| {
                child_within("blocked_child", &[("WICK_TEST_BLOCKED", "1")], std::time::Duration::from_secs(2))
            })
            .unwrap_err();
            let text = panic_text(&panic);
            assert!(text.contains("blocked_child") && text.contains("still running after 2s, killed"), "{text}");
            assert!(text.contains("Call graph:"), "no stacks: {text}");
            assert!(text.contains("BLOCKED-STARTED"), "not its output: {text}");
        }

        #[test]
        #[ignore = "run by test_a_blocked_child_fails_with_its_stacks in a separate process"]
        fn blocked_child() {
            if std::env::var_os("WICK_TEST_BLOCKED").is_none() {
                return;
            }
            println!("BLOCKED-STARTED");
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }

        // A test's other processes are killed as its panic unwinds, not
        // left running.
        #[test]
        fn test_others_are_killed_by_a_panic() {
            let others = Others(vec![
                Command::new("/bin/sleep")
                    .arg("3600")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            ]);
            let pid = i32::try_from(others.0[0].id()).unwrap();
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _others = others;
                panic!("a test's failure");
            }))
            .unwrap_err();
            assert_eq!(panic_text(&panic), "a test's failure");
            // SAFETY: signal 0 only asks whether the pid exists.
            let alive = unsafe { libc::kill(pid, 0) };
            assert_eq!((alive, std::io::Error::last_os_error().raw_os_error()), (-1, Some(libc::ESRCH)));
        }

        // A terminal lock still held at the wait's end fails naming the
        // processes that hold the file, instead of waiting on.
        #[test]
        fn test_a_held_terminal_lock_fails_naming_its_holders() {
            let held = terminal_lock(TERMINAL_LOCK_WAIT);
            let panic = std::panic::catch_unwind(|| terminal_lock(std::time::Duration::from_secs(1))).unwrap_err();
            // SAFETY: the descriptor terminal_lock returned.
            unsafe { libc::close(held) };
            let text = panic_text(&panic);
            assert!(text.contains("is still locked after 1s"), "{text}");
            let me = format!(" {} ", std::process::id());
            assert!(text.contains(&me), "this process is not named: {text}");
            // Released: taken again at once.
            // SAFETY: the descriptor terminal_lock returns.
            unsafe { libc::close(terminal_lock(std::time::Duration::from_secs(1))) };
        }

        /// A child's exit status, output and error output, for an assertion's
        /// message: a child that died before its marker says how.
        fn text(out: &std::process::Output) -> String {
            format!(
                "{:?}\n--- stdout\n{}\n--- stderr\n{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        }

        fn run_child(name: &str, env: &[(&str, &str)]) {
            let out = child(name, env);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success(), "{}", text(&out));
            assert!(stdout.contains("CHILD-OK"), "{}", text(&out));
        }

        #[test]
        fn test_sandbox_restricts_child() {
            run_child("sandboxed_child", &[]);
        }

        // prepare() compiles in a child: the same bytecode as compiling here,
        // and the compiler's error when the profile does not compile. (The
        // test binary has other threads; libmalloc's fork handlers keep
        // malloc usable in the child, which is all the compiler needs.)
        #[test]
        fn test_profile_compiles_in_a_child() {
            let profile = profile_for(None, None).unwrap();
            // SAFETY: see above.
            let child = unsafe { Compiled::in_child(&profile) }.unwrap();
            assert_eq!(child.0, Compiled::here(&profile).unwrap().0);
            assert!(!child.0.is_empty());
            // SAFETY: as above.
            let err = unsafe { Compiled::in_child("(version 1)\n(allow no-such-operation)\n") }
                .unwrap_err()
                .to_string();
            assert!(err.contains("no-such-operation"), "{err}");
        }

        // A system call outside SYSCALLS is a denial, as a seccomp filter's
        // trap does (the test binary has no handler, so it dies of it).
        #[test]
        fn test_unlisted_syscalls_are_denials() {
            for name in [
                "exec_child", "unlisted_child", "unlisted_trap_child", "unlisted_mig_child", "tcp_child",
                "udp_child", "listen_after_narrow_child",
            ] {
                let out = child(name, &[]);
                assert!(denied(&out), "{name}: {}", text(&out));
                assert!(!String::from_utf8_lossy(&out.stdout).contains("CHILD-SURVIVED"), "{name}: {}", text(&out));
            }
        }

        // With upstream's signal handlers, a denied call ends Firecracker by
        // the kernel's kill: SIGKILL, with the sandbox's exit reason. On
        // Linux a seccomp violation exits 148 through upstream's handler,
        // with its log line and fault metric; Seatbelt has no action that
        // traps the call (docs/COMPATIBILITY.md).
        #[test]
        fn test_a_denied_syscall_ends_firecracker_by_the_sandboxs_kill() {
            let out = child("handled_child", &[]);
            assert!(denied(&out), "{}", text(&out));
            assert!(!String::from_utf8_lossy(&out.stdout).contains("CHILD-SURVIVED"), "{}", text(&out));
        }

        /// How many times each kind of denied call is made, each in a
        /// process of its own.
        const DENIED_CALL_TRIALS: usize = 200;

        // A denied call never returns to the thread that made it: the
        // kernel ends the process inside the call, as Linux's seccomp ends
        // the calling thread's run there (a trap's SIGSYS is forced on that
        // thread before it returns to user space, kernel/seccomp.c
        // `__seccomp_filter`, SECCOMP_RET_TRAP). Each kind of call (a raw
        // `svc` that no libc stub wraps, a libc stub, a Mach trap) is made
        // DENIED_CALL_TRIALS times on a thread that stamps a shared page as
        // the call returns; the page is never stamped, and every process
        // ends by SIGKILL with the sandbox's exit reason. Where Linux exits
        // 148 with upstream's log line and fault metric, here the process
        // ends by SIGKILL: Seatbelt has no action that traps the calling
        // thread, and a signal to the process left the thread running on
        // (docs/COMPATIBILITY.md).
        //
        // Each kill leaves the process exiting until the crash reporter has
        // taken its corpse (the exit reason asks for a crash report): 200
        // kills took 30 s at load average 30 (macOS 27.2, M1 Pro), so the
        // three kinds run at once, each with a limit of its own.
        #[test]
        fn test_a_denied_call_never_returns_to_its_thread() {
            let outs: Vec<_> = std::thread::scope(|s| {
                let runs: Vec<_> = ["svc", "libc", "machtrap"]
                    .into_iter()
                    .map(|call| {
                        s.spawn(move || {
                            let limit = std::time::Duration::from_secs(600);
                            (call, child_within("denied_call_child", &[("WICK_TEST_CALL", call)], limit))
                        })
                    })
                    .collect();
                runs.into_iter().map(|r| r.join().unwrap()).collect()
            });
            for (call, out) in outs {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let want = format!("{call}: returned 0, sandbox kills {DENIED_CALL_TRIALS}, other ends []");
                assert!(stdout.contains(&want), "{call}: {}", text(&out));
            }
        }

        #[test]
        #[ignore = "run by test_a_denied_call_never_returns_to_its_thread in a separate process"]
        fn denied_call_child() {
            unsafe extern "C" {
                static mach_task_self_: libc::mach_port_t;
                fn pid_for_task(task: libc::mach_port_t, pid: *mut libc::c_int) -> libc::c_int;
            }
            let call = std::env::var("WICK_TEST_CALL").unwrap();
            crate::signal_handler::register_signal_handlers().unwrap();
            select(Policy::Default);
            let _ = COMPILED.set((Compiled::here(&profile().unwrap()).unwrap(), Compiled::here(&api_profile()).unwrap()));
            // SAFETY: a shared anonymous page, kept for the process's life.
            let page = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    16384,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_SHARED,
                    -1,
                    0,
                )
            };
            assert_ne!(page, libc::MAP_FAILED);
            let stamp = page.cast::<std::sync::atomic::AtomicU64>();
            let (mut returned, mut killed, mut others) = (0, 0, Vec::new());
            for _ in 0..DENIED_CALL_TRIALS {
                // SAFETY: the shared page above.
                unsafe { (*stamp).store(0, Ordering::SeqCst) };
                // SAFETY: the child calls only what a fork's child may before
                // it exits or is killed: the sandbox's apply, a thread, the
                // call.
                let pid = unsafe { libc::fork() };
                assert!(pid >= 0);
                if pid == 0 {
                    apply().unwrap();
                    let stamp = stamp as usize;
                    let call = call.clone();
                    let thread = std::thread::spawn(move || {
                        match call.as_str() {
                            // SAFETY: getppid takes no arguments; not in
                            // SYSCALLS.
                            "svc" => unsafe {
                                svc(39, [0; 8]);
                            },
                            // SAFETY: as above, through its libc stub.
                            "libc" => unsafe {
                                libc::getppid();
                            },
                            // SAFETY: the task's own port, set before main; a
                            // valid output pointer; not in MACH_TRAPS.
                            _ => unsafe {
                                let mut pid = 0;
                                pid_for_task(mach_task_self_, &mut pid);
                            },
                        }
                        // SAFETY: the shared page.
                        unsafe { (*(stamp as *const std::sync::atomic::AtomicU64)).store(1, Ordering::SeqCst) };
                    });
                    let _ = thread.join();
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    // SAFETY: ends the child.
                    unsafe { libc::_exit(0) };
                }
                let reason = exit_reason(pid);
                let mut status = 0;
                // SAFETY: our child, exited.
                assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
                // SAFETY: the shared page.
                if unsafe { (*stamp).load(Ordering::SeqCst) } != 0 {
                    returned += 1;
                }
                if libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL && sandbox_kill(reason)
                {
                    killed += 1;
                } else if others.len() < 5 {
                    others.push(format!("status {status:#x} reason {reason:x?}"));
                }
            }
            println!("{call}: returned {returned}, sandbox kills {killed}, other ends {others:?}");
        }

        // A process whose SIGSYS is ignored or caught by a handler that
        // returns is ended by its denied call all the same: the kernel's
        // kill does not go through the signal's disposition, as Linux's
        // seccomp trap does not (kernel/signal.c `force_sig_info_to_task`
        // resets an ignored or blocked SIGSYS before it delivers it). Set in
        // the setup phase, where `sigaction` is allowed.
        #[test]
        fn test_an_ignored_or_replaced_sigsys_cannot_keep_a_denied_process_running() {
            use std::os::unix::process::ExitStatusExt;
            for case in ["ignored", "replaced"] {
                let (out, reason) = child_reason("sigsys_disposition_child", &[("WICK_TEST_CASE", case)]);
                assert!(!String::from_utf8_lossy(&out.stdout).contains("CHILD-SURVIVED"), "{case}: {}", text(&out));
                assert_eq!(out.status.signal(), Some(libc::SIGKILL), "{case}: {}", text(&out));
                assert!(sandbox_kill(reason), "{case}: {}", text(&out));
            }
        }

        #[test]
        #[ignore = "run by test_an_ignored_or_replaced_sigsys_cannot_keep_a_denied_process_running in a separate process"]
        fn sigsys_disposition_child() {
            extern "C" fn returns(_: libc::c_int) {}
            crate::signal_handler::register_signal_handlers().unwrap();
            select(Policy::Default);
            apply().unwrap();
            let handler = match std::env::var("WICK_TEST_CASE").unwrap().as_str() {
                "ignored" => libc::SIG_IGN,
                _ => returns as *const () as usize,
            };
            // SAFETY: a zeroed sigaction with the case's handler.
            unsafe {
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = handler;
                assert_eq!(libc::sigaction(libc::SIGSYS, &act, std::ptr::null_mut()), 0);
            }
            // SAFETY: no arguments; not in SYSCALLS.
            std::thread::spawn(|| unsafe { libc::getppid() }).join().unwrap();
            std::thread::sleep(std::time::Duration::from_secs(2));
            println!("CHILD-SURVIVED");
        }

        // A process that blocks SIGSYS on all of its threads at once (xnu's
        // `sigprocmask` sets every thread's mask, bsd/kern/kern_sig.c
        // `sigprocmask` and `set_procsigmask`; Apple's `abort` does it) is
        // ended by its denied call all the same, as Linux's seccomp trap
        // unblocks SIGSYS to deliver it (kernel/signal.c
        // `force_sig_info_to_task`).
        #[test]
        fn test_a_process_wide_sigsys_block_cannot_keep_a_denied_process_running() {
            use std::os::unix::process::ExitStatusExt;
            let (out, reason) = child_reason("sigsys_blocked_child", &[]);
            assert!(!String::from_utf8_lossy(&out.stdout).contains("CHILD-SURVIVED"), "{}", text(&out));
            assert_eq!(out.status.signal(), Some(libc::SIGKILL), "{}", text(&out));
            assert!(sandbox_kill(reason), "{}", text(&out));
        }

        #[test]
        #[ignore = "run by test_a_process_wide_sigsys_block_cannot_keep_a_denied_process_running in a separate process"]
        fn sigsys_blocked_child() {
            crate::signal_handler::register_signal_handlers().unwrap();
            select(Policy::Default);
            apply().unwrap();
            // SAFETY: a set of SIGSYS, blocked for the whole process.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGSYS);
                assert_eq!(libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()), 0);
            }
            // SAFETY: no arguments; not in SYSCALLS.
            std::thread::spawn(|| unsafe { libc::getppid() }).join().unwrap();
            std::thread::sleep(std::time::Duration::from_secs(2));
            println!("CHILD-SURVIVED");
        }

        // Before narrow(), what building the microVM takes is allowed; after
        // it, only the run phase's lists: a call of the setup phase is a
        // denial, as one outside the VMM thread's filter does on Linux.
        #[test]
        fn test_narrow_ends_the_setup_phase() {
            let out = child("narrowed_child", &[]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("SETUP-OK"), "{}", text(&out));
            assert!(stdout.contains("EPOLL-OK"), "{}", text(&out));
            assert!(denied(&out), "{}", text(&out));
            assert!(!stdout.contains("CHILD-SURVIVED"), "{}", text(&out));
        }

        // A handled signal that lands while a thread is blocked in a
        // cancellation point (the vCPU kick, SIGRTMIN here as upstream sends
        // it, with upstream's flags: no SA_RESTART) makes the call fail with
        // EINTR, and the thread goes on, in every phase and profile, as on
        // Linux. libsystem's stub of such a call asks the kernel whether the
        // thread was cancelled (__pthread_canceled(0)) before it returns
        // EINTR (Libsyscall custom/errno.c `cerror`, libpthread
        // pthread_cancelable.c `_pthread_exit_if_canceled`); unlisted, that
        // query raised SIGSYS and stopped the microVM. Two cancellation
        // points: read on a pipe, and nanosleep (__semwait_signal) where the
        // profile lets a thread sleep (not the API process's: it has no
        // clock or __semwait_signal).
        #[test]
        fn test_a_handled_signal_interrupts_a_blocking_call() {
            for case in ["setup", "run", "api"] {
                let out = child("interrupted_child", &[("WICK_TEST_CASE", case)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(stdout.contains("SANDBOXED"), "{case}: {}", text(&out));
                assert!(out.status.success() && stdout.contains("CHILD-OK"), "{case}: {}", text(&out));
            }
        }

        // A fault or a trap of a thread is its signal under every profile,
        // as on Linux, where no filter sees the kernel raise it: the
        // process ends by SIGSEGV or SIGBUS (a store to address 0) or by
        // SIGTRAP (`brk`), at their default action here. Under macOS 15's
        // Seatbelt the kernel's own message for it has to be allowed
        // (`EXCEPTION_MIG_ROUTINES`): without the allowance each case ends
        // by the sandbox's kill there.
        #[test]
        fn test_a_fault_is_its_signal_under_each_profile() {
            use std::os::unix::process::ExitStatusExt;
            let mut failed = Vec::new();
            for profile in ["setup", "run", "api"] {
                for how in ["fault", "trap"] {
                    let out = child("faulting_child", &[("WICK_TEST_CASE", &format!("{profile}-{how}"))]);
                    let signal = out.status.signal();
                    let ok = match how {
                        "fault" => signal == Some(libc::SIGSEGV) || signal == Some(libc::SIGBUS),
                        _ => signal == Some(libc::SIGTRAP),
                    };
                    if !ok || !String::from_utf8_lossy(&out.stdout).contains("SANDBOXED") {
                        failed.push(format!("{profile}-{how}: {}", text(&out)));
                    }
                }
            }
            assert!(failed.is_empty(), "{} of 6 cases:\n{}", failed.len(), failed.join("\n=====\n"));
        }

        #[test]
        #[ignore = "run by test_a_fault_is_its_signal_under_each_profile in a separate process"]
        fn faulting_child() {
            // In a fork of this thread, one thread, as the API process is
            // when its profile is applied (as api_child).
            in_fork(|| {
                let case = std::env::var("WICK_TEST_CASE").unwrap();
                let (profile, how) = case.split_once('-').unwrap();
                // The default action for each: no handler of the test
                // harness's (std's for a stack overflow) or of the sandbox's.
                for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGTRAP, libc::SIGSYS] {
                    // SAFETY: the default action for a valid signal.
                    unsafe { libc::signal(sig, libc::SIG_DFL) };
                }
                select(Policy::Default);
                match profile {
                    "setup" => apply().unwrap(),
                    "run" => {
                        apply().unwrap();
                        narrow().unwrap();
                    }
                    _ => apply_api().unwrap(),
                }
                // SAFETY: the default action again where `apply` put the
                // sandbox's handlers; then a store to address 0, which
                // faults, or a breakpoint trap.
                unsafe {
                    for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGTRAP] {
                        libc::signal(sig, libc::SIG_DFL);
                    }
                    libc::write(1, c"SANDBOXED\n".as_ptr().cast(), 10);
                    if how == "fault" {
                        std::ptr::write_volatile(std::ptr::null_mut::<u8>(), 1);
                    } else {
                        std::arch::asm!("brk #1");
                    }
                }
            })
        }

        // What the allowance of EXCEPTION_MIG_ROUTINES lets the process do
        // itself: its own `mach_exception_raise` message, sent to a kernel
        // object it holds (its task port; the id alone picks the routine,
        // XNU osfmk/kern/ipc_kobject.c `find_mig_hash_entry`), is answered
        // KERN_FAILURE by `catch_mach_exception_raise` (bsd/uxkern/
        // ux_handler.c: not the host's exception port) and raises no signal,
        // here at a fault's default action, as without a sandbox (the
        // control); the routines that would hand it an exception port are
        // denied, and the API process sends no Mach message at all.
        // On macOS 26 and 27 the filter is not consulted for the message, so
        // there the cases show what the routine does; on 15 they also show
        // the allowance.
        #[test]
        fn test_an_exception_message_of_its_own_does_nothing() {
            let lists = [
                SETUP_MIG_ROUTINES, SETUP_MIG_ROUTINES_IF_DEFINED, MIG_ROUTINES, PVTIME_MIG_ROUTINES,
                API_MIG_ROUTINES, EXCEPTION_MIG_ROUTINES,
            ]
            .concat();
            for denied in [
                "host_get_exception_ports", "host_swap_exception_ports", "task_get_exception_ports",
                "task_swap_exception_ports", "thread_get_exception_ports", "thread_swap_exception_ports",
                "host_get_special_port", "host_get_host_priv_port",
            ] {
                assert!(!lists.contains(&denied), "{denied}");
            }
            let mut failed = Vec::new();
            let cases = ["none-raise", "setup-raise", "setup-get_ports", "run-raise", "run-get_ports", "api-raise", "api-get_ports"];
            for name in cases {
                let out = child("exception_message_child", &[("WICK_TEST_CASE", name)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                let ok = stdout.contains("SANDBOXED")
                    && match name {
                        // KERN_FAILURE (5) in the routine's reply (2405 + 100).
                        "none-raise" | "setup-raise" | "run-raise" => {
                            out.status.success() && stdout.contains("MACH-MSG 0 REPLY-ID 2505\nRETCODE 5\n")
                        }
                        _ => denied(&out) && !stdout.contains("RETCODE"),
                    };
                if !ok {
                    failed.push(format!("{name}: {}", text(&out)));
                }
            }
            assert!(failed.is_empty(), "{} of {} cases:\n{}", failed.len(), cases.len(), failed.join("\n=====\n"));
        }

        #[test]
        #[ignore = "run by test_an_exception_message_of_its_own_does_nothing in a separate process"]
        fn exception_message_child() {
            #[repr(C, packed(4))]
            struct Raise {
                // mach_msg_header_t
                bits: u32,
                size: u32,
                remote: u32,
                local: u32,
                voucher: u32,
                id: i32,
                // mach_msg_body_t, two mach_msg_port_descriptor_t
                descriptors: u32,
                thread: [u32; 3],
                task: [u32; 3],
                ndr: [u8; 8],
                exception: i32,
                code_count: u32,
                code: [i64; 2],
            }
            unsafe extern "C" {
                static mach_task_self_: libc::mach_port_t;
                static NDR_record: [u8; 8];
                fn mig_get_reply_port() -> libc::mach_port_t;
                // libsystem_kernel's way into mach_msg2_trap, called as its
                // MIG clients call it (each pair of 32-bit fields in one
                // word; disassembled task_get_exception_ports, macOS 27.2).
                fn mach_msg2_internal(
                    data: *mut u8,
                    options: u64,
                    bits_and_send_size: u64,
                    remote_and_local: u64,
                    voucher_and_id: u64,
                    descriptors_and_rcv_name: u64,
                    rcv_size_and_priority: u64,
                    timeout: u64,
                ) -> i32;
                fn task_get_exception_ports(
                    task: libc::mach_port_t,
                    mask: u32,
                    masks: *mut u32,
                    count: *mut u32,
                    handlers: *mut libc::mach_port_t,
                    behaviors: *mut i32,
                    flavors: *mut i32,
                ) -> i32;
            }
            // In a fork of this thread, one thread, as faulting_child.
            in_fork(|| {
                let case = std::env::var("WICK_TEST_CASE").unwrap();
                let (profile, case) = case.split_once('-').unwrap();
                // SAFETY: set by libSystem before main; this thread's port
                // and its MIG reply port (made here, before the profile).
                let (task, thread, reply) = unsafe {
                    (mach_task_self_, libc::pthread_mach_thread_np(libc::pthread_self()), mig_get_reply_port())
                };
                for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGTRAP, libc::SIGSYS] {
                    // SAFETY: the default action for a valid signal.
                    unsafe { libc::signal(sig, libc::SIG_DFL) };
                }
                select(Policy::Default);
                match profile {
                    "setup" => apply().unwrap(),
                    "run" => {
                        apply().unwrap();
                        narrow().unwrap();
                    }
                    // The control: the same message without a sandbox.
                    "none" => {}
                    _ => apply_api().unwrap(),
                }
                for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGTRAP] {
                    // SAFETY: as above, where `apply` put the sandbox's handlers.
                    unsafe { libc::signal(sig, libc::SIG_DFL) };
                }
                // SAFETY: a valid buffer.
                unsafe { libc::write(1, c"SANDBOXED\n".as_ptr().cast(), 10) };
                if case == "get_ports" {
                    let (mut masks, mut handlers, mut behaviors, mut flavors) = ([0u32; 32], [0; 32], [0; 32], [0; 32]);
                    let mut count = 32;
                    // SAFETY: arrays of `count` entries each.
                    let kr = unsafe {
                        task_get_exception_ports(
                            task,
                            0x7ffe, // EXC_MASK_ALL
                            masks.as_mut_ptr(),
                            &mut count,
                            handlers.as_mut_ptr(),
                            behaviors.as_mut_ptr(),
                            flavors.as_mut_ptr(),
                        )
                    };
                    println!("GOT-PORTS {kr}");
                    return;
                }
                // EXC_BAD_ACCESS (1) with KERN_INVALID_ADDRESS (1): SIGSEGV if
                // the routine raised it.
                let copy_send = 19 << 16; // MACH_MSG_TYPE_COPY_SEND, a port descriptor
                let mut msg = Raise {
                    // MACH_MSGH_BITS_COMPLEX, COPY_SEND to the remote, MAKE_SEND_ONCE for the reply.
                    bits: 0x8000_0000 | 19 | (21 << 8),
                    size: u32::try_from(std::mem::size_of::<Raise>()).unwrap(),
                    remote: task,
                    local: reply,
                    voucher: 0,
                    id: 2405, // mach_exception_raise, osfmk/mach/mach_exc.defs
                    descriptors: 2,
                    thread: [thread, 0, copy_send],
                    task: [task, 0, copy_send],
                    // SAFETY: a constant of libSystem's.
                    ndr: unsafe { NDR_record },
                    exception: 1,
                    code_count: 2,
                    code: [1, 0],
                };
                let mut buf = [0u8; 256];
                // SAFETY: `msg` is copied into `buf`, which takes the reply.
                let mr = unsafe {
                    std::ptr::copy_nonoverlapping((&raw mut msg).cast::<u8>(), buf.as_mut_ptr(), std::mem::size_of::<Raise>());
                    // MACH64_SEND_KOBJECT_CALL | MACH_RCV_MSG | MACH_SEND_MSG, as
                    // libsystem's clients send to a kernel object.
                    mach_msg2_internal(
                        buf.as_mut_ptr(),
                        0x2_0000_0003,
                        u64::from(msg.bits) | (u64::from(msg.size) << 32),
                        u64::from(task) | (u64::from(reply) << 32),
                        2405 << 32,
                        2 | (u64::from(reply) << 32),
                        256,
                        0,
                    )
                };
                // mig_reply_error_t: the header, NDR, then RetCode.
                let retcode = i32::from_ne_bytes(buf[32..36].try_into().unwrap());
                let id = i32::from_ne_bytes(buf[20..24].try_into().unwrap());
                println!("MACH-MSG {mr} REPLY-ID {id}");
                println!("RETCODE {retcode}");
            })
        }

        #[test]
        #[ignore = "run by test_a_handled_signal_interrupts_a_blocking_call in a separate process"]
        fn interrupted_child() {
            // In a fork of this thread, so that the process holds only the
            // threads the work makes: libtest's main thread, waiting for the
            // test's end on its parker, makes its kernel semaphore at its
            // first wait (libdispatch `_dispatch_sema4_create_slow`:
            // semaphore_create, over mach_msg2_trap), which the API
            // profile denies if that wait comes after it (as api_child).
            in_fork(|| {
                let ok = std::panic::catch_unwind(interrupted_body).is_ok();
                let _ = std::io::Write::flush(&mut std::io::stdout());
                if !ok {
                    // SAFETY: ends the fork, as a panic ends a test.
                    unsafe { libc::_exit(101) };
                }
            })
        }

        /// [`interrupted_child`]'s work, in its fork. No thread of it parks
        /// (a channel, a join): a parker's first wait after the profile
        /// would be denied as libtest's is. The blocked thread's results
        /// come back in atomics.
        fn interrupted_body() {
            use std::os::unix::thread::JoinHandleExt;
            use std::sync::atomic::{AtomicBool, AtomicI32, AtomicIsize, AtomicU8};
            use std::time::{Duration, Instant};

            use crate::utils::signal::{register_signal_handler, sigrtmin};
            extern "C" fn kicked(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {}
            register_signal_handler(sigrtmin(), kicked).unwrap();
            let mut fds = [0; 2];
            // SAFETY: an array of two descriptors to fill.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            // How far the blocked thread is: 1 its read returned, 2 its
            // sleep did; and what each returned, with its errno.
            static STARTED: AtomicBool = AtomicBool::new(false);
            static STAGE: AtomicU8 = AtomicU8::new(0);
            static READ: AtomicIsize = AtomicIsize::new(0);
            static READ_ERR: AtomicI32 = AtomicI32::new(0);
            static SLEEP: AtomicI32 = AtomicI32::new(0);
            static SLEEP_ERR: AtomicI32 = AtomicI32::new(0);
            let reader = fds[0];
            let case = std::env::var("WICK_TEST_CASE").unwrap();
            let sleeps = case != "api";
            // Made, and running, before the sandbox, as the vCPU and API
            // threads are.
            let blocked = std::thread::spawn(move || {
                STARTED.store(true, Ordering::Release);
                let mut byte = 0u8;
                // SAFETY: one byte into a local, from the pipe's read end.
                let read = unsafe { libc::read(reader, (&raw mut byte).cast(), 1) };
                READ_ERR.store(std::io::Error::last_os_error().raw_os_error().unwrap_or(0), Ordering::Relaxed);
                READ.store(read, Ordering::Relaxed);
                STAGE.store(1, Ordering::Release);
                let (mut sleep, mut sleep_err) = (-1, libc::EINTR);
                if sleeps {
                    let long = libc::timespec { tv_sec: 30, tv_nsec: 0 };
                    // SAFETY: a time to sleep and no remainder asked for.
                    sleep = unsafe { libc::nanosleep(&long, std::ptr::null_mut()) };
                    sleep_err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                }
                SLEEP.store(sleep, Ordering::Relaxed);
                SLEEP_ERR.store(sleep_err, Ordering::Relaxed);
                STAGE.store(2, Ordering::Release);
            });
            while !STARTED.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            assert_eq!(process_threads(), 2, "the profile is applied with this thread and the blocked one only");
            match case.as_str() {
                "setup" => {
                    select(Policy::Default);
                    apply().unwrap();
                }
                "run" => {
                    select(Policy::Default);
                    apply().unwrap();
                    narrow().unwrap();
                }
                "api" => {
                    select(Policy::Default);
                    apply_api().unwrap();
                }
                other => panic!("no case {other}"),
            }
            println!("SANDBOXED");
            // A signal may come before the thread blocks: it is sent again
            // until both calls have returned.
            let start = Instant::now();
            while STAGE.load(Ordering::Acquire) < 2 {
                assert!(start.elapsed() < Duration::from_secs(10), "stage {}", STAGE.load(Ordering::Acquire));
                // SAFETY: a live thread of this process.
                assert_eq!(unsafe { libc::pthread_kill(blocked.as_pthread_t(), sigrtmin()) }, 0);
                // Spun, not slept: the API process's profile has no sleep.
                let sent = Instant::now();
                while sent.elapsed() < Duration::from_millis(20) {
                    std::hint::spin_loop();
                }
            }
            let read = (READ.load(Ordering::Relaxed), READ_ERR.load(Ordering::Relaxed));
            let sleep = (SLEEP.load(Ordering::Relaxed), SLEEP_ERR.load(Ordering::Relaxed));
            assert_eq!(read, (-1, libc::EINTR));
            assert_eq!(sleep, (-1, libc::EINTR));
            println!("CHILD-OK");
        }

        // narrow() cannot be undone: after it, no extension can be issued or
        // taken (each is a denial), and a thread cannot be created (Linux's
        // VMM filter has no clone).
        #[test]
        fn test_narrowing_is_one_way() {
            for case in ["issue", "consume", "thread", "thread-policy"] {
                let out = child("one_way_child", &[("WICK_TEST_CASE", case)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(stdout.contains("NARROWED"), "{case}: {}", text(&out));
                assert!(denied(&out), "{case}: {}", text(&out));
                assert!(!stdout.contains("CHILD-SURVIVED"), "{case}: {}", text(&out));
            }
        }

        #[test]
        #[ignore = "run by test_narrow_ends_the_setup_phase in a separate process"]
        fn narrowed_child() {
            let end_of_stream = EndOfStream::new();
            select(Policy::Default);
            apply().unwrap();
            // SAFETY: dup of the standard output, closed again.
            let fd = unsafe { libc::dup(1) };
            assert!(fd >= 0);
            // SAFETY: the descriptor just created.
            unsafe { libc::close(fd) };
            // A vCPU thread's latency tier is set in the setup phase
            // (ext::vcpu_thread).
            let (end, wait) = std::sync::mpsc::channel::<()>();
            let thread = std::thread::spawn(move || {
                let _ = wait.recv();
            });
            crate::ext::vcpu_thread::spawned(&thread).unwrap();
            drop(end);
            thread.join().unwrap();
            println!("SETUP-OK");
            narrow().unwrap();
            // A second call does nothing.
            narrow().unwrap();
            // A VMM thread's epoll at the end of a stream (a vsock
            // connection's, the serial's): the run phase's lists.
            end_of_stream.check();
            println!("EPOLL-OK");
            // SAFETY: as above.
            unsafe { libc::dup(1) };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // The API process's profile (ext::api_process) allows what an HTTP
        // server on an open socket needs, as upstream's api filter: a call
        // outside API_SYSCALLS, shared memory, an executable mapping, madvise
        // with advice other than MADV_DONTNEED and an fcntl command other
        // than F_GETFD and F_SETFD are denials; a file fails with an error,
        // as outside the chroot.
        #[test]
        fn test_api_profile_denies_outside_its_list() {
            for case in ["dup", "shm", "exec", "socketpair", "madvise", "dontneed", "fcntl"] {
                let out = child("api_child", &[("WICK_TEST_CASE", case)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(stdout.contains("SETUP-OK"), "{case}: {}", text(&out));
                assert!(denied(&out), "{case}: {}", text(&out));
                assert!(!stdout.contains("CHILD-SURVIVED"), "{case}: {}", text(&out));
            }
            let out = child("api_child", &[("WICK_TEST_CASE", "allowed")]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success() && stdout.contains("CHILD-OK"), "{}", text(&out));
        }

        #[test]
        #[ignore = "run by test_api_profile_denies_outside_its_list in a separate process"]
        fn api_child() {
            use std::os::unix::process::ExitStatusExt;
            // The API process is a fork made with one thread
            // (`api_process::fork` checks it), and nothing else runs in it
            // when its profile is applied. Here the test thread runs beside
            // libtest's main thread, which waits for the test's end on its
            // thread parker, a libdispatch semaphore whose kernel semaphore
            // is made at the first wait (libdispatch src/semaphore.c,
            // src/shims/lock.c `_dispatch_sema4_create_slow`:
            // `semaphore_create`, a Mach message). When that first wait came
            // after the profile, mach_msg2_trap was denied and the process
            // ended with SIGSYS before SETUP-OK (CI run 43316721239, macOS
            // 15: "SIGSYS step 01 O", its only denial `syscall-mach 47`; 1
            // run in 20 on macOS 26 before). So the profile is applied in a
            // fork of this thread, as in the API process, and its end is
            // this process's.
            // SAFETY: the child runs only this thread's code and ends with
            // `_exit` or a signal, never returning into libtest.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
            if pid == 0 {
                let ok = std::panic::catch_unwind(api_child_body).is_ok();
                let _ = std::io::Write::flush(&mut std::io::stdout());
                // SAFETY: ends the forked child.
                unsafe { libc::_exit(if ok { 0 } else { 101 }) };
            }
            // Its exit reason, which only this process may read, for
            // [`denied`].
            if let Some((namespace, code)) = exit_reason(pid) {
                println!("\n{EXIT_REASON_LINE}{namespace} {code:#x}");
            }
            let mut status = 0;
            // SAFETY: our child; an out-pointer.
            while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
                let err = std::io::Error::last_os_error();
                assert_eq!(err.raw_os_error(), Some(libc::EINTR), "waitpid: {err}");
            }
            let status = std::process::ExitStatus::from_raw(status);
            if let Some(signal) = status.signal() {
                // The child's signal ends this process too, as the test reads it.
                // SAFETY: the default action of a valid signal, then the signal.
                unsafe {
                    libc::signal(signal, libc::SIG_DFL);
                    libc::raise(signal);
                }
            }
            assert!(status.success(), "the forked child: {status:?}");
        }

        /// This process's threads.
        fn process_threads() -> usize {
            // SAFETY: an all-zero proc_taskinfo is a valid output buffer.
            let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
            let size = i32::try_from(std::mem::size_of::<libc::proc_taskinfo>()).unwrap();
            // SAFETY: a valid output buffer of the size passed.
            let got = unsafe {
                libc::proc_pidinfo(
                    libc::getpid(),
                    libc::PROC_PIDTASKINFO,
                    0,
                    std::ptr::from_mut(&mut info).cast(),
                    size,
                )
            };
            assert_eq!(got, size, "proc_pidinfo: {}", std::io::Error::last_os_error());
            usize::try_from(info.pti_threadnum).unwrap()
        }

        /// [`api_child`]'s work, in its one-thread fork.
        fn api_child_body() {
            use std::io::{Read, Write};
            use std::sync::atomic::{AtomicU8, AtomicUsize};
            // Diagnosis of a SIGSYS before SETUP-OK: which step the thread
            // had reached, and the thread the signal came on (T: this
            // thread, O: another). Seatbelt signals the process, so the
            // thread is not the offender's.
            assert_eq!(process_threads(), 1, "the API profile is applied in a process of one thread");
            static STEP: AtomicU8 = AtomicU8::new(0);
            static TEST_THREAD: AtomicUsize = AtomicUsize::new(0);
            extern "C" fn on_sigsys(_: libc::c_int) {
                // SAFETY: TLS read, no system call.
                let me = unsafe { libc::pthread_self() } as usize;
                let which = if me == TEST_THREAD.load(Ordering::Relaxed) { b'T' } else { b'O' };
                let step = STEP.load(Ordering::Relaxed);
                let msg = [b'S', b'I', b'G', b'S', b'Y', b'S', b' ', b's', b't', b'e', b'p', b' ',
                    b'0' + step / 10, b'0' + step % 10, b' ', which, b'\n'];
                // SAFETY: async-signal-safe calls; the handler was reset to
                // the default action (SA_RESETHAND), so the signal ends the
                // process as before.
                unsafe {
                    libc::write(2, msg.as_ptr().cast(), msg.len());
                    libc::pthread_kill(libc::pthread_self(), libc::SIGSYS);
                }
            }
            // SAFETY: a plain handler, installed once.
            unsafe {
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = on_sigsys as *const () as usize;
                act.sa_flags = libc::SA_RESETHAND | libc::SA_NODEFER;
                assert_eq!(libc::sigaction(libc::SIGSYS, &act, std::ptr::null_mut()), 0);
                TEST_THREAD.store(libc::pthread_self() as usize, Ordering::Relaxed);
            }
            let step = |n: u8| STEP.store(n, Ordering::Relaxed);
            let case = std::env::var("WICK_TEST_CASE").unwrap();
            let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
            let end_of_stream = EndOfStream::new();
            select(Policy::Default);
            step(1);
            apply_api().unwrap();
            // What the API process does: Unix socket I/O, memory, time,
            // randomness, threads' locks.
            step(2);
            a.write_all(b"ping").unwrap();
            let mut buf = [0u8; 4];
            b.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            step(3);
            let v: Vec<u8> = vec![7; 1 << 20];
            assert_eq!(v.iter().map(|&x| u64::from(x)).sum::<u64>(), 7 << 20);
            step(4);
            let _ = std::time::SystemTime::now();
            step(5);
            let mut entropy = [0u8; 16];
            // SAFETY: a 16-byte output buffer.
            assert_eq!(unsafe { libc::getentropy(entropy.as_mut_ptr().cast(), 16) }, 0);
            // Files fail with an error.
            step(6);
            std::fs::File::open("/etc/hosts").unwrap_err();
            // Upstream's api filter: fcntl F_SETFD. (Its madvise with
            // MADV_DONTNEED reads the region first with a Mach message here,
            // which the API process's lists do not allow.)
            const PAGE: usize = 16384;
            step(7);
            // SAFETY: a new anonymous mapping.
            let page = unsafe {
                libc::mmap(std::ptr::null_mut(), PAGE, libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0)
            };
            assert_ne!(page, libc::MAP_FAILED);
            step(8);
            // SAFETY: a descriptor of this process.
            assert_eq!(unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&a), libc::F_SETFD, libc::FD_CLOEXEC) }, 0);
            // The API server's epoll at a client's close.
            step(9);
            end_of_stream.check();
            step(10);
            println!("SETUP-OK");
            std::io::stdout().flush().unwrap();
            step(11);
            match case.as_str() {
                "allowed" => {
                    println!("CHILD-OK");
                    return;
                }
                // SAFETY: a plain call.
                "dup" => unsafe {
                    libc::dup(1);
                },
                // SAFETY: a NUL-terminated name.
                "shm" => unsafe {
                    libc::shm_open(c"/wick-api-test".as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600);
                },
                // SAFETY: a new anonymous mapping.
                "exec" => unsafe {
                    libc::mmap(std::ptr::null_mut(), 16384, libc::PROT_READ | libc::PROT_EXEC,
                        libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0);
                },
                // Other advice (the compatibility libc's check).
                // SAFETY: the mapping made above.
                "madvise" => unsafe {
                    libc::madvise(page, PAGE, libc::MADV_WILLNEED);
                },
                // MADV_DONTNEED: the compatibility libc reads the region
                // first with a Mach message, outside the API process's lists.
                // SAFETY: as above.
                "dontneed" => unsafe {
                    libc::madvise(page, PAGE, libc::MADV_DONTNEED);
                },
                // Another fcntl command (Seatbelt's system-fcntl).
                // SAFETY: a descriptor of this process.
                "fcntl" => unsafe {
                    libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&a), libc::F_GETFL);
                },
                _ => {
                    let mut fds = [0; 2];
                    // SAFETY: a two-element output buffer.
                    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
                }
            }
            // Seatbelt signals the process, not the thread.
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // Executable mappings end the process as upstream's mmap and mprotect
        // rules do (they trap on PROT_EXEC): a file mapped executable and a
        // MAP_JIT mapping always (Seatbelt), an anonymous one after narrow()
        // (the compatibility libc's check). Before narrow(), where Linux's
        // VMM thread is unfiltered, an anonymous one is made.
        #[test]
        fn test_executable_mappings_are_denials() {
            for case in ["file", "jit", "mmap", "mprotect", "blocked"] {
                let out = child("exec_map_child", &[("WICK_TEST_CASE", case)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(stdout.contains("SETUP-OK"), "{case}: {}", text(&out));
                assert!(denied(&out), "{case}: {}", text(&out));
                assert!(!stdout.contains("CHILD-SURVIVED"), "{case}: {}", text(&out));
            }
        }

        #[test]
        #[ignore = "run by test_executable_mappings_are_denials in a separate process"]
        fn exec_map_child() {
            const PAGE: usize = 16384;
            let anon = |prot| {
                // SAFETY: a new anonymous mapping.
                unsafe {
                    libc::mmap(std::ptr::null_mut(), PAGE, prot, libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0)
                }
            };
            let case = std::env::var("WICK_TEST_CASE").unwrap();
            let lib = std::fs::File::open("/usr/lib/dyld")
                .or_else(|_| std::fs::File::open(std::env::current_exe().unwrap()))
                .unwrap();
            select(Policy::Default);
            apply().unwrap();
            let rw = anon(libc::PROT_READ | libc::PROT_WRITE);
            assert_ne!(rw, libc::MAP_FAILED);
            if case == "mmap" || case == "mprotect" || case == "blocked" {
                assert_ne!(anon(libc::PROT_READ | libc::PROT_EXEC), libc::MAP_FAILED);
                narrow().unwrap();
                // Not executable: allowed.
                assert_ne!(anon(libc::PROT_READ), libc::MAP_FAILED);
                // SAFETY: the mapping made above.
                assert_eq!(unsafe { libc::mprotect(rw, PAGE, libc::PROT_READ) }, 0);
            }
            if case == "blocked" {
                // SAFETY: a valid signal set.
                unsafe {
                    let mut set: libc::sigset_t = std::mem::zeroed();
                    libc::sigemptyset(&mut set);
                    libc::sigaddset(&mut set, libc::SIGSYS);
                    libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
                }
            }
            println!("SETUP-OK");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            let p = match case.as_str() {
                // SAFETY: a mapping of an open file.
                "file" => unsafe {
                    libc::mmap(std::ptr::null_mut(), PAGE, libc::PROT_READ | libc::PROT_EXEC,
                        libc::MAP_PRIVATE, std::os::unix::io::AsRawFd::as_raw_fd(&lib), 0)
                },
                "jit" => {
                    // SAFETY: a new anonymous mapping.
                    unsafe {
                        libc::mmap(std::ptr::null_mut(), PAGE,
                            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                            libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_JIT, -1, 0)
                    }
                }
                "mmap" | "blocked" => anon(libc::PROT_READ | libc::PROT_EXEC),
                // SAFETY: the mapping made above.
                _ => match unsafe { libc::mprotect(rw, PAGE, libc::PROT_READ | libc::PROT_EXEC) } {
                    0 => rw,
                    _ => libc::MAP_FAILED,
                },
            };
            // Seatbelt signals the process, not the thread: the denied call
            // returns EPERM here until the signal lands on a thread.
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED {p:?}");
        }

        // What the running microVM needs a thread for exists before narrow()
        // forbids making one: a timer made only after it (a hot-plugged
        // device's rate limiter, with no timer made at boot) fires, with no
        // thread made then (a new thread would are denials, as in
        // test_narrowing_is_one_way).
        #[test]
        fn test_threads_the_run_phase_needs_exist_before_narrow() {
            let out = child("late_timer_child", &[]);
            assert!(out.status.success(), "{}", text(&out));
            assert!(String::from_utf8_lossy(&out.stdout).contains("CHILD-OK"), "{}", text(&out));
        }

        #[test]
        #[ignore = "run by test_threads_the_run_phase_needs_exist_before_narrow in a separate process"]
        fn late_timer_child() {
            select(Policy::Default);
            apply().unwrap();
            narrow().unwrap();
            // SAFETY: plain call.
            let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };
            assert!(fd >= 0, "{}", std::io::Error::last_os_error());
            let spec = libc::itimerspec {
                it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
                it_value: libc::timespec { tv_sec: 0, tv_nsec: 10_000_000 },
            };
            // SAFETY: valid descriptor and spec.
            assert_eq!(unsafe { libc::timerfd_settime(fd, 0, &spec, std::ptr::null_mut()) }, 0);
            let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            // SAFETY: one valid pollfd.
            assert_eq!(unsafe { libc::poll(&mut p, 1, 30_000) }, 1, "the timer did not fire");
            println!("CHILD-OK");
        }

        #[test]
        #[ignore = "run by test_narrowing_is_one_way in a separate process"]
        fn one_way_child() {
            // Issued before the sandbox, as the narrowed token is.
            let early = Token::issue(c"com.toollyst.wick.test").unwrap();
            select(Policy::Default);
            apply().unwrap();
            narrow().unwrap();
            println!("NARROWED");
            match std::env::var("WICK_TEST_CASE").unwrap().as_str() {
                "issue" => {
                    let _ = Token::issue(NARROWED);
                }
                "consume" => {
                    let _ = early.consume();
                }
                "thread" => {
                    let _ = std::thread::spawn(|| ()).join();
                }
                // A thread's policy is setup's to set (a vCPU thread's
                // latency tier, ext::vcpu_thread).
                "thread-policy" => {
                    // SAFETY: no arguments.
                    let _ = kvm_ioctls::latency::vcpu_thread(unsafe { libc::pthread_self() });
                }
                other => panic!("{other}"),
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        #[test]
        #[ignore = "run by test_a_denied_syscall_ends_firecracker_by_the_sandboxs_kill in a separate process"]
        fn handled_child() {
            crate::signal_handler::register_signal_handlers().unwrap();
            select(Policy::Default);
            apply().unwrap();
            // SAFETY: no arguments.
            unsafe { libc::getppid() };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        /// A system call number the kernel has no entry for (macOS has
        /// `SYS_MAXSYSCALL` 558): xnu's `unix_syscall` checks it with the
        /// sandbox as SYS_invalid (63) and, let through, runs `nosys` for it
        /// (bsd/dev/arm/systemcalls.c :112, :161), which fails with ENOSYS
        /// and signals the calling thread (bsd/kern/subr_xxx.c,
        /// `psignal_uthread`).
        const UNKNOWN_SYSCALL: u16 = 1000;

        // With the sandbox, a call the kernel has no number for is a denial,
        // as upstream's filters trap a number they do not list: no list has
        // SYS_invalid, as which the kernel checks it.
        #[test]
        fn test_an_unknown_syscall_number_is_a_denial() {
            let out = child("unknown_syscall_child", &[("WICK_TEST_POLICY", "default")]);
            assert!(denied(&out), "{}", text(&out));
        }

        // Without the sandbox (--no-seccomp) the same call fails with ENOSYS
        // and Firecracker runs on, as on Linux with no seccomp filter.
        #[test]
        fn test_an_unknown_syscall_number_without_the_sandbox_fails_with_enosys() {
            let out = child("unknown_syscall_child", &[("WICK_TEST_POLICY", "none")]);
            assert!(out.status.success(), "{}", text(&out));
            assert!(String::from_utf8_lossy(&out.stdout).contains("ENOSYS-AND-ALIVE"), "{}", text(&out));
        }

        #[test]
        #[ignore = "run by test_an_unknown_syscall_number_is_a_denial and test_an_unknown_syscall_number_without_the_sandbox_fails_with_enosys in a separate process"]
        fn unknown_syscall_child() {
            crate::signal_handler::register_signal_handlers().unwrap();
            let none = std::env::var("WICK_TEST_POLICY").unwrap() == "none";
            select(if none { Policy::None } else { Policy::Default });
            apply().unwrap();
            let (r0, _, failed) = std::thread::spawn(|| {
                // SAFETY: a number the kernel has no call for; it reads none
                // of its arguments.
                unsafe { svc(UNKNOWN_SYSCALL, [0; 8]) }
            })
            .join()
            .unwrap();
            assert!(failed && r0 == libc::ENOSYS as usize, "{r0} {failed}");
            std::thread::sleep(std::time::Duration::from_secs(1));
            println!("ENOSYS-AND-ALIVE");
        }

        /// Runs `ending_child` with `case`, "<who>-<how>": the thread `who`
        /// (`denier`, after a denied call; `none`, with no denied call) ends
        /// the process `how`, in the run phase.
        fn ending(case: &str) -> (std::process::Output, Option<ExitReason>) {
            child_reason("ending_child", &[("WICK_TEST_CASE", case)])
        }

        const HOWS: [&str; 5] = ["abort", "panic", "fault", "exit", "trap"];

        /// The metrics upstream's handler writes for a seccomp fault.
        const FAULT_METRIC: &str = "\"seccomp\":{\"num_faults\":1}";

        /// A failed case's output, with what Seatbelt reported for its
        /// process (the case's `CHILD-PID` line): the kernel logs each call
        /// it denies by its number or name ("deny(1) syscall-unix 39"), with
        /// the threads' stacks, which the exit does not carry. Read from the
        /// log store here, since a CI step that reads it after all the tests
        /// has thousands of other tests' lines. Not every denied call has a
        /// line: the kernel leaves out a report it takes for a duplicate.
        fn text_and_denials(out: &std::process::Output) -> String {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let Some(pid) = stdout.lines().find_map(|l| l.strip_prefix("CHILD-PID ")) else {
                return format!("{}\n--- Seatbelt's reports: no CHILD-PID line", text(out));
            };
            let predicate = format!("eventMessage CONTAINS \"Sandbox: \" AND eventMessage CONTAINS \"({pid}) \"");
            // A report reaches the store after the call it is for: read
            // until one is there, 10 s at most (a case with no denied call
            // has none).
            let start = std::time::Instant::now();
            let reports = loop {
                let log = Command::new("/usr/bin/log")
                    .args(["show", "--last", "5m", "--style", "compact", "--predicate", &predicate])
                    .output();
                let lines = match &log {
                    Ok(log) => String::from_utf8_lossy(&log.stdout).into_owned(),
                    Err(e) => break format!("/usr/bin/log: {e}"),
                };
                if lines.contains("Sandbox: ") {
                    break lines;
                }
                if start.elapsed() > std::time::Duration::from_secs(10) {
                    break "none in 10 s".to_owned();
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            };
            format!("{}\n--- Seatbelt's reports for process {pid}\n{reports}", text(out))
        }

        // The thread whose call the sandbox denied does nothing after it:
        // whatever it would have done next (an abort, a panic, a fault
        // upstream's handler exits on, exit, a trap) never runs, and the
        // process ends by the kernel's kill, with none of that end's output.
        // On Linux too that thread runs nothing after its trapped call;
        // there the process exits 148 with upstream's log line and fault
        // metric, here it ends by SIGKILL (docs/COMPATIBILITY.md). (Under
        // the earlier action, SIGSYS to the process, the thread ran on, and
        // each of these ends needed a check of its own.)
        #[test]
        fn test_a_denied_calls_thread_cannot_end_firecracker_another_way() {
            use std::os::unix::process::ExitStatusExt;
            // Every case runs, and each one that fails is reported.
            let mut failed = Vec::new();
            for how in HOWS {
                let case = format!("denier-{how}");
                let (out, reason) = ending(&case);
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut wrong = Vec::new();
                if out.status.signal() != Some(libc::SIGKILL) || !sandbox_kill(reason) {
                    wrong.push(format!("not the sandbox's kill: reason {reason:x?}"));
                }
                for other in [
                    "Firecracker panicked",
                    "intercepting signal",
                    "\"panic_count\":1",
                    "AFTER-THE-DENIED-CALL",
                    "CHILD-SURVIVED",
                ] {
                    if stdout.contains(other) {
                        wrong.push(format!("{other:?}"));
                    }
                }
                if !wrong.is_empty() {
                    failed.push(format!("{case}: {}: {}", wrong.join(", "), text_and_denials(&out)));
                }
            }
            assert!(failed.is_empty(), "{} of 5 cases:\n{}", failed.len(), failed.join("\n=====\n"));
        }

        // With no denied call each of those ends is what it is on Linux,
        // in the run phase: the signal's default action or upstream's
        // handler, the panic hook, exit's code. A panic's abort() ends the
        // process by SIGABRT with run-phase `sigaction` denied: Firecracker
        // has no SIGABRT handler, so the reset to the default action that
        // Linux's filter allows (`rt_sigaction` for SIGABRT only, and Apple's
        // `__abort` makes too, Libc stdlib/FreeBSD/abort.c) is never reached.
        #[test]
        fn test_the_other_ends_are_unchanged_without_a_denied_call() {
            use std::os::unix::process::ExitStatusExt;
            // Every case runs, and each one that fails is reported.
            let mut failed = Vec::new();
            for how in HOWS {
                let (out, _) = ending(&format!("none-{how}"));
                let (code, signal) = (out.status.code(), out.status.signal());
                let stdout = String::from_utf8_lossy(&out.stdout);
                let ok = match how {
                    "abort" => signal == Some(libc::SIGABRT),
                    "panic" => signal == Some(libc::SIGABRT) && stdout.contains("Firecracker panicked"),
                    "fault" => {
                        code == Some(crate::FcExitCode::SIGSEGV as i32) || code == Some(crate::FcExitCode::SIGBUS as i32)
                    }
                    "exit" => code == Some(7),
                    _ => signal == Some(libc::SIGTRAP),
                };
                if !ok || stdout.contains(FAULT_METRIC) {
                    failed.push(format!("{how}: {}", text_and_denials(&out)));
                }
            }
            assert!(failed.is_empty(), "{} of 5 cases:\n{}", failed.len(), failed.join("\n=====\n"));
        }

        #[test]
        #[ignore = "run by the tests of a denied call's thread ending the process"]
        fn ending_child() {
            use std::os::fd::FromRawFd;

            use crate::logger::{LOGGER, METRICS, StoreMetric};
            let case = std::env::var("WICK_TEST_CASE").unwrap();
            let (who, how) = case.split_once('-').unwrap();
            let (denies, how) = (who == "denier", how.to_owned());
            // For the parent's read of Seatbelt's reports (`text_and_denials`).
            // SAFETY: no arguments.
            println!("CHILD-PID {}", unsafe { libc::getpid() });
            crate::signal_handler::register_signal_handlers().unwrap();
            let _ = LOGGER.init();
            // SAFETY: a new descriptor of standard output, owned here.
            let out = unsafe { std::fs::File::from_raw_fd(libc::dup(1)) };
            METRICS.init(std::io::LineWriter::new(crate::ext::fifo::plain(out))).unwrap();
            // Upstream's hook (firecracker/src/main.rs), with the abort of
            // its panic = "abort".
            std::panic::set_hook(Box::new(|info| {
                crate::logger::error_unrestricted!("Firecracker {}", info);
                METRICS.vmm.panic_count.store(1);
                let _ = METRICS.write();
                std::process::abort();
            }));
            select(Policy::Default);
            apply().unwrap();
            // A line logged in the setup phase, as Firecracker logs its start:
            // the log's first local time reads the time zone (libc's
            // `localtime_r` -> `tzsetwall_basic`, which calls `access`), once.
            crate::logger::error_unrestricted!("setup");
            // The thread is made before narrow(), which ends making them.
            let (go, ready) = std::sync::mpsc::channel::<()>();
            let act = move || {
                let _ = ready.recv();
                if denies {
                    // SAFETY: no arguments; denied.
                    unsafe { libc::getppid() };
                    println!("AFTER-THE-DENIED-CALL");
                }
                match how.as_str() {
                    // SAFETY: ends the process.
                    "abort" => unsafe { libc::abort() },
                    "panic" => panic!("in the run phase"),
                    // SAFETY: a write to address 0, which faults.
                    "fault" => unsafe { std::ptr::write_volatile(std::ptr::null_mut::<u8>(), 1) },
                    // SAFETY: ends the process, through its atexit handlers.
                    "exit" => unsafe { libc::exit(7) },
                    // SAFETY: a breakpoint trap, as libdispatch's for a
                    // Mach call that failed.
                    _ => unsafe { std::arch::asm!("brk #1") },
                }
            };
            let thread = std::thread::spawn(act);
            narrow().unwrap();
            go.send(()).unwrap();
            let _ = thread.join();
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        /// Runs `body` in a fork of this process and ends as the fork ends:
        /// the fork's only thread, which `body` runs on, is then the
        /// process's first. The fork's exit reason, which only this process
        /// may read, goes to standard output as [`child_run`] writes it, for
        /// [`denied`].
        fn in_fork(body: impl FnOnce()) -> ! {
            // SAFETY: the fork runs `body` and ends; this process waits.
            match unsafe { libc::fork() } {
                -1 => panic!("fork: {}", std::io::Error::last_os_error()),
                0 => {
                    body();
                    // SAFETY: ends the fork.
                    unsafe { libc::_exit(0) }
                }
                pid => {
                    if let Some((namespace, code)) = exit_reason(pid) {
                        println!("\n{EXIT_REASON_LINE}{namespace} {code:#x}");
                    }
                    let mut status = 0;
                    // SAFETY: the fork's pid; ends this process as the fork
                    // ended (by its code, or its signal's default action).
                    unsafe {
                        libc::waitpid(pid, &mut status, 0);
                        if libc::WIFEXITED(status) {
                            libc::_exit(libc::WEXITSTATUS(status));
                        }
                        libc::signal(libc::WTERMSIG(status), libc::SIG_DFL);
                        libc::raise(libc::WTERMSIG(status));
                        libc::_exit(1)
                    }
                }
            }
        }

        #[test]
        fn test_syscall_names_are_known() {
            // The profile compiles only if Seatbelt knows every name; an
            // unknown one fails `sandbox_compile_string`, which test_sandbox_restricts_child
            // would show. Here: no duplicates, and the calls Firecracker cannot
            // run without are in.
            let mut names = [SYSCALLS, SETUP_SYSCALLS, PVTIME_SYSCALLS].concat();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), SYSCALLS.len() + SETUP_SYSCALLS.len() + PVTIME_SYSCALLS.len());
            // A call the table numbers is written by number, since an older
            // libsandbox may not know its name (macOS 15 and 26: SYS_getumask).
            let rules = [syscall_rule(), api_profile()].concat();
            for (name, number, ..) in UNFILTERED_SYSCALLS {
                for end in [" ", ")"] {
                    assert!(!rules.contains(&format!("SYS_{name}{end}")), "{name} by name");
                }
                if names.contains(name) {
                    assert!(rules.contains(&format!(" {number} ")) || rules.contains(&format!(" {number})")), "{name}");
                }
            }
            for needed in ["read", "write", "mmap", "kevent", "exit", "__pthread_kill"] {
                assert!(SYSCALLS.contains(&needed), "{needed}");
            }
            // Building the microVM only: on Linux the VMM thread's filter
            // allows none of them (no clone, bind, listen, socketpair).
            for setup in ["bsdthread_create", "bind", "listen", "socketpair", "kqueue", "__mac_syscall"] {
                assert!(SETUP_SYSCALLS.contains(&setup) && !SYSCALLS.contains(&setup), "{setup}");
            }
            for denied in [
                "fork", "vfork", "execve", "posix_spawn", "ptrace", "setuid", "chroot", "mount", "kill",
                // Would lift the jail's CPU limit (ext::jail).
                "process_policy", "ledger",
            ] {
                assert!(!names.contains(&denied), "{denied}");
            }
        }

        #[test]
        #[ignore = "run by test_unlisted_syscalls_are_denials in a separate process"]
        fn exec_child() {
            select(Policy::Default);
            apply().unwrap();
            let _ = std::process::Command::new("/bin/echo").output();
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // An IP socket is made after narrow() (socket is decided by
        // system-socket, which Seatbelt does not consult for an IP socket:
        // test_system_socket_is_not_consulted_for_these), and connecting it
        // is a denial.
        #[test]
        fn test_ip_sockets_are_made_but_not_used() {
            let out = child("ip_socket_child", &[]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("MADE"), "{}", text(&out));
            assert!(denied(&out), "{}", text(&out));
            assert!(!stdout.contains("CHILD-SURVIVED"), "{}", text(&out));
        }

        #[test]
        #[ignore = "run by test_ip_sockets_are_made_but_not_used in a separate process"]
        #[allow(clippy::cast_possible_truncation)]
        fn ip_socket_child() {
            select(Policy::Default);
            apply().unwrap();
            narrow().unwrap();
            // SAFETY: plain calls; the address is a valid sockaddr_in.
            unsafe {
                let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                assert!(fd >= 0);
                println!("MADE");
                use std::io::Write;
                std::io::stdout().flush().unwrap();
                let mut sin: libc::sockaddr_in = std::mem::zeroed();
                sin.sin_len = 16;
                sin.sin_family = libc::AF_INET as u8;
                sin.sin_port = 9u16.to_be();
                sin.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
                libc::connect(fd, (&raw const sin).cast(), 16);
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        /// The families of [`test_system_socket_is_not_consulted_for_these`]:
        /// name, domain, type, protocol, and whether Seatbelt consulted
        /// `system-socket` when one was made (the same on each of
        /// [`SOCKET_MEASURED_MAJORS`]).
        const SOCKET_DOMAINS: &[(&str, i32, i32, i32, bool)] = &[
            ("AF_UNIX", libc::AF_UNIX, libc::SOCK_STREAM, 0, false),
            ("AF_INET", libc::AF_INET, libc::SOCK_STREAM, 0, false),
            ("AF_INET6", libc::AF_INET6, libc::SOCK_STREAM, 0, false),
            ("AF_ROUTE", libc::AF_ROUTE, libc::SOCK_RAW, 0, true),
            ("AF_SYSTEM", libc::AF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL, true),
        ];

        /// The majors [`SOCKET_DOMAINS`] was measured on: 27.2 on a Mac, 15.8.2
        /// and 26.7.2 on CI's runners (macos-seatbelt, run 43433573394).
        const SOCKET_MEASURED_MAJORS: &[u32] = &[15, 26, 27];

        // Why an IP socket is still made after narrow(): the kernel asks the
        // MAC policies about every socket made, whatever its family
        // (xnu-12377.1.9 bsd/kern/uipc_syscalls.c socket_common calls
        // mac_socket_check_create, security/mac_socket.c, with the domain),
        // but Sandbox.kext does not consult `system-socket` for a Unix or IP
        // one: under `(deny system-socket)` they are made, a routing and a
        // kernel control socket fail with EPERM. Measured on macOS 15, 26 and
        // 27 (SOCKET_MEASURED_MAJORS); this sentinel fails on them if that
        // changes (a macOS that consults it for IP sockets lets the run
        // phase refuse them when made, as Linux's filters refuse
        // socket(AF_INET)), and on another major prints what it finds (CI
        // runs it with --nocapture).
        #[test]
        fn test_system_socket_is_not_consulted_for_these() {
            let major = macos_major();
            let out = child("socket_domain_child", &[]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success() && stdout.contains("APPLIED"), "{}", text(&out));
            let mut found = Vec::new();
            for (name, .., consulted) in SOCKET_DOMAINS {
                let plain = format!("{name} plain made");
                assert!(stdout.contains(&plain), "{name} is not made with no sandbox: {}", text(&out));
                let sandboxed = format!("{name} sandboxed ");
                let line = stdout.lines().find(|l| l.starts_with(&sandboxed)).unwrap_or("no line");
                let made = line == format!("{name} sandboxed made");
                println!("macOS {major}, under (deny system-socket): {line}");
                found.push((*name, made, *consulted));
            }
            if !SOCKET_MEASURED_MAJORS.contains(&major) {
                println!("macOS {major} is not measured: printed only");
                return;
            }
            for (name, made, consulted) in found {
                assert_eq!(
                    made,
                    !consulted,
                    "macOS {major}: Seatbelt {} system-socket for {name} now; if it consults it for IP sockets, \
                     the run phase can refuse them when made (RUN_DENIED_OPERATIONS), as Linux's filters \
                     refuse socket(AF_INET); update SOCKET_DOMAINS and COMPATIBILITY.md's Argument checks\n{}",
                    if made { "skips" } else { "consults" },
                    text(&out)
                );
            }
        }

        #[test]
        #[ignore = "run by test_system_socket_is_not_consulted_for_these in a separate process"]
        fn socket_domain_child() {
            let make = |phase: &str| {
                for (name, domain, kind, protocol, _) in SOCKET_DOMAINS {
                    // SAFETY: plain calls; the descriptor is closed.
                    let fd = unsafe { libc::socket(*domain, *kind, *protocol) };
                    if fd >= 0 {
                        // SAFETY: the descriptor made above.
                        unsafe { libc::close(fd) };
                        println!("{name} {phase} made");
                    } else {
                        println!("{name} {phase} failed: {}", std::io::Error::last_os_error());
                    }
                }
            };
            make("plain");
            install("(version 1)(allow default)(deny system-socket)").unwrap();
            println!("APPLIED");
            make("sandboxed");
        }

        // IP networking: on Linux socket(AF_INET) is outside every filter.
        #[test]
        #[ignore = "run by test_unlisted_syscalls_are_denials in a separate process"]
        fn tcp_child() {
            select(Policy::Default);
            apply().unwrap();
            let _ = std::net::TcpStream::connect("127.0.0.1:9");
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        #[test]
        #[ignore = "run by test_unlisted_syscalls_are_denials in a separate process"]
        fn udp_child() {
            select(Policy::Default);
            apply().unwrap();
            let _ = std::net::UdpSocket::bind("127.0.0.1:0");
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // A running microVM's VMM may punch holes (discard, Linux's
        // fallocate in the VMM filter) and restore the terminal on shutdown
        // (TCSETS); another driver request, here simulating terminal input
        // (TIOCSTI), is a denial, as an ioctl outside the filter's requests
        // does on Linux.
        #[test]
        fn test_run_phase_ioctls_and_holes() {
            run_child("run_phase_child", &[]);
            let out = child("other_ioctl_child", &[]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("NARROWED"), "{}", text(&out));
            assert!(denied(&out), "{}", text(&out));
        }

        // Shared memory after narrow(): the memfds this process makes, an
        // ordinary one and a 2 MiB huge page one (guest memory for a
        // vhost-user device on huge pages), are created; a name of another
        // process is a denial.
        #[test]
        fn test_own_memfds_are_made_after_narrow() {
            let out = child("memfd_child", &[]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("MEMFDS-OK"), "{}", text(&out));
            assert!(denied(&out), "{}", text(&out));
            assert!(!stdout.contains("CHILD-SURVIVED"), "{}", text(&out));
        }

        #[test]
        #[ignore = "run by test_own_memfds_are_made_after_narrow in a separate process"]
        fn memfd_child() {
            select(Policy::Default);
            apply().unwrap();
            narrow().unwrap();
            for huge in [None, Some(memfd::HugetlbSize::Huge2MB)] {
                let mfd = memfd::MemfdOptions::default()
                    .hugetlb(huge)
                    .allow_sealing(true)
                    .create("guest_mem")
                    .unwrap_or_else(|e| panic!("memfd {huge:?}: {e}"));
                mfd.as_file().set_len(2 << 20).unwrap();
            }
            println!("MEMFDS-OK");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            // Another process's memfd name: the default rule, a denial.
            let other = std::ffi::CString::new(format!("{}1.0", libc::HUGE_MEMFD_PREFIX)).unwrap();
            // SAFETY: a plain call.
            unsafe { libc::shm_open(other.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // fcntl: after narrow(), the commands of FCNTL_COMMANDS run and any
        // other one is a denial, as upstream's fcntl rules trap every
        // command but F_SETFD and F_ADD_SEALS (Seatbelt's system-fcntl,
        // which checks every command).
        #[test]
        fn test_fcntl_commands_outside_the_list_are_denials() {
            let out = child("fcntl_child", &[]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("LISTED-OK"), "{}", text(&out));
            assert!(denied(&out), "{}", text(&out));
            assert!(!stdout.contains("CHILD-SURVIVED"), "{}", text(&out));
        }

        #[test]
        #[ignore = "run by test_fcntl_commands_outside_the_list_are_denials in a separate process"]
        fn fcntl_child() {
            use std::os::fd::AsRawFd;
            let file = std::fs::File::open("/dev/null").unwrap();
            let fd = file.as_raw_fd();
            select(Policy::Default);
            apply().unwrap();
            // Before narrow(): any command.
            // SAFETY: a descriptor this process holds.
            assert!(unsafe { libc::fcntl(fd, libc::F_GETFL) } >= 0);
            narrow().unwrap();
            // SAFETY: as above.
            unsafe {
                assert_eq!(libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC), 0);
                assert_eq!(libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
            }
            println!("LISTED-OK");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            // SAFETY: plain data.
            let mut lock: libc::flock = unsafe { std::mem::zeroed() };
            // SAFETY: a lock query on a descriptor this process holds.
            unsafe { libc::fcntl(fd, libc::F_GETLK, &mut lock) };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // futex: upstream's rules allow FUTEX_WAIT and FUTEX_WAKE (and their
        // private and bitset forms) and trap the others, FUTEX_LOCK_PI and
        // the requeues among them. macOS's locks are the ulock and psynch
        // calls, whose operation Seatbelt does not check: after narrow(), an
        // owner-tracking unfair-lock wake (UL_UNFAIR_LOCK, Linux's
        // FUTEX_UNLOCK_PI) returns as any other operation does.
        #[test]
        fn test_futex_operations_are_not_checked() {
            run_child("futex_child", &[]);
        }

        #[test]
        #[ignore = "run by test_futex_operations_are_not_checked in a separate process"]
        fn futex_child() {
            unsafe extern "C" {
                // <sys/ulock.h> (libsystem_kernel).
                fn __ulock_wake(operation: u32, addr: *mut libc::c_void, wake_value: u64) -> libc::c_int;
            }
            const UL_COMPARE_AND_WAIT: u32 = 1;
            const UL_UNFAIR_LOCK: u32 = 2;
            const ULF_WAKE_ALL: u32 = 0x100;
            let mut word = 0u32;
            select(Policy::Default);
            apply().unwrap();
            narrow().unwrap();
            for op in [UL_COMPARE_AND_WAIT, UL_UNFAIR_LOCK | ULF_WAKE_ALL] {
                // SAFETY: a word of this thread's; nothing waits on it.
                let ret = unsafe { __ulock_wake(op, (&raw mut word).cast(), 0) };
                let err = std::io::Error::last_os_error().raw_os_error();
                assert_eq!((ret, err), (-1, Some(libc::ENOENT)), "operation {op:#x}");
            }
            // The signal Seatbelt would send arrives within this.
            std::thread::sleep(std::time::Duration::from_secs(1));
            println!("CHILD-OK");
        }

        // accept4: upstream's rule allows the flags SOCK_CLOEXEC only. macOS
        // has no accept4: accept takes no flags, and Rust's std, which makes
        // the call, marks the accepted socket close-on-exec at once
        // (ioctl FIOCLEX); after narrow() that holds as before it.
        #[test]
        fn test_accepted_sockets_are_close_on_exec() {
            // Removed here: after narrow() the child may not remove it.
            let path = std::env::temp_dir().join(format!("wick-accept-{}", std::process::id()));
            let _ = std::fs::remove_file(&path);
            run_child("accept_child", &[("WICK_TEST_PATH", path.to_str().unwrap())]);
            std::fs::remove_file(&path).unwrap();
        }

        #[test]
        #[ignore = "run by test_accepted_sockets_are_close_on_exec in a separate process"]
        fn accept_child() {
            use std::os::fd::AsRawFd;
            let path = std::path::PathBuf::from(std::env::var("WICK_TEST_PATH").unwrap());
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            select(Policy::Default);
            apply().unwrap();
            narrow().unwrap();
            let _client = std::os::unix::net::UnixStream::connect(&path).unwrap();
            let (accepted, _) = listener.accept().unwrap();
            // SAFETY: a descriptor this process holds.
            let flags = unsafe { libc::fcntl(accepted.as_raw_fd(), libc::F_GETFD) };
            assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
            println!("CHILD-OK");
        }

        /// The lock [`pty`]'s callers open their terminals under.
        const TERMINAL_LOCK: &std::ffi::CStr = c"/tmp/wick-test-posix_openpt.lock";
        /// How long [`pty`] waits for it: each holder holds it across one
        /// posix_openpt.
        const TERMINAL_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

        /// [`TERMINAL_LOCK`], taken: its descriptor, whose close releases
        /// it. The kernel drops the lock with its holder's last descriptor
        /// (flock(2)), so a holder's end, however it ends, frees it; it is
        /// held across one posix_openpt, whose retries are bounded. A holder
        /// that is stopped (SIGSTOP, a debugger) would hold it on, so the
        /// wait ends at `wait`, failing with the processes that have the
        /// file open (lsof).
        fn terminal_lock(wait: std::time::Duration) -> libc::c_int {
            let path = TERMINAL_LOCK;
            // SAFETY: a NUL-terminated path; the descriptor is returned.
            let lock = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CREAT | libc::O_CLOEXEC, 0o644) };
            assert!(lock >= 0, "{path:?}: {}", std::io::Error::last_os_error());
            let since = std::time::Instant::now();
            // SAFETY: the descriptor opened above.
            while unsafe { libc::flock(lock, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let err = std::io::Error::last_os_error();
                assert_eq!(err.raw_os_error(), Some(libc::EWOULDBLOCK), "flock {path:?}: {err}");
                if since.elapsed() >= wait {
                    let holders = Command::new("/usr/sbin/lsof")
                        .arg(path.to_str().unwrap())
                        .output()
                        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                        .unwrap_or_else(|e| format!("lsof: {e}"));
                    // SAFETY: the descriptor opened above, not used after.
                    unsafe { libc::close(lock) };
                    panic!("{path:?} is still locked after {wait:?}; the processes with it open:\n{holders}");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            lock
        }

        /// A pseudo-terminal's controller, opened before the sandbox.
        fn pty() -> libc::c_int {
            // SAFETY: plain calls on a descriptor this function opens.
            unsafe {
                // XNU hands two terminals opened at the same moment the same
                // minor (xnu-12377.1.9 tty_ptmx.c ptmx_clone: "if we did this
                // twice at the same time, we could return the same minor to
                // two callers"); the loser's open fails with EREDRIVEOPEN
                // (tty_dev.c ptcopen), which vn_open_auth retries 10 times
                // and then returns to the caller as errno -6 (vfs_vnops.c,
                // sys/errno.h). Linux v6.1 takes a pty's index from an IDA,
                // which allocates under its own lock (drivers/tty/pty.c
                // ptmx_open, fs/devpts/inode.c devpts_new_index:
                // ida_alloc_max), and has no such failure. CI run 43435331370 (macOS 26) lost
                // 3 children of test_unfiltered_syscalls_are_limited_by_their_rule
                // to it; on macOS 27.2 32 processes opening 300 terminals
                // each lost 36 opens, all errno -6, with 36 "vn_open_auth:
                // reached max_retries error -6" kernel lines
                // (agent-state/mac9/ptyrace/race3.c). So the test processes
                // open their terminals one at a time, under an flock on one
                // path for every process (not under TMPDIR, which the
                // children of that test set differently): with it the same
                // run lost none and the kernel printed nothing. A process
                // outside the tests opening a terminal at that moment can
                // still race with one; that is XNU's, and fails below.
                let lock = terminal_lock(TERMINAL_LOCK_WAIT);
                let fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
                let err = std::io::Error::last_os_error();
                libc::close(lock);
                // A failure says why, and how many terminals the host has
                // against its limit: ENXIO is the limit (tty_dev.c ptcopen,
                // tty_ptmx.c ptmx_get_ioctl), -6 the race above.
                if fd < 0 {
                    let mut max: libc::c_int = 0;
                    let mut len = size_of_val(&max);
                    let max = if libc::sysctlbyname(
                        c"kern.tty.ptmx_max".as_ptr(),
                        (&raw mut max).cast(),
                        &raw mut len,
                        std::ptr::null_mut(),
                        0,
                    ) == 0
                    {
                        max.to_string()
                    } else {
                        format!("unread ({})", std::io::Error::last_os_error())
                    };
                    let nodes = std::fs::read_dir("/dev").map(|d| {
                        d.filter_map(Result::ok)
                            .filter(|e| e.file_name().as_encoded_bytes().starts_with(b"ttys"))
                            .count()
                    });
                    panic!(
                        "posix_openpt: {err} (errno {:?}); kern.tty.ptmx_max {max}; /dev/ttys* nodes: {nodes:?}",
                        err.raw_os_error()
                    );
                }
                assert_eq!(libc::grantpt(fd), 0);
                assert_eq!(libc::unlockpt(fd), 0);
                let name = libc::ptsname(fd);
                assert!(!name.is_null());
                let sub = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
                assert!(sub >= 0);
                sub
            }
        }

        #[test]
        #[ignore = "run by test_run_phase_ioctls_and_holes in a separate process"]
        fn run_phase_child() {
            use std::os::unix::io::AsRawFd;
            let tty = pty();
            let path = std::env::temp_dir().join(format!("wick-holes-{}", std::process::id()));
            let file = std::fs::File::create(&path).unwrap();
            file.set_len(1 << 20).unwrap();
            std::fs::remove_file(&path).unwrap();
            select(Policy::Default);
            apply().unwrap();
            narrow().unwrap();
            // SAFETY: termios is plain data the call fills.
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: a terminal descriptor and a termios to fill and set.
            unsafe {
                assert_eq!(libc::tcgetattr(tty, &mut t), 0);
                assert_eq!(libc::tcsetattr(tty, libc::TCSANOW, &t), 0);
            }
            // SAFETY: a regular file; the compatibility libc's fallocate.
            let ret = unsafe {
                libc::fallocate(
                    file.as_raw_fd(),
                    // FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE (Linux values).
                    0x02 | 0x01,
                    4096,
                    65536,
                )
            };
            assert_eq!(ret, 0, "{}", std::io::Error::last_os_error());
            println!("CHILD-OK");
        }

        #[test]
        #[ignore = "run by test_run_phase_ioctls_and_holes in a separate process"]
        fn other_ioctl_child() {
            let tty = pty();
            select(Policy::Default);
            apply().unwrap();
            narrow().unwrap();
            println!("NARROWED");
            let c: libc::c_char = 0;
            // SAFETY: TIOCSTI on a terminal descriptor with a one-byte argument.
            unsafe { libc::ioctl(tty, libc::TIOCSTI, &c) };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // Starting a vmnet interface is part of building the microVM: its
        // service lookup succeeds before narrow() and is a denial after
        // it; no other service is looked up in either phase.
        #[test]
        fn test_vmnet_lookup_is_setups_only() {
            for case in ["vmnet", "other"] {
                let out = child("lookup_child", &[("WICK_TEST_CASE", case)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert_eq!(stdout.contains("SETUP-LOOKUP-OK"), case == "vmnet", "{case}: {}", text(&out));
                assert!(denied(&out), "{case}: {}", text(&out));
                assert!(!stdout.contains("CHILD-SURVIVED"), "{case}: {}", text(&out));
            }
        }

        #[test]
        #[ignore = "run by test_vmnet_lookup_is_setups_only in a separate process"]
        fn lookup_child() {
            unsafe extern "C" {
                // <servers/bootstrap.h> (libSystem).
                static bootstrap_port: libc::mach_port_t;
                fn bootstrap_look_up(
                    bp: libc::mach_port_t,
                    name: *const libc::c_char,
                    sp: *mut libc::mach_port_t,
                ) -> libc::c_int;
            }
            let look_up = |name: &CStr| {
                let mut port: libc::mach_port_t = 0;
                // SAFETY: the task's bootstrap port, a NUL-terminated name and
                // an out-pointer.
                unsafe { bootstrap_look_up(bootstrap_port, name.as_ptr(), &mut port) }
            };
            select(Policy::Default);
            apply().unwrap();
            if std::env::var("WICK_TEST_CASE").unwrap() == "other" {
                look_up(c"com.apple.SystemConfiguration.configd");
            } else {
                assert_eq!(look_up(c"com.apple.NetworkSharing"), 0);
                println!("SETUP-LOOKUP-OK");
                narrow().unwrap();
                look_up(c"com.apple.NetworkSharing");
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // A vmnet interface hot-plugged into a running microVM is refused
        // with an error the API reports, before any of vmnet's calls (its
        // start makes setup's calls: a pipe, the NetworkSharing lookup), and
        // the microVM runs on. The device is made as the hot-plug makes it
        // (Net::new, rpc_interface's hotplug_device).
        #[test]
        fn test_vmnet_hotplug_after_narrow_is_refused() {
            for name in ["vmnet-shared", "vmnet-host", "vmnet-br-en0"] {
                let out = child("vmnet_hotplug_child", &[("WICK_TEST_CASE", name)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(out.status.success(), "{name}: {}", text(&out));
                assert!(stdout.contains("REFUSED"), "{name}: {}", text(&out));
                assert!(stdout.contains("a Unix endpoint can be hot-plugged"), "{name}: {}", text(&out));
                assert!(stdout.contains("CHILD-SURVIVED"), "{name}: {}", text(&out));
            }
        }

        #[test]
        #[ignore = "run by test_vmnet_hotplug_after_narrow_is_refused in a separate process"]
        fn vmnet_hotplug_child() {
            let name = std::env::var("WICK_TEST_CASE").unwrap();
            select(Policy::Default);
            apply().unwrap();
            narrow().unwrap();
            let net = crate::devices::virtio::net::Net::new(
                "hotplugged".into(),
                &name,
                None,
                Default::default(),
                Default::default(),
                None,
            );
            match net {
                Ok(_) => println!("STARTED"),
                Err(err) => println!("REFUSED {err}"),
            }
            // Time for a denial's kill to land.
            std::thread::sleep(std::time::Duration::from_secs(2));
            println!("CHILD-SURVIVED");
        }

        // Listening on a Unix socket is setup's only: Linux's VMM filter has
        // no bind or listen. A socket bound before narrow() (its name gone)
        // cannot listen after it.
        #[test]
        #[ignore = "run by test_unlisted_syscalls_are_denials in a separate process"]
        fn listen_after_narrow_child() {
            let path = std::env::temp_dir().join(format!("wick-bind-{}", std::process::id()));
            select(Policy::Default);
            apply().unwrap();
            // SAFETY: plain calls on a socket this child makes.
            let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            assert!(fd >= 0);
            let (addr, len) = sockaddr_un(&path);
            // SAFETY: a socket address of the given length.
            assert_eq!(unsafe { libc::bind(fd, (&raw const addr).cast(), len) }, 0);
            std::fs::remove_file(&path).unwrap();
            println!("SETUP-BIND-OK");
            narrow().unwrap();
            // SAFETY: a bound socket.
            unsafe { libc::listen(fd, 1) };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        /// A Unix socket address for `path`.
        fn sockaddr_un(path: &std::path::Path) -> (libc::sockaddr_un, libc::socklen_t) {
            use std::os::unix::ffi::OsStrExt;
            // SAFETY: plain data.
            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            let bytes = path.as_os_str().as_bytes();
            assert!(bytes.len() < addr.sun_path.len(), "{path:?}");
            addr.sun_family = libc::sa_family_t::try_from(libc::AF_UNIX).unwrap();
            for (to, from) in addr.sun_path.iter_mut().zip(bytes) {
                *to = (*from).cast_signed();
            }
            let len = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_un>()).unwrap();
            (addr, len)
        }

        // Binding a socket is setup's, as Linux's VMM filter has no bind,
        // but for a hot-plugged network device's endpoint, which Linux's
        // filter lets open its TAP: after narrow() a Unix socket binds
        // where setup could bind one (the jail, its network, or outside a
        // jail the operator's path: RUN_DENIED_OPERATIONS, run_rule), an IP
        // socket is a denial, a stream socket bound then cannot listen,
        // a path outside the jail fails with EPERM (the file rule's, as a
        // file there), and at a stale socket's path platform::net::bind
        // fails with EADDRINUSE (replacing it would remove a name) and the
        // process runs on.
        #[test]
        fn test_unix_bind_after_narrow_is_where_setup_binds() {
            let base = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("wick-bind-{}", std::process::id()));
            let (jail, net) = (base.join("jail"), base.join("net"));
            for case in [
                "datagram",
                "datagram-outside",
                "stream",
                "datagram-network",
                "datagram-network-stale",
                "free",
                "free-stale",
                "free-ip",
            ] {
                std::fs::create_dir_all(&jail).unwrap();
                std::fs::create_dir_all(&net).unwrap();
                let out = child(
                    "bind_after_narrow_child",
                    &[("WICK_TEST_CASE", case), ("WICK_TEST_JAIL", jail.to_str().unwrap())],
                );
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(stdout.contains("SETUP-BIND-OK"), "{case}: {}", text(&out));
                if case == "free-ip" {
                    assert!(denied(&out), "{case}: {}", text(&out));
                    assert!(!stdout.contains("CHILD-SURVIVED"), "{case}: {}", text(&out));
                } else if case == "datagram-outside" {
                    // The file rule decides a socket file outside the jail,
                    // with EPERM, as a file there (measured; the bind rule
                    // comes later).
                    let err = format!("LATE-BIND-ERR {}", std::io::Error::from_raw_os_error(libc::EPERM));
                    assert!(
                        out.status.success() && stdout.contains(&err) && stdout.contains("CHILD-SURVIVED"),
                        "{case}: {:?}\n{stdout}",
                        out.status
                    );
                } else if case == "stream" {
                    assert!(denied(&out), "{case}: {}", text(&out));
                    assert!(stdout.contains("LATE-BIND-OK") && !stdout.contains("CHILD-SURVIVED"), "{case}: {}", text(&out));
                } else {
                    let late = if case.ends_with("-stale") { "STALE-REFUSED" } else { "LATE-BIND-OK" };
                    assert!(
                        out.status.success() && stdout.contains(late) && stdout.contains("CHILD-SURVIVED"),
                        "{case}: {:?}\n{stdout}",
                        out.status
                    );
                    if case.ends_with("-stale") {
                        let dir = if case.starts_with("free") { &base } else { &net };
                        assert!(dir.join("late").exists(), "{case}: the stale socket was removed");
                    }
                }
                std::fs::remove_dir_all(&base).unwrap();
            }
        }

        #[test]
        #[ignore = "run by test_unix_bind_after_narrow_is_where_setup_binds in a separate process"]
        fn bind_after_narrow_child() {
            let case = std::env::var("WICK_TEST_CASE").unwrap();
            let jail = std::path::PathBuf::from(std::env::var("WICK_TEST_JAIL").unwrap());
            let base = jail.parent().unwrap().to_owned();
            let net = base.join("net");
            let (dir, root, network) = match case.as_str() {
                "datagram-network" | "datagram-network-stale" => (net.clone(), Some(jail.as_path()), Some(net.as_path())),
                "free" | "free-stale" | "free-ip" => (base.clone(), None, None),
                _ => (jail.clone(), Some(jail.as_path()), None),
            };
            // The late bind's directory: outside the jail for that case.
            let late_dir = if case == "datagram-outside" { base.clone() } else { dir.clone() };
            let profile = profile_for(root, network).unwrap();
            COMPILED
                .set((Compiled::here(&profile).unwrap(), Compiled::here(&api_profile()).unwrap()))
                .unwrap();
            select(Policy::Default);
            apply().unwrap();
            let bind = |dir: &std::path::Path, name: &str| {
                let kind = if case == "stream" { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
                // SAFETY: plain calls on a socket made here.
                let fd = unsafe { libc::socket(libc::AF_UNIX, kind, 0) };
                assert!(fd >= 0);
                let (addr, len) = sockaddr_un(&dir.join(name));
                // SAFETY: a socket address of the given length.
                (unsafe { libc::bind(fd, (&raw const addr).cast(), len) }, fd)
            };
            assert_eq!(bind(&dir, "early").0, 0, "{}", std::io::Error::last_os_error());
            println!("SETUP-BIND-OK");
            if case.ends_with("-stale") {
                // A process that died left its socket file at the path.
                assert_eq!(bind(&dir, "late").0, 0, "{}", std::io::Error::last_os_error());
            }
            narrow().unwrap();
            println!("NARROWED");
            if case == "free-ip" {
                // SAFETY: plain calls on a socket made here.
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
                assert!(fd >= 0);
                // SAFETY: plain data.
                let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                addr.sin_family = libc::sa_family_t::try_from(libc::AF_INET).unwrap();
                addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
                let len = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>()).unwrap();
                // SAFETY: a socket address of the given length.
                unsafe { libc::bind(fd, (&raw const addr).cast(), len) };
            } else if case.ends_with("-stale") {
                // SAFETY: plain calls on a socket made here.
                let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
                assert!(fd >= 0);
                // SAFETY: a descriptor made above, owned by nothing else.
                let sock = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
                let err = crate::platform::net::bind_endpoint(&sock, &dir.join("late")).unwrap_err();
                assert_eq!(err.raw_os_error(), Some(libc::EADDRINUSE), "{err}");
                println!("STALE-REFUSED");
            } else {
                let (ret, fd) = bind(&late_dir, "late");
                if ret == 0 {
                    println!("LATE-BIND-OK");
                } else {
                    println!("LATE-BIND-ERR {}", std::io::Error::last_os_error());
                }
                if case == "stream" {
                    // Bound, it cannot listen: listen is setup's.
                    // SAFETY: a plain call on the socket bound above.
                    unsafe { libc::listen(fd, 1) };
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // --new-pid-ns: in a PID namespace of its own on Linux, Firecracker
        // sees and signals no other process. Here its sandbox holds it:
        // information about another process fails (EPERM; Seatbelt's default
        // rule does not cover it, the profile's explicit rule does), and a
        // signal to one is a denial (the test's own process stands for any
        // other).
        #[test]
        fn test_no_other_process_in_reach() {
            let me = std::process::id().to_string();
            let out = child("other_pid_info_child", &[("WICK_TEST_OTHER_PID", &me)]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success() && stdout.contains("OTHER-DENIED"), "{}", text(&out));
            let out = child("other_pid_signal_child", &[("WICK_TEST_OTHER_PID", &me)]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(denied(&out), "{}", text(&out));
            assert!(!stdout.contains("CHILD-SURVIVED"), "{}", text(&out));
        }

        fn other_pid() -> libc::pid_t {
            std::env::var("WICK_TEST_OTHER_PID").unwrap().parse().unwrap()
        }

        #[test]
        #[ignore = "run by test_no_other_process_in_reach in a separate process"]
        fn other_pid_info_child() {
            let pid = other_pid();
            // Its own process information stays readable.
            // SAFETY: plain data the call fills.
            let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
            let size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).unwrap();
            select(Policy::Default);
            apply().unwrap();
            // SAFETY: a buffer of `size` bytes.
            let own = unsafe {
                libc::proc_pidinfo(std::process::id().cast_signed(), libc::PROC_PIDTBSDINFO, 0,
                    (&raw mut info).cast(), size)
            };
            assert_eq!(own, size);
            // SAFETY: as above.
            let other = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
            let err = std::io::Error::last_os_error();
            assert_eq!((other, err.raw_os_error()), (0, Some(libc::EPERM)), "{err}");
            let mut path = [0u8; 1024];
            // SAFETY: a buffer of its length.
            let other = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), 1024) };
            assert_eq!(other, 0);
            let mut pids = [0i32; 4096];
            // SAFETY: a buffer of its size in bytes.
            let all = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), 4096 * 4) };
            assert!(all <= 0, "{all} pids listed");
            println!("OTHER-DENIED");
        }

        #[test]
        #[ignore = "run by test_no_other_process_in_reach in a separate process"]
        fn other_pid_signal_child() {
            let pid = other_pid();
            select(Policy::Default);
            apply().unwrap();
            // SAFETY: signal 0 only checks that the process can be signalled.
            unsafe { libc::kill(pid, 0) };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        #[test]
        #[ignore = "run by test_unlisted_syscalls_are_denials in a separate process"]
        fn unlisted_child() {
            select(Policy::Default);
            apply().unwrap();
            // SAFETY: no arguments.
            unsafe { libc::getppid() };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        #[test]
        #[ignore = "run by test_unlisted_syscalls_are_denials in a separate process"]
        fn unlisted_trap_child() {
            unsafe extern "C" {
                // <mach/mach_init.h>: the task's own port, what mach_task_self() reads.
                static mach_task_self_: libc::mach_port_t;
                fn pid_for_task(task: libc::mach_port_t, pid: *mut libc::c_int) -> libc::c_int;
            }
            // SAFETY: set by libSystem before main, never written after.
            let task = unsafe { mach_task_self_ };
            select(Policy::Default);
            apply().unwrap();
            let mut pid = 0;
            // SAFETY: valid output pointer; the trap is not in MACH_TRAPS.
            unsafe { pid_for_task(task, &mut pid) };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        #[test]
        #[ignore = "run by test_unlisted_syscalls_are_denials in a separate process"]
        fn unlisted_mig_child() {
            unsafe extern "C" {
                static mach_task_self_: libc::mach_port_t;
                // <mach/task.h>: a MIG routine of the task, not in MIG_ROUTINES.
                fn task_threads(
                    task: libc::mach_port_t,
                    threads: *mut *mut libc::mach_port_t,
                    count: *mut libc::c_uint,
                ) -> libc::c_int;
            }
            // SAFETY: set by libSystem before main, never written after.
            let task = unsafe { mach_task_self_ };
            select(Policy::Default);
            apply().unwrap();
            let (mut threads, mut count) = (std::ptr::null_mut(), 0);
            // SAFETY: valid output pointers.
            unsafe { task_threads(task, &mut threads, &mut count) };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        #[test]
        fn test_mig_routine_names_are_known() {
            let mut names = [MIG_ROUTINES, PVTIME_MIG_ROUTINES].concat();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), MIG_ROUTINES.len() + PVTIME_MIG_ROUTINES.len());
            for needed in ["clock_get_time", "mach_vm_map_external", "semaphore_create"] {
                assert!(MIG_ROUTINES.contains(&needed), "{needed}");
            }
            for denied in [
                "task_threads", "task_set_special_port", "task_set_exception_ports",
                "thread_set_exception_ports", "host_get_special_port", "thread_get_state",
                "thread_set_state", "mach_port_is_connection_for_service",
            ] {
                assert!(!MIG_ROUTINES.contains(&denied), "{denied}");
            }
        }

        // Where PV steal time is offered (macOS 27), a running microVM reads
        // its threads' CPU time and state: its own (thread_selfusage) and a
        // vCPU thread's (thread_info, the PV time kicker). The routines next
        // to thread_info on a thread port, which change a thread, are denied
        // after narrowing (thread_policy_set is SETUP_MIG_ROUTINES' only, for
        // the vCPU threads' latency tier) (task_threads, which would give the ports of the task's
        // threads, is unlisted_mig_child's). Where PV time is not offered,
        // neither read is in the profile.
        #[test]
        fn test_thread_reads_are_pv_times_only() {
            let offered = kvm_ioctls::pv_time_offered();
            for case in ["reads", "thread_set_state", "thread_policy_set", "thread_suspend"] {
                let out = child("thread_read_child", &[("WICK_TEST_CASE", case)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(stdout.contains("NARROWED"), "{case}: {}", text(&out));
                if case == "reads" && offered {
                    assert!(out.status.success(), "{case}: {}", text(&out));
                    assert!(stdout.contains("READS-OK"), "{case}: {}", text(&out));
                } else {
                    assert!(denied(&out), "{case} (PV time offered: {offered}): {}", text(&out));
                    assert!(!stdout.contains("CHILD-SURVIVED"), "{case}: {}", text(&out));
                }
            }
        }

        #[test]
        #[ignore = "run by test_thread_reads_are_pv_times_only in a separate process"]
        fn thread_read_child() {
            unsafe extern "C" {
                // <mach/thread_act.h>, MIG routines on a thread port.
                fn thread_set_state(thread: libc::mach_port_t, flavor: i32, state: *const u32, count: u32) -> i32;
                fn thread_policy_set(thread: libc::mach_port_t, flavor: u32, policy: *const i32, count: u32) -> i32;
                fn thread_suspend(thread: libc::mach_port_t) -> i32;
            }
            // A thread of this process, as a vCPU thread is the kicker's.
            let sibling = std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_secs(30)));
            // SAFETY: a live thread of this process.
            let port = unsafe { libc::pthread_mach_thread_np(std::os::unix::thread::JoinHandleExt::as_pthread_t(&sibling)) };
            select(Policy::Default);
            apply().unwrap();
            narrow().unwrap();
            println!("NARROWED");
            match std::env::var("WICK_TEST_CASE").unwrap().as_str() {
                "reads" => {
                    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
                    // SAFETY: a valid timespec.
                    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) }, 0);
                    // SAFETY: a zeroed plain-data structure.
                    let mut info: libc::thread_basic_info = unsafe { std::mem::zeroed() };
                    let mut count = libc::THREAD_BASIC_INFO_COUNT;
                    // SAFETY: a thread port of this process and a buffer of `count` words.
                    let ret = unsafe {
                        libc::thread_info(
                            port,
                            libc::THREAD_BASIC_INFO as libc::thread_flavor_t,
                            std::ptr::from_mut(&mut info).cast(),
                            &mut count,
                        )
                    };
                    assert_eq!(ret, libc::KERN_SUCCESS);
                    println!("READS-OK");
                }
                // Flavor 0 and no state: refused by the kernel if it ever ran.
                // SAFETY: as above, with an empty state.
                "thread_set_state" => drop(unsafe { thread_set_state(port, 0, std::ptr::null(), 0) }),
                // SAFETY: as above, with an empty policy.
                "thread_policy_set" => drop(unsafe { thread_policy_set(port, 0, std::ptr::null(), 0) }),
                // SAFETY: suspends the sleeping sibling, if it ever ran.
                "thread_suspend" => drop(unsafe { thread_suspend(port) }),
                other => panic!("{other}"),
            }
            std::thread::sleep(std::time::Duration::from_secs(3));
            println!("CHILD-SURVIVED");
        }

        #[test]
        fn test_setup_mig_routines_are_distinct() {
            let mut names = SETUP_MIG_ROUTINES.to_vec();
            names.extend(SETUP_MIG_ROUTINES_IF_DEFINED);
            names.extend(MIG_ROUTINES);
            names.extend(EXCEPTION_MIG_ROUTINES);
            names.sort_unstable();
            names.dedup();
            assert_eq!(
                names.len(),
                SETUP_MIG_ROUTINES.len()
                    + SETUP_MIG_ROUTINES_IF_DEFINED.len()
                    + MIG_ROUTINES.len()
                    + EXCEPTION_MIG_ROUTINES.len()
            );
            assert!(SETUP_MIG_ROUTINES_IF_DEFINED.contains(&"mach_vm_reallocate"));
            // The kernel's message for a fault is allowed by every profile.
            for rule in [syscall_rule(), api_profile()] {
                assert!(
                    rule.contains(
                        "(when (defined? 'mach_exception_raise) (allow syscall-mig (kernel-mig-routine mach_exception_raise)))"
                    ),
                    "{rule}"
                );
            }
        }

        // The profiles compile on this host, whatever its macOS major: a
        // name the kernel does not define (a MIG routine of a later macOS,
        // as mach_vm_reallocate on macOS 15) fails the compile, naming it.
        #[test]
        fn test_profiles_compile_on_this_major() {
            let major = macos_major();
            let base = std::env::temp_dir().join(format!("wick-compile-{}", std::process::id()));
            let (jail, net) = (base.join("jail"), base.join("net"));
            std::fs::create_dir_all(&jail).unwrap();
            std::fs::create_dir_all(&net).unwrap();
            for (name, profile) in [
                ("no jail", profile_for(None, None)),
                ("jail", profile_for(Some(&jail), None)),
                ("jail with a network", profile_for(Some(&jail), Some(&net))),
                ("API process", Ok(api_profile())),
            ] {
                let profile = profile.unwrap_or_else(|e| panic!("{name}: {e}"));
                Compiled::here(&profile).unwrap_or_else(|e| panic!("{name} on macOS {major}: {e}"));
            }
            std::fs::remove_dir_all(&base).unwrap();
        }

        #[test]
        fn test_mach_trap_names_are_known() {
            let mut names = MACH_TRAPS.to_vec();
            names.extend(MACH_TRAPS_IF_DEFINED);
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), MACH_TRAPS.len() + MACH_TRAPS_IF_DEFINED.len());
            for needed in ["mach_msg2_trap", "_kernelrpc_mach_vm_map_trap", "semaphore_wait_trap"] {
                assert!(MACH_TRAPS.contains(&needed), "{needed}");
            }
            for denied in [
                "task_for_pid", "pid_for_task", "task_name_for_pid", "iokit_user_client_trap",
                "macx_swapon", "macx_swapoff", "macx_triggers", "debug_control_port_for_pid",
                "mach_msg_overwrite_trap",
            ] {
                assert!(!names.contains(&denied), "{denied}");
            }
        }

        #[test]
        fn test_jail_profile_limits_files() {
            let base = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("wick-jail-profile-{}", std::process::id()));
            let jail = base.join("a \"quoted\" jail");
            std::fs::create_dir_all(&jail).unwrap();
            std::fs::write(base.join("outside"), b"secret").unwrap();
            std::fs::write(jail.join("inside"), b"guest").unwrap();
            run_child("jailed_child", &[("WICK_TEST_JAIL", jail.to_str().unwrap())]);
            std::fs::remove_dir_all(&base).unwrap();
        }

        // A jail's network is its own directory in the network directory
        // (`<network>/<id>`, the jailer's `network_for_jail`). Its profile
        // lets it make and remove its endpoints there and send to the
        // sockets directly in the network directory, the operator's
        // switch's; another jail's directory in the same network is out of
        // reach, whatever the files' permissions say (two jails of one uid:
        // the kernel's file checks do not tell them apart, this does).
        #[test]
        fn test_jail_network_profile_limits_sockets() {
            let base = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("wick-jail-net-{}", std::process::id()));
            let (jail, net, other) = (base.join("jail"), base.join("net"), base.join("other"));
            for dir in [&jail, &net.join("a"), &net.join("b"), &other] {
                std::fs::create_dir_all(dir).unwrap();
            }
            // The switch, in the network; another jail's endpoint, in its
            // own directory there (this user's, as a jail of the same uid's
            // would be); a peer in another network.
            let _switch = std::os::unix::net::UnixDatagram::bind(net.join("switch")).unwrap();
            let _theirs = std::os::unix::net::UnixDatagram::bind(net.join("b/tap0")).unwrap();
            let _stranger = std::os::unix::net::UnixDatagram::bind(other.join("peer")).unwrap();
            run_child(
                "jailed_net_child",
                &[("WICK_TEST_JAIL", jail.to_str().unwrap()), ("WICK_TEST_NET", net.join("a").to_str().unwrap())],
            );
            // Nothing of the other jail's or the switch's was removed.
            assert!(net.join("b/tap0").exists() && net.join("switch").exists());
            std::fs::remove_dir_all(&base).unwrap();
        }

        #[test]
        #[ignore = "run by test_jail_network_profile_limits_sockets in a separate process"]
        fn jailed_net_child() {
            use std::os::fd::AsRawFd;
            use std::os::unix::net::UnixDatagram;
            unsafe extern "C" {
                fn pthread_fchdir_np(fd: libc::c_int) -> libc::c_int;
            }
            let jail = std::path::PathBuf::from(std::env::var("WICK_TEST_JAIL").unwrap());
            let net = std::path::PathBuf::from(std::env::var("WICK_TEST_NET").unwrap());
            let network = net.parent().unwrap().to_owned();
            let base = jail.parent().unwrap().to_owned();
            // The jail's directory in the network, opened before the sandbox
            // (and, in a jail, before the chroot).
            let dir = std::fs::File::open(&net).unwrap();
            install(&format!("{PROFILE}{}{}", syscall_rule(), files_in_jail(&jail, Some(&net)).unwrap()))
                .unwrap();
            let denied = |e: std::io::Error| e.raw_os_error() == Some(libc::EPERM);
            // SAFETY: a directory descriptor; this thread's working directory.
            assert_eq!(unsafe { pthread_fchdir_np(dir.as_raw_fd()) }, 0);
            // In its own directory: an endpoint is bound; it reaches the
            // switch, in the network directory, and sees that it is a socket.
            let ep = UnixDatagram::bind("tap0").unwrap();
            ep.send_to(b"frame", "../switch").unwrap();
            assert!(std::os::unix::fs::FileTypeExt::is_socket(
                &std::fs::symlink_metadata("../switch").unwrap().file_type()
            ));
            // The network directory's owner is read (whose sockets the
            // switch's are); the directory is not listed.
            std::fs::symlink_metadata("..").unwrap();
            assert!(denied(std::fs::read_dir("..").map(|_| ()).unwrap_err()));
            // No other file there.
            assert!(denied(std::fs::write("file", b"x").unwrap_err()));
            // Another jail's directory in the same network: its endpoint is
            // not sent to, connected to, looked at or removed, and no name is
            // taken there.
            assert!(denied(ep.send_to(b"frame", "../b/tap0").unwrap_err()), "sent to another jail's endpoint");
            assert!(denied(UnixDatagram::unbound().unwrap().connect("../b/tap0").unwrap_err()));
            assert!(denied(std::fs::symlink_metadata("../b/tap0").unwrap_err()));
            assert!(denied(std::fs::remove_file("../b/tap0").unwrap_err()), "removed another jail's endpoint");
            assert!(denied(UnixDatagram::bind("../b/tap1").unwrap_err()), "bound in another jail's directory");
            // The network directory itself: the switch's sockets are sent
            // to, not removed, and no name is taken next to them.
            assert!(denied(std::fs::remove_file("../switch").unwrap_err()), "removed the switch's socket");
            assert!(denied(UnixDatagram::bind("../tap0").unwrap_err()), "bound in the network directory");
            // Climbing out of it reaches no other network, nor anything
            // next to the jail.
            assert!(denied(ep.send_to(b"frame", "../../other/peer").unwrap_err()));
            assert!(denied(UnixDatagram::unbound().unwrap().connect("../../other/peer").unwrap_err()));
            assert!(denied(UnixDatagram::bind("../../other/tap0").unwrap_err()));
            // SAFETY: back to the process's working directory.
            assert_eq!(unsafe { pthread_fchdir_np(-1) }, 0);
            // By absolute path: the same.
            assert!(denied(ep.send_to(b"frame", base.join("other/peer")).unwrap_err()));
            assert!(denied(ep.send_to(b"frame", network.join("b/tap0")).unwrap_err()));
            ep.send_to(b"frame", network.join("switch")).unwrap();
            // Its own endpoint is its to remove.
            std::fs::remove_file(net.join("tap0")).unwrap();
            // The jail's own sockets still work.
            let _l = std::os::unix::net::UnixListener::bind(jail.join("s")).unwrap();
            std::os::unix::net::UnixStream::connect(jail.join("s")).unwrap();
            println!("CHILD-OK");
        }

        #[test]
        fn test_files_in_jail_rejects_bad_paths() {
            for bad in ["relative", "/a\nb"] {
                files_in_jail(Path::new(bad), None).unwrap_err();
                files_in_jail(Path::new("/jail"), Some(Path::new(bad))).unwrap_err();
            }
        }

        #[test]
        #[ignore = "run by test_jail_profile_limits_files in a separate process"]
        fn jailed_child() {
            let jail = std::path::PathBuf::from(std::env::var("WICK_TEST_JAIL").unwrap());
            let base = jail.parent().unwrap().to_owned();
            // A descriptor opened before the sandbox stays usable.
            let early = std::fs::File::open(base.join("outside")).unwrap();
            install(&format!("{PROFILE}{}{}", syscall_rule(), files_in_jail(&jail, None).unwrap())).unwrap();
            let denied = |e: std::io::Error| e.raw_os_error() == Some(libc::EPERM);
            // Inside the jail: read, write, create, remove, Unix sockets.
            assert_eq!(std::fs::read(jail.join("inside")).unwrap(), b"guest");
            std::fs::write(jail.join("new"), b"x").unwrap();
            std::fs::remove_file(jail.join("new")).unwrap();
            let sock = jail.join("s");
            let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            std::os::unix::net::UnixStream::connect(&sock).unwrap();
            // Outside it: nothing, not even next to the jail.
            assert!(denied(std::fs::read(base.join("outside")).unwrap_err()));
            assert!(denied(std::fs::write(base.join("new"), b"x").unwrap_err()));
            assert!(denied(std::fs::read("/etc/hosts").unwrap_err()));
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut &early, &mut buf).unwrap();
            assert_eq!(buf, "secret");
            println!("CHILD-OK");
        }

        #[test]
        #[ignore = "run by test_sandbox_restricts_child in a separate process"]
        fn sandboxed_child() {
            select(Policy::Default);
            apply().unwrap();
            // Second call is a no-op.
            apply().unwrap();
            // Files and Unix sockets still work.
            let dir = std::env::temp_dir();
            let path = dir.join(format!("wick-sandbox-{}", std::process::id()));
            std::fs::write(&path, b"x").unwrap();
            std::fs::remove_file(&path).unwrap();
            let (_a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
            // A file the profile does not allow fails with an error, as a
            // path outside the chroot does on Linux (IP networking and program
            // execution are denials: test_unlisted_syscalls_are_denials).
            println!("CHILD-OK");
        }

        /// A raw system call (`svc #0x80`, the number in x16): x0, x1 and
        /// whether it failed (carry set; x0 is then the errno).
        ///
        /// # Safety
        /// The arguments are valid for the call.
        unsafe fn svc(n: u16, a: [usize; 8]) -> (usize, usize, bool) {
            let (r0, r1, carry): (usize, usize, usize);
            // SAFETY: the caller's.
            unsafe {
                std::arch::asm!(
                    "svc #0x80",
                    "cset {c}, cs",
                    c = lateout(reg) carry,
                    inout("x16") usize::from(n) => _,
                    inout("x0") a[0] => r0,
                    inout("x1") a[1] => r1,
                    inout("x2") a[2] => _,
                    inout("x3") a[3] => _,
                    inout("x4") a[4] => _,
                    inout("x5") a[5] => _,
                    inout("x6") a[6] => _,
                    inout("x7") a[7] => _,
                    out("x17") _,
                    options(nostack),
                )
            };
            (r0, r1, carry != 0)
        }

        /// Children `name` with each of `envs`, at most 16 at a time.
        fn children(name: &str, envs: Vec<Vec<(String, String)>>) -> Vec<std::process::Output> {
            let mut outs = Vec::new();
            for chunk in envs.chunks(16) {
                outs.extend(std::thread::scope(|s| {
                    let handles: Vec<_> = chunk
                        .iter()
                        .map(|env| {
                            s.spawn(move || {
                                let env: Vec<(&str, &str)> =
                                    env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                                child(name, &env)
                            })
                        })
                        .collect();
                    handles.into_iter().map(|h| h.join().unwrap()).collect::<Vec<_>>()
                }));
            }
            outs
        }

        /// The highest BSD system call number (`SYS_MAXSYSCALL`,
        /// <sys/syscall.h> of the macOS 27 SDK).
        const SYS_MAXSYSCALL: u16 = 558;

        /// The host's macOS major (`kern.osproductversion`).
        fn macos_major() -> u32 {
            let mut buf = [0u8; 32];
            let mut len = buf.len();
            // SAFETY: a NUL-terminated name, a buffer and its length.
            let r = unsafe {
                libc::sysctlbyname(
                    c"kern.osproductversion".as_ptr(),
                    buf.as_mut_ptr().cast(),
                    &raw mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            assert_eq!(r, 0, "kern.osproductversion: {}", std::io::Error::last_os_error());
            let version = std::str::from_utf8(&buf[..len]).unwrap().trim_end_matches('\0');
            version.split('.').next().unwrap().parse().unwrap_or_else(|e| panic!("macOS {version:?}: {e}"))
        }

        // Seatbelt skips the rule on a call's number when a rule allows the
        // operation the call makes: under (allow default), with a rule
        // denying one number, exactly the calls of UNFILTERED_SYSCALLS that
        // Skip says it skips on this major run (each other one raises
        // SIGSYS). Measured here, every number in turn; a major outside
        // MEASURED_MAJORS fails with what was measured there. A call of the
        // table that raises SIGSYS with no sandbox at all is one the kernel
        // does not have (nosys): exactly ABSENT's for this major.
        #[test]
        fn test_seatbelt_skips_the_number_of_these() {
            use std::os::unix::process::ExitStatusExt;
            let major = macos_major();
            let envs = (0..SYS_MAXSYSCALL)
                .map(|n| vec![("WICK_TEST_SYSCALL".to_owned(), n.to_string())])
                .collect();
            let outs = children("number_child", envs);
            let mut ran = Vec::new();
            for (n, out) in outs.iter().enumerate() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(stdout.contains("APPLIED"), "{n}: {:?}\n{stdout}", out.status);
                if out.status.signal() != Some(libc::SIGSYS) {
                    ran.push(u16::try_from(n).unwrap());
                }
            }
            let plain = children(
                "number_child",
                UNFILTERED_SYSCALLS
                    .iter()
                    .map(|(_, n, ..)| {
                        vec![
                            ("WICK_TEST_SYSCALL".to_owned(), n.to_string()),
                            ("WICK_TEST_NO_SANDBOX".to_owned(), "1".to_owned()),
                        ]
                    })
                    .collect(),
            );
            let missing: Vec<&str> = UNFILTERED_SYSCALLS
                .iter()
                .zip(&plain)
                .filter(|(_, out)| out.status.signal() == Some(libc::SIGSYS))
                .map(|((name, ..), _)| *name)
                .collect();
            let table: Vec<u16> = UNFILTERED_SYSCALLS
                .iter()
                .filter(|(name, .., s)| s.on(major) && !absent(name, major))
                .map(|(_, n, ..)| *n)
                .collect();
            assert!(
                MEASURED_MAJORS.contains(&major),
                "macOS {major} is not measured: Seatbelt skips the number of {ran:?} there (the table says \
                 {table:?}), and the kernel has none of {missing:?}; add it to MEASURED_MAJORS, to the Skip \
                 of each entry it differs on, and to ABSENT"
            );
            let want: Vec<&str> =
                UNFILTERED_SYSCALLS.iter().map(|(name, ..)| *name).filter(|name| absent(name, major)).collect();
            assert_eq!(missing, want, "macOS {major}: the calls its kernel does not have (ABSENT)");
            assert_eq!(ran, table, "macOS {major}");
        }

        #[test]
        #[ignore = "run by test_seatbelt_skips_the_number_of_these in a separate process"]
        fn number_child() {
            // SAFETY: no arguments.
            assert_ne!(unsafe { libc::geteuid() }, 0, "never as root: the calls run");
            let n: u16 = std::env::var("WICK_TEST_SYSCALL").unwrap().parse().unwrap();
            // With no sandbox: whether the kernel has the call (ABSENT).
            if std::env::var_os("WICK_TEST_NO_SANDBOX").is_none() {
                install(&format!(
                    "(version 1)(allow default)(deny syscall-unix (syscall-number {n}) (with send-signal SIGSYS))"
                ))
                .unwrap();
            }
            println!("APPLIED");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            // Arguments of 0: most calls fail at once (a null path, an
            // empty buffer). msgget's: a key no queue has and no IPC_CREAT,
            // so that a queue is not made.
            let args = if n == 259 { [0x7769_636b, 0, 0, 0, 0, 0, 0, 0] } else { [0; 8] };
            // SAFETY: see above; a fork's child (x1 = 1) leaves at once.
            let (_, r1, _) = unsafe { svc(n, args) };
            if n == 2 && r1 == 1 {
                // SAFETY: the forked child ends.
                unsafe { libc::_exit(0) };
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        // Each call of UNFILTERED_SYSCALLS, with an argument this profile
        // denies, after narrow() and in a jail: it is a denial, or fails
        // with EPERM, as its Limit says, and runs once the rule named is
        // lifted (an allow rule for its operation, or for its number). The
        // ones nothing decides run. The calls that remove a name also with
        // the names a running microVM removes, which they remove unlifted
        // (ALLOWED_NAMES), and others, which are denials (DENIED_NAMES). A
        // call whose number Seatbelt checks on this major (Skip) is denied
        // by its number whatever is lifted, unless SYSCALLS has it.
        #[test]
        fn test_unfiltered_syscalls_are_limited_by_their_rule() {
            use std::os::unix::process::ExitStatusExt;
            let major = macos_major();
            assert!(
                MEASURED_MAJORS.contains(&major),
                "macOS {major} is not measured (test_seatbelt_skips_the_number_of_these)"
            );
            let base = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("wick-unfiltered-{}", std::process::id()));
            let jail = base.join("jail");
            std::fs::create_dir_all(jail.join("mnt")).unwrap();
            std::fs::create_dir_all(jail.join("tmp")).unwrap();
            std::fs::create_dir_all(base.join("net")).unwrap();
            let mut cases = Vec::new();
            for (name, _, limit, skip) in UNFILTERED_SYSCALLS {
                if matches!(limit, Limit::Upstream(_)) || ["exit"].contains(name) {
                    continue;
                }
                let by_number = !skip.on(major) && !SYSCALLS.contains(name);
                let mut lifts: Vec<&str> = match limit {
                    Limit::Impossible(_) | Limit::Default => vec!["0"],
                    _ => vec!["0", "1"],
                };
                for (call, names) in ALLOWED_NAMES.iter().chain(DENIED_NAMES) {
                    if call.split(' ').any(|c| c == *name) {
                        lifts.extend(*names);
                    }
                }
                for lift in &lifts {
                    // pid_suspend and pid_resume, lifted, as root only. XNU's
                    // pid_suspend (bsd/kern/kern_proc.c) asks the sandbox
                    // first (mac_proc_check_suspend_resume) and then, for a
                    // caller that is not root and another process, taskgated
                    // (__KERNEL_WAITING_ON_TASKGATED_CHECK_ACCESS_UPCALL__),
                    // and waits for its answer: once taskgated asked authd
                    // for system.privilege.taskport.debug, a password dialog
                    // nobody answered held the call, and every task-port
                    // request of the host, for ever (macOS 27.2). Unlifted,
                    // the sandbox refuses first, so no case and no microVM
                    // reaches taskgated: the profile never allows the
                    // operation, and the jailer's freezer, which does, is root.
                    // SAFETY: no arguments.
                    if ["pid_suspend", "pid_resume"].contains(name) && *lift == "1" && unsafe { libc::geteuid() } != 0 {
                        eprintln!(
                            "{name} lifted: NOT RUN: as a plain user it waits on taskgated, which can put up a \
                             password dialog and block every debugger of the host; run the test as root"
                        );
                        continue;
                    }
                    for file in ["inside", "second"] {
                        let _ = std::fs::remove_file(jail.join(format!("{file}-{name}-{lift}")));
                    }
                    std::fs::write(jail.join(format!("inside-{name}-{lift}")), b"x").unwrap();
                    std::fs::write(base.join(format!("outside-{name}-{lift}")), b"x").unwrap();
                    cases.push((*name, *limit, *lift, by_number));
                }
            }
            // Another process for each case, which a lifted call may signal,
            // stop or end: never this one. Long enough for the cases to run
            // on a loaded host (a target gone before its case runs fails
            // that case with ESRCH in place of the sandbox's answer); killed
            // when `others` goes, by the test's end or its panic, and with
            // none of this process's standard streams, so that one left
            // behind cannot keep a reader of them (CI's step) waiting.
            let others = Others(
                cases
                    .iter()
                    .map(|_| {
                        Command::new("/bin/sleep")
                            .arg("3600")
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .spawn()
                            .unwrap()
                    })
                    .collect(),
            );
            let envs = cases
                .iter()
                .zip(&others.0)
                .enumerate()
                .map(|(i, ((name, _, lift, _), other))| {
                    let other = other.id().to_string();
                    let ipc = ipc_name(i);
                    // In a jail, the temporary directory is its /tmp (the
                    // jailer's TMPDIR).
                    let tmp = if lift.starts_with("free-") {
                        std::env::temp_dir().to_str().unwrap().to_owned()
                    } else {
                        "/tmp".to_owned()
                    };
                    [
                        ("WICK_TEST_CASE", *name),
                        ("WICK_TEST_LIFT", *lift),
                        ("WICK_TEST_JAIL", jail.to_str().unwrap()),
                        ("WICK_TEST_OTHER_PID", other.as_str()),
                        ("WICK_TEST_IPC_NAME", ipc.as_str()),
                        ("TMPDIR", tmp.as_str()),
                    ]
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect()
                })
                .collect();
            let outs = children("unfiltered_child", envs);
            drop(others);
            // The POSIX shared memory objects and semaphores a case left.
            for i in 0..cases.len() {
                let name = std::ffi::CString::new(ipc_name(i)).unwrap();
                // SAFETY: a NUL-terminated name.
                unsafe {
                    libc::shm_unlink(name.as_ptr());
                    libc::sem_unlink(name.as_ptr());
                }
            }
            // A lifted mount mounted: undone here.
            for name in ["mount", "fmount"] {
                let mnt = std::ffi::CString::new(jail.join("mnt").as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: a NUL-terminated path.
                let _ = (name, unsafe { libc::unmount(mnt.as_ptr(), libc::MNT_FORCE) });
            }
            let mut failures = Vec::new();
            for ((name, limit, lift, by_number), out) in cases.iter().zip(&outs) {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let signal = out.status.signal();
                let ret = stdout.lines().find_map(|l| l.strip_prefix("RET ")).unwrap_or("none");
                let allowed = ALLOWED_NAMES.iter().any(|(_, names)| names.contains(lift));
                let denied_name = DENIED_NAMES.iter().any(|(_, names)| names.contains(lift));
                let ok = stdout.contains("NARROWED")
                    && match (limit, *lift) {
                        // The kernel's nosys raises it (ABSENT).
                        _ if absent(name, major) => signal == Some(libc::SIGSYS),
                        _ if *by_number => denied(out),
                        _ if allowed => out.status.success() && ret == "ok 0" && stdout.contains("SURVIVED"),
                        _ if denied_name => denied(out),
                        (Limit::Signal(_) | Limit::Number | Limit::Default, "0") => denied(out),
                        (Limit::Error(_), "0") => {
                            out.status.success() && ret == format!("err {}", libc::EPERM)
                        }
                        // quotactl and undelete fail in the kernel.
                        (Limit::Impossible(_), _) => {
                            let expected = match *name {
                                "quotactl" => Some(format!("err {}", libc::ENOTSUP)),
                                "undelete" => Some(format!("err {}", libc::EPERM)),
                                _ => None,
                            };
                            out.status.success()
                                && stdout.contains("SURVIVED")
                                && expected.is_none_or(|e| ret == e)
                        }
                        // Lifted: the call runs, and fails, if it does, with
                        // the kernel's error, not the sandbox's.
                        (Limit::Error(_), _) => {
                            out.status.success() && ret != format!("err {}", libc::EPERM)
                        }
                        _ => out.status.success() && stdout.contains("SURVIVED"),
                    };
                if !ok {
                    let rule = if *by_number { "the number rule, on this major" } else { "" };
                    failures.push(format!(
                        "{name} (lifted {lift}, {limit:?}{rule}; macOS {major}): {:?} RET {ret}\n{}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr).lines().take(3).collect::<Vec<_>>().join("\n")
                    ));
                }
            }
            std::fs::remove_dir_all(&base).unwrap();
            assert!(failures.is_empty(), "{}", failures.join("\n"));
        }

        /// The names a running microVM removes, by the calls that remove them
        /// (cases of `unfiltered_child`): in a jail, an eventfd's and a
        /// timer's FIFO in its /tmp, a memfd's shared memory object and a
        /// huge page one's; outside a jail, an eventfd's FIFO in the
        /// temporary directory.
        const ALLOWED_NAMES: &[(&str, &[&str])] =
            &[("unlink unlinkat", &["fifo", "free-fifo", "timer"]), ("shm_unlink", &["memfd", "huge"])];

        /// Names a running microVM does not remove: a file in the jail, a
        /// file at an eventfd FIFO's name, a network endpoint's socket in
        /// the jail's network and a socket elsewhere in the jail, a FIFO
        /// with another process's eventfd or timer name, and outside a jail
        /// a file in the temporary directory and an endpoint's socket at a
        /// path of the operator's choosing. (A name outside the jail is the
        /// unlifted case.)
        const DENIED_NAMES: &[(&str, &[&str])] = &[(
            "unlink unlinkat",
            &[
                "inside", "fifo-name", "endpoint", "socket", "fifo-other", "timer-other", "free-file",
                "free-endpoint",
            ],
        )];

        /// A POSIX IPC name of this test process's case `i` (31 bytes at most).
        fn ipc_name(i: usize) -> String {
            format!("/wick-u.{}.{i}", std::process::id())
        }

        #[test]
        #[ignore = "run by test_unfiltered_syscalls_are_limited_by_their_rule in a separate process"]
        // A system call's arguments are machine words: descriptors, numbers
        // and pointers are packed into them as they are.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
        fn unfiltered_child() {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            // SAFETY: no arguments.
            assert_ne!(unsafe { libc::geteuid() }, 0, "never as root: lifted calls run");
            let name = std::env::var("WICK_TEST_CASE").unwrap();
            let lift = std::env::var("WICK_TEST_LIFT").unwrap();
            let lifted = lift == "1";
            let jail = std::path::PathBuf::from(std::env::var("WICK_TEST_JAIL").unwrap());
            let base = jail.parent().unwrap().to_owned();
            let other = other_pid() as usize;
            let (n, limit) =
                UNFILTERED_SYSCALLS.iter().find(|(x, ..)| *x == name).map(|(_, n, l, _)| (*n, *l)).unwrap();
            let c = |p: &std::path::Path| CString::new(p.as_os_str().as_bytes()).unwrap();
            let tag = format!("{name}-{lift}");
            let inside = c(&jail.join(format!("inside-{tag}")));
            let second = c(&jail.join(format!("second-{tag}")));
            let outside = c(&base.join(format!("outside-{tag}")));
            let pid = std::process::id();
            let other_name = match lift.as_str() {
                "memfd" => CString::new(format!("/fcm.{pid}.u")).unwrap(),
                "huge" => CString::new(format!("{}{pid}.u", libc::HUGE_MEMFD_PREFIX)).unwrap(),
                _ => CString::new(std::env::var("WICK_TEST_IPC_NAME").unwrap()).unwrap(),
            };
            // What unlink and unlinkat remove: a file outside the jail,
            // unless a case of ALLOWED_NAMES or DENIED_NAMES. Each is made
            // here, before the sandbox. Another process's name is the live
            // `other` process's: a name with this pid + 1, which a denied
            // unlink leaves in the shared jail, was the name of a later
            // child that got that pid (mkfifo: EEXIST, CI on macOS 26).
            let fifo = |dir: &std::path::Path, prefix: &str, pid: u32| {
                let path = dir.join(format!("{prefix}{pid}-0"));
                // SAFETY: a NUL-terminated path.
                let ret = unsafe { libc::mkfifo(c(&path).as_ptr(), 0o600) };
                assert_eq!(ret, 0, "{path:?}: {}", std::io::Error::last_os_error());
                path
            };
            let socket = |path: std::path::PathBuf| {
                std::mem::forget(std::os::unix::net::UnixDatagram::bind(&path).unwrap());
                path
            };
            let file = |path: std::path::PathBuf| {
                std::fs::write(&path, b"x").unwrap();
                path
            };
            let free_tmp = std::env::temp_dir().canonicalize().unwrap();
            let victim = match lift.as_str() {
                "inside" => jail.join(format!("inside-{tag}")),
                "fifo" => fifo(&jail.join("tmp"), vmm_sys_util::eventfd::FIFO_PREFIX, pid),
                "timer" => fifo(&jail.join("tmp"), libc::TIMERFD_FIFO_PREFIX, pid),
                "timer-other" => fifo(&jail.join("tmp"), libc::TIMERFD_FIFO_PREFIX, other as u32),
                "fifo-name" => {
                    file(jail.join("tmp").join(format!("{}{pid}-1", vmm_sys_util::eventfd::FIFO_PREFIX)))
                }
                "fifo-other" => fifo(&jail.join("tmp"), vmm_sys_util::eventfd::FIFO_PREFIX, other as u32),
                "endpoint" => socket(base.join("net").join(format!("e-{n}"))),
                "socket" => socket(base.join(format!("s-{n}"))),
                "free-fifo" => fifo(&free_tmp, vmm_sys_util::eventfd::FIFO_PREFIX, pid),
                // At a path the operator names, as boot-test's net stage does.
                "free-endpoint" => socket(free_tmp.join(format!("wick-ep-{pid}-{n}"))),
                _ => base.join(format!("outside-{tag}")),
            };
            let victim = c(&victim);
            let mnt = c(&jail.join("mnt"));
            let jailc = c(&jail);
            let attr = c"user.wick";
            // SAFETY: plain calls before the sandbox, on what this child made.
            let (fd_in, inet, uid, gid) = unsafe {
                libc::setxattr(inside.as_ptr(), attr.as_ptr(), c"x".as_ptr().cast(), 1, 0, 0);
                // What shm_unlink and sem_unlink remove (a name that is not
                // there fails before Seatbelt decides).
                match name.as_str() {
                    "shm_unlink" => {
                        libc::close(libc::shm_open(other_name.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600));
                    }
                    "sem_unlink" => {
                        libc::sem_close(libc::sem_open(other_name.as_ptr(), libc::O_CREAT, 0o600, 0));
                    }
                    _ => {}
                }
                (
                    libc::open(inside.as_ptr(), libc::O_RDWR) as usize,
                    libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) as usize,
                    libc::getuid() as usize,
                    libc::getgid() as usize,
                )
            };
            let tty = pty() as usize;
            // SAFETY: plain data.
            let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sin.sin_len = 16;
            sin.sin_family = libc::AF_INET as u8;
            sin.sin_port = 9u16.to_be();
            sin.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
            // sa_endpoints_t: no source; the destination above.
            #[repr(C)]
            struct Endpoints {
                srcif: u32,
                srcaddr: *const libc::sockaddr_in,
                srcaddrlen: u32,
                dstaddr: *const libc::sockaddr_in,
                dstaddrlen: u32,
            }
            let eps = Endpoints {
                srcif: 0,
                srcaddr: std::ptr::null(),
                srcaddrlen: 0,
                dstaddr: &raw const sin,
                dstaddrlen: 16,
            };
            // This process's audit token (TASK_AUDIT_TOKEN), for csops_audittoken.
            let mut token = [0u32; 8];
            {
                unsafe extern "C" {
                    static mach_task_self_: libc::mach_port_t;
                    fn task_info(t: libc::mach_port_t, f: u32, i: *mut u32, c: *mut u32) -> i32;
                }
                let mut count = 8u32;
                // SAFETY: an 8-word buffer and its size in words.
                assert_eq!(unsafe { task_info(mach_task_self_, 15, token.as_mut_ptr(), &mut count) }, 0);
            }
            let lift_rule = match (lifted, limit) {
                (false, _) => String::new(),
                (true, Limit::Number) => format!("(allow syscall-unix (syscall-number {n}))\n"),
                // With a filter that holds: a rule with a filter takes
                // precedence over one without (measured), whatever their order.
                (true, Limit::Signal(ops) | Limit::Error(ops)) => ops
                    .split(' ')
                    .map(|op| format!("(allow {op} (extension \"{}\"))\n", NARROWED.to_str().unwrap()))
                    .collect(),
                (true, _) => unreachable!(),
            };
            let profile = match lift.as_str() {
                "endpoint" => profile_for(Some(&jail), Some(&base.join("net"))),
                l if l.starts_with("free-") => profile_for(None, None),
                _ => profile_for(Some(&jail), None),
            };
            let profile = format!("{}{lift_rule}", profile.unwrap());
            COMPILED
                .set((Compiled::here(&profile).unwrap(), Compiled::here(&api_profile()).unwrap()))
                .unwrap();
            select(Policy::Default);
            apply().unwrap();
            narrow().unwrap();
            println!("NARROWED");
            let p = |s: &CString| s.as_ptr() as usize;
            let mut buf = [0u8; 256];
            let bp = buf.as_mut_ptr() as usize;
            let mib = [libc::CTL_KERN, libc::KERN_OSTYPE];
            let mut len: usize = 256;
            let ostype = c"kern.ostype";
            let cwd = libc::AT_FDCWD as usize;
            const NONE: usize = 0xffff_ff9b; // KAUTH_UID_NONE, KAUTH_GID_NONE
            const IPC_CREAT_600: usize = 0o1600;
            let a: [usize; 8] = match name.as_str() {
                "fork" => [0; 8],
                "open" | "open_nocancel" => [p(&outside), 0, 0, 0, 0, 0, 0, 0],
                "openat" | "openat_nocancel" => [cwd, p(&outside), 0, 0, 0, 0, 0, 0],
                "unlink" => [p(&victim), 0, 0, 0, 0, 0, 0, 0],
                "unlinkat" => [cwd, p(&victim), 0, 0, 0, 0, 0, 0],
                "link" => [p(&inside), p(&second), 0, 0, 0, 0, 0, 0],
                "linkat" => [cwd, p(&inside), cwd, p(&second), 0, 0, 0, 0],
                "mknod" => [p(&second), (libc::S_IFIFO | 0o600) as usize, 0, 0, 0, 0, 0, 0],
                "chmod" => [p(&inside), 0o600, 0, 0, 0, 0, 0, 0],
                "fchmod" => [fd_in, 0o600, 0, 0, 0, 0, 0, 0],
                "fchmodat" => [cwd, p(&inside), 0o600, 0, 0, 0, 0, 0],
                "chmod_extended" => [p(&inside), NONE, NONE, 0o600, 0, 0, 0, 0],
                "fchmod_extended" => [fd_in, NONE, NONE, 0o600, 0, 0, 0, 0],
                "chown" | "lchown" => [p(&inside), uid, gid, 0, 0, 0, 0, 0],
                "fchown" => [fd_in, uid, gid, 0, 0, 0, 0, 0],
                "fchownat" => [cwd, p(&inside), uid, gid, 0, 0, 0, 0],
                "chflags" => [p(&inside), 0, 0, 0, 0, 0, 0, 0],
                "fchflags" => [fd_in, 0, 0, 0, 0, 0, 0, 0],
                "utimes" => [p(&inside), 0, 0, 0, 0, 0, 0, 0],
                "futimes" => [fd_in, 0, 0, 0, 0, 0, 0, 0],
                "setxattr" => [p(&inside), attr.as_ptr() as usize, bp, 1, 0, 0, 0, 0],
                "fsetxattr" => [fd_in, attr.as_ptr() as usize, bp, 1, 0, 0, 0, 0],
                "removexattr" => [p(&inside), attr.as_ptr() as usize, 0, 0, 0, 0, 0, 0],
                "fremovexattr" => [fd_in, attr.as_ptr() as usize, 0, 0, 0, 0, 0, 0],
                "clonefileat" => [cwd, p(&inside), cwd, p(&second), 0, 0, 0, 0],
                "fclonefileat" => [fd_in, cwd, p(&second), 0, 0, 0, 0, 0],
                "revoke" => [p(&inside), 0, 0, 0, 0, 0, 0, 0],
                "searchfs" => [p(&jailc), 0, 0, 0, 0, 0, 0, 0],
                // FSIOC_SYNC_VOLUME (_IOW('A', 1, uint32_t)).
                "fsctl" => [p(&inside), 0x8004_4101, bp, 0, 0, 0, 0, 0],
                "ffsctl" => [fd_in, 0x8004_4101, bp, 0, 0, 0, 0, 0],
                "undelete" => [p(&inside), 0, 0, 0, 0, 0, 0, 0],
                "quotactl" => [p(&jailc), 0, 0, 0, 0, 0, 0, 0],
                "mount" => [c"devfs".as_ptr() as usize, p(&mnt), 0, 0, 0, 0, 0, 0],
                "fmount" => {
                    // SAFETY: a NUL-terminated path.
                    let dir = unsafe { libc::open(mnt.as_ptr(), libc::O_RDONLY) } as usize;
                    [c"devfs".as_ptr() as usize, dir, 0, 0, 0, 0, 0, 0]
                }
                "unmount" => [p(&mnt), 0, 0, 0, 0, 0, 0, 0],
                "chroot" => [p(&jailc), 0, 0, 0, 0, 0, 0, 0],
                // RB_HALT: as an unprivileged user it fails, lifted or not.
                "reboot" => [0x08, 0, 0, 0, 0, 0, 0, 0],
                "acct" => [p(&inside), 0, 0, 0, 0, 0, 0, 0],
                "swapon" => [p(&inside), 0, 0, 0, 0, 0, 0, 0],
                "nfssvc" => [0, 0, 0, 0, 0, 0, 0, 0],
                "fs_snapshot" => [1 /* SNAPSHOT_OP_CREATE */, fd_in, p(&second), 0, 0, 0, 0, 0],
                "kill" => [other, 0, 0, 0, 0, 0, 0, 0],
                "terminate_with_payload" => [other, 0, 0, 0, 0, 0, 0, 0],
                "ptrace" => [libc::PT_ATTACHEXC as usize, other, 0, 0, 0, 0, 0, 0],
                "pid_suspend" | "pid_resume" => [other, 0, 0, 0, 0, 0, 0, 0],
                // PROC_INFO_CALL_PIDINFO, PROC_PIDTBSDINFO of another process.
                "proc_info" => [2, other, libc::PROC_PIDTBSDINFO as usize, 0, bp, 136, 0, 0],
                "proc_info_extended_id" => [2, other, libc::PROC_PIDTBSDINFO as usize, 0, 0, 0, bp, 136],
                "setpriority" => [libc::PRIO_PROCESS as usize, 0, 5, 0, 0, 0, 0, 0],
                "getpriority" => [libc::PRIO_PROCESS as usize, 0, 0, 0, 0, 0, 0, 0],
                "csops" => [0, 0 /* CS_OPS_STATUS */, bp, 4, 0, 0, 0, 0],
                "csops_audittoken" => [0, 0, bp, 4, token.as_ptr() as usize, 0, 0, 0],
                "sysctl" => [mib.as_ptr() as usize, 2, bp, (&raw mut len) as usize, 0, 0, 0, 0],
                "sysctlbyname" => {
                    [ostype.as_ptr() as usize, 11, bp, (&raw mut len) as usize, 0, 0, 0, 0]
                }
                // TIOCSWINSZ: setting the terminal's size, a request outside
                // RUN_OPERATIONS' (with a size read before, TIOCGWINSZ).
                "ioctl" => {
                    // SAFETY: a terminal descriptor and a winsize to fill.
                    unsafe { libc::ioctl(tty as i32, libc::TIOCGWINSZ, bp) };
                    [tty, libc::TIOCSWINSZ as usize, bp, 0, 0, 0, 0, 0]
                }
                // PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL: a kernel control socket.
                "socket" => [32, 2, 2, 0, 0, 0, 0, 0],
                "connect" | "connect_nocancel" => [inet, (&raw const sin) as usize, 16, 0, 0, 0, 0, 0],
                "connectx" => [inet, (&raw const eps) as usize, 0, 0, 0, 0, 0, 0],
                "bind" => [inet, (&raw const sin) as usize, 16, 0, 0, 0, 0, 0],
                "semget" | "msgget" => [0 /* IPC_PRIVATE */, 1, IPC_CREAT_600, 0, 0, 0, 0, 0],
                "shmget" => [0, 16384, IPC_CREAT_600, 0, 0, 0, 0, 0],
                // IPC_STAT of no object: an error, once allowed.
                "semctl" | "msgctl" | "shmctl" => [usize::MAX >> 1, 0, 2, bp, 0, 0, 0, 0],
                "semop" | "shmat" => [usize::MAX >> 1, bp, 0, 0, 0, 0, 0, 0],
                "msgsnd" | "msgsnd_nocancel" | "msgrcv" | "msgrcv_nocancel" => {
                    [usize::MAX >> 1, bp, 8, 0, 0x800 /* IPC_NOWAIT */, 0, 0, 0]
                }
                "shmdt" => [bp, 0, 0, 0, 0, 0, 0, 0],
                "shm_open" => {
                    [other_name.as_ptr() as usize, (libc::O_RDWR | libc::O_CREAT) as usize, 0o600, 0, 0, 0, 0, 0]
                }
                "shm_unlink" | "sem_unlink" => [other_name.as_ptr() as usize, 0, 0, 0, 0, 0, 0, 0],
                "sem_open" => [other_name.as_ptr() as usize, libc::O_CREAT as usize, 0o600, 0, 0, 0, 0, 0],
                "sem_close" | "sem_wait" | "sem_wait_nocancel" | "sem_trywait" | "sem_post" => {
                    [bp, 0, 0, 0, 0, 0, 0, 0]
                }
                "getpid" | "getuid" | "getgid" | "issetugid" | "getumask" => [0; 8],
                "umask" => [0o022, 0, 0, 0, 0, 0, 0, 0],
                other => panic!("no case for {other}"),
            };
            // SAFETY: arguments for this call, made above.
            let (r0, r1, err) = unsafe { svc(n, a) };
            if name == "fork" && r1 == 1 {
                // SAFETY: the forked child ends.
                unsafe { libc::_exit(0) };
            }
            if err {
                println!("RET err {r0}");
            } else {
                println!("RET ok {r0}");
            }
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            // What a lifted call made is undone (the lifted rule allows it).
            if lifted && !err {
                // SAFETY: plain calls on what the call above returned.
                unsafe {
                    match name.as_str() {
                        "semget" => drop(libc::semctl(r0 as i32, 0, libc::IPC_RMID)),
                        "msgget" => drop(svc(258, [r0, libc::IPC_RMID as usize, 0, 0, 0, 0, 0, 0])),
                        "shmget" => drop(libc::shmctl(r0 as i32, libc::IPC_RMID, std::ptr::null_mut())),
                        "shm_open" => drop(libc::shm_unlink(other_name.as_ptr())),
                        "sem_open" => drop(libc::sem_unlink(other_name.as_ptr())),
                        _ => {}
                    }
                }
            }
            // Seatbelt signals the process, not the thread.
            std::thread::sleep(std::time::Duration::from_secs(1));
            println!("SURVIVED");
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    //! The Windows sandbox: a process mitigation profile ([`MITIGATIONS`]),
    //! each mitigation standing for a rule of upstream's seccomp filters
    //! (resources/seccomp/x86_64-unknown-linux-musl.json). The mitigations
    //! are permanent: once set, the process cannot lift them. Each is read
    //! back after it is set, and start-up fails if one is missing.
    //!
    //! As on Linux, where the VMM thread builds the microVM unfiltered and
    //! gets its narrow filter before the event loop, the profile comes in two
    //! phases ([`Phase`]): [`apply`] sets what building the microVM can live
    //! with, [`narrow`] the rest once it is built and every library it needs
    //! is loaded (no dynamic code, the image load restrictions).
    //!
    //! A seccomp filter traps a denied call: SIGSYS, and upstream's handler
    //! exits with the bad-syscall code. Two denials do the same here, by
    //! raising SIGSYS synchronously on the thread that made the call:
    //!
    //! - `mmap` and `mprotect` with `PROT_EXEC` after [`narrow`] (the POSIX
    //!   layer's own check, the same rule as upstream's filter), which the
    //!   dynamic code policy denies;
    //! - a handle the process does not hold: strict handle checks raise
    //!   `STATUS_INVALID_HANDLE`, which a vectored exception handler turns
    //!   into SIGSYS.
    //!
    //! Windows reports the other mitigations' denials as an error status of
    //! the call, with no documented way to be told of them: creating a
    //! process fails with `ERROR_CHILD_PROCESS_BLOCKED`, loading a win32k
    //! library with `ERROR_DLL_INIT_FAILED`, an unsigned image with
    //! `ERROR_INVALID_IMAGE_HASH`, a remote or low-label image with
    //! `ERROR_ACCESS_DENIED`. Those fail closed, and Firecracker goes on.

    use std::ffi::c_void;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetProcessMitigationPolicy, PROCESS_MITIGATION_POLICY,
        ProcessChildProcessPolicy, ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy,
        ProcessImageLoadPolicy, ProcessSignaturePolicy, ProcessStrictHandleCheckPolicy,
        ProcessSystemCallDisablePolicy, SetProcessMitigationPolicy, TerminateProcess,
    };

    use super::{Policy, SandboxError};

    /// When a mitigation is set.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Phase {
        /// By [`apply`], where upstream installs the first seccomp filter.
        Setup,
        /// By [`narrow`], where upstream installs the VMM thread's filter.
        Run,
    }

    /// One process mitigation policy and the flags the sandbox sets.
    #[derive(Debug, Clone, Copy)]
    pub struct Mitigation {
        /// The policy's name (`PROCESS_MITIGATION_POLICY`).
        pub name: &'static str,
        /// The policy.
        pub policy: PROCESS_MITIGATION_POLICY,
        /// Its flags word, as `SetProcessMitigationPolicy` takes it.
        pub flags: u32,
        /// The rule of upstream's seccomp filters it stands for.
        pub linux: &'static str,
        /// When it is set.
        pub phase: Phase,
        /// Its audit flags, set instead of `flags` by a discovery build
        /// (`--cfg wick_sandbox_discovery`, tools/windows/mitigation-audit.ps1):
        /// Windows then reports what the mitigation would deny in the
        /// Security-Mitigations event log, and allows it. 0 where Windows
        /// reports no audit at run time (measured on Windows Server 2022:
        /// the signature and image load audits stay silent, their
        /// enforcement is reported); the discovery build enforces those.
        pub audit: u32,
    }

    /// The mitigation profile, in the order it is applied.
    pub const MITIGATIONS: &[Mitigation] = &[
        Mitigation {
            name: "ProcessExtensionPointDisablePolicy",
            policy: ProcessExtensionPointDisablePolicy,
            // DisableExtensionPoints: no AppInit DLLs, window hooks, input
            // method editors or other legacy ways into the process.
            flags: 1,
            linux: "mmap/mprotect: arg 2 & PROT_EXEC == 0 (no code mapped into a filtered thread)",
            phase: Phase::Setup,
            audit: 0,
        },
        Mitigation {
            name: "ProcessImageLoadPolicy",
            policy: ProcessImageLoadPolicy,
            // NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images.
            flags: 0b111,
            linux: "mmap/mprotect: arg 2 & PROT_EXEC == 0 (no executable mapping of a file); here: \
                    no image from the network or labelled low, system DLLs from System32",
            phase: Phase::Run,
            audit: 0,
        },
        Mitigation {
            name: "ProcessSignaturePolicy",
            policy: ProcessSignaturePolicy,
            // MicrosoftSignedOnly: Firecracker is one executable and loads
            // system DLLs only.
            flags: 1,
            linux: "mmap/mprotect: arg 2 & PROT_EXEC == 0 (no new code); here: no image Microsoft \
                    did not sign",
            phase: Phase::Setup,
            audit: 0,
        },
        Mitigation {
            name: "ProcessStrictHandleCheckPolicy",
            policy: ProcessStrictHandleCheckPolicy,
            // RaiseExceptionOnInvalidHandleReference |
            // HandleExceptionsPermanentlyEnabled.
            flags: 0b11,
            linux: "default action trap: a call the filter does not allow ends the process; here: \
                    a handle the process does not hold",
            phase: Phase::Setup,
            audit: 0,
        },
        Mitigation {
            name: "ProcessSystemCallDisablePolicy",
            policy: ProcessSystemCallDisablePolicy,
            // DisallowWin32kSystemCalls.
            flags: 1,
            linux: "default action trap for every call not listed: no filter lists a call to a \
                    display or input device (ioctl is limited to KVM, TUN, vsock, block and \
                    terminal requests)",
            phase: Phase::Setup,
            audit: 0b10 /* AuditDisallowWin32kSystemCalls */,
        },
        Mitigation {
            name: "ProcessDynamicCodePolicy",
            policy: ProcessDynamicCodePolicy,
            // ProhibitDynamicCode.
            flags: 1,
            linux: "mmap/mprotect: arg 2 & PROT_EXEC == 0",
            phase: Phase::Run,
            audit: 0b1000 /* AuditProhibitDynamicCode */,
        },
        Mitigation {
            name: "ProcessChildProcessPolicy",
            policy: ProcessChildProcessPolicy,
            // NoChildProcessCreation.
            flags: 1,
            linux: "no clone without CLONE_THREAD, fork, vfork, execve or execveat in any filter",
            phase: Phase::Setup,
            audit: 0b10 /* AuditNoChildProcessCreation */,
        },
    ];

    /// `si_code` of a SIGSYS from a seccomp filter (`SYS_SECCOMP`).
    const SYS_SECCOMP: libc::c_int = 1;
    /// `STATUS_INVALID_HANDLE`, raised by strict handle checks.
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    /// `STATUS_HANDLE_NOT_CLOSABLE`, raised by strict handle checks.
    const STATUS_HANDLE_NOT_CLOSABLE: u32 = 0xC000_0235;
    /// `STATUS_DYNAMIC_CODE_BLOCKED`, what the dynamic code policy answers.
    const STATUS_DYNAMIC_CODE_BLOCKED: u32 = 0xC000_0604;

    /// What the sandbox denied (an NTSTATUS), once it did: for
    /// [`denied_syscall`].
    static DENIED: AtomicU32 = AtomicU32::new(0);
    static INSTALLED: AtomicBool = AtomicBool::new(false);

    /// Ends the process for a denied operation as a seccomp trap does:
    /// SIGSYS on this thread, whose handler (upstream's) exits with the
    /// bad-syscall code; without a handler, the default action, the end of
    /// the process as by the signal (`128 + SIGSYS`, as `kill` reports it).
    fn deny(status: u32) -> ! {
        if DENIED.compare_exchange(0, status, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr(),
                "The host sandbox denied an operation (NTSTATUS {status:#010x})"
            );
            // Where: the return addresses in Firecracker's image, as offsets
            // from its base, which the release's PDB resolves (a jail has no
            // PDB beside its copy of the binary). The process ends here.
            let base = unsafe {
                windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null())
            } as usize;
            let mut frames = [std::ptr::null_mut::<c_void>(); 48];
            // SAFETY: a buffer of 48 frames.
            let n = unsafe {
                windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace(
                    0,
                    48,
                    frames.as_mut_ptr(),
                    std::ptr::null_mut(),
                )
            };
            let mut line = String::from("  at firecracker.exe+");
            for f in &frames[..usize::from(n)] {
                let ip = *f as usize;
                if ip >= base && ip - base < 64 << 20 {
                    line.push_str(&format!("{:#x} ", ip - base));
                }
            }
            let _ = writeln!(std::io::stderr(), "{line}");
            vmm_sys_util::signal::raise_synchronous(libc::SIGSYS, SYS_SECCOMP);
        }
        // SAFETY: ends this process.
        unsafe { TerminateProcess(GetCurrentProcess(), (128 + libc::SIGSYS).cast_unsigned()) };
        unreachable!("the process ended");
    }

    extern "C" fn exec_denied(_prot: libc::c_int) {
        deny(STATUS_DYNAMIC_CODE_BLOCKED);
    }

    #[repr(C)]
    struct ExceptionRecord {
        code: u32,
        flags: u32,
        record: *mut ExceptionRecord,
        address: *mut c_void,
    }

    #[repr(C)]
    struct ExceptionPointers {
        record: *mut ExceptionRecord,
        context: *mut c_void,
    }

    /// `EXCEPTION_CONTINUE_SEARCH`.
    const CONTINUE_SEARCH: i32 = 0;
    /// `EXCEPTION_CONTINUE_EXECUTION`.
    const CONTINUE_EXECUTION: i32 = -1;

    unsafe extern "system" fn on_exception(info: *mut ExceptionPointers) -> i32 {
        // SAFETY: Windows passes valid exception pointers.
        let code = unsafe { (*(*info).record).code };
        if INSTALLED.load(Ordering::Acquire)
            && (code == STATUS_INVALID_HANDLE || code == STATUS_HANDLE_NOT_CLOSABLE)
        {
            // The POSIX layer asking whether a descriptor is still open
            // (libc's descriptor table, about descriptors std closed
            // itself): meant to fail for one that is not, as EBADF on Linux.
            // The call returns its error (measured continuable). Found as
            // SIGSYS on the 19th network interface of test_max_devices,
            // when the table's sweep met a closed descriptor.
            if code == STATUS_INVALID_HANDLE && libc::wick_fd::probing() {
                return CONTINUE_EXECUTION;
            }
            deny(code);
        }
        CONTINUE_SEARCH
    }

    // windows-sys gates it behind Win32_System_Diagnostics_Debug, which the
    // vmm crate does not otherwise need.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AddVectoredExceptionHandler(
            first: u32,
            handler: unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
        ) -> *mut c_void;
    }

    /// Whether a SIGSYS is the sandbox denying an operation. Async-signal-safe.
    ///
    /// # Safety
    /// `info` is the siginfo a SIGSYS handler was given.
    pub unsafe fn denied_syscall(si_code: libc::c_int, _info: *mut libc::siginfo_t) -> bool {
        si_code == SYS_SECCOMP && DENIED.load(Ordering::SeqCst) != 0
    }

    struct State {
        policy: Policy,
        installed: bool,
        narrowed: bool,
    }

    static STATE: Mutex<State> = Mutex::new(State {
        policy: Policy::None,
        installed: false,
        narrowed: false,
    });

    /// Selects the sandbox to install. Called once at start-up from the seccomp
    /// configuration.
    pub fn select(policy: Policy) {
        STATE.lock().unwrap().policy = policy;
    }

    /// The selected sandbox.
    pub fn selected() -> Policy {
        STATE.lock().unwrap().policy
    }

    /// The API process's sandbox (`ext::api_process`), the counterpart of
    /// upstream's `api` filter: the whole profile at once, the [`Phase::Setup`]
    /// and [`Phase::Run`] mitigations and the trap on executable mappings,
    /// before the process reads a byte from the API socket. The `api` filter
    /// allows less than the VMM thread's; a mitigation profile has nothing
    /// narrower than every mitigation, so the API process gets them all, from
    /// the start. Applied once, before [`apply`]; nothing with `--no-seccomp`.
    pub fn apply_api() -> Result<(), SandboxError> {
        let mut state = STATE.lock().unwrap();
        if state.policy == Policy::None {
            return Ok(());
        }
        if state.installed {
            return Err(SandboxError::Install(
                "the API process's sandbox is applied before any other".into(),
            ));
        }
        // SAFETY: registers a handler that only reads the exception record.
        if unsafe { AddVectoredExceptionHandler(1, on_exception) }.is_null() {
            return Err(SandboxError::Install(format!(
                "the exception handler: {}",
                std::io::Error::last_os_error()
            )));
        }
        set_phase(Phase::Setup).map_err(SandboxError::Install)?;
        set_phase(Phase::Run).map_err(SandboxError::Install)?;
        INSTALLED.store(true, Ordering::Release);
        libc::wick_mm::deny_exec(exec_denied);
        state.installed = true;
        state.narrowed = true;
        Ok(())
    }

    /// The flags of `policy` in force for this process.
    pub fn read_back(policy: PROCESS_MITIGATION_POLICY) -> Result<u32, SandboxError> {
        let mut flags = 0u32;
        // SAFETY: a 4-byte buffer of the size passed.
        let ok = unsafe {
            GetProcessMitigationPolicy(
                GetCurrentProcess(),
                policy,
                std::ptr::from_mut(&mut flags).cast(),
                std::mem::size_of::<u32>(),
            )
        };
        if ok == 0 {
            return Err(SandboxError::Install(format!(
                "reading back mitigation policy {policy}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(flags)
    }

    /// The flags the sandbox sets for `m`: its audit flags in a discovery
    /// build, where it has them.
    #[allow(unexpected_cfgs)]
    fn flags_to_set(m: &Mitigation) -> u32 {
        if cfg!(wick_sandbox_discovery) && m.audit != 0 { m.audit } else { m.flags }
    }

    /// Sets the mitigations of `phase`, each read back.
    fn set_phase(phase: Phase) -> Result<(), String> {
        for m in MITIGATIONS.iter().filter(|m| m.phase == phase) {
            let flags = flags_to_set(m);
            // SAFETY: a 4-byte policy value of the size passed.
            let ok = unsafe {
                SetProcessMitigationPolicy(
                    m.policy,
                    std::ptr::from_ref(&flags).cast(),
                    std::mem::size_of::<u32>(),
                )
            };
            if ok == 0 {
                return Err(format!("{}: {}", m.name, std::io::Error::last_os_error()));
            }
            let back = read_back(m.policy).map_err(|e| e.to_string())?;
            if back & flags != flags {
                return Err(format!("{}: {back:#x} in force, {flags:#x} set", m.name));
            }
        }
        Ok(())
    }

    /// Installs the selected sandbox if it is not installed yet: the trap on
    /// invalid handles, then the [`Phase::Setup`] mitigations, checked by
    /// reading them back. Any step that fails is an error, and start-up
    /// fails with it.
    pub fn apply() -> Result<(), SandboxError> {
        let mut state = STATE.lock().unwrap();
        if state.policy == Policy::None || state.installed {
            return Ok(());
        }
        // SAFETY: registers a handler that only reads the exception record.
        if unsafe { AddVectoredExceptionHandler(1, on_exception) }.is_null() {
            return Err(SandboxError::Install(format!(
                "the exception handler: {}",
                std::io::Error::last_os_error()
            )));
        }
        set_phase(Phase::Setup).map_err(SandboxError::Install)?;
        INSTALLED.store(true, Ordering::Release);
        state.installed = true;
        Ok(())
    }

    /// Ends the setup phase for good: the [`Phase::Run`] mitigations, read
    /// back, and the trap on executable mappings. Nothing if the sandbox is
    /// not installed (`--no-seccomp`) or already narrowed.
    #[allow(unexpected_cfgs)]
    pub fn narrow() -> Result<(), SandboxError> {
        let mut state = STATE.lock().unwrap();
        if !state.installed || state.narrowed {
            return Ok(());
        }
        set_phase(Phase::Run).map_err(SandboxError::Narrow)?;
        // A discovery build lets the mapping through, for the audit to report.
        if !cfg!(wick_sandbox_discovery) {
            libc::wick_mm::deny_exec(exec_denied);
        }
        state.narrowed = true;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use std::process::{Command, Output};
        use std::sync::OnceLock;

        use super::*;

        // The sandbox is permanent, so it runs in a child process (the test
        // binary itself, filtered to one of the ignored tests below). When
        // tests run one at a time (RUST_TEST_THREADS=1, as upstream's CI and
        // tools/windows/check-unit-tests.py run tests), libtest writes
        // "test <name> ... " before a test runs (library/test/src/formatters/
        // pretty.rs, write_test_start), so the child's first line would
        // follow it (measured: CI run 43277608081); it gets a line of its own.
        fn child(name: &str, env: &[(&str, &str)]) -> Output {
            let test = format!("ext::sandbox::windows::tests::{name}");
            let mut out = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test, "--ignored", "--nocapture"])
                .envs(env.iter().copied())
                .output()
                .unwrap();
            let start = format!("test {test} ... ");
            let at = out.stdout.windows(start.len()).position(|w| w == start.as_bytes());
            if let Some(at) = at {
                out.stdout.insert(at + start.len(), b'\n');
            }
            out
        }

        fn text(out: &Output) -> String {
            format!(
                "{:?}\n{}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        }

        /// What a sandboxed child reads back, once for all the tests.
        fn read_back_in_child() -> &'static str {
            static OUT: OnceLock<String> = OnceLock::new();
            OUT.get_or_init(|| {
                let out = child("read_back_child", &[]);
                assert!(out.status.success(), "{}", text(&out));
                String::from_utf8_lossy(&out.stdout).into_owned()
            })
        }

        fn check_in_force(name: &str) {
            let m = MITIGATIONS.iter().find(|m| m.name == name).unwrap();
            let out = read_back_in_child();
            let back = |phase: &str| {
                let line = out
                    .lines()
                    .find(|l| l.starts_with(&format!("{phase} {name} ")))
                    .unwrap_or_else(|| panic!("{name} not read back: {out}"));
                u32::from_str_radix(line.rsplit(' ').next().unwrap(), 16).unwrap() & m.flags
            };
            // In force from its phase on, not before.
            assert_eq!(back("setup"), if m.phase == Phase::Setup { m.flags } else { 0 }, "{name}");
            assert_eq!(back("run"), m.flags, "{name}");
        }

        #[test]
        #[ignore = "run by the test_*_policy tests in a separate process"]
        fn read_back_child() {
            // Nothing is in force before the sandbox.
            for m in MITIGATIONS {
                assert_eq!(read_back(m.policy).unwrap() & m.flags, 0, "{}", m.name);
            }
            select(Policy::Default);
            apply().unwrap();
            // A second call does nothing.
            apply().unwrap();
            for m in MITIGATIONS {
                println!("setup {} {:x}", m.name, read_back(m.policy).unwrap());
            }
            narrow().unwrap();
            narrow().unwrap();
            for m in MITIGATIONS {
                println!("run {} {:x}", m.name, read_back(m.policy).unwrap());
            }
        }

        #[test]
        fn test_extension_point_policy() {
            check_in_force("ProcessExtensionPointDisablePolicy");
        }

        #[test]
        fn test_image_load_policy() {
            check_in_force("ProcessImageLoadPolicy");
        }

        #[test]
        fn test_signature_policy() {
            check_in_force("ProcessSignaturePolicy");
        }

        #[test]
        fn test_strict_handle_check_policy() {
            check_in_force("ProcessStrictHandleCheckPolicy");
        }

        #[test]
        fn test_win32k_policy() {
            check_in_force("ProcessSystemCallDisablePolicy");
        }

        #[test]
        fn test_dynamic_code_policy() {
            check_in_force("ProcessDynamicCodePolicy");
        }

        #[test]
        fn test_child_process_policy() {
            check_in_force("ProcessChildProcessPolicy");
        }

        // The API process's profile: every mitigation of both phases in force
        // at once, and an executable mapping ends the process as a seccomp
        // trap does (the `api` filter has no mmap/mprotect with PROT_EXEC).
        #[test]
        fn test_api_profile_is_the_whole_profile_at_once() {
            let out = child("api_read_back_child", &[]);
            assert!(out.status.success(), "{}", text(&out));
            let stdout = String::from_utf8_lossy(&out.stdout);
            for m in MITIGATIONS {
                let line = stdout
                    .lines()
                    .find(|l| l.starts_with(&format!("api {} ", m.name)))
                    .unwrap_or_else(|| panic!("{} not read back: {stdout}", m.name));
                let back = u32::from_str_radix(line.rsplit(' ').next().unwrap(), 16).unwrap();
                assert_eq!(back & m.flags, m.flags, "{}", m.name);
            }
            assert!(stdout.contains("API-TWICE-REFUSED"), "{stdout}");
        }

        #[test]
        #[ignore = "run by test_api_profile_is_the_whole_profile_at_once in a separate process"]
        fn api_read_back_child() {
            for m in MITIGATIONS {
                assert_eq!(read_back(m.policy).unwrap() & m.flags, 0, "{}", m.name);
            }
            select(Policy::Default);
            apply_api().unwrap();
            for m in MITIGATIONS {
                println!("api {} {:x}", m.name, read_back(m.policy).unwrap());
            }
            // Once; and the VMM's phases do nothing more after it.
            if apply_api().is_err() {
                println!("API-TWICE-REFUSED");
            }
            apply().unwrap();
            narrow().unwrap();
        }

        #[test]
        fn test_api_profile_denies_executable_mappings() {
            let out = child("api_exec_child", &[("WICK_TEST_HANDLERS", "1")]);
            assert_eq!(out.status.code(), Some(crate::FcExitCode::BadSyscall as i32), "{}", text(&out));
            assert!(!text(&out).contains("CHILD-SURVIVED"), "{}", text(&out));
        }

        #[test]
        #[ignore = "run by test_api_profile_denies_executable_mappings in a separate process"]
        fn api_exec_child() {
            crate::signal_handler::register_signal_handlers().unwrap();
            select(Policy::Default);
            apply_api().unwrap();
            let p = anonymous(RWX);
            println!("CHILD-SURVIVED {p:?}");
        }

        #[test]
        fn test_every_mitigation_names_its_linux_rule() {
            let mut names: Vec<_> = MITIGATIONS.iter().map(|m| m.name).collect();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), MITIGATIONS.len());
            for m in MITIGATIONS {
                assert!(m.linux.len() > 20, "{}", m.name);
                assert_ne!(m.flags, 0, "{}", m.name);
            }
        }

        /// The denials that end Firecracker as a seccomp trap does: with
        /// upstream's handlers, the bad-syscall exit code.
        const TRAPS: [&str; 3] = ["exec_mmap_child", "exec_mprotect_child", "bad_handle_child"];

        #[test]
        fn test_denied_operation_exits_as_seccomp() {
            for name in TRAPS {
                let out = child(name, &[("WICK_TEST_HANDLERS", "1")]);
                assert_eq!(
                    out.status.code(),
                    Some(crate::FcExitCode::BadSyscall as i32),
                    "{name}: {}",
                    text(&out)
                );
                assert!(!text(&out).contains("CHILD-SURVIVED"), "{name}");
            }
        }

        // Without a handler, the default action of SIGSYS.
        #[test]
        fn test_denied_operation_raises_sigsys() {
            for name in TRAPS {
                let out = child(name, &[]);
                assert_eq!(out.status.code(), Some(128 + libc::SIGSYS), "{name}: {}", text(&out));
                assert!(!text(&out).contains("CHILD-SURVIVED"), "{name}");
            }
        }

        fn sandboxed() {
            if std::env::var_os("WICK_TEST_HANDLERS").is_some() {
                crate::signal_handler::register_signal_handlers().unwrap();
            }
            select(Policy::Default);
            apply().unwrap();
        }

        fn anonymous(prot: libc::c_int) -> *mut c_void {
            // SAFETY: an anonymous mapping.
            unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            }
        }

        const RWX: libc::c_int = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;

        // What building the microVM may do, a running one may not: an
        // executable mapping is allowed until narrow(), and ends the process
        // as a seccomp trap after it.
        #[test]
        fn test_narrow_ends_the_setup_phase() {
            let out = child("narrowed_child", &[("WICK_TEST_HANDLERS", "1")]);
            assert_eq!(out.status.code(), Some(crate::FcExitCode::BadSyscall as i32), "{}", text(&out));
            assert!(text(&out).contains("SETUP-OK"), "{}", text(&out));
            assert!(!text(&out).contains("CHILD-SURVIVED"), "{}", text(&out));
        }

        #[test]
        #[ignore = "run by test_narrow_ends_the_setup_phase in a separate process"]
        fn narrowed_child() {
            sandboxed();
            assert_ne!(anonymous(RWX), libc::MAP_FAILED);
            println!("SETUP-OK");
            narrow().unwrap();
            let p = anonymous(RWX);
            println!("CHILD-SURVIVED {p:?}");
        }

        // The run phase cannot be undone: each mitigation stays in force after
        // an attempt to clear it.
        #[test]
        fn test_narrowing_is_one_way() {
            let out = child("one_way_child", &[]);
            assert!(out.status.success(), "{}", text(&out));
            assert!(text(&out).contains("CHILD-OK"), "{}", text(&out));
        }

        #[test]
        #[ignore = "run by test_narrowing_is_one_way in a separate process"]
        fn one_way_child() {
            sandboxed();
            narrow().unwrap();
            for m in MITIGATIONS {
                let none = 0u32;
                // SAFETY: a 4-byte policy value of the size passed.
                unsafe { SetProcessMitigationPolicy(m.policy, std::ptr::from_ref(&none).cast(), 4) };
                assert_eq!(read_back(m.policy).unwrap() & m.flags, m.flags, "{}", m.name);
            }
            println!("CHILD-OK");
        }

        #[test]
        #[ignore = "run by test_denied_operation_* in a separate process"]
        fn exec_mmap_child() {
            sandboxed();
            narrow().unwrap();
            let p = anonymous(RWX);
            println!("CHILD-SURVIVED {p:?}");
        }

        #[test]
        #[ignore = "run by test_denied_operation_* in a separate process"]
        fn exec_mprotect_child() {
            sandboxed();
            narrow().unwrap();
            let p = anonymous(libc::PROT_READ | libc::PROT_WRITE);
            assert_ne!(p, libc::MAP_FAILED);
            // SAFETY: the mapping above.
            let r = unsafe { libc::mprotect(p, 4096, libc::PROT_READ | libc::PROT_EXEC) };
            println!("CHILD-SURVIVED {r}");
        }

        #[test]
        #[ignore = "run by test_denied_operation_* in a separate process"]
        fn bad_handle_child() {
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn SetEvent(h: *mut c_void) -> i32;
                fn GetLastError() -> u32;
                fn GetFileType(h: *mut c_void) -> u32;
            }
            sandboxed();
            // A value no process holds a handle at: a process holds at most
            // 2^24 handles (Microsoft Learn, "Kernel Objects": "The
            // per-process limit on kernel handles is 2^24"), at values four
            // apart (the low two bits are no part of a handle:
            // OBJ_HANDLE_TAGBITS, wdm.h), so every handle is below 2^26;
            // positive, so no pseudo-handle (those are -1 to -6). It was
            // 0x1234, which a process can hold: in CI run 43403250054 this
            // child, started without handlers right after the same child
            // with them had raised, got FALSE from SetEvent and went on
            // (CHILD-SURVIVED 0): no exception, so 0x1234 was a handle it
            // held, since strict handle checks raise for one that is not
            // there (PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
            // RaiseExceptionOnInvalidHandleReference), and SetEvent failed
            // for it as for an object that is no event. A child inherits
            // its parent's inheritable handles with "the same value"
            // (Microsoft Learn, "Handle Inheritance"), so which values a
            // child holds follows the test process that starts it, which
            // on the runner had run some 600 tests by then.
            let bad = (1usize << 30) as *mut c_void;
            // SAFETY: a value no handle has; strict handle checks raise for
            // it.
            let r = unsafe { SetEvent(bad) };
            // Only if it did not raise: why, and what the value is.
            // SAFETY: plain calls.
            let (error, kind) = unsafe { (GetLastError(), GetFileType(bad)) };
            println!("CHILD-SURVIVED {r} (error {error}, file type {kind})");
        }

        // A descriptor closed behind the POSIX layer's back (std closes its
        // handles itself) that the layer then asks about: the question fails,
        // as EBADF on Linux, and the process goes on under strict handle
        // checks. (Firecracker died of SIGSYS on the 19th network interface
        // of test_max_devices, when libc's descriptor table swept such a
        // descriptor.)
        #[test]
        fn test_probing_a_closed_descriptor_is_not_a_denial() {
            let out = child("closed_descriptor_child", &[("WICK_TEST_HANDLERS", "1")]);
            assert!(out.status.success(), "{}", text(&out));
            assert!(text(&out).contains("CHILD-SURVIVED none"), "{}", text(&out));
        }

        #[test]
        #[ignore = "run by test_probing_a_closed_descriptor_is_not_a_denial in a separate process"]
        fn closed_descriptor_child() {
            use std::os::windows::io::{FromRawHandle, OwnedHandle};
            sandboxed();
            // A descriptor with state in libc's table (a timerfd's schedule).
            // SAFETY: plain call.
            let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
            assert!(fd >= 0);
            // Closed as std closes a handle, past libc's close (a descriptor
            // is its handle's value).
            // SAFETY: the timerfd's handle, owned from here and closed.
            drop(unsafe { OwnedHandle::from_raw_handle(fd as isize as *mut c_void) });
            let state = libc::wick_fd::attached::<u64>(fd);
            println!("CHILD-SURVIVED {}", if state.is_none() { "none" } else { "some" });
        }

        /// The denials Windows reports as an error: each fails, and the
        /// process goes on (`ERROR_*` code of each, winerror.h).
        #[test]
        fn test_denied_operations_fail_closed() {
            let dir = std::env::temp_dir().join(format!("wick-sandbox-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            // An image Microsoft did not sign: this test binary.
            let unsigned = dir.join("unsigned.dll");
            std::fs::copy(std::env::current_exe().unwrap(), &unsigned).unwrap();
            // A Microsoft-signed image labelled low.
            let low = dir.join("low");
            std::fs::create_dir_all(&low).unwrap();
            let system = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap())
                .join(r"System32\version.dll");
            let low_dll = low.join("version.dll");
            std::fs::copy(&system, &low_dll).unwrap();
            let st = Command::new("icacls")
                .arg(&low_dll)
                .args(["/setintegritylevel", "low"])
                .output()
                .unwrap();
            assert!(st.status.success(), "{}", text(&st));
            let out = child(
                "fail_closed_child",
                &[
                    ("WICK_TEST_UNSIGNED", unsigned.to_str().unwrap()),
                    ("WICK_TEST_LOW", low_dll.to_str().unwrap()),
                ],
            );
            std::fs::remove_dir_all(&dir).unwrap();
            let all = text(&out);
            assert!(out.status.success(), "{all}");
            for expected in [
                "child-process 367",   // ERROR_CHILD_PROCESS_BLOCKED
                "win32k 1114",         // ERROR_DLL_INIT_FAILED
                "unsigned-image 577",  // ERROR_INVALID_IMAGE_HASH
                "low-label-image 5",   // ERROR_ACCESS_DENIED
                "CHILD-OK",
            ] {
                assert!(all.lines().any(|l| l == expected), "{expected}: {all}");
            }
        }

        #[test]
        #[ignore = "run by test_denied_operations_fail_closed in a separate process"]
        fn fail_closed_child() {
            use std::os::windows::ffi::OsStrExt;
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn LoadLibraryW(path: *const u16) -> *mut c_void;
                fn GetLastError() -> u32;
            }
            let load = |path: &std::ffi::OsStr| {
                let wide: Vec<u16> = path.encode_wide().chain(Some(0)).collect();
                // SAFETY: a NUL-terminated path.
                let h = unsafe { LoadLibraryW(wide.as_ptr()) };
                // SAFETY: plain call.
                if h.is_null() { unsafe { GetLastError() } } else { 0 }
            };
            sandboxed();
            narrow().unwrap();
            let e = Command::new("cmd.exe").args(["/c", "exit"]).status().unwrap_err();
            println!("child-process {}", e.raw_os_error().unwrap_or(0));
            println!("win32k {}", load("user32.dll".as_ref()));
            println!("unsigned-image {}", load(&std::env::var_os("WICK_TEST_UNSIGNED").unwrap()));
            println!("low-label-image {}", load(&std::env::var_os("WICK_TEST_LOW").unwrap()));
            println!("CHILD-OK");
        }
    }
}
