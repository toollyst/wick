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
    FILES_ANYWHERE, Limit, MACH_TRAPS, MACH_TRAPS_IF_DEFINED, MIG_ROUTINES, PROFILE,
    RUN_DENIED_OPERATIONS, SYSCALLS, UNFILTERED_SYSCALLS, api_profile, apply, apply_api,
    denied_syscall, files_in_jail, narrow, prepare, profile, profile_for, select, selected,
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
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{Policy, SandboxError};

    /// Seatbelt profile installed by default on macOS, after the file rule
    /// ([`FILES_ANYWHERE`], or [`files_in_jail`] when the jailer started
    /// Firecracker).
    pub const PROFILE: &str = r#"(version 1)
; Whatever no rule below allows raises SIGSYS, on which Firecracker exits as
; for a seccomp violation, except what DENIED_WITH_ERROR lists (default_rule).
(deny default)
; Unix sockets only: API server, vsock backends, console. Binding one is
; setup's (RUN_DENIED_OPERATIONS), as on Linux the VMM thread's filter has no
; bind.
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
; signal to another process raises SIGSYS (the default rule), as kill is in
; none of upstream's filters.
(allow signal (target self))
(deny process-info*)
(allow process-info* (target self))
; No code mapped in: upstream's filters trap mmap and mprotect asking for
; PROT_EXEC. A file mapped executable and a MAP_JIT mapping raise SIGSYS here
; (without the explicit rule Seatbelt lets a file under /usr/lib be mapped
; executable); an anonymous mapping is the compatibility libc's check
; (libc::wick_mm), turned on by narrow().
(deny file-map-executable (with send-signal SIGSYS))
(deny dynamic-code-generation (with send-signal SIGSYS))
; System calls: only those in SYSCALLS, Mach traps: only those in MACH_TRAPS,
; kernel MIG routines: only those in MIG_ROUTINES. Any other one fails and
; raises SIGSYS, on which Firecracker exits as for a seccomp violation
; (upstream's filters trap, and its SIGSYS handler exits with the bad-syscall
; code).
(deny syscall-unix (with send-signal SIGSYS))
(deny syscall-mach (with send-signal SIGSYS))
(deny syscall-mig (with send-signal SIGSYS))
; Two phases, as upstream's filters have: setup, until the microVM is built
; (on Linux the VMM thread runs unfiltered until then), and run. What only
; setup needs is allowed until the process holds the narrowed extension,
; which narrow() takes. Then it cannot be undone: no extension can be issued,
; and the Sandbox call that takes one (mac-syscall 6) and every other
; mac-syscall raise SIGSYS; none releases one.
(deny generic-issue-extension)
(deny system-mac-syscall (with send-signal SIGSYS))
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
    /// a rule allows the operation they make; for those, that table names the
    /// rule that decides each one.
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
        // getrandom, clock_gettime, gettid.
        "getentropy", "gettimeofday", "thread_selfid",
        // rt_sigaction, rt_sigprocmask, rt_sigreturn, sigaltstack, tkill.
        "sigaction", "sigprocmask", "__pthread_sigmask", "sigreturn", "sigaltstack",
        "__pthread_kill",
        // exit, exit_group: a thread's exit, a worker thread parking, a panic.
        "exit", "bsdthread_terminate", "__disable_threadsignal", "workq_open", "workq_kernreturn",
        "abort_with_payload", "os_fault_with_payload",
    ];

    /// What decides a system call of [`UNFILTERED_SYSCALLS`] in this
    /// profile, after [`narrow`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Limit {
        /// No rule allows the operation the call makes, so the rule on its
        /// number decides: it is in none of the lists, and raises SIGSYS.
        Number,
        /// The rule of this operation (or these, space separated): a call
        /// it denies raises SIGSYS.
        Signal(&'static str),
        /// The rule of this operation: a call it denies fails with `EPERM`,
        /// as a path outside the chroot or another process's `/proc` entry
        /// does on Linux.
        Error(&'static str),
        /// No rule allows what it asks for, and the default rule raises
        /// SIGSYS; no single operation's rule lifts it (measured for `link`:
        /// with files, and every other class of operation, allowed, it still
        /// raises SIGSYS; only `(allow default)` lets it run).
        Default,
        /// Allowed after narrowing, as the rule of upstream's filters named
        /// allows it, with no argument checked there (descriptors are opened
        /// under the file rule).
        Upstream(&'static str),
        /// Nothing in Seatbelt decides it, for the reason given: the call
        /// runs (or the kernel itself refuses it, as said).
        Impossible(&'static str),
    }

    /// The system calls whose number Seatbelt does not check when a rule
    /// allows the operation they make (measured on macOS 27: under
    /// `(allow default)` each one runs with a rule denying its number,
    /// `test_seatbelt_skips_the_number_of_these`), with the rule of this
    /// profile that decides each one after [`narrow`]
    /// (`test_unfiltered_syscalls_are_limited_by_their_rule`). For the others
    /// the rule on the number decides ([`SYSCALLS`]).
    #[rustfmt::skip]
    pub const UNFILTERED_SYSCALLS: &[(&str, u16, Limit)] = &[
        ("exit", 1, Limit::Upstream("exit")),
        ("fork", 2, Limit::Signal("process-fork")),
        ("write", 4, Limit::Upstream("write")),
        ("open", 5, Limit::Error("file-read* file-write*")),
        ("close", 6, Limit::Upstream("close")),
        ("link", 9, Limit::Default),
        ("unlink", 10, Limit::Signal("file-write-unlink")),
        ("mknod", 14, Limit::Number),
        ("chmod", 15, Limit::Signal("file-write-mode")),
        ("chown", 16, Limit::Signal("file-write-owner")),
        ("getpid", 20, Limit::Impossible(NO_OPERATION)),
        ("getuid", 24, Limit::Impossible(NO_OPERATION)),
        ("ptrace", 26, Limit::Signal("system-debug")),
        ("chflags", 34, Limit::Signal("file-write-flags")),
        ("fchflags", 35, Limit::Signal("file-write-flags")),
        ("kill", 37, Limit::Signal("signal")),
        ("getgid", 47, Limit::Impossible(NO_OPERATION)),
        ("acct", 51, Limit::Signal("system-acct")),
        ("ioctl", 54, Limit::Signal("file-ioctl")),
        ("reboot", 55, Limit::Signal("system-reboot")),
        ("revoke", 56, Limit::Signal("file-revoke")),
        ("umask", 60, Limit::Impossible(NO_OPERATION)),
        ("chroot", 61, Limit::Signal("file-chroot")),
        ("swapon", 85, Limit::Signal("system-swap")),
        ("setpriority", 96, Limit::Signal("system-sched")),
        ("socket", 97, Limit::Signal("system-socket")),
        ("connect", 98, Limit::Signal("network-outbound")),
        ("getpriority", 100, Limit::Signal("system-sched")),
        ("bind", 104, Limit::Signal("network-bind")),
        ("writev", 121, Limit::Upstream("writev")),
        ("fchown", 123, Limit::Signal("file-write-owner")),
        ("fchmod", 124, Limit::Signal("file-write-mode")),
        ("utimes", 138, Limit::Signal("file-write-times")),
        ("futimes", 139, Limit::Signal("file-write-times")),
        ("pwrite", 154, Limit::Upstream("write")),
        ("nfssvc", 155, Limit::Signal("system-nfssvc")),
        ("unmount", 159, Limit::Signal("file-unmount")),
        ("quotactl", 165, Limit::Impossible(QUOTAS)),
        ("mount", 167, Limit::Signal("file-mount")),
        ("csops", 169, Limit::Signal("process-codesigning*")),
        ("csops_audittoken", 170, Limit::Signal("process-codesigning*")),
        ("sysctl", 202, Limit::Signal("sysctl-read")),
        ("undelete", 205, Limit::Impossible(WHITEOUTS)),
        ("getumask", 215, Limit::Impossible(NO_OPERATION)),
        ("searchfs", 225, Limit::Signal("file-search")),
        ("setxattr", 236, Limit::Signal("file-write-xattr")),
        ("fsetxattr", 237, Limit::Signal("file-write-xattr")),
        ("removexattr", 238, Limit::Signal("file-write-xattr")),
        ("fremovexattr", 239, Limit::Signal("file-write-xattr")),
        ("fsctl", 242, Limit::Signal("system-fsctl file-fsctl")),
        ("ffsctl", 245, Limit::Signal("system-fsctl file-fsctl")),
        ("semctl", 254, Limit::Signal("ipc-sysv*")),
        ("semget", 255, Limit::Signal("ipc-sysv*")),
        ("semop", 256, Limit::Signal("ipc-sysv*")),
        ("msgctl", 258, Limit::Signal("ipc-sysv*")),
        ("msgget", 259, Limit::Signal("ipc-sysv*")),
        ("msgsnd", 260, Limit::Signal("ipc-sysv*")),
        ("msgrcv", 261, Limit::Signal("ipc-sysv*")),
        ("shmat", 262, Limit::Signal("ipc-sysv*")),
        ("shmctl", 263, Limit::Signal("ipc-sysv*")),
        ("shmdt", 264, Limit::Signal("ipc-sysv*")),
        ("shmget", 265, Limit::Signal("ipc-sysv*")),
        ("shm_open", 266, Limit::Signal("ipc-posix-shm*")),
        ("shm_unlink", 267, Limit::Signal("ipc-posix-shm*")),
        ("sem_open", 268, Limit::Signal("ipc-posix-sem*")),
        ("sem_close", 269, Limit::Number),
        ("sem_unlink", 270, Limit::Signal("ipc-posix-sem*")),
        ("sem_wait", 271, Limit::Number),
        ("sem_trywait", 272, Limit::Number),
        ("sem_post", 273, Limit::Number),
        ("sysctlbyname", 274, Limit::Signal("sysctl-read")),
        ("chmod_extended", 282, Limit::Signal("file-write-mode file-write-acl")),
        ("fchmod_extended", 283, Limit::Signal("file-write-mode file-write-acl")),
        ("issetugid", 327, Limit::Impossible(NO_OPERATION)),
        ("__pthread_kill", 328, Limit::Upstream("tkill")),
        ("proc_info", 336, Limit::Error("process-info*")),
        ("lchown", 364, Limit::Signal("file-write-owner")),
        ("write_nocancel", 397, Limit::Upstream("write")),
        ("open_nocancel", 398, Limit::Error("file-read* file-write*")),
        ("close_nocancel", 399, Limit::Upstream("close")),
        ("connect_nocancel", 409, Limit::Signal("network-outbound")),
        ("writev_nocancel", 412, Limit::Upstream("writev")),
        ("pwrite_nocancel", 415, Limit::Upstream("write")),
        ("msgsnd_nocancel", 418, Limit::Signal("ipc-sysv*")),
        ("msgrcv_nocancel", 419, Limit::Signal("ipc-sysv*")),
        ("sem_wait_nocancel", 420, Limit::Number),
        ("pid_suspend", 433, Limit::Signal("system-suspend-resume")),
        ("pid_resume", 434, Limit::Signal("system-suspend-resume")),
        ("connectx", 447, Limit::Signal("network-outbound")),
        ("clonefileat", 462, Limit::Signal("file-clone")),
        ("openat", 463, Limit::Error("file-read* file-write*")),
        ("openat_nocancel", 464, Limit::Error("file-read* file-write*")),
        ("fchmodat", 467, Limit::Signal("file-write-mode")),
        ("fchownat", 468, Limit::Signal("file-write-owner")),
        ("linkat", 471, Limit::Default),
        ("unlinkat", 472, Limit::Signal("file-write-unlink")),
        ("fclonefileat", 517, Limit::Signal("file-clone")),
        ("fs_snapshot", 518, Limit::Signal("fs-snapshot*")),
        ("terminate_with_payload", 520, Limit::Signal("signal")),
        ("abort_with_payload", 521, Limit::Upstream("exit_group")),
        ("fmount", 526, Limit::Signal("file-mount")),
        ("pwritev", 541, Limit::Upstream("writev")),
        ("pwritev_nocancel", 543, Limit::Upstream("writev")),
        ("proc_info_extended_id", 545, Limit::Error("process-info*")),
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
        "getpid", "getuid", "geteuid", "access", "dup", "pipe", "getegid", "dup2", "bind",
        "listen", "getrusage", "socketpair", "csops", "csops_audittoken",
        "kdebug_typefilter", "kdebug_trace_string", "kdebug_trace64", "getrlimit", "sysctl",
        "getattrlist", "shm_open", "shm_unlink", "gettid", "issetugid", "proc_info",
        "getdirentries64", "bsdthread_create", "kqueue", "sigsuspend_nocancel", "fileport_makefd",
        // vmnet.framework's XPC connection reads the process's persona once
        // the process forked (the API process, ext::api_process): measured,
        // syscall-unix 494 in the sandbox's report.
        "persona",
        // The Sandbox call narrow() takes the narrowed extension with
        // (PROFILE's system-mac-syscall rules).
        "__mac_syscall",
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

    /// MIG routines allowed until [`narrow`] only, in addition to
    /// [`MIG_ROUTINES`].
    pub const SETUP_MIG_ROUTINES: &[&str] = &[
        "host_get_clock_service", "_mach_make_memory_entry", "mach_memory_entry_ownership",
        "mach_vm_copy", "mach_vm_reallocate", "vm_reallocate", "host_info", "task_info_from_user",
        "mach_port_set_attributes", "mach_port_request_notification",
        "mach_port_get_context_from_user", "task_restartable_ranges_register",
        "mach_voucher_attr_command",
    ];

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
(deny file-map-executable (with send-signal SIGSYS))
(deny dynamic-code-generation (with send-signal SIGSYS))
(deny syscall-unix (with send-signal SIGSYS))
(deny syscall-mach (with send-signal SIGSYS))
(deny syscall-mig (with send-signal SIGSYS))
(deny generic-issue-extension)
(deny system-mac-syscall (with send-signal SIGSYS))
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
        rule.push_str(&fcntl_rule("", API_FCNTL_COMMANDS));
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
        INSTALLED.store(true, Ordering::Relaxed);
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

    /// File rule in a jail: only the jail directory, by its path outside the
    /// chroot (Seatbelt matches the real path of a file, and the chroot
    /// already hides everything else; this also covers descriptors opened
    /// before the chroot).
    ///
    /// With the jail's network (`netns`, `--netns`): also the Unix sockets
    /// in that directory and nothing else there, as on Linux a network
    /// namespace gives its interfaces and no file. The directory is reached
    /// through a descriptor opened before the chroot, from which a relative
    /// path could climb out (`..`), so Unix sockets are then connected to
    /// only in the jail and in the network: file rules do not cover
    /// `connect` or `sendto` (measured: both reach a socket elsewhere with
    /// only the file rules), `network-outbound` does.
    pub fn files_in_jail(root: &Path, netns: Option<&Path>) -> Result<String, SandboxError> {
        let root = quoted(root, "jail")?;
        let mut rule = format!("(allow file-read* file-write* (subpath \"{root}\"))\n");
        if let Some(netns) = netns {
            let netns = quoted(netns, "network")?;
            rule.push_str(&format!(
                "(allow file-read* file-write* (require-all (subpath \"{netns}\") (vnode-type SOCKET)))\n\
                 (deny network-outbound (remote unix-socket))\n\
                 (allow network-outbound (remote unix-socket (subpath \"{root}\")) \
                 (remote unix-socket (subpath \"{netns}\")))\n"
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
            "{profile}{}{}{}{files}{}{}",
            shm_rule(std::process::id()),
            syscall_rule(),
            operation_rule(),
            run_rule(),
            unlink_rule(root, netns, std::process::id())?
        ))
    }

    /// The POSIX shared memory objects of the process `pid`: the names the
    /// compatibility memfd gives them (`/fcm.<pid>.<n>`, and
    /// `/fcmH.<pid>.<n>` for a huge page one, `libc::HUGE_MEMFD_PREFIX`;
    /// made and unlinked at once). Another name fails and raises SIGSYS (the
    /// default rule): on Linux a memfd has no name another process could
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
    /// same operation, `file-write-unlink`), after [`narrow`]: an eventfd's
    /// FIFO, which vmm-sys-util names `.eventfd-<pid>-<n>` in the temporary
    /// directory and removes once open (an eventfd made when the guest
    /// activates a device), and the sockets of the network endpoints
    /// (`platform::net`, which removes its own when the device goes). Any
    /// other name raises SIGSYS, as on Linux upstream's filters have no
    /// `unlink`: Linux's eventfd and tap have no name. The file rule's other
    /// operations are unchanged. Seatbelt matches the real path, so the
    /// directories are given by theirs: in a jail (`root`), its `/tmp`
    /// (the jailer's `TMPDIR`) and the jail and its network `netns`, by
    /// their paths outside it; outside a jail, the temporary directory and
    /// `firecracker-net` in the user's temporary directory.
    ///
    /// Memfds take no name a microVM removes: their shared memory objects
    /// are `shm_rule`'s (`shm_unlink` is decided by `ipc-posix-shm*`), and
    /// the compatibility libc's `memfd_create`, which makes a file, is not
    /// called by Firecracker.
    #[allow(unexpected_cfgs)]
    fn unlink_rule(root: Option<&Path>, netns: Option<&Path>, pid: u32) -> Result<String, SandboxError> {
        let tmp = std::env::temp_dir();
        let fail = |what: &str, path: &Path, err: std::io::Error| {
            SandboxError::Install(format!("{what} {path:?}: {err}"))
        };
        let (tmp, sockets) = match root {
            Some(root) => {
                let inside = tmp
                    .strip_prefix("/")
                    .map_err(|_| SandboxError::Install(format!("temporary directory {tmp:?}")))?;
                (root.join(inside), [Some(root.to_owned()), netns.map(Path::to_owned)])
            }
            None => {
                let dir = crate::platform::net::user_endpoint_dir()
                    .map_err(|err| SandboxError::Install(format!("network endpoint directory: {err}")))?;
                // The directory itself may not exist yet; its parent does.
                let parent = dir.parent().unwrap_or(&dir);
                let parent = parent.canonicalize().map_err(|err| fail("directory", parent, err))?;
                let tmp = tmp.canonicalize().map_err(|err| fail("temporary directory", &tmp, err))?;
                (tmp, [Some(parent.join("firecracker-net")), None])
            }
        };
        let narrowed = format!("(extension \"{}\")", NARROWED.to_str().unwrap());
        let fifo = quoted(&tmp.join(format!("{}{pid}-", vmm_sys_util::eventfd::FIFO_PREFIX)), "FIFO")?;
        let mut rule = format!("(deny file-write-unlink {narrowed} (with send-signal SIGSYS))\n");
        // Discovery build: allowed and reported instead.
        #[cfg(wick_sandbox_discovery)]
        rule.push_str(&format!("(allow file-write-unlink {narrowed} (with report))\n"));
        rule.push_str(&format!(
            "(allow file-write-unlink (require-all {narrowed} (vnode-type FIFO) (prefix \"{fifo}\")))\n"
        ));
        for dir in sockets.iter().flatten() {
            rule.push_str(&format!(
                "(allow file-write-unlink (require-all {narrowed} (vnode-type SOCKET) (subpath \"{}\")))\n",
                quoted(dir, "network endpoint directory")?
            ));
        }
        Ok(rule)
    }

    /// Operations a running microVM may not ask for, after the file rule
    /// (which allows them on the files it covers until [`narrow`]):
    /// changing a file's mode, owner, flags, times, extended attributes or
    /// ACL, and cloning one. They raise SIGSYS, as `chmod`, `fchmod`,
    /// `chown`, `utimensat`, `setxattr` and `copy_file_range` are in none
    /// of upstream's filters. And binding a Unix socket, which the
    /// `network-inbound` rule allows until then (it decides a bind no
    /// `network-bind` rule matches; this one, for the same operation and
    /// with a filter, is the more specific, measured): as Linux's VMM filter
    /// has no `bind`, every socket Firecracker binds (network endpoints, the
    /// vsock device's) is bound while the microVM is built or restored.
    /// Seatbelt decides their system calls by these operations, not by
    /// number ([`UNFILTERED_SYSCALLS`]).
    pub const RUN_DENIED_OPERATIONS: &[&str] = &[
        "file-write-mode", "file-write-owner", "file-write-flags", "file-write-times",
        "file-write-xattr", "file-write-acl", "file-write-setugid", "file-clone",
        "network-bind",
    ];

    /// The `fcntl` commands a running microVM may use (`F_<name>`,
    /// <sys/fcntl.h>), each line for the rule of upstream's filters in its
    /// comment, measured as [`SYSCALLS`] are. Any other command raises
    /// SIGSYS after [`narrow`] (Seatbelt's `system-fcntl`, which checks
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
    ];

    /// The API process's `fcntl` commands: upstream's `api` filter allows
    /// `F_SETFD`.
    pub const API_FCNTL_COMMANDS: &[&str] = &["F_GETFD", "F_SETFD"];

    /// `(allow system-fcntl ...)` for `commands` after a deny with SIGSYS
    /// under `condition` (none: always).
    #[allow(unexpected_cfgs)]
    fn fcntl_rule(condition: &str, commands: &[&str]) -> String {
        let mut rule = if condition.is_empty() {
            "(deny system-fcntl (with send-signal SIGSYS))\n".to_owned()
        } else {
            format!("(deny system-fcntl {condition} (with send-signal SIGSYS))\n")
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
    /// outside [`FCNTL_COMMANDS`] raise SIGSYS once the process holds the
    /// narrowed extension.
    #[allow(unexpected_cfgs)]
    fn run_rule() -> String {
        let narrowed = format!("(extension \"{}\")", NARROWED.to_str().unwrap());
        let mut rule = format!(
            "(deny {} {narrowed} (with send-signal SIGSYS))\n",
            RUN_DENIED_OPERATIONS.join(" ")
        );
        // Discovery build: allowed and reported instead.
        #[cfg(wick_sandbox_discovery)]
        rule.push_str(&format!(
            "(allow {} {narrowed} (with report))\n",
            RUN_DENIED_OPERATIONS.join(" ")
        ));
        rule.push_str(&fcntl_rule(&narrowed, FCNTL_COMMANDS));
        rule
    }

    /// What a denied operation does: on Linux a system call outside a
    /// thread's filter traps, so here an operation no rule allows raises
    /// SIGSYS. Except for files, which fail with an error, as on Linux a path
    /// outside the chroot does, and what [`DENIED_WITH_ERROR`] lists.
    #[allow(unexpected_cfgs)]
    fn default_rule() -> String {
        let mut rule = String::from("(deny default (with send-signal SIGSYS))\n(deny file-read* file-write*)\n");
        for (op, why) in DENIED_WITH_ERROR {
            rule.push_str(&format!("; {why}\n(deny {op})\n"));
        }
        // Discovery build: every operation no rule allows is allowed and
        // reported instead.
        #[cfg(wick_sandbox_discovery)]
        rule.push_str("(allow default (with report))\n(deny file-read* file-write*)\n");
        rule
    }

    /// Operations denied with an error rather than SIGSYS: ones the system
    /// libraries make and handle failing, that Firecracker never asks for.
    pub const DENIED_WITH_ERROR: &[(&str, &str)] = &[
        (
            "mach-priv-host-port",
            "libsandbox asks for the host's privileged port right after sandbox_init.",
        ),
        (
            "system-info (info-type \"vfs.disk-space\")",
            "fstatfs (fallocate's hole punching, for the block size) then reports no exact free space.",
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
    fn allow(op: &str, condition: &str, filter: &str, prefix: &str, names: &[&str]) -> String {
        if names.is_empty() {
            return String::new();
        }
        let mut list = format!("({filter}");
        for name in names {
            list.push(' ');
            list.push_str(prefix);
            list.push_str(name);
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
        for name in MACH_TRAPS_IF_DEFINED {
            rule.push_str(&format!(
                "(when (defined? 'MSC_{name}) (allow syscall-mach (machtrap-number MSC_{name})))\n"
            ));
        }
        rule
    }

    /// The discovery build's rule (`tools/macos/sandbox-discovery.sh`, never
    /// released): after narrow(), a call outside the run phase's lists is
    /// allowed and reported instead of raising SIGSYS, so that one run of the
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

    /// Set once the sandbox is installed, for [`denied_syscall`].
    static INSTALLED: AtomicBool = AtomicBool::new(false);

    /// Whether a SIGSYS is the sandbox denying a system call: the sandbox
    /// signals the process itself, with no code (and does not say which
    /// call). Async-signal-safe.
    ///
    /// # Safety
    /// `info` is the siginfo the kernel passed to a SIGSYS handler.
    pub unsafe fn denied_syscall(si_code: libc::c_int, info: *mut libc::siginfo_t) -> bool {
        if !INSTALLED.load(Ordering::Relaxed) || si_code != 0 || info.is_null() {
            return false;
        }
        // SAFETY: the caller passes the handler's siginfo; getpid has no
        // arguments.
        unsafe { (*info).si_pid == libc::getpid() }
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
        INSTALLED.store(true, Ordering::Relaxed);
        state.narrowed = Some(narrowed);
        Ok(())
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

    /// Raises SIGSYS on this thread for an `mmap` or `mprotect` asking for
    /// `PROT_EXEC` after [`narrow`], or the API process's `madvise` with
    /// advice other than `MADV_DONTNEED`, as a seccomp trap does: the signal is
    /// the one Seatbelt sends (no code, this process), so upstream's handler
    /// exits with the bad-syscall code ([`denied_syscall`]). If the signal is
    /// blocked or ignored, the default action, as the kernel forces a seccomp
    /// trap's SIGSYS.
    extern "C" fn exec_denied(_prot: libc::c_int) {
        // SAFETY: plain calls on this thread, with a valid signal set.
        unsafe {
            libc::pthread_kill(libc::pthread_self(), libc::SIGSYS);
            libc::signal(libc::SIGSYS, libc::SIG_DFL);
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGSYS);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            libc::pthread_kill(libc::pthread_self(), libc::SIGSYS);
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

        // The sandbox is permanent, so it is tested in a child process
        // (the test binary itself, filtered to the child test below).
        fn child(name: &str, env: &[(&str, &str)]) -> std::process::Output {
            let exe = std::env::current_exe().unwrap();
            Command::new(exe)
                .args([
                    "--exact",
                    &format!("ext::sandbox::macos::tests::{name}"),
                    "--ignored",
                    "--nocapture",
                ])
                .envs(env.iter().copied())
                .output()
                .unwrap()
        }

        fn run_child(name: &str, env: &[(&str, &str)]) {
            let out = child(name, env);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success(),
                "{stdout}\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(stdout.contains("CHILD-OK"), "{stdout}");
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

        // A system call outside SYSCALLS raises SIGSYS, as a seccomp filter's
        // trap does (the test binary has no handler, so it dies of it).
        #[test]
        fn test_unlisted_syscalls_raise_sigsys() {
            use std::os::unix::process::ExitStatusExt;
            for name in [
                "exec_child", "unlisted_child", "unlisted_trap_child", "unlisted_mig_child", "tcp_child",
                "udp_child", "listen_after_narrow_child",
            ] {
                let out = child(name, &[]);
                assert_eq!(
                    out.status.signal(),
                    Some(libc::SIGSYS),
                    "{name}: {:?}\n{}",
                    out.status,
                    String::from_utf8_lossy(&out.stdout)
                );
                assert!(!String::from_utf8_lossy(&out.stdout).contains("CHILD-SURVIVED"));
            }
        }

        // With upstream's signal handlers, a denied call ends Firecracker as a
        // seccomp violation does: the bad-syscall exit code.
        #[test]
        fn test_denied_syscall_exits_as_seccomp() {
            let out = child("handled_child", &[]);
            assert_eq!(
                out.status.code(),
                Some(crate::FcExitCode::BadSyscall as i32),
                "{:?}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stdout)
            );
        }

        // Before narrow(), what building the microVM takes is allowed; after
        // it, only the run phase's lists: a call of the setup phase raises
        // SIGSYS, as one outside the VMM thread's filter does on Linux.
        #[test]
        fn test_narrow_ends_the_setup_phase() {
            use std::os::unix::process::ExitStatusExt;
            let out = child("narrowed_child", &[]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("SETUP-OK"), "{stdout}");
            assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{:?}\n{stdout}", out.status);
            assert!(!stdout.contains("CHILD-SURVIVED"), "{stdout}");
        }

        // narrow() cannot be undone: after it, no extension can be issued or
        // taken (each raises SIGSYS), and a thread cannot be created (Linux's
        // VMM filter has no clone).
        #[test]
        fn test_narrowing_is_one_way() {
            use std::os::unix::process::ExitStatusExt;
            for case in ["issue", "consume", "thread"] {
                let out = child("one_way_child", &[("WICK_TEST_CASE", case)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(stdout.contains("NARROWED"), "{case}: {stdout}");
                assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{case}: {:?}\n{stdout}", out.status);
                assert!(!stdout.contains("CHILD-SURVIVED"), "{case}: {stdout}");
            }
        }

        #[test]
        #[ignore = "run by test_narrow_ends_the_setup_phase in a separate process"]
        fn narrowed_child() {
            select(Policy::Default);
            apply().unwrap();
            // SAFETY: dup of the standard output, closed again.
            let fd = unsafe { libc::dup(1) };
            assert!(fd >= 0);
            // SAFETY: the descriptor just created.
            unsafe { libc::close(fd) };
            println!("SETUP-OK");
            narrow().unwrap();
            // A second call does nothing.
            narrow().unwrap();
            // SAFETY: as above.
            unsafe { libc::dup(1) };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // The API process's profile (ext::api_process) allows what an HTTP
        // server on an open socket needs, as upstream's api filter: a call
        // outside API_SYSCALLS, shared memory, an executable mapping, madvise
        // with advice other than MADV_DONTNEED and an fcntl command other
        // than F_GETFD and F_SETFD raise SIGSYS; a file fails with an error,
        // as outside the chroot.
        #[test]
        fn test_api_profile_raises_sigsys_outside_its_list() {
            use std::os::unix::process::ExitStatusExt;
            for case in ["dup", "shm", "exec", "socketpair", "madvise", "dontneed", "fcntl"] {
                let out = child("api_child", &[("WICK_TEST_CASE", case)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(stdout.contains("SETUP-OK"), "{case}: {stdout}");
                assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{case}: {:?}\n{stdout}", out.status);
                assert!(!stdout.contains("CHILD-SURVIVED"), "{case}: {stdout}");
            }
            let out = child("api_child", &[("WICK_TEST_CASE", "allowed")]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success() && stdout.contains("CHILD-OK"), "{:?}\n{stdout}", out.status);
        }

        #[test]
        #[ignore = "run by test_api_profile_raises_sigsys_outside_its_list in a separate process"]
        fn api_child() {
            use std::io::{Read, Write};
            let case = std::env::var("WICK_TEST_CASE").unwrap();
            let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
            select(Policy::Default);
            apply_api().unwrap();
            // What the API process does: Unix socket I/O, memory, time,
            // randomness, threads' locks.
            a.write_all(b"ping").unwrap();
            let mut buf = [0u8; 4];
            b.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            let v: Vec<u8> = vec![7; 1 << 20];
            assert_eq!(v.iter().map(|&x| u64::from(x)).sum::<u64>(), 7 << 20);
            let _ = std::time::SystemTime::now();
            let mut entropy = [0u8; 16];
            // SAFETY: a 16-byte output buffer.
            assert_eq!(unsafe { libc::getentropy(entropy.as_mut_ptr().cast(), 16) }, 0);
            // Files fail with an error.
            std::fs::File::open("/etc/hosts").unwrap_err();
            // Upstream's api filter: fcntl F_SETFD. (Its madvise with
            // MADV_DONTNEED reads the region first with a Mach message here,
            // which the API process's lists do not allow.)
            const PAGE: usize = 16384;
            // SAFETY: a new anonymous mapping.
            let page = unsafe {
                libc::mmap(std::ptr::null_mut(), PAGE, libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0)
            };
            assert_ne!(page, libc::MAP_FAILED);
            // SAFETY: a descriptor of this process.
            assert_eq!(unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&a), libc::F_SETFD, libc::FD_CLOEXEC) }, 0);
            println!("SETUP-OK");
            std::io::stdout().flush().unwrap();
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
        fn test_executable_mappings_raise_sigsys() {
            use std::os::unix::process::ExitStatusExt;
            for case in ["file", "jit", "mmap", "mprotect", "blocked"] {
                let out = child("exec_map_child", &[("WICK_TEST_CASE", case)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert!(stdout.contains("SETUP-OK"), "{case}: {stdout}");
                assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{case}: {:?}\n{stdout}", out.status);
                assert!(!stdout.contains("CHILD-SURVIVED"), "{case}: {stdout}");
            }
        }

        #[test]
        #[ignore = "run by test_executable_mappings_raise_sigsys in a separate process"]
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
                other => panic!("{other}"),
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        #[test]
        #[ignore = "run by test_denied_syscall_exits_as_seccomp in a separate process"]
        fn handled_child() {
            crate::signal_handler::register_signal_handlers().unwrap();
            select(Policy::Default);
            apply().unwrap();
            // SAFETY: no arguments.
            unsafe { libc::getppid() };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        #[test]
        fn test_syscall_names_are_known() {
            // The profile compiles only if Seatbelt knows every name; an
            // unknown one fails `sandbox_compile_string`, which test_sandbox_restricts_child
            // would show. Here: no duplicates, and the calls Firecracker cannot
            // run without are in.
            let mut names = [SYSCALLS, SETUP_SYSCALLS].concat();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), SYSCALLS.len() + SETUP_SYSCALLS.len());
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
        #[ignore = "run by test_unlisted_syscalls_raise_sigsys in a separate process"]
        fn exec_child() {
            select(Policy::Default);
            apply().unwrap();
            let _ = std::process::Command::new("/bin/echo").output();
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // An IP socket is made after narrow() (Seatbelt checks no family when
        // a socket is made: socket is decided by system-socket, which covers
        // other families), and connecting it raises SIGSYS.
        #[test]
        fn test_ip_sockets_are_made_but_not_used() {
            use std::os::unix::process::ExitStatusExt;
            let out = child("ip_socket_child", &[]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("MADE"), "{stdout}");
            assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{:?}\n{stdout}", out.status);
            assert!(!stdout.contains("CHILD-SURVIVED"), "{stdout}");
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

        // IP networking: on Linux socket(AF_INET) is outside every filter.
        #[test]
        #[ignore = "run by test_unlisted_syscalls_raise_sigsys in a separate process"]
        fn tcp_child() {
            select(Policy::Default);
            apply().unwrap();
            let _ = std::net::TcpStream::connect("127.0.0.1:9");
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        #[test]
        #[ignore = "run by test_unlisted_syscalls_raise_sigsys in a separate process"]
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
        // (TIOCSTI), raises SIGSYS, as an ioctl outside the filter's requests
        // does on Linux.
        #[test]
        fn test_run_phase_ioctls_and_holes() {
            run_child("run_phase_child", &[]);
            use std::os::unix::process::ExitStatusExt;
            let out = child("other_ioctl_child", &[]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("NARROWED"), "{stdout}");
            assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{:?}\n{stdout}", out.status);
        }

        // Shared memory after narrow(): the memfds this process makes, an
        // ordinary one and a 2 MiB huge page one (guest memory for a
        // vhost-user device on huge pages), are created; a name of another
        // process raises SIGSYS.
        #[test]
        fn test_own_memfds_are_made_after_narrow() {
            use std::os::unix::process::ExitStatusExt;
            let out = child("memfd_child", &[]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("MEMFDS-OK"), "{stdout}");
            assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{:?}\n{stdout}", out.status);
            assert!(!stdout.contains("CHILD-SURVIVED"), "{stdout}");
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
            // Another process's memfd name: the default rule, SIGSYS.
            let other = std::ffi::CString::new(format!("{}1.0", libc::HUGE_MEMFD_PREFIX)).unwrap();
            // SAFETY: a plain call.
            unsafe { libc::shm_open(other.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // fcntl: after narrow(), the commands of FCNTL_COMMANDS run and any
        // other one raises SIGSYS, as upstream's fcntl rules trap every
        // command but F_SETFD and F_ADD_SEALS (Seatbelt's system-fcntl,
        // which checks every command).
        #[test]
        fn test_fcntl_commands_outside_the_list_raise_sigsys() {
            use std::os::unix::process::ExitStatusExt;
            let out = child("fcntl_child", &[]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains("LISTED-OK"), "{stdout}");
            assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{:?}\n{stdout}", out.status);
            assert!(!stdout.contains("CHILD-SURVIVED"), "{stdout}");
        }

        #[test]
        #[ignore = "run by test_fcntl_commands_outside_the_list_raise_sigsys in a separate process"]
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

        /// A pseudo-terminal's controller, opened before the sandbox.
        fn pty() -> libc::c_int {
            // SAFETY: plain calls on a descriptor this function opens.
            unsafe {
                let fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
                assert!(fd >= 0);
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
        // service lookup succeeds before narrow() and raises SIGSYS after
        // it; no other service is looked up in either phase.
        #[test]
        fn test_vmnet_lookup_is_setups_only() {
            use std::os::unix::process::ExitStatusExt;
            for case in ["vmnet", "other"] {
                let out = child("lookup_child", &[("WICK_TEST_CASE", case)]);
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert_eq!(stdout.contains("SETUP-LOOKUP-OK"), case == "vmnet", "{case}: {stdout}");
                assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{case}: {:?}\n{stdout}", out.status);
                assert!(!stdout.contains("CHILD-SURVIVED"), "{case}: {stdout}");
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

        // Listening on a Unix socket is setup's only: Linux's VMM filter has
        // no bind or listen. A socket bound before narrow() (its name gone)
        // cannot listen after it.
        #[test]
        #[ignore = "run by test_unlisted_syscalls_raise_sigsys in a separate process"]
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

        // Binding a Unix socket is setup's only, as Linux's VMM filter has no
        // bind: a datagram endpoint and a stream socket bind before narrow(),
        // and after it binding either raises SIGSYS (RUN_DENIED_OPERATIONS),
        // in a jail's network too.
        #[test]
        fn test_unix_bind_is_setups_only() {
            use std::os::unix::process::ExitStatusExt;
            let base = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("wick-bind-{}", std::process::id()));
            let (jail, net) = (base.join("jail"), base.join("net"));
            for case in ["datagram", "stream", "datagram-network"] {
                std::fs::create_dir_all(&jail).unwrap();
                std::fs::create_dir_all(&net).unwrap();
                let out = child(
                    "bind_after_narrow_child",
                    &[("WICK_TEST_CASE", case), ("WICK_TEST_JAIL", jail.to_str().unwrap())],
                );
                let stdout = String::from_utf8_lossy(&out.stdout);
                assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{case}: {:?}\n{stdout}", out.status);
                assert!(stdout.contains("SETUP-BIND-OK") && !stdout.contains("CHILD-SURVIVED"), "{case}: {stdout}");
                std::fs::remove_dir_all(&base).unwrap();
            }
        }

        #[test]
        #[ignore = "run by test_unix_bind_is_setups_only in a separate process"]
        fn bind_after_narrow_child() {
            let case = std::env::var("WICK_TEST_CASE").unwrap();
            let jail = std::path::PathBuf::from(std::env::var("WICK_TEST_JAIL").unwrap());
            let net = jail.parent().unwrap().join("net");
            let (dir, network) = match case.as_str() {
                "datagram-network" => (net.clone(), Some(net.as_path())),
                _ => (jail.clone(), None),
            };
            let profile = profile_for(Some(&jail), network).unwrap();
            COMPILED
                .set((Compiled::here(&profile).unwrap(), Compiled::here(&api_profile()).unwrap()))
                .unwrap();
            select(Policy::Default);
            apply().unwrap();
            let bind = |name: &str| {
                let kind = if case == "stream" { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
                // SAFETY: plain calls on a socket made here.
                let fd = unsafe { libc::socket(libc::AF_UNIX, kind, 0) };
                assert!(fd >= 0);
                let (addr, len) = sockaddr_un(&dir.join(name));
                // SAFETY: a socket address of the given length.
                unsafe { libc::bind(fd, (&raw const addr).cast(), len) }
            };
            assert_eq!(bind("early"), 0, "{}", std::io::Error::last_os_error());
            println!("SETUP-BIND-OK");
            narrow().unwrap();
            println!("NARROWED");
            bind("late");
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        // --new-pid-ns: in a PID namespace of its own on Linux, Firecracker
        // sees and signals no other process. Here its sandbox holds it:
        // information about another process fails (EPERM; Seatbelt's default
        // rule does not cover it, the profile's explicit rule does), and a
        // signal to one raises SIGSYS (the test's own process stands for any
        // other).
        #[test]
        fn test_no_other_process_in_reach() {
            use std::os::unix::process::ExitStatusExt;
            let me = std::process::id().to_string();
            let out = child("other_pid_info_child", &[("WICK_TEST_OTHER_PID", &me)]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success() && stdout.contains("OTHER-DENIED"), "{:?}\n{stdout}", out.status);
            let out = child("other_pid_signal_child", &[("WICK_TEST_OTHER_PID", &me)]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert_eq!(out.status.signal(), Some(libc::SIGSYS), "{:?}\n{stdout}", out.status);
            assert!(!stdout.contains("CHILD-SURVIVED"));
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
        #[ignore = "run by test_unlisted_syscalls_raise_sigsys in a separate process"]
        fn unlisted_child() {
            select(Policy::Default);
            apply().unwrap();
            // SAFETY: no arguments.
            unsafe { libc::getppid() };
            std::thread::sleep(std::time::Duration::from_secs(5));
            println!("CHILD-SURVIVED");
        }

        #[test]
        #[ignore = "run by test_unlisted_syscalls_raise_sigsys in a separate process"]
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
        #[ignore = "run by test_unlisted_syscalls_raise_sigsys in a separate process"]
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
            let mut names = MIG_ROUTINES.to_vec();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), MIG_ROUTINES.len());
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

        #[test]
        fn test_jail_network_profile_limits_sockets() {
            let base = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("wick-jail-net-{}", std::process::id()));
            let (jail, net, other) = (base.join("jail"), base.join("net"), base.join("other"));
            for dir in [&jail, &net, &other] {
                std::fs::create_dir_all(dir).unwrap();
            }
            // A peer in the jail's network, and one in another network.
            let _peer = std::os::unix::net::UnixDatagram::bind(net.join("peer")).unwrap();
            let _stranger = std::os::unix::net::UnixDatagram::bind(other.join("peer")).unwrap();
            run_child(
                "jailed_net_child",
                &[("WICK_TEST_JAIL", jail.to_str().unwrap()), ("WICK_TEST_NET", net.to_str().unwrap())],
            );
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
            let base = jail.parent().unwrap().to_owned();
            // The network directory, opened before the sandbox (and, in a
            // jail, before the chroot).
            let dir = std::fs::File::open(&net).unwrap();
            install(&format!("{PROFILE}{}{}", syscall_rule(), files_in_jail(&jail, Some(&net)).unwrap()))
                .unwrap();
            let denied = |e: std::io::Error| e.raw_os_error() == Some(libc::EPERM);
            // SAFETY: a directory descriptor; this thread's working directory.
            assert_eq!(unsafe { pthread_fchdir_np(dir.as_raw_fd()) }, 0);
            // In the network: an endpoint is bound, reaches a peer, is removed.
            let ep = UnixDatagram::bind("tap0").unwrap();
            ep.send_to(b"frame", "peer").unwrap();
            std::fs::remove_file("tap0").unwrap();
            // No other file there.
            assert!(denied(std::fs::write("file", b"x").unwrap_err()));
            // Climbing out of it reaches no other network, nor anything
            // next to the jail.
            assert!(denied(ep.send_to(b"frame", "../other/peer").unwrap_err()));
            assert!(denied(UnixDatagram::unbound().unwrap().connect("../other/peer").unwrap_err()));
            assert!(denied(UnixDatagram::bind("../other/tap0").unwrap_err()));
            assert!(denied(UnixDatagram::bind("../tap0").unwrap_err()));
            // SAFETY: back to the process's working directory.
            assert_eq!(unsafe { pthread_fchdir_np(-1) }, 0);
            // By absolute path: the same.
            assert!(denied(ep.send_to(b"frame", base.join("other/peer")).unwrap_err()));
            ep.send_to(b"frame", net.join("peer")).unwrap();
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
            // execution raise SIGSYS: test_unlisted_syscalls_raise_sigsys).
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

        // Seatbelt skips the rule on a call's number when a rule allows the
        // operation the call makes: under (allow default), with a rule
        // denying one number, exactly the calls of UNFILTERED_SYSCALLS run
        // (each other one raises SIGSYS). Measured here, every number in turn.
        #[test]
        fn test_seatbelt_skips_the_number_of_these() {
            use std::os::unix::process::ExitStatusExt;
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
            let table: Vec<u16> = UNFILTERED_SYSCALLS.iter().map(|(_, n, _)| *n).collect();
            assert_eq!(ran, table);
        }

        #[test]
        #[ignore = "run by test_seatbelt_skips_the_number_of_these in a separate process"]
        fn number_child() {
            // SAFETY: no arguments.
            assert_ne!(unsafe { libc::geteuid() }, 0, "never as root: the calls run");
            let n: u16 = std::env::var("WICK_TEST_SYSCALL").unwrap().parse().unwrap();
            install(&format!(
                "(version 1)(allow default)(deny syscall-unix (syscall-number {n}) (with send-signal SIGSYS))"
            ))
            .unwrap();
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
        // denies, after narrow() and in a jail: it raises SIGSYS, or fails
        // with EPERM, as its Limit says, and runs once the rule named is
        // lifted (an allow rule for its operation, or for its number). The
        // ones nothing decides run. The calls that remove a name also with
        // the names a running microVM removes, which they remove unlifted
        // (ALLOWED_NAMES), and others, which raise SIGSYS (DENIED_NAMES).
        #[test]
        fn test_unfiltered_syscalls_are_limited_by_their_rule() {
            use std::os::unix::process::ExitStatusExt;
            let base = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("wick-unfiltered-{}", std::process::id()));
            let jail = base.join("jail");
            std::fs::create_dir_all(jail.join("mnt")).unwrap();
            std::fs::create_dir_all(jail.join("tmp")).unwrap();
            std::fs::create_dir_all(base.join("net")).unwrap();
            let mut cases = Vec::new();
            for (name, _, limit) in UNFILTERED_SYSCALLS {
                if matches!(limit, Limit::Upstream(_)) || ["exit"].contains(name) {
                    continue;
                }
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
                    for file in ["inside", "second"] {
                        let _ = std::fs::remove_file(jail.join(format!("{file}-{name}-{lift}")));
                    }
                    std::fs::write(jail.join(format!("inside-{name}-{lift}")), b"x").unwrap();
                    std::fs::write(base.join(format!("outside-{name}-{lift}")), b"x").unwrap();
                    cases.push((*name, *limit, *lift));
                }
            }
            // Another process for each case, which a lifted call may signal,
            // stop or end: never this one.
            let mut others: Vec<std::process::Child> = cases
                .iter()
                .map(|_| Command::new("/bin/sleep").arg("60").spawn().unwrap())
                .collect();
            let envs = cases
                .iter()
                .zip(&others)
                .enumerate()
                .map(|(i, ((name, _, lift), other))| {
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
            for other in &mut others {
                let _ = other.kill();
                let _ = other.wait();
            }
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
            for ((name, limit, lift), out) in cases.iter().zip(&outs) {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let signal = out.status.signal();
                let ret = stdout.lines().find_map(|l| l.strip_prefix("RET ")).unwrap_or("none");
                let allowed = ALLOWED_NAMES.iter().any(|(_, names)| names.contains(lift));
                let denied = DENIED_NAMES.iter().any(|(_, names)| names.contains(lift));
                let ok = stdout.contains("NARROWED")
                    && match (limit, *lift) {
                        _ if allowed => out.status.success() && ret == "ok 0" && stdout.contains("SURVIVED"),
                        _ if denied => signal == Some(libc::SIGSYS),
                        (Limit::Signal(_) | Limit::Number | Limit::Default, "0") => {
                            signal == Some(libc::SIGSYS)
                        }
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
                    failures.push(format!(
                        "{name} (lifted {lift}, {limit:?}): {:?} RET {ret}\n{}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr).lines().take(3).collect::<Vec<_>>().join("\n")
                    ));
                }
            }
            std::fs::remove_dir_all(&base).unwrap();
            assert!(failures.is_empty(), "{}", failures.join("\n"));
        }

        /// The names a running microVM removes, by the calls that remove them
        /// (cases of `unfiltered_child`): in a jail, an eventfd's FIFO in its
        /// /tmp, a network endpoint's socket in its network, a memfd's
        /// shared memory object and a huge page one's; outside a jail, a
        /// FIFO in the temporary directory and an endpoint's socket in
        /// `firecracker-net`.
        const ALLOWED_NAMES: &[(&str, &[&str])] = &[
            ("unlink unlinkat", &["fifo", "endpoint", "free-fifo", "free-endpoint"]),
            ("shm_unlink", &["memfd", "huge"]),
        ];

        /// Names a running microVM does not remove: a file in the jail, a
        /// file at an eventfd FIFO's name, a socket outside the network, a
        /// FIFO with another process's eventfd name, and outside a jail a
        /// file in the temporary directory. (A name outside the jail is the
        /// unlifted case.)
        const DENIED_NAMES: &[(&str, &[&str])] =
            &[("unlink unlinkat", &["inside", "fifo-name", "socket", "fifo-other", "free-file"])];

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
                UNFILTERED_SYSCALLS.iter().find(|(x, ..)| *x == name).map(|(_, n, l)| (*n, *l)).unwrap();
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
            // here, before the sandbox.
            let fifo = |dir: &std::path::Path, pid: u32| {
                let path = dir.join(format!("{}{pid}-0", vmm_sys_util::eventfd::FIFO_PREFIX));
                // SAFETY: a NUL-terminated path.
                assert_eq!(unsafe { libc::mkfifo(c(&path).as_ptr(), 0o600) }, 0, "{path:?}");
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
                "fifo" => fifo(&jail.join("tmp"), pid),
                "fifo-name" => {
                    file(jail.join("tmp").join(format!("{}{pid}-1", vmm_sys_util::eventfd::FIFO_PREFIX)))
                }
                "fifo-other" => fifo(&jail.join("tmp"), pid + 1),
                "endpoint" => socket(base.join("net").join(format!("e-{n}"))),
                "socket" => socket(base.join(format!("s-{n}"))),
                "free-fifo" => fifo(&free_tmp, pid),
                "free-endpoint" => {
                    let dir = crate::platform::net::user_endpoint_dir().unwrap();
                    std::fs::create_dir_all(&dir).unwrap();
                    socket(dir.join(format!("wick-u-{pid}-{n}")))
                }
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

    unsafe extern "system" fn on_exception(info: *mut ExceptionPointers) -> i32 {
        // SAFETY: Windows passes valid exception pointers.
        let code = unsafe { (*(*info).record).code };
        if INSTALLED.load(Ordering::Acquire)
            && (code == STATUS_INVALID_HANDLE || code == STATUS_HANDLE_NOT_CLOSABLE)
        {
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
        // binary itself, filtered to one of the ignored tests below).
        fn child(name: &str, env: &[(&str, &str)]) -> Output {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("ext::sandbox::windows::tests::{name}"),
                    "--ignored",
                    "--nocapture",
                ])
                .envs(env.iter().copied())
                .output()
                .unwrap()
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
            }
            sandboxed();
            // SAFETY: a handle value the process does not hold; strict
            // handle checks raise for it.
            let r = unsafe { SetEvent(0x1234 as *mut c_void) };
            println!("CHILD-SURVIVED {r}");
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
