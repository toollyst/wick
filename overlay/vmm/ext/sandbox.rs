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
//! program execution, no fork, no IP networking, no Mach service lookups, no
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
    API_MACH_TRAPS, API_MIG_ROUTINES, API_SYSCALLS, FILES_ANYWHERE, MACH_TRAPS,
    MACH_TRAPS_IF_DEFINED, MIG_ROUTINES, PROFILE, SYSCALLS, api_profile, apply, apply_api,
    denied_syscall, files_in_jail, narrow, profile, select, selected,
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
pub use windows::{MITIGATIONS, Mitigation, Phase, apply, denied_syscall, narrow, select};

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
; setup's (SETUP_OPERATIONS), as on Linux the VMM thread's filter has no bind.
(allow network-inbound (local unix-socket))
(allow network-outbound (remote unix-socket))
; Guest memory backed by POSIX shared memory (memfd_create).
(allow ipc-posix-shm*)
; Own process only.
(allow signal (target self))
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
    /// Seatbelt cannot deny some system calls by number (measured: `write`,
    /// `open`, `close`, `socket`, `connect`, `bind`, `ioctl`, `sysctl`,
    /// `shm_open`, `getpid`, ... 91 of them); those listed here only say that
    /// a running microVM uses them, and the operation rules of [`PROFILE`]
    /// (files, network, IPC, sysctl) are what limit them.
    pub const SYSCALLS: &[&str] = &[
        // mmap, munmap, mprotect, madvise, mincore.
        "mmap", "munmap", "mprotect", "madvise", "mincore",
        // futex.
        "psynch_mutexwait", "psynch_mutexdrop", "psynch_cvbroad", "psynch_cvsignal",
        "psynch_cvwait", "psynch_cvclrprepost", "ulock_wait", "ulock_wake", "ulock_wait2",
        "__semwait_signal", "__semwait_signal_nocancel",
        // epoll_ctl, epoll_pwait.
        "kevent", "kevent_qos", "kevent_id", "poll", "poll_nocancel",
        // read, readv, write, writev, recvfrom, recvmsg, sendmsg, sendto, lseek.
        "read", "read_nocancel", "readv", "readv_nocancel", "write", "write_nocancel", "writev",
        "writev_nocancel", "pread", "pread_nocancel", "pwrite", "pwrite_nocancel", "recvmsg",
        "recvmsg_nocancel", "recvfrom", "recvfrom_nocancel", "sendmsg", "sendmsg_nocancel",
        "sendto", "sendto_nocancel", "recvmsg_x", "sendmsg_x", "lseek",
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

    /// System calls allowed until [`narrow`] only, in addition to
    /// [`SYSCALLS`]: what building the microVM takes (on Linux the VMM thread
    /// runs unfiltered until then), measured as [`SYSCALLS`] are.
    pub const SETUP_SYSCALLS: &[&str] = &[
        "getpid", "getuid", "geteuid", "access", "dup", "pipe", "getegid", "dup2", "bind",
        "listen", "getrusage", "socketpair", "csops", "csops_audittoken",
        "kdebug_typefilter", "kdebug_trace_string", "kdebug_trace64", "getrlimit", "sysctl",
        "getattrlist", "shm_open", "shm_unlink", "gettid", "issetugid", "proc_info",
        "getdirentries64", "bsdthread_create", "kqueue", "sigsuspend_nocancel", "fileport_makefd",
        "bsdthread_ctl",
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
    pub fn api_profile() -> String {
        let mut rule = format!("(version 1)\n{}{API_PROFILE}", default_rule());
        rule.push_str(&api_discovery_rule());
        rule.push_str(&allow("syscall-unix", "", "syscall-number", "SYS_", API_SYSCALLS));
        rule.push_str(&allow("syscall-mach", "", "machtrap-number", "MSC_", API_MACH_TRAPS));
        rule.push_str(&allow("syscall-mig", "", "kernel-mig-routine", "", API_MIG_ROUTINES));
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
        install(&api_profile())?;
        state.installed = true;
        INSTALLED.store(true, Ordering::Relaxed);
        state.narrowed_done = true;
        if !cfg!(wick_sandbox_discovery) {
            libc::wick_mm::deny_exec(exec_denied);
        }
        Ok(())
    }

    /// File rule without the jailer: guest kernels, disks, snapshots, logs,
    /// metrics and the API socket are chosen by the operator, also after
    /// start-up (hot-plug, snapshots), as on Linux without the jailer.
    pub const FILES_ANYWHERE: &str = "(allow file-read* file-write*)\n";

    /// File rule in a jail: only the jail directory, by its path outside the
    /// chroot (Seatbelt matches the real path of a file, and the chroot
    /// already hides everything else; this also covers descriptors opened
    /// before the chroot).
    pub fn files_in_jail(root: &Path) -> Result<String, SandboxError> {
        let root = root
            .to_str()
            .filter(|r| r.starts_with('/') && !r.contains(['\0', '\n']))
            .ok_or_else(|| SandboxError::Install(format!("jail path {root:?}")))?;
        let quoted = root.replace('\\', "\\\\").replace('"', "\\\"");
        Ok(format!("(allow file-read* file-write* (subpath \"{quoted}\"))\n"))
    }

    /// The profile for this process.
    pub fn profile() -> Result<String, SandboxError> {
        let files = match crate::ext::jail::root() {
            Some(root) => files_in_jail(root)?,
            None => FILES_ANYWHERE.to_owned(),
        };
        let profile = PROFILE.replacen("(deny default)\n", &default_rule(), 1);
        Ok(format!("{profile}{}{}{files}", syscall_rule(), operation_rule()))
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
    /// console's terminal, binds the API and vsock sockets, and reads system
    /// information; on Linux the VMM thread's filter allows no bind, and
    /// ioctl only for KVM, the TAP device and the terminal.
    pub const SETUP_OPERATIONS: &[&str] = &[
        "file-ioctl",
        "sysctl-read",
        "system-socket",
        "network-bind (local unix-socket)",
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
        for op in RUN_OPERATIONS {
            let (name, filter) = op.split_once(' ').unwrap_or((op, ""));
            rule.push_str(&format!("(allow {name} {filter})\n"));
        }
        // Discovery build: after narrow(), the setup operations' kinds are
        // allowed and reported (last, so that this rule decides; a default
        // rule's reports miss some of them, sysctl reads among them).
        #[cfg(wick_sandbox_discovery)]
        {
            let narrowed = format!("(extension \"{}\")", NARROWED.to_str().unwrap());
            for op in SETUP_OPERATIONS {
                let name = op.split_once(' ').map_or(*op, |(name, _)| name);
                rule.push_str(&format!("(allow {name} {narrowed} (with report))\n"));
            }
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
        // libsystem_sandbox (part of libSystem). Deprecated in the SDK headers but
        // still the documented way to apply an SBPL profile string.
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
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
        install(&profile()?)?;
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
    /// `PROT_EXEC` after [`narrow`], as a seccomp trap does: the signal is
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
    fn install(profile: &str) -> Result<(), SandboxError> {
        let profile = std::ffi::CString::new(profile)
            .map_err(|_| SandboxError::Install("profile contains NUL".into()))?;
        let mut err: *mut c_char = std::ptr::null_mut();
        // SAFETY: valid NUL-terminated profile and output pointer; flags 0 means
        // "the string is an SBPL profile".
        let ret = unsafe { sandbox_init(profile.as_ptr(), 0, &mut err) };
        if ret != 0 {
            let msg = if err.is_null() {
                std::io::Error::last_os_error().to_string()
            } else {
                // SAFETY: sandbox_init returns a NUL-terminated message that we free.
                let msg = unsafe { CStr::from_ptr(err) }
                    .to_string_lossy()
                    .into_owned();
                // SAFETY: as above.
                unsafe { sandbox_free_error(err) };
                msg
            };
            return Err(SandboxError::Install(msg));
        }
        Ok(())
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

        // A system call outside SYSCALLS raises SIGSYS, as a seccomp filter's
        // trap does (the test binary has no handler, so it dies of it).
        #[test]
        fn test_unlisted_syscalls_raise_sigsys() {
            use std::os::unix::process::ExitStatusExt;
            for name in [
                "exec_child", "unlisted_child", "unlisted_trap_child", "unlisted_mig_child", "tcp_child",
                "udp_child", "bind_after_narrow_child",
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
        // outside API_SYSCALLS, shared memory and an executable mapping raise
        // SIGSYS; a file fails with an error, as outside the chroot.
        #[test]
        fn test_api_profile_raises_sigsys_outside_its_list() {
            use std::os::unix::process::ExitStatusExt;
            for case in ["dup", "shm", "exec", "socketpair"] {
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
            // unknown one fails `sandbox_init`, which test_sandbox_restricts_child
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

        // Binding a Unix socket is setup's only: Linux's VMM filter has no bind.
        #[test]
        #[ignore = "run by test_unlisted_syscalls_raise_sigsys in a separate process"]
        fn bind_after_narrow_child() {
            let path = std::env::temp_dir().join(format!("wick-bind-{}", std::process::id()));
            select(Policy::Default);
            apply().unwrap();
            let early = std::os::unix::net::UnixListener::bind(&path).unwrap();
            drop(early);
            let _ = std::fs::remove_file(&path);
            narrow().unwrap();
            let _ = std::os::unix::net::UnixListener::bind(&path);
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
        fn test_files_in_jail_rejects_bad_paths() {
            for bad in ["relative", "/a\nb"] {
                files_in_jail(Path::new(bad)).unwrap_err();
            }
        }

        #[test]
        #[ignore = "run by test_jail_profile_limits_files in a separate process"]
        fn jailed_child() {
            let jail = std::path::PathBuf::from(std::env::var("WICK_TEST_JAIL").unwrap());
            let base = jail.parent().unwrap().to_owned();
            // A descriptor opened before the sandbox stays usable.
            let early = std::fs::File::open(base.join("outside")).unwrap();
            install(&format!("{PROFILE}{}{}", syscall_rule(), files_in_jail(&jail).unwrap())).unwrap();
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
