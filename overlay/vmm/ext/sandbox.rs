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
//! | (default)               | built-in BPF filters  | built-in Seatbelt profile ([`PROFILE`]) | child-process-creation block ([`windows`])|
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
//! The Windows sandbox blocks child-process creation (the `exec`/`fork` escape
//! vector) with a process mitigation policy. Network and filesystem confinement
//! on Windows needs an AppContainer lowbox token, which is the next hardening
//! step and is tracked in `docs/ROADMAP.md`; it is not silently assumed
//! here — what is installed is exactly what is documented.

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
    FILES_ANYWHERE, MACH_TRAPS, MACH_TRAPS_IF_DEFINED, MIG_ROUTINES, PROFILE, SYSCALLS, apply,
    denied_syscall, files_in_jail, narrow, profile, select,
};

/// Narrows the sandbox to what a running microVM needs, for good. Called
/// where upstream installs the VMM thread's seccomp filter, after the microVM
/// is built (on Linux that thread runs unfiltered until then). On Linux each
/// thread's seccomp filter does this; on Windows nothing narrows yet, and the
/// sandbox stays as [`apply`] installed it (docs/PORTING.md, row 1).
#[cfg(not(target_os = "macos"))]
pub fn narrow() -> Result<(), SandboxError> {
    Ok(())
}

/// Whether a SIGSYS is the host sandbox denying a system call (upstream's
/// handler then exits as for a seccomp violation). Async-signal-safe.
///
/// # Safety
/// `info` is the siginfo the kernel passed to a SIGSYS handler.
#[cfg(not(target_os = "macos"))]
pub unsafe fn denied_syscall(_si_code: libc::c_int, _info: *mut libc::siginfo_t) -> bool {
    false
}

#[cfg(target_os = "windows")]
pub use windows::{apply, select};

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
(deny default)
; Descriptors the process already holds (the console, inherited sockets).
(allow file-ioctl)
; Unix sockets only: API server, vsock backends, console.
(allow system-socket)
(allow network-bind (local unix-socket))
(allow network-inbound (local unix-socket))
(allow network-outbound (remote unix-socket))
; Guest memory backed by POSIX shared memory.
(allow ipc-posix-shm*)
; Own process only.
(allow signal (target self))
(allow process-info* (target self))
(allow sysctl-read)
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
        Ok(format!("{PROFILE}{}{files}", syscall_rule()))
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
    pub fn narrow() -> Result<(), SandboxError> {
        let mut state = STATE.lock().unwrap();
        if !state.installed || state.narrowed_done {
            return Ok(());
        }
        let fail = |what: &str, err: std::io::Error| SandboxError::Narrow(format!("{what}: {err}"));
        let token = state.narrowed.take().expect("the narrowed token is kept until narrow()");
        token.consume().map_err(|err| fail("taking the narrowed extension", err))?;
        drop(token);
        state.narrowed_done = true;
        Ok(())
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
            for name in ["exec_child", "unlisted_child", "unlisted_trap_child", "unlisted_mig_child"] {
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
            // IP networking is denied (program execution raises SIGSYS:
            // test_unlisted_syscalls_raise_sigsys).
            let denied = |e: std::io::Error| e.raw_os_error() == Some(libc::EPERM);
            assert!(denied(
                std::net::TcpStream::connect("127.0.0.1:9").unwrap_err()
            ));
            assert!(denied(
                std::net::UdpSocket::bind("127.0.0.1:0").unwrap_err()
            ));
            println!("CHILD-OK");
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::sync::Mutex;

    use windows_sys::Win32::System::Threading::{
        ProcessChildProcessPolicy, SetProcessMitigationPolicy,
    };

    use super::{Policy, SandboxError};

    struct State {
        policy: Policy,
        installed: bool,
    }

    static STATE: Mutex<State> = Mutex::new(State {
        policy: Policy::None,
        installed: false,
    });

    /// Selects the sandbox to install. Called once at start-up from the seccomp
    /// configuration.
    pub fn select(policy: Policy) {
        STATE.lock().unwrap().policy = policy;
    }

    /// Installs the selected sandbox if it is not installed yet.
    ///
    /// Blocks child-process creation for the whole process with
    /// `ProcessChildProcessPolicy` (`NoChildProcessCreation`). The call is
    /// checked: if the policy cannot be set the sandbox is not silently
    /// skipped — an error is returned and start-up fails.
    pub fn apply() -> Result<(), SandboxError> {
        let mut state = STATE.lock().unwrap();
        if state.policy == Policy::None || state.installed {
            return Ok(());
        }
        // Bit 0 of the policy flags is `NoChildProcessCreation`.
        let flags: u32 = 1;
        // SAFETY: a 4-byte policy value of the size passed, for the current
        // process's `ProcessChildProcessPolicy`.
        let ok = unsafe {
            SetProcessMitigationPolicy(
                ProcessChildProcessPolicy,
                std::ptr::from_ref(&flags).cast(),
                std::mem::size_of::<u32>(),
            )
        };
        if ok == 0 {
            return Err(SandboxError::Install(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        state.installed = true;
        Ok(())
    }
}
