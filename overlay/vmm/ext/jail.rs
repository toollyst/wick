// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The jailed side of the jailer, on hosts where a program cannot be started
//! inside a chroot.
//!
//! On Linux the upstream jailer chroots, drops to `--uid`/`--gid` and then
//! execs Firecracker. On macOS no program can start inside a chroot: dyld maps
//! the system libraries from the shared cache, which is outside any jail (the
//! kernel keeps one shared region per root directory). So the macOS backend of
//! the jailer (overlay/jailer/platform) runs upstream's jailer up to the exec,
//! leaves the chroot for the exec only, and execs Firecracker with [`ENV`] set
//! to `<uid>:<gid>:<jail root>`. [`enter`], the first thing Firecracker does
//! (before the logger, argument parsing or any other thread), then does what
//! the jailer's exec does on Linux: chroot into the jail, drop to `uid:gid`
//! and check that root cannot be regained. The Seatbelt sandbox
//! ([`super::sandbox`]) then also limits file access to the jail ([`root`]).
//!
//! The binary the jailer execs as root is a root-owned copy outside the jail,
//! which the jailed user never had a chance to write.
//!
//! [`ENV`] is only honoured from root: a process that cannot chroot fails
//! instead of running unjailed.
//!
//! A CPU cgroup limit comes as [`CPU_ENV`], in percent of one CPU. macOS
//! keeps a process's CPU limit with its task, which an exec replaces, and lets
//! a process set only its own, so [`enter`] applies it: the kernel then blocks
//! all of Firecracker's threads once they used that share of each second. A
//! process can also lift its own limit; the sandbox's system call allow-list
//! denies the call that would ([`super::sandbox`]), and the sandbox refuses to
//! be turned off while a CPU limit is set ([`cpu_limit`]).
//!
//! A memory cgroup limit comes as [`MEMORY_ENV`], in MiB: the jailer set it
//! as Firecracker's jetsam limit at the exec.
//!
//! On Linux one cgroup holds all of Firecracker, its API thread included. On
//! macOS the API server's HTTP side is a process of its own
//! ([`super::api_process`]), and both limits are per process: a fork does not
//! inherit the CPU limit, and only root sets a jetsam limit. So when the jail
//! has a limit and the API is on, [`enter`] makes the API process while
//! Firecracker is still root, gives it a fixed share of each limit
//! ([`API_MEMORY_MIB`], [`API_CPU_PERCENT`]) and keeps the rest: together
//! they stay within the jail's limit, as one cgroup would.

use std::path::Path;

/// Environment variable through which the jailer hands the jail over.
pub const ENV: &str = "WICK_JAIL";

/// Environment variable through which the jailer hands a CPU limit over.
pub const CPU_ENV: &str = "WICK_JAIL_CPU";

/// Environment variable through which the jailer hands the memory limit (MiB)
/// over.
pub const MEMORY_ENV: &str = "WICK_JAIL_MEMORY";

/// Environment variable through which the jailer says Firecracker runs in
/// a PID namespace of its own (`--new-pid-ns`): `1`.
pub const PID_NS_ENV: &str = "WICK_JAIL_PID_NS";

/// The signals whose default action ends or stops a process and that
/// upstream's Firecracker does not handle. In a PID namespace of its own on
/// Linux, Firecracker is the namespace's init, and the kernel drops such a
/// signal sent to it from outside (pid_namespaces(7)); with
/// [`PID_NS_ENV`], [`enter`] ignores them, so the same signals stay
/// without effect. Where upstream installs a handler later (SIGHUP here; and
/// SIGPIPE, SIGSYS, SIGBUS, SIGSEGV, SIGILL, SIGXFSZ, SIGXCPU and the vCPU
/// kick, not listed), the handler replaces the ignoring, as on Linux a
/// handler lets the signal reach init. SIGKILL and SIGSTOP cannot be
/// ignored, as the kernel delivers them to a namespace's init from outside.
/// The faults a process raises itself (SIGABRT, SIGFPE, SIGTRAP) are left
/// as they are: the kernel delivers those to init as well.
// Not in a Windows test build: Windows has no SIGTSTP, SIGTTIN, SIGTTOU, SIGVTALRM or SIGPROF.
#[cfg(any(target_os = "macos", all(test, not(windows))))]
pub const DROPPED_IN_PID_NS: &[libc::c_int] = &[
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGALRM,
    libc::SIGTERM,
    libc::SIGTSTP,
    libc::SIGTTIN,
    libc::SIGTTOU,
    libc::SIGVTALRM,
    libc::SIGPROF,
    libc::SIGHUP,
];

/// Environment variable through which the jailer hands the jail's network
/// over (`--netns`): the absolute path of the directory the network
/// endpoints (`platform::net`) are made in, in place of the temporary
/// directory.
pub const NETNS_ENV: &str = "WICK_NETNS";

/// The API process's share of a jail's memory limit, in MiB: a process
/// forked at start-up (a few MiB) and the requests it holds, at most the API
/// payload limit each.
pub const API_MEMORY_MIB: u32 = 32;

/// The API process's share of a jail's CPU limit, in percent of one CPU:
/// parsing requests and passing them on.
pub const API_CPU_PERCENT: u8 = 1;

/// Marks a binary that takes the jail over from the jailer. The jailer refuses
/// to exec a binary without it as root, since such a binary would run unjailed.
#[used]
pub static HANDOVER_MARK: [u8; 24] = *b"wick-jail-handover:v1\0\0\0";

/// Errors entering the jail.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum JailError {
    /// Invalid WICK_JAIL value {0:?}: expected <uid>:<gid>:<absolute jail root>
    Format(String),
    /// The jailer's hand-over needs root, but Firecracker runs as uid {0}
    NotRoot(u32),
    /// Failed to chroot into {0}: {1}
    Chroot(String, std::io::Error),
    /// Failed to change into the jail's root directory: {0}
    Chdir(std::io::Error),
    /// Invalid WICK_JAIL_CPU value {0:?}: expected a percentage of one CPU from 1 to 255, with WICK_JAIL
    CpuFormat(String),
    /// Failed to limit Firecracker to {0}% of one CPU: {1}
    CpuLimit(u8, std::io::Error),
    /// Failed to set the supplementary groups to [{0}]: {1}
    SetGroups(u32, std::io::Error),
    /// Failed to set the group to {0}: {1}
    SetGid(u32, std::io::Error),
    /// Failed to set the user to {0}: {1}
    SetUid(u32, std::io::Error),
    /// Privileges were not dropped: {0}
    StillPrivileged(String),
    /// Failed to revert to the jail's token: {0}
    Revert(std::io::Error),
    /// Invalid WICK_JAIL_MEMORY value {0:?}: expected a memory limit in MiB, with WICK_JAIL
    MemoryFormat(String),
    /// The jail's memory limit of {0} MiB leaves too little once the API process has its share of 32 MiB: give it more than 64 MiB, or run with --no-api
    MemoryTooSmall(u32),
    /// The jail's CPU limit of {0}% cannot be shared with the API process (1%): give it 2% or more, or run with --no-api
    CpuTooSmall(u8),
    /// Failed to set the jetsam memory limit of {0} MiB: {1}
    MemoryLimit(u32, std::io::Error),
    /// Failed to make the API process: {0}
    ApiProcess(std::io::Error),
    /// The jail's network {0:?} (WICK_NETNS): {1}
    #[cfg(target_os = "macos")]
    Netns(std::ffi::OsString, std::io::Error),
    /// {0}
    #[cfg(target_os = "macos")]
    Sandbox(crate::ext::sandbox::SandboxError),
    /// Invalid WICK_JAIL_PID_NS (1 or unset): {0}
    #[cfg(target_os = "macos")]
    PidNsFormat(String),
    /// Failed to ignore signal {0} in the PID namespace: {1}
    #[cfg(target_os = "macos")]
    PidNs(i32, std::io::Error),
}

/// The jail's root directory, as a path outside the jail, if Firecracker was
/// started by the jailer.
pub fn root() -> Option<&'static Path> {
    imp::root()
}

/// Enters the jail the jailer prepared, if [`ENV`] is set. Must be called
/// before any other thread starts.
pub fn enter() -> Result<(), JailError> {
    imp::enter()
}

/// The jail's network ([`NETNS_ENV`]): the directory the network endpoints
/// are made in, if the jailer gave one, as a path outside the jail.
#[cfg(any(target_os = "macos", windows))]
pub fn netns() -> Option<&'static Path> {
    imp::netns()
}

/// The jail's network directory, opened before the chroot: a jailed
/// Firecracker reaches it only through this descriptor
/// (`platform::net` resolves endpoint names against it).
#[cfg(target_os = "macos")]
pub fn netns_dir() -> Option<std::os::fd::BorrowedFd<'static>> {
    imp::netns_dir()
}

/// Closes the jail's network directory ([`netns_dir`]) in the API process,
/// which reaches no network, as upstream's API thread opens no interface.
///
/// # Safety
/// The child of a fork, which never uses [`netns_dir`] afterwards.
#[cfg(target_os = "macos")]
pub unsafe fn close_netns_in_child() {
    // SAFETY: the caller's contract.
    unsafe { imp::close_netns_in_child() }
}

/// The CPU limit (percent of one CPU) [`enter`] applied, if any.
#[cfg(target_os = "macos")]
pub fn cpu_limit() -> Option<u8> {
    imp::cpu_limit()
}

/// The [`MEMORY_ENV`] value: MiB, at least 1.
#[cfg(any(target_os = "macos", test))]
fn parse_memory(value: &str) -> Result<u32, JailError> {
    match value.parse::<u32>() {
        Ok(mib) if mib > 0 && value.bytes().all(|b| b.is_ascii_digit()) => Ok(mib),
        _ => Err(JailError::MemoryFormat(value.to_owned())),
    }
}

/// How a jail's limits are shared when the API server is a process of its
/// own: `(Firecracker's, the API process's)` CPU and memory limits.
#[cfg(any(target_os = "macos", test))]
#[allow(clippy::type_complexity)]
fn share(
    cpu: Option<u8>,
    memory: Option<u32>,
) -> Result<((Option<u8>, Option<u8>), (Option<u32>, Option<u32>)), JailError> {
    let cpu = match cpu {
        Some(p) if p <= API_CPU_PERCENT => return Err(JailError::CpuTooSmall(p)),
        Some(p) => (Some(p - API_CPU_PERCENT), Some(API_CPU_PERCENT)),
        None => (None, None),
    };
    let memory = match memory {
        Some(m) if m <= 2 * API_MEMORY_MIB => return Err(JailError::MemoryTooSmall(m)),
        Some(m) => (Some(m - API_MEMORY_MIB), Some(API_MEMORY_MIB)),
        None => (None, None),
    };
    Ok((cpu, memory))
}

/// The [`CPU_ENV`] value: a percentage of one CPU, 1 to 255.
#[cfg(any(target_os = "macos", test))]
fn parse_cpu(value: &str) -> Result<u8, JailError> {
    match value.parse::<u8>() {
        Ok(percent) if percent > 0 && value.bytes().all(|b| b.is_ascii_digit()) => Ok(percent),
        _ => Err(JailError::CpuFormat(value.to_owned())),
    }
}

/// The hand-over value: `<uid>:<gid>:<root>`.
#[derive(Debug, PartialEq, Eq)]
struct Spec {
    uid: u32,
    gid: u32,
    root: String,
}

fn parse(value: &str) -> Result<Spec, JailError> {
    let bad = || JailError::Format(value.to_owned());
    let mut parts = value.splitn(3, ':');
    let uid = parts.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    let gid = parts.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
    let root = parts.next().ok_or_else(bad)?;
    #[cfg(not(windows))]
    let absolute = root.starts_with('/');
    #[cfg(windows)]
    let absolute = Path::new(root).is_absolute();
    if !absolute || root.contains('\0') {
        return Err(bad());
    }
    Ok(Spec {
        uid,
        gid,
        root: root.to_owned(),
    })
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::CString;
    use std::io::Error;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use super::{
        CPU_ENV, ENV, JailError, MEMORY_ENV, NETNS_ENV, PID_NS_ENV, Spec, parse, parse_cpu,
        parse_memory, share,
    };

    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    static CPU_LIMIT: OnceLock<u8> = OnceLock::new();
    /// The jail's network: its path outside the jail, and the directory
    /// opened before the chroot.
    static NETNS: OnceLock<(PathBuf, OwnedFd)> = OnceLock::new();

    pub fn root() -> Option<&'static Path> {
        ROOT.get().map(PathBuf::as_path)
    }

    pub fn netns() -> Option<&'static Path> {
        NETNS.get().map(|(path, _)| path.as_path())
    }

    pub fn netns_dir() -> Option<BorrowedFd<'static>> {
        NETNS.get().map(|(_, fd)| fd.as_fd())
    }

    /// See [`super::close_netns_in_child`].
    pub unsafe fn close_netns_in_child() {
        if let Some((_, dir)) = NETNS.get() {
            // SAFETY: the caller's contract: NETNS is not used in this
            // process again, so its descriptor may go.
            unsafe { libc::close(dir.as_raw_fd()) };
        }
    }

    /// Opens the jail's network directory ([`super::NETNS_ENV`]), which
    /// must be absolute, before the chroot (outside the jail no path
    /// reaches it).
    fn open_netns(value: &std::ffi::OsStr) -> Result<(PathBuf, OwnedFd), JailError> {
        use std::os::unix::ffi::OsStrExt;
        let fail = |e| JailError::Netns(value.to_owned(), e);
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(fail(Error::other("not an absolute path")));
        }
        let c_path = CString::new(value.as_bytes()).map_err(|_| fail(Error::other("a NUL in the path")))?;
        // SAFETY: a NUL-terminated path; the descriptor is owned below.
        let fd = unsafe {
            libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(fail(Error::last_os_error()));
        }
        // SAFETY: just opened, owned here.
        Ok((path, unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    pub fn cpu_limit() -> Option<u8> {
        CPU_LIMIT.get().copied()
    }

    /// `proc_policy_cpuusage_attr_t` (sys/process_policy.h).
    #[repr(C)]
    #[derive(Debug, Default)]
    struct CpuUsageAttr {
        action: u32,
        percentage: u32,
        /// Seconds.
        interval: u64,
        deadline: u64,
    }

    // sys/process_policy.h.
    const PROC_POLICY_SCOPE_PROCESS: libc::c_int = 1;
    const PROC_POLICY_ACTION_APPLY: libc::c_int = 1;
    const PROC_POLICY_ACTION_GET: libc::c_int = 11;
    const PROC_POLICY_RESOURCE_USAGE: libc::c_int = 4;
    const PROC_POLICY_RUSAGE_CPU: libc::c_int = 3;
    const PROC_POLICY_RSRCACT_THROTTLE: u32 = 1;

    unsafe extern "C" {
        // The process_policy system call (libsystem_kernel), behind
        // libproc's proc_setcpu_percentage.
        fn __process_policy(
            scope: libc::c_int,
            action: libc::c_int,
            policy: libc::c_int,
            policy_subtype: libc::c_int,
            attr: *mut CpuUsageAttr,
            target_pid: libc::pid_t,
            target_threadid: u64,
        ) -> libc::c_int;
    }

    fn cpu_policy(action: libc::c_int, attr: &mut CpuUsageAttr) -> Result<(), Error> {
        // SAFETY: a valid attribute buffer of the size the kernel copies; pid
        // 0 is the calling process.
        let ret = unsafe {
            __process_policy(
                PROC_POLICY_SCOPE_PROCESS,
                action,
                PROC_POLICY_RESOURCE_USAGE,
                PROC_POLICY_RUSAGE_CPU,
                attr,
                0,
                0,
            )
        };
        if ret == -1 { Err(Error::last_os_error()) } else { Ok(()) }
    }

    /// Limits the whole process to `percent` of one CPU per second, and
    /// reads the limit back.
    pub(super) fn limit_cpu(percent: u8) -> Result<(), JailError> {
        let fail = |e| JailError::CpuLimit(percent, e);
        let mut attr = CpuUsageAttr {
            action: PROC_POLICY_RSRCACT_THROTTLE,
            percentage: percent.into(),
            interval: 1,
            deadline: 0,
        };
        cpu_policy(PROC_POLICY_ACTION_APPLY, &mut attr).map_err(fail)?;
        let mut got = CpuUsageAttr::default();
        cpu_policy(PROC_POLICY_ACTION_GET, &mut got).map_err(fail)?;
        if (got.action, got.percentage, got.interval) != (attr.action, attr.percentage, 1) {
            return Err(fail(Error::other(format!("the kernel reports {got:?}"))));
        }
        Ok(())
    }

    /// Applies a CPU limit of `percent` that refills every `interval`
    /// seconds, and returns the interval the kernel reads back.
    #[cfg(test)]
    pub(super) fn cpu_refill_interval(percent: u8, interval: u64) -> u64 {
        let mut attr = CpuUsageAttr {
            action: PROC_POLICY_RSRCACT_THROTTLE,
            percentage: percent.into(),
            interval,
            deadline: 0,
        };
        cpu_policy(PROC_POLICY_ACTION_APPLY, &mut attr).unwrap();
        let mut got = CpuUsageAttr::default();
        cpu_policy(PROC_POLICY_ACTION_GET, &mut got).unwrap();
        got.interval
    }

    fn check(ret: libc::c_int) -> Result<(), Error> {
        if ret == 0 { Ok(()) } else { Err(Error::last_os_error()) }
    }

    /// `memorystatus_memlimit_properties_t` (sys/kern_memorystatus.h).
    #[repr(C)]
    #[derive(Debug, Default, PartialEq, Eq)]
    struct MemlimitProperties {
        active: i32,
        active_attr: u32,
        inactive: i32,
        inactive_attr: u32,
    }

    // sys/kern_memorystatus.h.
    const MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES: u32 = 7;
    const MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES: u32 = 8;
    const MEMORYSTATUS_MEMLIMIT_ATTR_FATAL: u32 = 1;

    unsafe extern "C" {
        fn memorystatus_control(
            command: u32,
            pid: i32,
            flags: u32,
            buffer: *mut libc::c_void,
            size: libc::size_t,
        ) -> libc::c_int;
    }

    /// Sets this process's jetsam limit to `mib` (killed when it goes over,
    /// as the jailer's limit at the exec), and reads it back. Needs root.
    fn limit_memory(mib: u32) -> Result<(), JailError> {
        let fail = |e| JailError::MemoryLimit(mib, e);
        let limit = i32::try_from(mib).map_err(|_| fail(Error::other("too large")))?;
        let mut set = MemlimitProperties {
            active: limit,
            active_attr: MEMORYSTATUS_MEMLIMIT_ATTR_FATAL,
            inactive: limit,
            inactive_attr: MEMORYSTATUS_MEMLIMIT_ATTR_FATAL,
        };
        let size = std::mem::size_of::<MemlimitProperties>();
        // SAFETY: a valid properties buffer of the size passed; this process.
        check(unsafe {
            memorystatus_control(
                MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES,
                libc::getpid(),
                0,
                std::ptr::from_mut(&mut set).cast(),
                size,
            )
        })
        .map_err(fail)?;
        let mut got = MemlimitProperties::default();
        // SAFETY: as above.
        check(unsafe {
            memorystatus_control(
                MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES,
                libc::getpid(),
                0,
                std::ptr::from_mut(&mut got).cast(),
                size,
            )
        })
        .map_err(fail)?;
        if got.active != limit || got.inactive != limit || got.active_attr & 1 == 0 {
            return Err(fail(Error::other(format!("the kernel reports {got:?}"))));
        }
        Ok(())
    }

    fn drop_privileges(uid: u32, gid: u32) -> Result<(), JailError> {
        let groups = [gid];
        // SAFETY: a one-element group list.
        check(unsafe { libc::setgroups(1, groups.as_ptr()) })
            .map_err(|e| JailError::SetGroups(gid, e))?;
        // SAFETY: no pointers.
        check(unsafe { libc::setgid(gid) }).map_err(|e| JailError::SetGid(gid, e))?;
        // SAFETY: no pointers.
        check(unsafe { libc::setuid(uid) }).map_err(|e| JailError::SetUid(uid, e))?;
        verify_dropped(uid, gid)
    }

    /// The API process's side of [`enter`]: its share of the limits, the
    /// same privileges as Firecracker, then it waits for the API server.
    fn api_process(link: std::os::unix::net::UnixStream, uid: u32, gid: u32, cpu: Option<u8>, memory: Option<u32>) -> ! {
        // SAFETY: the child of a fork made with one thread.
        unsafe { close_netns_in_child() };
        let result = (|| {
            if let Some(mib) = memory {
                limit_memory(mib)?;
            }
            drop_privileges(uid, gid)?;
            if let Some(percent) = cpu {
                limit_cpu(percent)?;
            }
            Ok::<(), JailError>(())
        })();
        if let Err(err) = result {
            eprintln!("The API server process could not enter the jail: {err}");
            // SAFETY: ends this process (Firecracker's exit code is the parent's).
            unsafe { libc::_exit(1) };
        }
        crate::ext::api_process::wait_for_server(link)
    }

    pub fn enter() -> Result<(), JailError> {
        let cpu = std::env::var_os(CPU_ENV).map(|v| v.to_string_lossy().into_owned());
        let memory = std::env::var_os(MEMORY_ENV).map(|v| v.to_string_lossy().into_owned());
        let pid_ns = std::env::var_os(PID_NS_ENV).map(|v| v.to_string_lossy().into_owned());
        let netns = std::env::var_os(NETNS_ENV);
        let Some(value) = std::env::var_os(ENV) else {
            // A limit or PID namespace alone would be the jail's, without
            // the jail.
            return match (cpu, memory, pid_ns) {
                (Some(cpu), _, _) => Err(JailError::CpuFormat(cpu)),
                (_, Some(memory), _) => Err(JailError::MemoryFormat(memory)),
                (_, _, Some(pid_ns)) => Err(JailError::PidNsFormat(pid_ns)),
                (None, None, None) => {
                    // A network without a jail: Firecracker started in it, as
                    // `ip netns exec` starts it in a namespace on Linux.
                    if let Some(value) = netns {
                        // SAFETY: called first thing in main, with one thread.
                        unsafe { std::env::remove_var(NETNS_ENV) };
                        NETNS.set(open_netns(&value)?).expect("the jail is entered once");
                    }
                    // SAFETY: called first thing in main, with one thread.
                    unsafe { crate::ext::sandbox::prepare(None, None) }.map_err(JailError::Sandbox)
                }
            };
        };
        // SAFETY: called first thing in main, before any other thread exists.
        unsafe {
            std::env::remove_var(ENV);
            std::env::remove_var(CPU_ENV);
            std::env::remove_var(MEMORY_ENV);
            std::env::remove_var(PID_NS_ENV);
            std::env::remove_var(NETNS_ENV);
        }
        let value = value.to_string_lossy().into_owned();
        let Spec { uid, gid, root } = parse(&value)?;
        let cpu = cpu.as_deref().map(parse_cpu).transpose()?;
        let memory = memory.as_deref().map(parse_memory).transpose()?;
        match pid_ns.as_deref() {
            None => {}
            // Before the API process is made: it is in the namespace too.
            Some("1") => ignore_dropped_signals()?,
            Some(other) => return Err(JailError::PidNsFormat(other.to_owned())),
        }
        // SAFETY: no arguments.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return Err(JailError::NotRoot(euid));
        }
        // The jail's network, before the chroot hides it.
        if let Some(value) = netns {
            let opened = open_netns(&value)?;
            NETNS.set(opened).expect("the jail is entered once");
        }
        // The sandbox's profiles, compiled while there is one thread
        // (ext::sandbox::prepare says why).
        // SAFETY: called first thing in main, with one thread.
        unsafe { crate::ext::sandbox::prepare(Some(Path::new(&root)), self::netns()) }
            .map_err(JailError::Sandbox)?;
        let c_root = CString::new(root.as_str()).map_err(|_| JailError::Format(value.clone()))?;
        // SAFETY: NUL-terminated path.
        check(unsafe { libc::chroot(c_root.as_ptr()) })
            .map_err(|e| JailError::Chroot(root.clone(), e))?;
        // SAFETY: NUL-terminated path.
        check(unsafe { libc::chdir(c"/".as_ptr()) }).map_err(JailError::Chdir)?;
        // With a limit and the API on, the API process is made now, while
        // Firecracker is root and has one thread, with its share of the
        // limits (see the module's documentation).
        let mut own_cpu = cpu;
        let api = !std::env::args().any(|a| a == "--no-api");
        if api && (cpu.is_some() || memory.is_some()) {
            let ((vmm_cpu, api_cpu), (vmm_memory, api_memory)) = share(cpu, memory)?;
            let (ours, theirs) =
                std::os::unix::net::UnixStream::pair().map_err(JailError::ApiProcess)?;
            // SAFETY: called first thing in main, with one thread.
            match unsafe { libc::fork() } {
                -1 => return Err(JailError::ApiProcess(Error::last_os_error())),
                0 => {
                    drop(ours);
                    api_process(theirs, uid, gid, api_cpu, api_memory);
                }
                child => {
                    drop(theirs);
                    crate::ext::api_process::watch_child(child);
                }
            }
            if let Some(mib) = vmm_memory {
                limit_memory(mib)?;
            }
            own_cpu = vmm_cpu;
            crate::ext::api_process::set_waiting(ours);
        }
        drop_privileges(uid, gid)?;
        if let Some(percent) = own_cpu {
            limit_cpu(percent)?;
        }
        if let Some(percent) = cpu {
            CPU_LIMIT.set(percent).expect("the jail is entered once");
        }
        ROOT.set(PathBuf::from(root))
            .expect("the jail is entered once");
        Ok(())
    }

    /// `--new-pid-ns`: the signals a namespace's init does not get from
    /// outside are ignored ([`super::DROPPED_IN_PID_NS`]).
    pub(super) fn ignore_dropped_signals() -> Result<(), JailError> {
        for &signal in super::DROPPED_IN_PID_NS {
            // SAFETY: a valid signal number; SIG_IGN is no handler.
            if unsafe { libc::signal(signal, libc::SIG_IGN) } == libc::SIG_ERR {
                return Err(JailError::PidNs(signal, Error::last_os_error()));
            }
        }
        Ok(())
    }

    fn verify_dropped(uid: u32, gid: u32) -> Result<(), JailError> {
        // SAFETY: no arguments.
        let ids = unsafe { [libc::getuid(), libc::geteuid(), libc::getgid(), libc::getegid()] };
        if ids != [uid, uid, gid, gid] {
            return Err(JailError::StillPrivileged(format!(
                "uid {} euid {} gid {} egid {}",
                ids[0], ids[1], ids[2], ids[3]
            )));
        }
        let mut groups = [0 as libc::gid_t; 16];
        // SAFETY: the buffer holds 16 entries.
        let n = unsafe { libc::getgroups(16, groups.as_mut_ptr()) };
        let groups = usize::try_from(n).map(|n| &groups[..n]).unwrap_or(&[]);
        if groups.iter().any(|&g| g != gid) {
            return Err(JailError::StillPrivileged(format!("groups {groups:?}")));
        }
        // SAFETY: no pointers.
        if uid != 0 && unsafe { libc::setuid(0) } == 0 {
            return Err(JailError::StillPrivileged("setuid(0) succeeded".into()));
        }
        Ok(())
    }
}

/// Windows: the jailer (overlay/jailer/platform/windows) starts Firecracker
/// on a restricted token below medium integrity, with an initial impersonation token
/// (the same with the user's SID) on the main thread so the loader can start
/// the process, and the jail's root as the current directory (a drive of its
/// own). Entering the jail is reverting to the process token, then checking
/// that the thread impersonates no more and that the process token is the
/// jailer's restricted one: a process [`ENV`] reaches otherwise fails instead
/// of running with the user's identity.
///
/// The API server's HTTP side is a process of its own
/// ([`super::api_process`]). The jailer makes it as it makes Firecracker,
/// from the same binary on the same token in the same Job Object, so the
/// jail's limits cover both as one cgroup does, and hands each its end of
/// link: the API process listens, inside the jail, at the path it gets as
/// `WICK_API_LINK`; Firecracker connects there (`WICK_API_WAITING`), as
/// long as the API process runs (a handle to it, `WICK_API_PROCESS`). The
/// API process enters the jail as Firecracker does, then waits for its
/// server and never returns from here. Without the jailer, Firecracker
/// makes the API process itself (`api_process::split`), with
/// `WICK_API_LINK` and a handle to itself as `WICK_API_FIRECRACKER`, and a
/// process that finds `WICK_API_LINK` serves whether jailed or not.
#[cfg(windows)]
mod imp {
    use std::io::Error;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Threading::GetCurrentThread;

    use super::{ENV, JailError, Spec, parse};

    /// `TOKEN_QUERY` (winnt.h).
    const TOKEN_QUERY: u32 = 0x0008;

    // windows-sys gates these behind Win32_Security, which the vmm crate does
    // not otherwise need.
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RevertToSelf() -> i32;
        fn IsTokenRestricted(token: HANDLE) -> i32;
        fn OpenThreadToken(thread: HANDLE, access: u32, open_as_self: i32, token: *mut HANDLE)
        -> i32;
    }

    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    static NETNS: OnceLock<PathBuf> = OnceLock::new();

    pub fn root() -> Option<&'static Path> {
        ROOT.get().map(PathBuf::as_path)
    }

    pub fn netns() -> Option<&'static Path> {
        NETNS.get().map(PathBuf::as_path)
    }

    /// The API process's side: it serves, and never returns.
    fn serve_api() -> Result<(), JailError> {
        crate::ext::api_process::serve_if_api_process()
            .map_err(|e| JailError::ApiProcess(Error::other(e.to_string())))
    }

    pub fn enter() -> Result<(), JailError> {
        let api = std::env::var_os(crate::ext::api_process::LINK_ENV).is_some();
        let Some(value) = std::env::var_os(ENV) else {
            // Without the jailer, Firecracker made this API process.
            if api {
                serve_api()?;
            }
            return Ok(());
        };
        let netns = std::env::var_os(super::NETNS_ENV);
        // SAFETY: called first thing in main, before any other thread exists.
        unsafe { std::env::remove_var(ENV) };
        let value = value.to_string_lossy().into_owned();
        let Spec { root, .. } = parse(&value)?;
        // SAFETY: plain call.
        if unsafe { RevertToSelf() } == 0 {
            return Err(JailError::Revert(Error::last_os_error()));
        }
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: our own thread; an out-pointer.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
            // SAFETY: the token just opened.
            unsafe { CloseHandle(token) };
            return Err(JailError::StillPrivileged("the main thread still impersonates".into()));
        }
        // The jailed process may not open its own token (the token object's
        // DACL is the jailer's); `GetCurrentProcessToken()`, the pseudo handle
        // -4, may always query it.
        let process_token = -4isize as HANDLE;
        // SAFETY: the pseudo handle of our own process token.
        let restricted = unsafe { IsTokenRestricted(process_token) } != 0;
        if !restricted {
            return Err(JailError::StillPrivileged(
                "the process token is not restricted: not started by the jailer".into(),
            ));
        }
        ROOT.set(PathBuf::from(root)).expect("the jail is entered once");
        if let Some(netns) = netns {
            // SAFETY: as above, before any other thread.
            unsafe { std::env::remove_var(super::NETNS_ENV) };
            let dir = PathBuf::from(&netns);
            if !dir.is_absolute() {
                return Err(JailError::Format(format!(
                    "{}: {}",
                    super::NETNS_ENV,
                    netns.to_string_lossy()
                )));
            }
            NETNS.set(dir).expect("the jail is entered once");
        }
        // SAFETY: as above, before any other thread.
        unsafe { crate::ext::api_process::take_waiting() }
            .map_err(|e| JailError::ApiProcess(Error::other(e.to_string())))?;
        if api {
            // The jailer made this API process: in the jail now, it serves.
            serve_api()?;
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    use std::path::Path;

    use super::JailError;

    // On Linux the upstream jailer has done all of it before exec.
    pub fn root() -> Option<&'static Path> {
        None
    }

    pub fn enter() -> Result<(), JailError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn test_parse_windows() {
        assert_eq!(
            parse(r"0:0:\\?\C:\jail\firecracker.exe\a\root").unwrap().root,
            r"\\?\C:\jail\firecracker.exe\a\root"
        );
        assert_eq!(parse(r"0:0:C:\j").unwrap().root, r"C:\j");
        for bad in [r"0:0:j\root", r"0:0:\root"] {
            assert!(matches!(parse(bad), Err(JailError::Format(_))), "{bad:?}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_enter_needs_the_jailers_token() {
        // A process the jailer did not start (an unrestricted token) fails,
        // never runs on with the user's identity. `enter` removes the
        // variable, so this runs in a child process.
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ext::jail::tests::enter_child_windows", "--ignored", "--nocapture"])
            .env(ENV, r"0:0:C:\wick-no-jail")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{stdout}");
        assert!(stdout.contains("ENTER-REFUSED"), "{stdout}");
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "run by test_enter_needs_the_jailers_token in a separate process"]
    fn enter_child_windows() {
        assert!(matches!(enter(), Err(JailError::StillPrivileged(_))));
        assert!(std::env::var_os(ENV).is_none());
        assert!(root().is_none());
        println!("ENTER-REFUSED");
    }

    #[cfg(not(windows))]
    #[test]
    fn test_parse() {
        assert_eq!(
            parse("501:20:/srv/jail/firecracker/a:b/root").unwrap(),
            Spec {
                uid: 501,
                gid: 20,
                root: "/srv/jail/firecracker/a:b/root".into()
            }
        );
        for bad in ["", "1", "1:2", "1:2:", "1:2:rel", "x:2:/r", "1:-2:/r", "1:2:/r\0"] {
            assert!(matches!(parse(bad), Err(JailError::Format(_))), "{bad:?}");
        }
    }

    #[test]
    fn test_parse_cpu() {
        assert_eq!(parse_cpu("1").unwrap(), 1);
        assert_eq!(parse_cpu("255").unwrap(), 255);
        for bad in ["", "0", "256", "-1", "+5", " 5", "5%", "x"] {
            assert!(matches!(parse_cpu(bad), Err(JailError::CpuFormat(_))), "{bad:?}");
        }
    }

    #[test]
    fn test_parse_memory() {
        assert_eq!(parse_memory("1").unwrap(), 1);
        assert_eq!(parse_memory("4096").unwrap(), 4096);
        for bad in ["", "0", "-1", "+5", " 5", "5M", "x", "99999999999"] {
            assert!(matches!(parse_memory(bad), Err(JailError::MemoryFormat(_))), "{bad:?}");
        }
    }

    // The jail's limits, shared with the API process, add up to what the
    // jail allows, as one cgroup's would.
    #[test]
    fn test_limits_are_shared_with_the_api_process() {
        let ((vmm_cpu, api_cpu), (vmm_mem, api_mem)) = share(Some(50), Some(512)).unwrap();
        assert_eq!((vmm_cpu, api_cpu), (Some(49), Some(API_CPU_PERCENT)));
        assert_eq!((vmm_mem, api_mem), (Some(512 - API_MEMORY_MIB), Some(API_MEMORY_MIB)));
        assert_eq!(vmm_cpu.unwrap() + api_cpu.unwrap(), 50);
        assert_eq!(vmm_mem.unwrap() + api_mem.unwrap(), 512);
        assert_eq!(share(None, None).unwrap(), ((None, None), (None, None)));
        assert_eq!(share(Some(2), None).unwrap(), ((Some(1), Some(1)), (None, None)));
        assert!(matches!(share(Some(1), None), Err(JailError::CpuTooSmall(1))));
        assert!(matches!(share(None, Some(64)), Err(JailError::MemoryTooSmall(64))));
        assert_eq!(share(None, Some(65)).unwrap().1, (Some(33), Some(32)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_cpu_limit_holds() {
        // The limit stays with the process, so this runs in a child process.
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ext::jail::tests::cpu_limit_child", "--ignored", "--nocapture"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{stdout}");
        assert!(stdout.contains("CPU-LIMITED"), "{stdout}");
    }

    // The CPU limit's refill interval is a number of seconds (0 reads back
    // as 1): a CFS period, 1 ms to 1 s, below a second cannot be asked for.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_cpu_limit_refills_in_whole_seconds() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ext::jail::tests::cpu_refill_child", "--ignored", "--nocapture"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{stdout}");
        assert!(stdout.contains("REFILL 0->1 1->1 2->2"), "{stdout}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_cpu_limit_refills_in_whole_seconds in a separate process"]
    fn cpu_refill_child() {
        let got: Vec<u64> = [0, 1, 2].iter().map(|&i| imp::cpu_refill_interval(50, i)).collect();
        println!("REFILL 0->{} 1->{} 2->{}", got[0], got[1], got[2]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_cpu_limit_holds in a separate process"]
    fn cpu_limit_child() {
        use std::time::{Duration, Instant};
        fn cpu_time() -> Duration {
            // SAFETY: a zeroed rusage for getrusage to fill.
            let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
            // SAFETY: valid pointer.
            assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) }, 0);
            let tv = |t: libc::timeval| {
                Duration::new(t.tv_sec.try_into().unwrap(), u32::try_from(t.tv_usec).unwrap() * 1000)
            };
            tv(ru.ru_utime) + tv(ru.ru_stime)
        }
        imp::limit_cpu(10).unwrap();
        // Four threads spinning for 3 s would use up to 12 s of CPU time;
        // 10% of one CPU allows 0.3 s, plus a second's budget in hand.
        let start = (Instant::now(), cpu_time());
        let spinners: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(move || {
                    while start.0.elapsed() < Duration::from_secs(3) {
                        std::hint::spin_loop();
                    }
                })
            })
            .collect();
        for t in spinners {
            t.join().unwrap();
        }
        let used = cpu_time() - start.1;
        assert!(used < Duration::from_millis(600), "used {used:?} of CPU time");
        println!("CPU-LIMITED {used:?}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_enter_needs_root() {
        // A process that cannot chroot must fail, never run unjailed. The
        // variable is removed by `enter`, so this runs in a child process.
        // SAFETY: no arguments.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ext::jail::tests::enter_child", "--ignored", "--nocapture"])
            .env(ENV, "501:20:/var/empty")
            .env(CPU_ENV, "50")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{stdout}");
        assert!(stdout.contains("ENTER-REFUSED"), "{stdout}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_enter_needs_root in a separate process"]
    fn enter_child() {
        assert!(matches!(enter(), Err(JailError::NotRoot(_))));
        assert!(std::env::var_os(ENV).is_none());
        assert!(std::env::var_os(CPU_ENV).is_none());
        assert!(root().is_none());
        assert!(cpu_limit().is_none());
        println!("ENTER-REFUSED");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_cpu_limit_needs_the_jail() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ext::jail::tests::cpu_alone_child", "--ignored", "--nocapture"])
            .env_remove(ENV)
            .env(CPU_ENV, "50")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{stdout}");
        assert!(stdout.contains("CPU-ALONE-REFUSED"), "{stdout}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_cpu_limit_needs_the_jail in a separate process"]
    fn cpu_alone_child() {
        assert!(matches!(enter(), Err(JailError::CpuFormat(_))));
        println!("CPU-ALONE-REFUSED");
    }

    #[cfg(target_os = "macos")]
    fn run_child(name: &str, env: &[(&str, &str)]) -> String {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &format!("ext::jail::tests::{name}"), "--ignored", "--nocapture"])
            .env_remove(ENV)
            .envs(env.iter().copied())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "{name}: {:?}\n{stdout}", out.status);
        stdout
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_pid_ns_needs_the_jail() {
        let out = run_child("pid_ns_alone_child", &[(PID_NS_ENV, "1")]);
        assert!(out.contains("PID-NS-ALONE-REFUSED"), "{out}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_pid_ns_needs_the_jail in a separate process"]
    fn pid_ns_alone_child() {
        assert!(matches!(enter(), Err(JailError::PidNsFormat(_))));
        println!("PID-NS-ALONE-REFUSED");
    }

    // A network without the jail: Firecracker started in it (as `ip netns
    // exec` does on Linux) makes its endpoints there; a relative path or a
    // missing directory fails at start.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_netns_without_the_jail() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let path = dir.as_path().canonicalize().unwrap();
        let out = run_child("netns_alone_child", &[(NETNS_ENV, path.to_str().unwrap())]);
        assert!(out.contains("NETNS-ALONE-OK"), "{out}");
        for bad in ["relative", "/nonexistent/net"] {
            let out = run_child("netns_bad_child", &[(NETNS_ENV, bad)]);
            assert!(out.contains("NETNS-BAD-REFUSED"), "{bad}: {out}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_netns_without_the_jail in a separate process"]
    fn netns_alone_child() {
        let want = std::path::PathBuf::from(std::env::var_os(NETNS_ENV).unwrap());
        enter().unwrap();
        assert!(std::env::var_os(NETNS_ENV).is_none());
        assert_eq!(netns(), Some(want.as_path()));
        assert!(netns_dir().is_some());
        // An interface named without a path is an endpoint there.
        let tap = crate::platform::net::Tap::open_named("tap0").unwrap();
        assert!(want.join("tap0").exists());
        // The socket file stays when the device goes, as the API socket
        // does (platform::net, test_stale_endpoint_replaced).
        drop(tap);
        assert!(want.join("tap0").exists());
        println!("NETNS-ALONE-OK");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_netns_without_the_jail in a separate process"]
    fn netns_bad_child() {
        let err = enter().unwrap_err();
        assert!(matches!(err, JailError::Netns(..)), "{err}");
        assert!(netns().is_none());
        println!("NETNS-BAD-REFUSED");
    }

    // --new-pid-ns: what the kernel drops for a namespace's init, sent from
    // outside, has no effect; a handler installed later (upstream's, for
    // SIGHUP) gets its signal, as init's handler does on Linux.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_pid_ns_drops_unhandled_signals() {
        let out = run_child("pid_ns_signals_child", &[]);
        assert!(out.contains("PID-NS-SIGNALS-DROPPED"), "{out}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_pid_ns_drops_unhandled_signals in a separate process"]
    fn pid_ns_signals_child() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static HUP: AtomicBool = AtomicBool::new(false);
        extern "C" fn on_hup(_: libc::c_int) {
            HUP.store(true, Ordering::SeqCst);
        }
        imp::ignore_dropped_signals().unwrap();
        for &signal in DROPPED_IN_PID_NS {
            // SAFETY: a signal to this process, which ignores it.
            assert_eq!(unsafe { libc::kill(libc::getpid(), signal) }, 0);
        }
        // SAFETY: a handler that only stores to an atomic.
        unsafe { libc::signal(libc::SIGHUP, on_hup as *const () as libc::sighandler_t) };
        // SAFETY: as above, now handled.
        unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(HUP.load(Ordering::SeqCst));
        println!("PID-NS-SIGNALS-DROPPED");
    }
}
