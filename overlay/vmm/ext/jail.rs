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

use std::path::Path;

/// Environment variable through which the jailer hands the jail over.
pub const ENV: &str = "WICK_JAIL";

/// Environment variable through which the jailer hands a CPU limit over.
pub const CPU_ENV: &str = "WICK_JAIL_CPU";

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

/// The CPU limit (percent of one CPU) [`enter`] applied, if any.
#[cfg(target_os = "macos")]
pub fn cpu_limit() -> Option<u8> {
    imp::cpu_limit()
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
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use super::{CPU_ENV, ENV, JailError, Spec, parse, parse_cpu};

    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    static CPU_LIMIT: OnceLock<u8> = OnceLock::new();

    pub fn root() -> Option<&'static Path> {
        ROOT.get().map(PathBuf::as_path)
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

    fn check(ret: libc::c_int) -> Result<(), Error> {
        if ret == 0 { Ok(()) } else { Err(Error::last_os_error()) }
    }

    pub fn enter() -> Result<(), JailError> {
        let cpu = std::env::var_os(CPU_ENV).map(|v| v.to_string_lossy().into_owned());
        let Some(value) = std::env::var_os(ENV) else {
            // A CPU limit alone would be the jail's, without the jail.
            return match cpu {
                Some(cpu) => Err(JailError::CpuFormat(cpu)),
                None => Ok(()),
            };
        };
        // SAFETY: called first thing in main, before any other thread exists.
        unsafe {
            std::env::remove_var(ENV);
            std::env::remove_var(CPU_ENV);
        }
        let value = value.to_string_lossy().into_owned();
        let Spec { uid, gid, root } = parse(&value)?;
        let cpu = cpu.as_deref().map(parse_cpu).transpose()?;
        // SAFETY: no arguments.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return Err(JailError::NotRoot(euid));
        }
        let c_root = CString::new(root.as_str()).map_err(|_| JailError::Format(value.clone()))?;
        // SAFETY: NUL-terminated path.
        check(unsafe { libc::chroot(c_root.as_ptr()) })
            .map_err(|e| JailError::Chroot(root.clone(), e))?;
        // SAFETY: NUL-terminated path.
        check(unsafe { libc::chdir(c"/".as_ptr()) }).map_err(JailError::Chdir)?;
        let groups = [gid];
        // SAFETY: a one-element group list.
        check(unsafe { libc::setgroups(1, groups.as_ptr()) })
            .map_err(|e| JailError::SetGroups(gid, e))?;
        // SAFETY: no pointers.
        check(unsafe { libc::setgid(gid) }).map_err(|e| JailError::SetGid(gid, e))?;
        // SAFETY: no pointers.
        check(unsafe { libc::setuid(uid) }).map_err(|e| JailError::SetUid(uid, e))?;
        verify_dropped(uid, gid)?;
        if let Some(percent) = cpu {
            limit_cpu(percent)?;
            CPU_LIMIT.set(percent).expect("the jail is entered once");
        }
        ROOT.set(PathBuf::from(root))
            .expect("the jail is entered once");
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

    pub fn root() -> Option<&'static Path> {
        ROOT.get().map(PathBuf::as_path)
    }

    pub fn enter() -> Result<(), JailError> {
        let Some(value) = std::env::var_os(ENV) else {
            return Ok(());
        };
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
}
