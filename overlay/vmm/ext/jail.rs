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

use std::path::Path;

/// Environment variable through which the jailer hands the jail over.
pub const ENV: &str = "WICK_JAIL";

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

    use super::{ENV, JailError, Spec, parse};

    static ROOT: OnceLock<PathBuf> = OnceLock::new();

    pub fn root() -> Option<&'static Path> {
        ROOT.get().map(PathBuf::as_path)
    }

    fn check(ret: libc::c_int) -> Result<(), Error> {
        if ret == 0 { Ok(()) } else { Err(Error::last_os_error()) }
    }

    pub fn enter() -> Result<(), JailError> {
        let Some(value) = std::env::var_os(ENV) else {
            return Ok(());
        };
        // SAFETY: called first thing in main, before any other thread exists.
        unsafe { std::env::remove_var(ENV) };
        let value = value.to_string_lossy().into_owned();
        let Spec { uid, gid, root } = parse(&value)?;
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
/// on a restricted, low integrity token, with an initial impersonation token
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
        assert!(root().is_none());
        println!("ENTER-REFUSED");
    }
}
