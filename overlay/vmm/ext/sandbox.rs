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
    /// Custom seccomp-BPF filters can only be enforced on Linux
    CustomFilterUnsupported,
}

#[cfg(target_os = "macos")]
pub use macos::{FILES_ANYWHERE, PROFILE, apply, files_in_jail, profile, select};

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
"#;

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
        Ok(format!("{PROFILE}{files}"))
    }

    unsafe extern "C" {
        // libsystem_sandbox (part of libSystem). Deprecated in the SDK headers but
        // still the documented way to apply an SBPL profile string.
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    struct State {
        policy: Policy,
        installed: bool,
    }

    static STATE: Mutex<State> = Mutex::new(State {
        policy: Policy::None,
        installed: false,
    });

    /// Selects the sandbox to install. Called once at start-up from the seccomp configuration.
    pub fn select(policy: Policy) {
        STATE.lock().unwrap().policy = policy;
    }

    /// Installs the selected sandbox if it is not installed yet.
    pub fn apply() -> Result<(), SandboxError> {
        let mut state = STATE.lock().unwrap();
        if state.policy == Policy::None || state.installed {
            return Ok(());
        }
        install(&profile()?)?;
        state.installed = true;
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
        fn run_child(name: &str, env: &[(&str, &str)]) {
            let exe = std::env::current_exe().unwrap();
            let out = Command::new(exe)
                .args([
                    "--exact",
                    &format!("ext::sandbox::macos::tests::{name}"),
                    "--ignored",
                    "--nocapture",
                ])
                .envs(env.iter().copied())
                .output()
                .unwrap();
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
            install(&format!("{PROFILE}{}", files_in_jail(&jail).unwrap())).unwrap();
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
            // Program execution and IP networking are denied.
            std::process::Command::new("/bin/echo")
                .output()
                .unwrap_err();
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
