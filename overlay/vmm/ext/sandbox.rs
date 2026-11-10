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
//! The macOS sandbox restricts what the process can ask the kernel for, not
//! which paths it touches (guest images, snapshots and sockets are chosen by the
//! operator at run time): no program execution, no fork, no IP networking, no
//! Mach service lookups, no IOKit, no sysctl writes.
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
pub use macos::{PROFILE, apply, select};

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
    use std::sync::Mutex;

    use super::{Policy, SandboxError};

    /// Seatbelt profile installed by default on macOS.
    pub const PROFILE: &str = r#"(version 1)
(deny default)
; Files: guest kernels, disks, snapshots, logs, metrics and the API socket are
; chosen by the operator, also after start-up (hot-plug, snapshots).
(allow file-read* file-write* file-ioctl)
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
        let profile = std::ffi::CString::new(PROFILE).expect("profile has no NUL");
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
        state.installed = true;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use std::process::Command;

        use super::*;

        // The sandbox is permanent, so it is tested in a child process
        // (the test binary itself, filtered to the child test below).
        #[test]
        fn test_sandbox_restricts_child() {
            let exe = std::env::current_exe().unwrap();
            let out = Command::new(exe)
                .args([
                    "--exact",
                    "ext::sandbox::macos::tests::sandboxed_child",
                    "--ignored",
                    "--nocapture",
                ])
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
