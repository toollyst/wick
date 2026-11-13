// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The standard library, with `std::os::unix` and `std::os::fd` on Windows.
//!
//! A crate root that declares
//!
//! ```ignore
//! #[cfg(windows)]
//! extern crate wick_std as std;
//! ```
//!
//! resolves every `std::` path in the crate through this crate: everything
//! is the real standard library (re-exported), except that `std::os` also
//! has `unix` and `fd` from `wick_os`, wick's implementation of them on
//! Windows, and that on Windows `std::io::stdin`, `std::io::Stdin`,
//! `std::io::stdout` and `std::io::Stdout` are `wick_os::stdio`'s: an empty
//! non-blocking pipe reads as `EWOULDBLOCK`, as on Linux, not as the end
//! (Firecracker's serial input), and a write to a full non-blocking pipe fails
//! with `EWOULDBLOCK`, as on Linux, not with 0 bytes written (its serial
//! output and its logger); and `std::fs`'s opening calls fail with `EMFILE`
//! past the jailer's `--resource-limit no-file=` ([`fs`]). Macros
//! (`println!`, `vec!`, ...) still come from the real `std`, so
//! `print!`/`println!` write through std's own buffer.
//!
//! On Windows `std::os::raw::c_long` and `c_ulong` are also 64 bits wide: the
//! upstream crates use them in bindings of Linux kernel ABIs (`ifreq`,
//! io_uring, ...), whose layout is LP64; LLP64 Windows would make them 32
//! bits and change those layouts. The compatibility kvm-bindings fix them the
//! same way. Nothing in those crates calls a Windows C API with them.
//!
//! On other systems the real modules are re-exported unchanged.

pub use std::*;

/// `std::io`, with `stdin`, `Stdin`, `stdout` and `Stdout` from
/// `wick_os::stdio` on Windows (the names shadow the glob's).
#[cfg(windows)]
pub mod io {
    pub use std::io::*;

    pub use wick_os::stdio::{Stdin, Stdout, stdin, stdout};
}

/// `std::fs`. On Windows, the calls that make a descriptor on Linux fail
/// with `EMFILE` (the compat libc's, `WSAEMFILE`) past the jailer's
/// `--resource-limit no-file=`, before they open anything, as an `open`
/// past `RLIMIT_NOFILE` does (crates/compat/libc/src/windows_nofile.rs):
/// `OpenOptions::open`, `read`, `read_to_string`, `write`, `copy` (two
/// descriptors) and `read_dir`. `File::open`, `File::create` and
/// `File::try_clone` are std's own: shadowing them would replace `File`, the
/// type every crate shares, so they are counted and not refused.
///
/// A path may name a pipe (`\\.\pipe\<name>`, the counterpart of a FIFO for
/// the log, the metrics and a serial device's output), and whoever made a
/// pipe is its server, who may act as a client that opens it: "The
/// SecurityImpersonation level is the default for named pipe, RPC, and DDE
/// servers" (Microsoft Learn, Impersonation Levels), and `CreateFile` asks
/// for another level only with `SECURITY_SQOS_PRESENT` (CreateFileW,
/// `dwFlagsAndAttributes`). So `OpenOptions::open`, `read`,
/// `read_to_string` and `write` open at the anonymous level
/// (`SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS`: "The server cannot
/// impersonate or identify the client"), whatever the path names
/// (`test_a_pipe_opened_by_path_gives_its_maker_no_identity`). For a file
/// the same bit is `FILE_FLAG_OPEN_NO_RECALL`, which leaves a file of
/// remote storage where it is (CreateFileW). Not covered: `copy`
/// (`CopyFileEx` opens both files itself) and std's own `File::open` and
/// `File::create`.
pub mod fs {
    pub use std::fs::*;

    #[cfg(windows)]
    pub use self::windows::{OpenOptions, copy, read, read_dir, read_to_string, write};

    #[cfg(windows)]
    mod windows {
        use std::fs::{File, ReadDir};
        use std::io;
        use std::path::Path;

        use wick_os::windows::nofile::check;

        /// `SECURITY_ANONYMOUS` (winbase.h: `SecurityAnonymous << 16`).
        const SECURITY_ANONYMOUS: u32 = 0;

        /// `std::fs::OpenOptions`, whose `open` fails with `EMFILE` past the
        /// no-file limit and gives a pipe's maker no identity.
        #[derive(Clone, Debug)]
        pub struct OpenOptions(std::fs::OpenOptions);

        impl Default for OpenOptions {
            fn default() -> Self {
                Self::new()
            }
        }

        impl OpenOptions {
            /// `std::fs::OpenOptions::new`, at the anonymous impersonation
            /// level (the module's comment); `security_qos_flags` sets
            /// another.
            pub fn new() -> Self {
                let mut options = std::fs::OpenOptions::new();
                // std adds SECURITY_SQOS_PRESENT itself.
                std::os::windows::fs::OpenOptionsExt::security_qos_flags(&mut options, SECURITY_ANONYMOUS);
                OpenOptions(options)
            }
            /// `std::fs::OpenOptions::read`.
            pub fn read(&mut self, read: bool) -> &mut Self {
                self.0.read(read);
                self
            }
            /// `std::fs::OpenOptions::write`.
            pub fn write(&mut self, write: bool) -> &mut Self {
                self.0.write(write);
                self
            }
            /// `std::fs::OpenOptions::append`.
            pub fn append(&mut self, append: bool) -> &mut Self {
                self.0.append(append);
                self
            }
            /// `std::fs::OpenOptions::truncate`.
            pub fn truncate(&mut self, truncate: bool) -> &mut Self {
                self.0.truncate(truncate);
                self
            }
            /// `std::fs::OpenOptions::create`.
            pub fn create(&mut self, create: bool) -> &mut Self {
                self.0.create(create);
                self
            }
            /// `std::fs::OpenOptions::create_new`.
            pub fn create_new(&mut self, create_new: bool) -> &mut Self {
                self.0.create_new(create_new);
                self
            }
            /// `std::fs::OpenOptions::open`; `EMFILE` past the no-file limit.
            pub fn open<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
                check(1)?;
                self.0.open(path)
            }
        }

        impl std::os::windows::fs::OpenOptionsExt for OpenOptions {
            fn access_mode(&mut self, access: u32) -> &mut Self {
                self.0.access_mode(access);
                self
            }
            fn share_mode(&mut self, val: u32) -> &mut Self {
                self.0.share_mode(val);
                self
            }
            fn custom_flags(&mut self, flags: u32) -> &mut Self {
                self.0.custom_flags(flags);
                self
            }
            fn attributes(&mut self, val: u32) -> &mut Self {
                self.0.attributes(val);
                self
            }
            fn security_qos_flags(&mut self, flags: u32) -> &mut Self {
                self.0.security_qos_flags(flags);
                self
            }
        }

        /// `std::fs::read`; `EMFILE` past the no-file limit.
        pub fn read<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            io::Read::read_to_end(&mut OpenOptions::new().read(true).open(path)?, &mut bytes)?;
            Ok(bytes)
        }

        /// `std::fs::read_to_string`; `EMFILE` past the no-file limit.
        pub fn read_to_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
            let mut text = String::new();
            io::Read::read_to_string(&mut OpenOptions::new().read(true).open(path)?, &mut text)?;
            Ok(text)
        }

        /// `std::fs::write`; `EMFILE` past the no-file limit.
        pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
            let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(path)?;
            io::Write::write_all(&mut file, contents.as_ref())
        }

        /// `std::fs::copy`; `EMFILE` unless two descriptors fit, as Linux
        /// opens both files.
        pub fn copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<u64> {
            check(2)?;
            std::fs::copy(from, to)
        }

        /// `std::fs::read_dir`; `EMFILE` past the no-file limit (Linux's
        /// `opendir` holds a descriptor, as the search handle is held here).
        pub fn read_dir<P: AsRef<Path>>(path: P) -> io::Result<ReadDir> {
            check(1)?;
            std::fs::read_dir(path)
        }
    }
}

/// `std::os`, plus `unix` and `fd` on Windows.
pub mod os {
    pub use std::os::*;

    #[cfg(windows)]
    pub use wick_os::{fd, unix};

    /// What a Linux FIFO does for its writer, on a named pipe
    /// (`wick_os::fifo`): Firecracker's log, metrics and serial output.
    #[cfg(windows)]
    pub use wick_os::fifo;

    /// `std::os::raw`, with 64-bit `c_long` and `c_ulong` on Windows.
    #[cfg(windows)]
    pub mod raw {
        pub use std::os::raw::*;

        /// `long` of the Linux LP64 ABI.
        #[allow(non_camel_case_types)]
        pub type c_long = i64;
        /// `unsigned long` of the Linux LP64 ABI.
        #[allow(non_camel_case_types)]
        pub type c_ulong = u64;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_reexports_std() {
        let v: super::vec::Vec<u8> = super::vec![1];
        assert_eq!(super::mem::size_of_val(&v[0]), 1);
        #[cfg(windows)]
        let _: Option<super::os::unix::net::UnixStream> = None;
        #[cfg(windows)]
        assert_eq!(super::mem::size_of::<super::os::raw::c_ulong>(), 8);
        // The standard input and output are wick-os's, the rest of io std's.
        #[cfg(windows)]
        let _: wick_os::stdio::Stdin = super::io::stdin();
        #[cfg(windows)]
        let _: wick_os::stdio::Stdout = super::io::stdout();
        let _: super::io::ErrorKind = std::io::ErrorKind::WouldBlock;
        assert_eq!(super::mem::size_of::<super::os::raw::c_int>(), 4);
    }

    /// `std::fs`'s calls that make a descriptor on Linux fail with EMFILE
    /// (`WSAEMFILE`, the compat libc's) under a `--resource-limit no-file=`
    /// below the process's handles (`WICK_NO_FILE`, which the Windows jailer
    /// sets), as an `open` past `RLIMIT_NOFILE` does. Run in a process of
    /// its own: the limit is the process's.
    #[cfg(windows)]
    #[test]
    fn test_fs_opens_fail_with_emfile_past_the_limit() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::nofile_child", "--ignored", "--nocapture", "--test-threads=1"])
            .env("WICK_NO_FILE", "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();
        let text = std::format!(
            "{}{}",
            std::string::String::from_utf8_lossy(&out.stdout),
            std::string::String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success() && text.contains("nofile child: ok"), "exit {:?}: {text}", out.status.code());
    }

    /// A path Firecracker opens may name a pipe, whose maker is then its
    /// server: `fs`'s opens give it no identity to act with
    /// (`ImpersonateNamedPipeClient` is refused, or the thread's token is
    /// at the anonymous level), where std's own open, the control, gives
    /// the impersonation level.
    #[cfg(windows)]
    #[test]
    fn test_a_pipe_opened_by_path_gives_its_maker_no_identity() {
        use std::os::windows::ffi::OsStrExt;
        type Handle = *mut core::ffi::c_void;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CreateNamedPipeW(
                name: *const u16,
                open: u32,
                mode: u32,
                instances: u32,
                out: u32,
                input: u32,
                timeout: u32,
                sa: *const core::ffi::c_void,
            ) -> Handle;
            fn ReadFile(h: Handle, buf: *mut u8, len: u32, read: *mut u32, ov: *mut core::ffi::c_void) -> i32;
            fn CloseHandle(h: Handle) -> i32;
            fn GetCurrentThread() -> Handle;
            fn GetLastError() -> u32;
        }
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn ImpersonateNamedPipeClient(pipe: Handle) -> i32;
            fn RevertToSelf() -> i32;
            fn OpenThreadToken(thread: Handle, access: u32, as_self: i32, token: *mut Handle) -> i32;
            fn GetTokenInformation(token: Handle, class: i32, info: *mut core::ffi::c_void, len: u32, ret: *mut u32) -> i32;
        }
        const PIPE_ACCESS_DUPLEX: u32 = 3;
        const TOKEN_QUERY: u32 = 8;
        const TOKEN_IMPERSONATION_LEVEL: i32 = 9;

        // What the maker of a pipe gets of the client `open` gives, once
        // that client wrote a byte: the refusal's error code, or the level
        // (0 anonymous, 1 identification, 2 impersonation).
        let level_of = |name: &str, open: &dyn Fn(&std::path::Path) -> std::io::Result<std::fs::File>| -> Result<i32, u32> {
            let path = std::path::PathBuf::from(std::format!(r"\\.\pipe\wick-std-sqos-{}-{name}", std::process::id()));
            let wide: std::vec::Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
            // SAFETY: a NUL-terminated name; a byte pipe of one instance.
            let server =
                unsafe { CreateNamedPipeW(wide.as_ptr(), PIPE_ACCESS_DUPLEX, 0, 1, 4096, 4096, 0, core::ptr::null()) };
            assert!(!server.is_null() && server as isize != -1, "{}", std::io::Error::last_os_error());
            let client = open(&path).unwrap();
            std::io::Write::write_all(&mut &client, b"x").unwrap();
            // SAFETY: plain calls on this thread and our handles; the
            // thread is itself again before the block ends.
            unsafe {
                let (mut byte, mut n) = (0u8, 0u32);
                assert_ne!(ReadFile(server, &mut byte, 1, &mut n, core::ptr::null_mut()), 0);
                let result = if ImpersonateNamedPipeClient(server) == 0 {
                    Err(GetLastError())
                } else {
                    let mut token: Handle = core::ptr::null_mut();
                    let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token);
                    let open_error = GetLastError();
                    let (mut level, mut len) = (0i32, 0u32);
                    let got = opened != 0
                        && GetTokenInformation(token, TOKEN_IMPERSONATION_LEVEL, (&raw mut level).cast(), 4, &mut len)
                            != 0;
                    let level_error = GetLastError();
                    assert_ne!(RevertToSelf(), 0, "the thread could not be itself again");
                    if opened == 0 {
                        Err(open_error)
                    } else {
                        CloseHandle(token);
                        if got { Ok(level) } else { Err(level_error) }
                    }
                };
                drop(client);
                CloseHandle(server);
                result
            }
        };
        let control = level_of("control", &|p| std::fs::OpenOptions::new().read(true).write(true).open(p));
        // `fs::read`, `read_to_string` and `write` open through the same
        // `OpenOptions`.
        let options = level_of("options", &|p| super::fs::OpenOptions::new().read(true).write(true).open(p));
        std::println!("SQOSTEST std: std's own open: {control:?}; fs::OpenOptions: {options:?}");
        assert_eq!(control, Ok(2), "the control: std's own open of a pipe");
        assert!(matches!(options, Err(_) | Ok(0)), "the pipe's maker got level {options:?} of Firecracker");
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "run by test_fs_opens_fail_with_emfile_past_the_limit, in a process of its own"]
    fn nofile_child() {
        if std::env::var_os("WICK_NO_FILE").is_none() {
            return;
        }
        const EMFILE: i32 = 10024;
        let exe = std::env::current_exe().unwrap();
        let copy = std::env::temp_dir().join(std::format!("wick-std-nofile-{}", std::process::id()));
        let check = |what: &str, r: std::io::Result<()>| {
            let err = r.expect_err(what);
            assert_eq!(err.raw_os_error(), Some(EMFILE), "{what}: {err}");
        };
        check("OpenOptions::open", super::fs::OpenOptions::new().read(true).open(&exe).map(drop));
        check("fs::read", super::fs::read(&exe).map(drop));
        check("fs::read_to_string", super::fs::read_to_string(&exe).map(drop));
        check("fs::write", super::fs::write(&copy, b"x"));
        check("fs::copy", super::fs::copy(&exe, &copy).map(drop));
        check("fs::read_dir", super::fs::read_dir(std::env::temp_dir()).map(drop));
        assert!(!copy.exists(), "a refused call made {copy:?}");
        std::println!("nofile child: ok");
    }
}
