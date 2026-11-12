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

        /// `std::fs::OpenOptions`, whose `open` fails with `EMFILE` past the
        /// no-file limit.
        #[derive(Clone, Debug)]
        pub struct OpenOptions(std::fs::OpenOptions);

        impl Default for OpenOptions {
            fn default() -> Self {
                Self::new()
            }
        }

        impl OpenOptions {
            /// `std::fs::OpenOptions::new`.
            pub fn new() -> Self {
                OpenOptions(std::fs::OpenOptions::new())
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
            check(1)?;
            std::fs::read(path)
        }

        /// `std::fs::read_to_string`; `EMFILE` past the no-file limit.
        pub fn read_to_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
            check(1)?;
            std::fs::read_to_string(path)
        }

        /// `std::fs::write`; `EMFILE` past the no-file limit.
        pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
            check(1)?;
            std::fs::write(path, contents)
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
