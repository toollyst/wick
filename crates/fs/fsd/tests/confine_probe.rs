// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The confined process from the inside (docs/design-fs.md §6.1, rows 4 and
//! 8): each case forks a child that confines itself exactly as wick-fsd does
//! (`confine::linux::enter`, the backend on the new root, `lock`) and then
//! tries one thing the server must never be able to do. A call outside the
//! seccomp list ends the confined process with SIGSYS, which the waiting
//! stage-0 parent turns into exit code 159 (128 + 31); a refusal the
//! confinement gives (a path outside the share that is not there, `..`
//! refused beneath the root) is exit code 0.
//!
//! Not a libtest harness (`harness = false` in Cargo.toml): `fork` needs a
//! process with one thread, and libtest runs tests on threads.

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("confine_probe: Linux only; ran nothing");
}

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
    use std::path::Path;

    use wick_fs_sys as sys;
    use wick_fs_sys::confine::probe::Form;
    use wick_fs_sys::confine::{self as c, probe};
    use wick_fsd::confine::linux::{Plan, enter, lock};
    use wick_fsd::host::unix::{HostDir, Options};
    use wick_fsd::limits::Limits;
    use wick_fsd::stage0::{Share, check};

    use crate::common::remote::{give_share, userns_restricted};
    use crate::common::{remove, scratch};

    type Act = fn(&Path, BorrowedFd<'_>) -> i32;

    /// What a case leaves: SIGSYS (killed by the filter) or a clean exit.
    const KILLED: i32 = 128 + 31;

    fn confine_then(share: &Path, outside: &Path, act: Act) -> i32 {
        let plan = Plan {
            read_only: false,
            drop_to: (sys::euid() == 0).then_some((65534, 65534)),
        };
        let shared = Share {
            dir: share.to_path_buf(),
            read_only: false,
            case_insensitive_ok: true,
            limits: Limits {
                max_nodes: 256,
                max_handles: 16,
                ..Limits::default()
            },
        };
        // As wick-fsd's main: the soft limit what the share may hold, the
        // read-back's bound.
        sys::set_nofile(wick_fsd::limits::descriptors(&shared.limits)).unwrap();
        let checked = match check(&shared, None) {
            Ok(c) => c,
            Err(r) => {
                eprintln!("stage 0: {}", r.0);
                return 2;
            }
        };
        let (root, (), watch) = match enter(checked, plan, (), &[]) {
            Ok(x) => x,
            Err(r) => {
                eprintln!("{}", r.0);
                return 3;
            }
        };
        let dir_root = root.as_raw_fd();
        let dir = match HostDir::new(root, Options { case_insensitive_ok: true, ..Options::default() }) {
            Ok(d) => d,
            Err(r) => {
                eprintln!("{}", r.0);
                return 4;
            }
        };
        // A descriptor of the root for the cases (opened before the filter,
        // which has no openat).
        let Ok(root) = sys::open_root(Path::new("/")) else { return 6 };
        if let Err(r) = lock(plan, watch, &[dir_root, root.as_raw_fd()]) {
            eprintln!("{}", r.0);
            return 5;
        }
        let code = act(outside, root.as_fd());
        drop(dir);
        code
    }

    /// Runs `act` in a confined child: the code it exited with.
    fn case(name: &str, share: &Path, outside: &Path, act: Act) -> i32 {
        match c::fork().expect("fork (one thread)") {
            c::Forked::Child => {
                let code = confine_then(share, outside, act);
                #[allow(clippy::exit, reason = "the forked child of a case ends here")]
                std::process::exit(code);
            }
            c::Forked::Parent(pid) => match c::wait(pid).unwrap() {
                c::Ended::Exited(code) => {
                    println!("case {name}: exit {code}");
                    code
                }
                c::Ended::Signaled(s) => {
                    println!("case {name}: signal {s}");
                    128 + s
                }
            },
        }
    }

    pub fn main() {
        // As wick-fsd's first step: what this process was started with is
        // not the confined process's (a CI runner leaves descriptors open).
        sys::close_inherited(None).unwrap();
        if let Some(restricted) = userns_restricted() {
            println!("confine_probe: ran nothing confined: {restricted} (server.rs checks the refusal)");
            return;
        }
        let base = scratch("probe");
        let share = base.join("share");
        let outside = base.join("outside");
        std::fs::create_dir(&share).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"canary").unwrap();
        give_share(&share);
        let cases: &[(&str, Act, i32)] = &[
            // Row 8: no file handles, whatever the capabilities.
            ("open_by_handle_at", |_, _| i32::from(probe::open_by_handle().is_ok()), KILLED),
            // Opens go through openat2 beneath a held directory only.
            ("openat of /etc/passwd", |_, _| i32::from(probe::openat(Path::new("/etc/passwd")).is_ok()), KILLED),
            ("socket(AF_INET)", |_, _| i32::from(probe::socket_inet().is_ok()), KILLED),
            ("execve", |_, _| i32::from(probe::execve_true().is_ok()), KILLED),
            ("ptrace", |_, _| i32::from(probe::ptrace_traceme().is_ok()), KILLED),
            ("executable mmap", |_, _| i32::from(probe::mmap_exec().is_ok()), KILLED),
            // The host outside the share is not in the confined root: a
            // stat of the canary's host path finds nothing.
            ("the outside canary by its host path", |outside, _| {
                i32::from(std::fs::symlink_metadata(outside.join("secret")).is_ok())
            }, 0),
            ("/etc/passwd by stat", |_, _| i32::from(std::fs::symlink_metadata("/etc/passwd").is_ok()), 0),
            // `..` of the root is refused beneath it.
            ("openat2 of .. beneath the root", |_, root| i32::from(sys::open_dir(root, b"..").is_ok()), 0),
            // The argument rules: each form the server never makes of a call
            // it does make (docs/design-fs.md §6.1, step 9).
            ("utimensat with a path", |_, root| i32::from(probe::form(root, Form::UtimensatPath).is_ok()), KILLED),
            ("linkat AT_SYMLINK_FOLLOW", |_, root| i32::from(probe::form(root, Form::LinkatFollow).is_ok()), KILLED),
            ("linkat AT_EMPTY_PATH", |_, root| i32::from(probe::form(root, Form::LinkatEmptyPath).is_ok()), KILLED),
            ("newfstatat following a link", |_, root| i32::from(probe::form(root, Form::FstatatFollow).is_ok()), KILLED),
            ("statx following a link", |_, root| i32::from(probe::form(root, Form::StatxFollow).is_ok()), KILLED),
            ("unlinkat with another flag", |_, root| i32::from(probe::form(root, Form::UnlinkatFlag).is_ok()), KILLED),
            ("mkdirat with another mode", |_, root| i32::from(probe::form(root, Form::MkdiratMode).is_ok()), KILLED),
            ("renameat2 RENAME_WHITEOUT", |_, root| i32::from(probe::form(root, Form::RenameWhiteout).is_ok()), KILLED),
            ("fchmod setuid", |_, root| i32::from(probe::form(root, Form::FchmodSetuid).is_ok()), KILLED),
        ];
        let mut failed = Vec::new();
        for &(name, act, want) in cases {
            let got = case(name, &share, &outside, act);
            if got != want {
                failed.push(format!("{name}: {got}, expected {want}"));
            }
        }
        remove(&base);
        assert!(failed.is_empty(), "confine_probe: {failed:#?}");
        println!("confine_probe: {} cases ok", cases.len());
    }
}
