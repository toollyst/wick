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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    println!("confine_probe: Linux and macOS only; ran nothing");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod common;

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "macos")]
fn main() {
    macos::main();
}

/// macOS (docs/design-fs.md §6.2): each case's child confines itself as
/// wick-fsd does (stage 0's checks, the backend on the share, then
/// `confine::macos::confine`) and tries one thing the server must never do.
/// The profile kills (SIGKILL) inside the denied call: exit code 137
/// (128 + 9). A refusal the backend gives itself is exit code 0.
#[cfg(target_os = "macos")]
mod macos {
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::path::{Path, PathBuf};

    use wick_fs_sys as sys;
    use wick_fs_sys::seatbelt::probe::{self, Ended, Fcntl, Forked, InShare};
    use wick_fsd::confine::macos::{Plan, confine};
    use wick_fsd::host::unix::{HostDir, Options};
    use wick_fsd::limits::Limits;
    use wick_fsd::stage0::{Share, check};

    use crate::common::remote::give_share;
    use crate::common::{remove, scratch};

    /// What a case is given: the outside directory, a file in the share, and
    /// the share's root descriptor.
    struct Ctx<'a> {
        outside: &'a Path,
        inside: &'a Path,
        root: BorrowedFd<'a>,
        /// The outside canary's `/.vol/<dev>/<ino>`, read before the
        /// profile (its `lstat` is a call the server does not make).
        vol: &'a Path,
    }

    type Act = fn(&Ctx<'_>) -> i32;

    /// Killed by the profile.
    const KILLED: i32 = 128 + 9;

    fn ok<T, E>(r: Result<T, E>) -> i32 {
        i32::from(r.is_ok())
    }

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
        // As wick-fsd's main: the soft limit what the share may hold.
        sys::set_nofile(wick_fsd::limits::descriptors(&shared.limits)).unwrap();
        let checked = match check(&shared, None) {
            Ok(c) => c,
            Err(r) => {
                eprintln!("stage 0: {}", r.0);
                return 2;
            }
        };
        let dir_root = checked.root.as_raw_fd();
        let inside = checked.canonical.join("inside");
        let canonical = checked.canonical.clone();
        let dir = match HostDir::new(checked.root, Options { case_insensitive_ok: true, ..Options::default() }) {
            Ok(d) => d,
            Err(r) => {
                eprintln!("{}", r.0);
                return 4;
            }
        };
        let Ok(root) = sys::open_root(&canonical) else { return 6 };
        let vol = by_volume_id(&outside.join("secret"));
        if let Err(r) = confine(plan, &canonical, &[dir_root, root.as_raw_fd()]) {
            eprintln!("{}", r.0);
            return 5;
        }
        let code = act(&Ctx {
            outside,
            inside: &inside,
            root: root.as_fd(),
            vol: &vol,
        });
        drop(dir);
        code
    }

    fn case(name: &str, share: &Path, outside: &Path, act: Act) -> i32 {
        match probe::fork().expect("fork (one thread)") {
            Forked::Child => probe::exit_now(confine_then(share, outside, act)),
            Forked::Parent(pid) => match probe::wait(pid).unwrap() {
                Ended::Exited(code) => {
                    println!("case {name}: exit {code}");
                    code
                }
                Ended::Signaled(s) => {
                    println!("case {name}: signal {s}");
                    128 + s
                }
            },
        }
    }

    /// [`probe::in_share`] on the share's file, opened as the server opens:
    /// 1 done, 0 refused by a rule (EPERM), 2 not done otherwise (the kernel
    /// or the file system's own error, or the bit not kept), 3 not opened.
    fn in_share(c: &Ctx<'_>, form: InShare) -> i32 {
        let Ok(f) = std::fs::File::open(c.inside) else { return 3 };
        match probe::in_share(form, c.root, f.as_fd(), c.inside) {
            Ok(()) => 1,
            Err(sys::HostErrno(libc_eperm)) if libc_eperm == EPERM => 0,
            Err(_) => 2,
        }
    }

    const EPERM: i32 = 1;

    /// [`probe::fcntl_command`] on the share's file: 1 done, 0 not.
    fn fcntl_on_file(c: &Ctx<'_>, command: Fcntl) -> i32 {
        let Ok(f) = std::fs::File::open(c.inside) else { return 3 };
        ok(probe::fcntl_command(f.as_fd(), command))
    }

    /// 3 MiB written, grown to 8 MiB by realloc, both ends read back: 1.
    fn realloc_past_copy_threshold() -> i32 {
        let mut v = vec![1u8; 3 << 20];
        v.reserve_exact(5 << 20);
        v.resize(8 << 20, 2);
        let v = std::hint::black_box(v);
        i32::from(v[(3 << 20) - 1] == 1 && v[(8 << 20) - 1] == 2)
    }

    /// `/.vol/<dev>/<ino>` of `path`: the same file by its volume id.
    fn by_volume_id(path: &Path) -> PathBuf {
        let m = std::fs::symlink_metadata(path).unwrap();
        PathBuf::from(format!("/.vol/{}/{}", m.dev(), m.ino()))
    }

    /// On record: each directory above `path`, with its mode and owner, and,
    /// as root, whether the id the child drops to (65534) may search it. A
    /// case by path reaches the profile only through directories it may
    /// search; one it may not is refused at that directory first (EACCES), so
    /// such a directory fails the probe here, naming it.
    fn searchable_above(path: &Path) {
        let root = sys::euid() == 0;
        let mut blocked = Vec::new();
        for dir in path.ancestors().skip(1) {
            let m = std::fs::metadata(dir).unwrap();
            let mode = m.mode() & 0o7777;
            let search = !root
                || mode & 0o001 != 0
                || (m.uid() == 65534 && mode & 0o100 != 0)
                || (m.gid() == 65534 && mode & 0o010 != 0);
            let by_65534 = if root { format!(", searchable by 65534: {search}") } else { String::new() };
            println!("above the canary: {} mode {mode:o} owner {}:{}{by_65534}", dir.display(), m.uid(), m.gid());
            if !search {
                blocked.push(dir.to_path_buf());
            }
        }
        assert!(
            blocked.is_empty(),
            "the id the child drops to cannot search {blocked:?}: the cases by path would be refused there, before the profile"
        );
    }

    pub fn main() {
        // As wick-fsd's first step: what this process was started with is
        // not the confined process's.
        sys::close_inherited(None).unwrap();
        let base = scratch("probe");
        let share = base.join("share");
        let outside = std::fs::canonicalize(&base).unwrap().join("outside");
        std::fs::create_dir(&share).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"canary").unwrap();
        std::fs::write(share.join("inside"), b"shared").unwrap();
        give_share(&share);
        if sys::euid() == 0 {
            // The share's file is the dropped id's, as an unprivileged run's
            // is that user's: a case on it is then refused by the profile,
            // not by the file's owner (fchflags, fchown and fchmod of
            // another user's file are EPERM before any rule).
            std::os::unix::fs::chown(share.join("inside"), Some(65534), Some(65534)).unwrap();
        }
        searchable_above(&outside.join("secret"));
        let cases: &[(&str, Act, i32)] = &[
            ("the outside canary by its path", |c| ok(std::fs::read(c.outside.join("secret"))), KILLED),
            // By the call the server makes for metadata (fstatat64, listed):
            // the file rule kills it, not the call's number.
            ("the outside canary's metadata", |c| ok(probe::fstatat_path(&c.outside.join("secret"))), KILLED),
            ("/etc/passwd", |_| ok(std::fs::read("/etc/passwd")), KILLED),
            ("the outside canary by /.vol", |c| ok(std::fs::read(c.vol)), KILLED),
            ("the outside canary by its firmlink alias", |c| {
                ok(std::fs::read(Path::new("/System/Volumes/Data").join(c.outside.join("secret").strip_prefix("/").unwrap())))
            }, KILLED),
            // A file of the share by its own path: the profile's rule.
            // Opened and read as the server reads (open, then pread).
            ("a file of the share by its path", |c| {
                ok(std::fs::File::open(c.inside).and_then(|f| f.read_at(&mut [0; 6], 0)))
            }, 1),
            ("exec", |_| ok(std::process::Command::new("/usr/bin/true").status()), KILLED),
            ("fork", |_| match probe::fork() {
                Ok(Forked::Child) => probe::exit_now(0),
                r => ok(r),
            }, KILLED),
            ("a TCP connection", |_| ok(std::net::TcpStream::connect("127.0.0.1:9")), KILLED),
            ("ptrace", |_| ok(probe::ptrace_traceme()), KILLED),
            ("a signal to another process", |_| ok(probe::signal_check(probe::parent())), KILLED),
            ("MAP_JIT", |_| ok(probe::mmap_jit()), KILLED),
            // mmap is not a call the server makes: killed at its number
            // (197), before file-map-executable is asked.
            ("a file of the share mapped executable", |c| {
                ok(std::fs::File::open(c.inside).map_err(drop).and_then(|f| probe::mmap_file_exec(f.as_fd()).map_err(drop)))
            }, KILLED),
            ("an anonymous executable mapping", |_| ok(probe::mmap_exec()), KILLED),
            ("a sysctl read", |_| ok(probe::sysctl_hostname()), KILLED),
            // The ask itself is a Mach trap and a MIG routine the profile
            // does not list, so it is killed before any rule on the port:
            // `(deny mach-priv-host-port)` in BASE, which the apply needs,
            // grants nothing.
            ("the host's privileged port", |_| ok(probe::host_priv_port()), KILLED),
            // mach_msg2_trap is allowed (libmalloc's); behind it, a kernel
            // MIG routine not listed is killed by the syscall-mig rule, and
            // a lookup through libxpc at a trap before its message
            // (mach_port_mod_refs, 19; both measured from crash reports,
            // docs/design-fs.md §6.2).
            ("a kernel MIG routine not listed (task_info)", |_| ok(probe::task_info()), KILLED),
            ("a bootstrap lookup", |_| ok(probe::bootstrap_look_up("com.apple.system.notification_center")), KILLED),
            // The share's operations refused there with an error, not the
            // kill (confine::macos::ERROR_IN_SHARE: LINK's evaluation reaches
            // them): each still refused, by its rule or before it, killed at
            // a call the server does not make.
            ("flags of a file of the share", |c| in_share(c, InShare::Flags), 0),
            ("owner of a file of the share", |c| in_share(c, InShare::Owner), 0),
            // The call returns and the bit is not kept (unconfined it is).
            ("set-user-id on a file of the share", |c| in_share(c, InShare::SetUgid), 2),
            ("a clone in the share", |c| in_share(c, InShare::Clone), 0),
            ("an ioctl on a file of the share", |c| in_share(c, InShare::Ioctl), 0),
            // By fsetattrlist, a call the server makes (SETATTR of the
            // times): the share's rule refuses it.
            ("Finder information of a file of the share", |c| in_share(c, InShare::FinderInfo), 0),
            // By fcntl, a call the server makes: the command is not one of
            // FCNTL_COMMANDS, so system-fcntl kills it before the share's
            // file-lock rule is asked.
            ("an fcntl lock on a file of the share", |c| in_share(c, InShare::FcntlLock), KILLED),
            // fcntl commands the server does not make, on a file of the
            // share (confine::macos::FCNTL_COMMANDS), and one it makes.
            ("fcntl F_GETPATH (the host path)", |c| fcntl_on_file(c, Fcntl::GetPath), KILLED),
            ("fcntl F_DUPFD", |c| fcntl_on_file(c, Fcntl::DupFd), KILLED),
            ("fcntl F_SETFL", |c| fcntl_on_file(c, Fcntl::SetFl), KILLED),
            ("fcntl F_GETFD", |c| fcntl_on_file(c, Fcntl::GetFd), 1),
            // Killed, not refused by the share's rule: what they ask is
            // decided outside the share (unconfined, the kernel refuses
            // them to this user too: on record below).
            ("a snapshot of the share's volume", |c| in_share(c, InShare::Snapshot), KILLED),
            ("chroot to the share", |c| in_share(c, InShare::Chroot), KILLED),
            ("revoke of a file of the share", |c| in_share(c, InShare::Revoke), KILLED),
            ("a lock on a file of the share", |c| in_share(c, InShare::Lock), KILLED),
            ("a fifo in the share", |c| in_share(c, InShare::Fifo), KILLED),
            // graftdmg and ungraftdmg on the share (confine::macos::
            // ERROR_IN_SHARE_IF_DEFINED): killed on every major at their
            // numbers (549, 555), which SYSCALLS does not list and Seatbelt
            // checks, before the kernel's entitlement check or macOS 26's
            // file-graft rule; macOS 15 has no file-graft operation at all.
            // Unconfined, the kernel refuses both (EPERM without
            // com.apple.private.vfs.graftdmg): on record below.
            ("a graft onto the share", |c| in_share(c, InShare::Graft), KILLED),
            ("an ungraft of the share", |c| in_share(c, InShare::Ungraft), KILLED),
            ("exec of a file of the share", |c| ok(std::process::Command::new(c.inside).status()), KILLED),
            // What the server's own allocations make, allowed: a block past
            // libmalloc's 2 MiB copy threshold grown by realloc, which is
            // `mach_vm_reallocate` where the kernel defines it (macOS 27.2,
            // measured) and a copy where it does not (macOS 15's libmalloc:
            // `vm_copy` beyond 2 MiB), so each major says here whether its
            // way is in the profile.
            ("a realloc of a block past 2 MiB", |_| realloc_past_copy_threshold(), 1),
            // `..` of the root is refused beneath it, by the backend's open.
            (".. beneath the root", |c| ok(sys::open_dir(c.root, b"..")), 0),
        ];
        let mut failed = Vec::new();
        // On record for confine::macos, step 4: Seatbelt refuses a second
        // profile over one with a denial (EPERM). Under wick-fsd's own
        // profile a second apply does not get that far: its mac-syscall is
        // killed.
        let second = match probe::fork().expect("fork (one thread)") {
            Forked::Child => {
                // The first with a denial: after `(allow default)` alone a
                // second profile is taken (measured on macOS 27.2), as if
                // none were in force.
                let first = sys::seatbelt::compile("(version 1)\n(allow default)\n(deny file-read* (literal \"/private/etc/hosts\"))\n").unwrap();
                let open = sys::seatbelt::compile("(version 1)\n(allow default)\n").unwrap();
                let first = sys::seatbelt::apply(&first).is_ok();
                let again = sys::seatbelt::apply(&open).is_err();
                probe::exit_now(i32::from(first && again));
            }
            Forked::Parent(pid) => probe::wait(pid).unwrap(),
        };
        println!("a second profile refused: {second:?}");
        if second != Ended::Exited(1) {
            failed.push(format!("a second profile: {second:?}, expected it refused"));
        }
        for &(name, act, want) in cases {
            let got = case(name, &share, &outside, act);
            if got != want {
                failed.push(format!("{name}: {got}, expected {want}"));
            }
        }
        // On record: the same calls unconfined, as this user, so that a
        // refusal above the kernel gives anyway (chroot, a snapshot without
        // its entitlement) is told apart from the profile's.
        let root_dir = std::fs::File::open(&share).unwrap();
        let file = std::fs::File::open(share.join("inside")).unwrap();
        for form in [InShare::Flags, InShare::Owner, InShare::SetUgid, InShare::Clone, InShare::Ioctl, InShare::Snapshot, InShare::Chroot, InShare::Revoke, InShare::Lock, InShare::Fifo, InShare::FinderInfo, InShare::FcntlLock, InShare::Graft, InShare::Ungraft] {
            let r = probe::in_share(form, root_dir.as_fd(), file.as_fd(), &share.join("inside"));
            println!("unconfined {form:?}: {r:?}");
        }
        // The two Mach cases unconfined: each works, so the kill above is the profile's.
        assert_eq!(probe::task_info(), Ok(()), "task_info unconfined");
        assert_eq!(probe::bootstrap_look_up("com.apple.system.notification_center"), Ok(()), "bootstrap lookup unconfined");
        let _ = std::fs::remove_file(share.join("clone"));
        let _ = std::fs::remove_file(share.join("fifo"));
        remove(&base);
        assert!(failed.is_empty(), "confine_probe: {failed:#?}");
        println!("confine_probe: {} cases ok", cases.len());
    }
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
