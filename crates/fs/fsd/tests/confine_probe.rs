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

    /// How a case's child confines itself.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum How {
        /// As wick-fsd does (`confine::macos::confine`).
        Confined,
        /// wick-fsd's profile with every system call, Mach trap and MIG
        /// routine it does not list allowed and reported instead of killed
        /// (the discovery build's rule): on record only, what a case calls,
        /// named in the unified log by the case's pid.
        Reported,
    }

    fn confine_then(share: &Path, outside: &Path, act: Act, how: How) -> i32 {
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
        let confined = match how {
            How::Confined => confine(plan, &canonical, &[dir_root, root.as_raw_fd()]).map_err(|r| r.0),
            How::Reported => reported(&canonical),
        };
        if let Err(r) = confined {
            eprintln!("{r}");
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

    /// wick-fsd's profile for `canonical`, with the discovery build's rule
    /// added: what it does not list is allowed and reported.
    fn reported(canonical: &Path) -> Result<(), String> {
        let profile = wick_fsd::confine::macos::profile(canonical, false).map_err(|r| r.0)?
            + "(allow syscall-unix syscall-mach syscall-mig (with report))\n";
        let compiled = sys::seatbelt::compile(&profile)?;
        sys::seatbelt::apply(&compiled).map_err(|e| format!("applying the reporting profile: {e:?}"))
    }

    fn case(name: &str, share: &Path, outside: &Path, act: Act) -> i32 {
        case_as(name, share, outside, act, How::Confined).0
    }

    /// A case's exit code (killed: 128 + the signal) and its child's pid,
    /// which Seatbelt's reports name.
    fn case_as(name: &str, share: &Path, outside: &Path, act: Act, how: How) -> (i32, i32) {
        match probe::fork().expect("fork (one thread)") {
            Forked::Child => probe::exit_now(confine_then(share, outside, act, how)),
            Forked::Parent(pid) => {
                let code = match probe::wait(pid).unwrap() {
                    Ended::Exited(code) => {
                        println!("case {name} (pid {pid}): exit {code}");
                        code
                    }
                    Ended::Signaled(s) => {
                        println!("case {name} (pid {pid}): signal {s}");
                        128 + s
                    }
                };
                (code, pid)
            }
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

    /// `from` bytes written, grown to `to` by realloc, both ends read back,
    /// then freed: 1.
    fn realloc_then_free(from: usize, to: usize) -> i32 {
        let mut v = vec![1u8; from];
        v.reserve_exact(to - from);
        v.resize(to, 2);
        let v = std::hint::black_box(v);
        let done = v[from - 1] == 1 && v[to - 1] == 2;
        drop(v);
        i32::from(done)
    }

    /// How many times a shape repeats in one child: from the second time on
    /// the allocator hands out a block the child itself freed, so what it
    /// does with one (macOS 27.2's xzone clears a zeroed one with `madvise`)
    /// happens whatever heap the child inherited from this process, where
    /// once each it was chance (1 run of 8 done without it).
    const REPEAT: usize = 16;

    /// A zeroed block of `len` (`calloc`, as READ's reply buffer is), written
    /// at both ends, read back, freed, [`REPEAT`] times: 1.
    fn alloc_then_free(len: usize) -> i32 {
        let mut done = true;
        for _ in 0..REPEAT {
            let mut v = vec![0u8; len];
            v[0] = 1;
            v[len - 1] = 2;
            let v = std::hint::black_box(v);
            done &= v[0] == 1 && v[len - 1] == 2 && v[len / 2] == 0;
        }
        i32::from(done)
    }

    /// A buffer grown by appends of 4 KiB to the largest frame, as a
    /// growing `Vec` does (each growth a realloc to twice the capacity, the
    /// last to 2 MiB), then freed, [`REPEAT`] times: 1.
    fn grown_by_appends() -> i32 {
        let mut done = true;
        for _ in 0..REPEAT {
            let mut v = Vec::new();
            while v.len() < wick_fs_frame::MAX_FRAME_LEN {
                v.extend_from_slice(&[3u8; 4096]);
            }
            let v = std::hint::black_box(v);
            done &= v[v.len() - 1] == 3;
        }
        i32::from(done)
    }

    /// The size of a node table's value (`inodes::Entry` of the host
    /// backend's node).
    const ENTRY_LEN: usize = std::mem::size_of::<wick_fsd::inodes::Entry<wick_fsd::host::unix::HostNode>>();

    /// The node table's two maps grown entry by entry to the cap of
    /// `max_nodes` (`DEFAULT_MAX_NODES`, 2^18), as `Inodes` grows them (each
    /// growth a new table, the entries moved, the old one freed), then
    /// dropped, twice: 1. The values are the size of the real ones; the
    /// identity is the size of a `HostId` (a device and an inode number).
    fn node_tables_to_the_cap() -> i32 {
        use std::collections::HashMap;
        let cap = wick_fsd::limits::DEFAULT_MAX_NODES;
        let mut done = true;
        for _ in 0..2 {
            let mut map: HashMap<u64, [u8; ENTRY_LEN]> = HashMap::new();
            let mut by_id: HashMap<(u64, u64), u64> = HashMap::new();
            for n in 0..cap as u64 {
                map.insert(n, [0; ENTRY_LEN]);
                by_id.insert((n, n), n);
            }
            done &= map.len() == cap && by_id.len() == cap;
            drop(std::hint::black_box(map));
            drop(std::hint::black_box(by_id));
        }
        i32::from(done)
    }

    /// Many blocks of the server's large sizes held at once, then freed
    /// (frames of every length, READDIR buffers): more than one of macOS
    /// 15's medium regions holds (each new region a mapping, see `SHAPES`),
    /// and more than a large cache keeps where these sizes are large (16
    /// entries, or 64 with 32 GiB of memory or more, libmalloc-715
    /// thresholds.h), so it gives its oldest back, [`REPEAT`] / 4 times: 1.
    fn many_large_blocks() -> i32 {
        let span = wick_fs_frame::MAX_FRAME_LEN - (40 << 10);
        let mut done = true;
        for _ in 0..REPEAT / 4 {
            let held: Vec<Vec<u8>> = (0..96).map(|i| vec![4u8; (40 << 10) + i * span / 95]).collect();
            done &= held.iter().all(|v| v[v.len() - 1] == 4);
            drop(std::hint::black_box(held));
        }
        i32::from(done)
    }

    /// How many times each shape runs under the reporting profile: what an
    /// allocator calls depends on its state, so the calls on record are the
    /// union of these runs.
    const REPORTED_RUNS: usize = 4;

    /// The allocator shapes of the server, each checked confined (done,
    /// never killed) and, on record, run again reporting what it calls.
    const SHAPES: &[(&str, Act)] = &[
        ("a zeroed block of the largest frame, allocated and freed", |_| alloc_then_free(wick_fs_frame::MAX_FRAME_LEN)),
        ("a buffer grown by appends to the largest frame", |_| grown_by_appends()),
        ("a realloc to the largest frame, then free", |_| {
            i32::from((0..REPEAT).all(|_| realloc_then_free(256 << 10, wick_fs_frame::MAX_FRAME_LEN) == 1))
        }),
        ("the node tables grown to their cap", |_| node_tables_to_the_cap()),
        ("many large blocks of the server's sizes", |_| many_large_blocks()),
    ];

    /// On record, never checked: libmalloc's copy path past 2 MiB of data
    /// (`vm_copy` on macOS 15), which no buffer of the server reaches.
    const PAST_2_MIB: (&str, Act) =
        ("a realloc of a block past 2 MiB (not the server's)", |_| realloc_then_free(3 << 20, 8 << 20));

    /// On record: this process's allocator, from a copy of it started with
    /// `MallocReportConfig` (libmalloc-715 malloc.c :1523: it reports the
    /// magazine allocator's configuration, and nothing of the other, xzone),
    /// which allocator libmalloc engaged (`probe::engaged_allocator`), and the
    /// memory size and architecture, which decide the magazine's size
    /// classes: a block past 32 KiB is medium up to 8 MiB where the medium
    /// allocator is engaged (always on arm64, wick's only macOS host; on
    /// x86_64 at 32 GiB of memory or more; libmalloc-715 malloc.c :357,
    /// thresholds.h) and large past that or without it.
    fn allocator_on_record() {
        if std::env::var_os("WICK_FS_PROBE_ALLOCATOR").is_some() {
            let (secure, nano) = probe::engaged_allocator();
            let which = if secure != 0 { "xzone" } else { "magazine" };
            println!("engaged: {which} (malloc_engaged_secure_allocator {secure}), nano version {nano}");
            probe::exit_now(0);
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .env("WICK_FS_PROBE_ALLOCATOR", "1")
            .env("MallocReportConfig", "1")
            .output()
            .unwrap();
        for line in String::from_utf8_lossy(&out.stdout).lines().chain(String::from_utf8_lossy(&out.stderr).lines()) {
            println!("allocator: {line}");
        }
        if let Ok(m) = std::process::Command::new("/usr/sbin/sysctl").args(["-n", "hw.memsize", "kern.osversion", "hw.machine"]).output() {
            let said: Vec<String> = String::from_utf8_lossy(&m.stdout).split_whitespace().map(String::from).collect();
            println!("allocator: hw.memsize, kern.osversion, hw.machine: {}", said.join(", "));
        }
    }

    /// On record: Seatbelt's reports of the `pids` since `since` (the
    /// unified log, as CI's report step reads it). The reports reach the log
    /// a moment later: read until the last pid's (the control's) is there,
    /// for at most 30 s.
    fn reports_on_record(since: &str, pids: &[(&str, i32)]) {
        let last = format!("({})", pids.last().map_or(0, |p| p.1));
        let start = std::time::Instant::now();
        let text = loop {
            let out = std::process::Command::new("/usr/bin/log")
                .args(["show", "--start", since, "--style", "compact", "--predicate", "sender == \"Sandbox\""])
                .output();
            let text = out.map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
            if text.contains(&last) || start.elapsed() > std::time::Duration::from_secs(30) {
                break text;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        };
        if !text.contains(&last) {
            println!("reported: the control's report is not in the unified log after 30 s; nothing below is evidence");
        }
        // Per name, in the order first run: each call reported, with how
        // many of that name's runs reported it.
        let mut names: Vec<&str> = Vec::new();
        let mut union: std::collections::BTreeMap<&str, std::collections::BTreeMap<String, usize>> = Default::default();
        let mut runs: std::collections::BTreeMap<&str, usize> = Default::default();
        for &(name, pid) in pids {
            if !names.contains(&name) {
                names.push(name);
            }
            *runs.entry(name).or_default() += 1;
            let tag = format!("({pid})");
            let mut seen = std::collections::BTreeSet::new();
            for call in text.lines().filter_map(|l| l.split(&tag).nth(1).map(str::trim)) {
                seen.insert(call.trim_start_matches("allow ").to_string());
            }
            for call in seen {
                *union.entry(name).or_default().entry(call).or_default() += 1;
            }
        }
        for name in names {
            let n = runs[name];
            let said = union.get(name).map_or_else(|| "nothing".to_string(), |calls| {
                calls.iter().map(|(c, k)| format!("{c} ({k} of {n})")).collect::<Vec<_>>().join("; ")
            });
            println!("reported, {name}, {n} runs: {said}");
        }
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
        allocator_on_record();
        let since = std::process::Command::new("/bin/date").arg("+%Y-%m-%d %H:%M:%S").output().unwrap();
        let since = String::from_utf8_lossy(&since.stdout).trim().to_string();
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
        // What the server's own allocations make, at the sizes and in the
        // ways it makes them, must be allowed: each shape done, confined.
        // The calls depend on the allocator and its size classes (macOS
        // 27.2's xzone; macOS 15's magazine on arm64 serves these sizes from
        // its medium allocator, whose new region is mapped and, when it lands
        // above the entropic limit, given back with `mach_vm_deallocate` and
        // mapped again lower, libmalloc-715 vm.c :245; its large allocator,
        // past 8 MiB, grows a block in place with `vm_allocate`), so each
        // runs again reporting them, on record, and
        // so does a realloc past 2 MiB, which is not checked.
        let mut reported = Vec::new();
        for &(name, act) in SHAPES {
            let got = case(name, &share, &outside, act);
            if got != 1 {
                failed.push(format!("{name}: {got}, expected 1"));
            }
            for _ in 0..REPORTED_RUNS {
                reported.push((name, case_as(name, &share, &outside, act, How::Reported).1));
            }
        }
        let (name, act) = PAST_2_MIB;
        case(name, &share, &outside, act);
        for _ in 0..REPORTED_RUNS {
            reported.push((name, case_as(name, &share, &outside, act, How::Reported).1));
        }
        // The reports' control: a call the profile does not list, so
        // reported (a kernel MIG routine), where "nothing" above means none.
        let control = "control: task_info, a MIG routine not listed";
        reported.push((control, case_as(control, &share, &outside, |_| ok(probe::task_info()), How::Reported).1));
        reports_on_record(&since, &reported);
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
