// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The wick-fsd binary on Linux (docs/design-fs.md §4.2, §6.1): the
//! confined process's state as the kernel reports it (stage 0's one
//! connection and peer check: connection.rs, on macOS too), and one refusal per confinement step. Each refusal is
//! real: the server runs under a seccomp filter (installed by the test
//! before the exec) that makes that step's system call fail, and must then
//! refuse to serve, naming the step. wick-fsd has no switch that skips a
//! step.
//!
//! Run as root (the CI fs job's sudo step, the Docker run), the server drops
//! to uid 65534; run as a user, it makes a user namespace, and where the
//! host restricts those (Ubuntu's AppArmor sysctl) the tests that need a
//! confined server check the refusal instead.

#![cfg(target_os = "linux")]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use common::drive::G;
use common::remote::{Remote, Server, base_args, give_share, is_userns_refusal, userns_restricted};
use common::*;
use wick_fs_sys as sys;
use wick_fs_sys::confine::{self as c, nr};

struct Setup {
    base: PathBuf,
    share: PathBuf,
    socket: PathBuf,
}

impl Drop for Setup {
    fn drop(&mut self) {
        remove(&self.base);
    }
}

fn setup(tag: &str) -> Setup {
    let base = scratch(tag);
    let share = base.join("share");
    std::fs::create_dir(&share).unwrap();
    std::fs::write(share.join("marker"), b"in the share").unwrap();
    give_share(&share);
    let socket = base.join("fs.sock");
    Setup { base, share, socket }
}

/// A confined server connected; `None` (said on stderr) where this host
/// refuses the user namespace a server that is not root needs, after
/// checking that refusal.
fn confined(s: &Setup, extra: &[&str]) -> Option<Remote> {
    let mut args = base_args(&s.share, &s.socket);
    args.extend(extra.iter().map(ToString::to_string));
    match Remote::connect(Server::start(&args, |_| {})) {
        Ok(r) => Some(r),
        Err((mut server, why)) => {
            let (status, err) = server.wait();
            if let Some(restricted) = userns_restricted() {
                assert!(!status.success() && is_userns_refusal(&err), "{restricted}: not a user namespace's refusal: {err}");
                eprintln!("ran nothing confined: {restricted}; refused at its user namespace, as it must: {err}");
                return None;
            }
            panic!("no confined server ({why}; {status:?}): {err}");
        }
    }
}

fn status_field<'a>(status: &'a str, field: &str) -> &'a str {
    status
        .lines()
        .find_map(|l| l.strip_prefix(field).map(str::trim))
        .unwrap_or_else(|| panic!("no {field} in {status}"))
}

#[test]
fn test_confined_status() {
    let s = setup("srv-status");
    let Some(r) = confined(&s, &[]) else { return };
    let pid = r.server.confined_pid().expect("the confined child");
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    assert_eq!(status_field(&status, "Seccomp:"), "2", "seccomp filter mode");
    assert_eq!(status_field(&status, "NoNewPrivs:"), "1");
    for cap in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:", "CapBnd:"] {
        assert_eq!(status_field(&status, cap), "0000000000000000", "{cap}");
    }
    if sys_euid() == 0 {
        // Dropped to 65534, with no supplementary group.
        assert!(status_field(&status, "Uid:").split_whitespace().all(|u| u == "65534"), "{status}");
        assert!(status_field(&status, "Groups:").is_empty(), "no supplementary groups");
    } else {
        let me = sys_euid().to_string();
        assert_eq!(status_field(&status, "Uid:").split_whitespace().next(), Some(me.as_str()));
    }
    if sys_euid() != 0 {
        // Not dumpable: a process of the same uid cannot look in (the
        // namespaces' owner gets no access through them: the process's
        // memory belongs to the namespace it started in).
        let denied = std::fs::read_dir(format!("/proc/{pid}/root"));
        assert!(matches!(&denied, Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied), "{denied:?}");
    } else {
        // Its root is the share, in namespaces of its own.
        let names: Vec<_> = std::fs::read_dir(format!("/proc/{pid}/root"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["marker"], "/ of the confined server is the share");
        for ns in ["mnt", "pid", "net", "ipc"] {
            let theirs = std::fs::read_link(format!("/proc/{pid}/ns/{ns}")).unwrap();
            let ours = std::fs::read_link(format!("/proc/self/ns/{ns}")).unwrap();
            assert_ne!(theirs, ours, "{ns} namespace");
        }
    }
    // The waiting parent, outside the pid namespace: the same ids, no
    // capabilities, no_new_privs and a filter of its own.
    let parent = r.server.child.id();
    let status = std::fs::read_to_string(format!("/proc/{parent}/status")).unwrap();
    assert_eq!(status_field(&status, "Seccomp:"), "2", "the parent's seccomp filter mode");
    assert_eq!(status_field(&status, "NoNewPrivs:"), "1", "the parent");
    for cap in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:", "CapBnd:"] {
        assert_eq!(status_field(&status, cap), "0000000000000000", "the parent's {cap}");
    }
    let uid = if sys_euid() == 0 { "65534".to_string() } else { sys_euid().to_string() };
    assert!(status_field(&status, "Uid:").split_whitespace().all(|u| u == uid), "the parent: {status}");
    let mut g = G::over(r);
    g.getattr(ROOT, None).unwrap();
    let (status, err) = g.s.finish();
    assert!(status.success(), "{status:?}: {err}");
    assert!(err.contains("layer refusals 0"), "{err}");
}

/// What a careless launcher leaves open, each at a number of its own: a
/// file outside the share open for writing, the share's parent directory
/// and a socket (one end of a pair, the other returned). On the macOS
/// runner the step's shell holds two control sockets and two pipes so
/// (CI run 44233741878).
fn left_open(s: &Setup) -> (Vec<(OwnedFd, i32)>, UnixStream) {
    let file = std::fs::File::create(s.base.join("left-open")).unwrap();
    let dir = std::fs::File::open(&s.base).unwrap();
    let (ours, theirs) = UnixStream::pair().unwrap();
    (vec![(file.into(), 40), (dir.into(), 41), (theirs.into(), 42)], ours)
}

/// The descriptors of process `pid`, each with what it is (its
/// `/proc/<pid>/fd` link); `None` where this process may not read them (a
/// server that is not dumpable, read by a user).
fn descriptors_of(pid: u32) -> Option<Vec<(i32, String)>> {
    let dir = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(e) => panic!("/proc/{pid}/fd: {e}"),
    };
    let mut v: Vec<(i32, String)> = dir
        .map(|e| {
            let e = e.unwrap();
            let fd = e.file_name().to_str().unwrap().parse().unwrap();
            (fd, std::fs::read_link(e.path()).map_or_else(|e| e.to_string(), |p| p.display().to_string()))
        })
        .collect();
    v.sort();
    Some(v)
}

/// The pid each pidfd of process `pid` is on (its `/proc/<pid>/fdinfo`
/// `Pid:` line).
fn pidfds_of(pid: u32, fds: &[(i32, String)]) -> Vec<String> {
    fds.iter()
        .filter(|(_, what)| what == "anon_inode:[pidfd]")
        .map(|(fd, _)| {
            let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).unwrap();
            info.lines()
                .find_map(|l| l.strip_prefix("Pid:"))
                .map_or_else(|| format!("no Pid: line in {info:?}"), |p| p.trim().to_string())
        })
        .collect()
}

/// What wick-fsd was started with is closed before it serves, in its
/// confined process and its waiting parent alike: a file, a directory and
/// a socket left open by its launcher, by `close_range` and, where the
/// kernel has none (ENOSYS, as before Linux 5.9), by the kernel's list.
/// Read from outside as root; as a user the server's own read-back (it
/// serves only with exactly what it opened) is what holds.
#[test]
fn test_descriptors_it_was_started_with_are_closed() {
    for (tag, answer) in [("srv-left", None), ("srv-left-nosys", Some(c::Answer::Fail(38)))] {
        let s = setup(tag);
        let args = base_args(&s.share, &s.socket);
        let (fds, _ours) = left_open(&s);
        let mut supervisor = None;
        let server = Server::start(&args, |cmd| {
            sys::command_with_inherited(cmd, fds);
            if let Some(answer) = answer {
                let sock = c::command_with_supervisor(cmd, c::notify_program(&[(nr::CLOSE_RANGE, None)])).unwrap();
                supervisor = Some(c::supervise(sock, move |_| answer));
            }
        });
        let r = match Remote::connect(server) {
            Ok(r) => r,
            Err((mut server, why)) => {
                let (status, err) = server.wait();
                let Some(restricted) = userns_restricted() else { panic!("{tag}: {why} {status:?}: {err}") };
                assert!(!status.success() && is_userns_refusal(&err), "{restricted}: not a user namespace's refusal: {err}");
                eprintln!("ran nothing confined: {restricted}; refused at its user namespace, as it must: {err}");
                return;
            }
        };
        let child = u32::try_from(r.server.confined_pid().expect("the confined child")).unwrap();
        let parent = r.server.child.id();
        match (descriptors_of(child), descriptors_of(parent)) {
            (Some(theirs), Some(waiting)) => {
                // The standard streams, then: the confined server, the
                // connection and the share's root, and no pidfd (it closes
                // the parent watch it inherits at the fork); the waiting
                // parent, the pipe the child watches and two pidfds, the
                // parent watch's on this test process (the server's parent)
                // and the confined server's.
                let ours = std::process::id().to_string();
                for (who, pid, fds, n, pidfds) in [
                    ("the confined server", child, &theirs, 5, vec![]),
                    ("the waiting parent", parent, &waiting, 6, vec![ours.clone(), child.to_string()]),
                ] {
                    let left: Vec<_> = fds.iter().filter(|(fd, _)| [40, 41, 42].contains(fd)).collect();
                    assert!(left.is_empty(), "{tag}: {who} holds what it was started with: {fds:?}");
                    assert!(!fds.iter().any(|(_, what)| what.contains("left-open")), "{tag}: {who}: {fds:?}");
                    assert_eq!(fds.len(), n, "{tag}: {who}: {fds:?}");
                    assert_eq!(fds[0].1, "/dev/null", "{tag}: {who}'s standard input: {fds:?}");
                    let (mut got, mut want) = (pidfds_of(pid, fds), pidfds);
                    got.sort();
                    want.sort();
                    assert_eq!(got, want, "{tag}: {who}'s pidfds (the pids they are on): {fds:?}");
                }
            }
            _ => eprintln!(
                "ran nothing: /proc/<pid>/fd of a server that is not dumpable needs root (it served, so its own \
                 read-back of its descriptors held)"
            ),
        }
        let mut g = G::over(r);
        g.getattr(ROOT, None).unwrap();
        let (status, err) = g.s.finish();
        assert!(status.success(), "{tag}: {status:?}: {err}");
        if let Some(supervisor) = supervisor {
            let (calls, _) = supervisor.join().unwrap();
            assert!(!calls.is_empty(), "{tag}: close_range was not made");
        }
    }
}

/// A descriptor the server was started with that survives the close (its
/// `close_range` said done and was not, as the supervisor answers) is found
/// by the first step's read-back of the kernel's list, each named: the
/// server refuses before it binds its socket, on any host.
#[test]
fn test_refused_when_a_descriptor_it_was_started_with_survives() {
    let s = setup("srv-survives");
    let args = base_args(&s.share, &s.socket);
    let (fds, _ours) = left_open(&s);
    let mut supervisor = None;
    let mut server = Server::spawn(&args, |cmd| {
        sys::command_with_inherited(cmd, fds);
        let sock = c::command_with_supervisor(cmd, c::notify_program(&[(nr::CLOSE_RANGE, None)])).unwrap();
        supervisor = Some(c::supervise(sock, |_| c::Answer::Pretend));
    });
    let (status, err) = server.wait();
    assert!(!status.success(), "{status:?}: {err}");
    let named = "closing the descriptors it was started with (said done), left open: [";
    assert!(err.contains(named), "{err}");
    for what in ["40: file ", "left-open", "41: directory ", "42: socket "] {
        assert!(err.contains(what), "{what}: {err}");
    }
    assert!(err.contains("wick-fsd does not serve with them") && !s.socket.exists(), "{err}");
    let (calls, _) = supervisor.unwrap().join().unwrap();
    assert!(!calls.is_empty(), "close_range was not made");
}

/// A guest's MKDIR and SETATTR with every special bit pass the filter's
/// mkdirat and fchmod rules (`SERVER_SYSCALLS`): the host gets 0o700 and
/// the permission bits, the record the guest's mode.
#[test]
fn test_a_guest_s_special_mode_bits_pass_the_filter() {
    let s = setup("srv-special");
    let Some(r) = confined(&s, &[]) else { return };
    let mut g = G::over(r);
    let (e, out) = g.call(wick_fsd::fuse::Opcode::Mkdir, ROOT, &[&le32(0o7777), &le32(0), &name(b"d")]);
    assert_eq!(e, 0, "MKDIR 0o7777");
    let d = u64_at(&out, 0);
    assert_eq!(g.getattr(d, None).unwrap().mode & 0o7777, 0o7777);
    let (f, fh) = g.create(ROOT, b"f");
    g.release(f, fh);
    let a = g.setattr(f, common::drive::FATTR_MODE, 0, 0o6777, None).unwrap();
    assert_eq!(a.mode & 0o7777, 0o6777);
    let a = g.setattr(d, common::drive::FATTR_MODE, 0, 0o1755, None).unwrap();
    assert_eq!(a.mode & 0o7777, 0o1755);
    let (status, err) = g.s.finish();
    assert!(status.success(), "{status:?}: {err}");
    assert!(err.contains("layer refusals 0,"), "{err}");
}

/// Killing wick-fsd (the waiting parent) ends the confined server: its
/// parent-death signal holds after its drop to --uid/--gid, which clears it
/// (`commit_creds`, kernel/cred.c), so a root-started server armed it again.
#[test]
fn test_the_confined_server_dies_with_its_parent() {
    let s = setup("srv-death");
    let Some(mut r) = confined(&s, &[]) else { return };
    let pid = r.server.confined_pid().expect("the confined child");
    r.server.child.kill().unwrap();
    r.server.child.wait().unwrap();
    let start = std::time::Instant::now();
    let gone = loop {
        // Gone, or a zombie waiting for init to reap it.
        let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|st| st.rfind(')').map(|i| st[i + 2..].chars().next()))
            .flatten();
        if matches!(state, None | Some('Z' | 'X')) {
            break true;
        }
        if start.elapsed() > std::time::Duration::from_secs(10) {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert!(gone, "the confined server (pid {pid}) outlived its parent");
}

fn sys_euid() -> u32 {
    wick_fs_sys::euid()
}

/// Root only (the server is not dumpable): the confined server's view of
/// the file system, through `/proc/<pid>/root`, has nothing of the host
/// beyond the share. As a user, `confine_probe` checks the same from inside.
#[test]
fn test_outside_open_fails() {
    if sys_euid() != 0 {
        eprintln!("ran nothing: /proc/<pid>/root of a server that is not dumpable needs root (confine_probe checks it)");
        return;
    }
    let s = setup("srv-outside");
    let Some(mut r) = confined(&s, &[]) else { return };
    let pid = r.server.confined_pid().unwrap();
    let root = PathBuf::from(format!("/proc/{pid}/root"));
    // Its view is readable from here: the share's file is in it.
    std::fs::symlink_metadata(root.join("marker")).unwrap();
    for outside in ["etc/passwd", "proc/self", "dev/null", "tmp", "bin/sh"] {
        if let Ok(m) = std::fs::symlink_metadata(root.join(outside)) {
            panic!("{outside} reachable: {m:?}");
        }
    }
    // The share's own parent is not reachable either.
    let parent = s.base.strip_prefix("/").unwrap();
    std::fs::symlink_metadata(root.join(parent)).unwrap_err();
    std::fs::symlink_metadata(root.join("..").join("etc/passwd")).unwrap_err();
    let (status, err) = r.finish();
    assert!(status.success(), "{status:?}: {err}");
}

/// Runs a server whose `deny` system calls fail with `errno` and checks it
/// refuses to serve, naming `step`.
fn refused_when(tag: &str, deny: &[(std::ffi::c_long, Option<(u32, u32)>)], errno: i32, step: &str) {
    let s = setup(tag);
    let args = base_args(&s.share, &s.socket);
    let program = c::deny_program(deny, errno);
    let server = Server::start(&args, |cmd| c::command_with_filter(cmd, program));
    match Remote::connect(server) {
        Ok(mut r) => {
            let (status, err) = r.finish();
            panic!("served with {step} failing ({status:?}): {err}");
        }
        Err((mut server, _)) => {
            let (status, err) = server.wait();
            assert!(!status.success(), "{status:?}: {err}");
            if let Some(restricted) = userns_restricted()
                && !err.contains(step)
            {
                // The user namespace failed first, as this host restricts it.
                assert!(is_userns_refusal(&err), "{restricted}: not a user namespace's refusal: {err}");
                eprintln!("{restricted}: refused before {step}: {err}");
                return;
            }
            assert!(err.contains(step), "expected a refusal naming {step:?}: {err}");
            assert!(err.contains("does not serve unconfined"), "{err}");
            no_confined_child_left(&server, &s.share, step);
        }
    }
}

/// After its waiting parent's refusal, no process of the server is left:
/// the confined child, forked before the parent's step, ended with it. As
/// root the parent may die after its drop to --uid while the child is still
/// root (before `lock`): the kernel refuses the parent-death signal then
/// (`kill_ok_by_cred`, kernel/signal.c: neither id of the sender matches
/// the target's, and the sender has no `CAP_KILL`), and the child ends at
/// its own check of the parent's pipe when it arms the signal again after
/// its drop (confine/linux.rs, `lock`). Which of the two ended it is on
/// record.
fn no_confined_child_left(server: &Server, share: &std::path::Path, step: &str) {
    let named = share.to_str().unwrap();
    let live = || {
        let mut rows = Vec::new();
        for e in std::fs::read_dir("/proc").unwrap().flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let (Ok(cmd), Ok(stat)) = (
                std::fs::read(format!("/proc/{pid}/cmdline")),
                std::fs::read_to_string(format!("/proc/{pid}/stat")),
            ) else {
                continue;
            };
            let state = stat.rfind(')').and_then(|i| stat[i + 2..].chars().next());
            let cmd = String::from_utf8_lossy(&cmd).replace('\0', " ");
            if cmd.contains(named) && !matches!(state, Some('Z' | 'X') | None) {
                rows.push((pid, state));
            }
        }
        rows
    };
    let start = std::time::Instant::now();
    let mut left = live();
    while !left.is_empty() && start.elapsed() < std::time::Duration::from_secs(10) {
        std::thread::sleep(std::time::Duration::from_millis(20));
        left = live();
    }
    assert!(left.is_empty(), "{step}: the server's processes outlived its waiting parent: {left:?}");
    std::thread::sleep(std::time::Duration::from_millis(50));
    let err = server.stderr_now();
    let how = if err.contains("PR_SET_PDEATHSIG after the id drop") {
        "at its own check of the parent's pipe (the parent-death signal was refused or not yet armed again)"
    } else if err.matches("does not serve unconfined").count() > 1 {
        "at a refusal of its own"
    } else {
        "by the parent-death signal, or before it forked"
    };
    eprintln!("{step}: no process left; the confined child ended {how}");
}

const EPERM: i32 = 1;

#[test]
fn test_refused_without_unshare() {
    refused_when("srv-unshare", &[(nr::UNSHARE, None)], EPERM, "unshare of the namespaces");
}

#[test]
fn test_refused_without_fork() {
    refused_when(
        "srv-fork",
        &[(nr::CLONE, None), (nr::CLONE3, None)],
        EPERM,
        "fork into the pid namespace",
    );
}

#[test]
fn test_refused_without_mount() {
    refused_when("srv-mount", &[(nr::MOUNT, None)], EPERM, "making the mounts private");
}

#[test]
fn test_refused_without_pivot_root() {
    refused_when("srv-pivot", &[(nr::PIVOT_ROOT, None)], EPERM, "pivot_root to the share");
}

#[test]
fn test_refused_without_id_drop() {
    if sys_euid() != 0 {
        eprintln!("ran nothing: a server that is not root drops no ids");
        return;
    }
    refused_when("srv-drop", &[(nr::SETRESUID, None)], EPERM, "the waiting parent: dropping to --uid/--gid");
}

#[test]
fn test_refused_without_capability_drop() {
    refused_when("srv-capset", &[(nr::CAPSET, None)], EPERM, "the waiting parent: dropping the capabilities");
}

#[test]
fn test_refused_without_no_new_privs() {
    // prctl(PR_SET_NO_NEW_PRIVS, ...) only (38): the other prctl calls work.
    refused_when("srv-nnp", &[(nr::PRCTL, Some((0, 38)))], EPERM, "the waiting parent: PR_SET_NO_NEW_PRIVS");
}

#[test]
fn test_refused_without_seccomp() {
    refused_when("srv-seccomp", &[(nr::SECCOMP, None)], EPERM, "the waiting parent: the seccomp filter");
}

/// What a supervised run saw ([`in_the_child`]).
struct Seen {
    served: bool,
    err: String,
    /// The calls the confined child made of the one supervised.
    child_calls: usize,
    /// The test's own filter needed `no_new_privs` (no `CAP_SYS_ADMIN`), so
    /// the server had it before its own step.
    nnp_before: bool,
}

/// Runs a server whose confined child (and only it: its waiting parent's
/// same call is made as asked) gets `answer` for its `nth` call of `call`
/// (every one for `None`); `None` where this host refuses the user
/// namespace first. The refusal tests above fail the first process to make
/// a call, which for a step both make is the waiting parent; these reach
/// the child's own step (docs/design-fs.md §6.1, the refusal tests).
fn in_the_child(tag: &str, call: (std::ffi::c_long, Option<(u32, u32)>), nth: Option<usize>, answer: c::Answer) -> Option<Seen> {
    let s = setup(tag);
    let args = base_args(&s.share, &s.socket);
    let mut supervisor = None;
    let server = Server::start(&args, |cmd| {
        let sock = c::command_with_supervisor(cmd, c::notify_program(&[call])).unwrap();
        let mut seen = 0;
        supervisor = Some(c::supervise(sock, move |made| {
            if !made.nested {
                return c::Answer::Continue;
            }
            seen += 1;
            if nth.is_none_or(|n| n == seen) { answer } else { c::Answer::Continue }
        }));
    });
    let (served, err) = match Remote::connect(server) {
        Ok(r) => {
            let mut g = G::over(r);
            g.getattr(ROOT, None).unwrap();
            let (_, err) = g.s.finish();
            (true, err)
        }
        Err((mut server, _)) => {
            let (status, err) = server.wait();
            assert!(!status.success(), "{status:?}: {err}");
            (false, err)
        }
    };
    let (calls, nnp_before) = supervisor.unwrap().join().unwrap();
    let child_calls = calls.iter().filter(|c| c.nested).count();
    // A host that restricts user namespaces (as a user, without the CI
    // profile's grant): the server is refused at a step of its user
    // namespace, before any child exists. That refusal is what is checked
    // there; the child's step is reached as root and under the grant.
    if let Some(restricted) = userns_restricted() {
        assert!(!served, "served although {restricted}: {err}");
        assert!(is_userns_refusal(&err), "{restricted}: not a user namespace's refusal: {err}");
        assert_eq!(child_calls, 0, "{restricted}: a child made the call: {err}");
        eprintln!("ran nothing confined: {restricted}; refused at its user namespace, as it must: {err}");
        return None;
    }
    Some(Seen {
        served,
        err,
        child_calls,
        nnp_before,
    })
}

/// The child's own step failed: refused, naming it, not the parent's.
fn child_refused(seen: &Seen, nth: usize, step: &str) {
    assert!(seen.child_calls >= nth, "the child made the call {} times, not {nth}: {}", seen.child_calls, seen.err);
    assert!(!seen.served, "served with the child's {step} failing: {}", seen.err);
    assert!(seen.err.contains(&format!("confinement: {step} failed")), "{step}: {}", seen.err);
    assert!(!seen.err.contains("the waiting parent"), "{}", seen.err);
}

/// The child's step said it was done and was not: the read-back refuses.
fn read_back_refused(seen: &Seen, what: &str) {
    assert!(seen.child_calls >= 1, "the child never made the call: {}", seen.err);
    assert!(!seen.served, "served although {what}: {}", seen.err);
    assert!(seen.err.contains("read back after the steps, what did not hold") && seen.err.contains(what), "{what}: {}", seen.err);
}

const PR_SET_PDEATHSIG: u32 = 1;
const PR_SET_DUMPABLE: u32 = 4;
const PR_CAPBSET_DROP: u32 = 24;
const PR_SET_NO_NEW_PRIVS: u32 = 38;

#[test]
fn test_the_child_s_parent_death_signal_steps() {
    let call = (nr::PRCTL, Some((0, PR_SET_PDEATHSIG)));
    let Some(seen) = in_the_child("srv-c-pdeath1", call, Some(1), c::Answer::Fail(EPERM)) else { return };
    child_refused(&seen, 1, "PR_SET_PDEATHSIG");
    let seen = in_the_child("srv-c-pdeath2", call, Some(2), c::Answer::Fail(EPERM)).unwrap();
    child_refused(&seen, 2, "PR_SET_PDEATHSIG after the id drop");
    let seen = in_the_child("srv-c-pdeath0", call, None, c::Answer::Pretend).unwrap();
    read_back_refused(&seen, "the parent-death signal is 0, not SIGKILL");
}

#[test]
fn test_the_child_s_dumpable_steps() {
    let call = (nr::PRCTL, Some((0, PR_SET_DUMPABLE)));
    let Some(seen) = in_the_child("srv-c-dump1", call, Some(1), c::Answer::Fail(EPERM)) else { return };
    child_refused(&seen, 1, "PR_SET_DUMPABLE");
    let seen = in_the_child("srv-c-dump2", call, Some(2), c::Answer::Fail(EPERM)).unwrap();
    child_refused(&seen, 2, "PR_SET_DUMPABLE after the id drop");
    let seen = in_the_child("srv-c-dump0", call, None, c::Answer::Pretend).unwrap();
    // As root the id drop sets dumpable to fs.suid_dumpable (commit_creds):
    // where that is 0 the child is not dumpable without its own call, and
    // the read-back finds it so.
    let suid_dumpable = std::fs::read_to_string("/proc/sys/fs/suid_dumpable").unwrap();
    if sys_euid() == 0 && suid_dumpable.trim() == "0" {
        assert!(seen.served && seen.child_calls >= 2, "{}", seen.err);
    } else {
        read_back_refused(&seen, "the process is dumpable");
    }
}

#[test]
fn test_the_child_s_id_drop() {
    if sys_euid() != 0 {
        eprintln!("ran nothing: a server that is not root drops no ids");
        return;
    }
    let call = (nr::SETRESUID, None);
    let seen = in_the_child("srv-c-drop1", call, Some(1), c::Answer::Fail(EPERM)).unwrap();
    child_refused(&seen, 1, "dropping to --uid/--gid");
    // Said done and not: drop_ids reads its ids back itself.
    let seen = in_the_child("srv-c-drop0", call, None, c::Answer::Pretend).unwrap();
    child_refused(&seen, 1, "dropping to --uid/--gid");
}

#[test]
fn test_the_child_s_capability_drop() {
    let call = (nr::CAPSET, None);
    let Some(seen) = in_the_child("srv-c-capset1", call, Some(1), c::Answer::Fail(EPERM)) else { return };
    child_refused(&seen, 1, "dropping the capabilities");
    let seen = in_the_child("srv-c-capset0", call, None, c::Answer::Pretend).unwrap();
    if sys_euid() == 0 {
        // The drop from root to 65534 cleared them already
        // (security/commoncap.c, cap_emulate_setxuid): what holds is none.
        assert!(seen.served, "{}", seen.err);
    } else {
        read_back_refused(&seen, "capabilities (effective, permitted, inheritable) are left");
    }
    let bounding = (nr::PRCTL, Some((0, PR_CAPBSET_DROP)));
    let seen = in_the_child("srv-c-bset1", bounding, Some(1), c::Answer::Fail(EPERM)).unwrap();
    child_refused(&seen, 1, "dropping the bounding set");
    let seen = in_the_child("srv-c-bset0", bounding, None, c::Answer::Pretend).unwrap();
    read_back_refused(&seen, "the bounding set holds");
}

#[test]
fn test_the_child_s_no_new_privs() {
    let call = (nr::PRCTL, Some((0, PR_SET_NO_NEW_PRIVS)));
    let Some(seen) = in_the_child("srv-c-nnp1", call, Some(1), c::Answer::Fail(EPERM)) else { return };
    child_refused(&seen, 1, "PR_SET_NO_NEW_PRIVS");
    let seen = in_the_child("srv-c-nnp0", call, None, c::Answer::Pretend).unwrap();
    if seen.nnp_before {
        // The test's own filter needed it: it held before the step.
        assert!(seen.served, "{}", seen.err);
    } else {
        // Without it and without CAP_SYS_ADMIN the kernel refuses Landlock's
        // domain (security/landlock/syscalls.c, v6.12, :488) and the filter
        // (kernel/seccomp.c, :683 to :684), whichever comes first.
        let step = if seen.err.contains("Landlock failed") { "Landlock" } else { "the seccomp filter" };
        child_refused(&seen, 1, step);
    }
}

#[test]
fn test_the_child_s_seccomp_filter() {
    let call = (nr::SECCOMP, None);
    let Some(seen) = in_the_child("srv-c-seccomp1", call, Some(1), c::Answer::Fail(EPERM)) else { return };
    child_refused(&seen, 1, "the seccomp filter");
    let seen = in_the_child("srv-c-seccomp0", call, None, c::Answer::Pretend).unwrap();
    read_back_refused(&seen, "the seccomp filter is not in place");
}

#[test]
fn test_refused_when_landlock_fails() {
    let s = setup("srv-landlock");
    let args = base_args(&s.share, &s.socket);
    let program = c::deny_program(&[(nr::LANDLOCK_RESTRICT_SELF, None)], EPERM);
    let server = Server::start(&args, |cmd| c::command_with_filter(cmd, program));
    match Remote::connect(server) {
        Ok(mut r) => {
            let (status, err) = r.finish();
            // Only a kernel without Landlock never reaches the failing call.
            assert!(status.success() && err.contains("no Landlock"), "served with Landlock failing: {err}");
            eprintln!("ran nothing: this kernel has no Landlock");
        }
        Err((mut server, _)) => {
            let (status, err) = server.wait();
            assert!(!status.success());
            match userns_restricted() {
                Some(restricted) if !err.contains("Landlock") => {
                    assert!(is_userns_refusal(&err), "{restricted}: not a user namespace's refusal: {err}");
                    eprintln!("{restricted}: refused before Landlock: {err}");
                }
                _ => assert!(err.contains("Landlock failed"), "{err}"),
            }
        }
    }
}

/// Without Landlock (ENOSYS, as a kernel without it answers) the server
/// says so and serves: an added layer, never the only one (decision Q11).
#[test]
fn test_landlock_absent_is_logged() {
    let s = setup("srv-nolandlock");
    let args = base_args(&s.share, &s.socket);
    let program = c::deny_program(&[(nr::LANDLOCK_CREATE_RULESET, None)], 38);
    let server = Server::start(&args, |cmd| c::command_with_filter(cmd, program));
    let r = match Remote::connect(server) {
        Ok(r) => r,
        Err((mut server, why)) => {
            let (status, err) = server.wait();
            if let Some(restricted) = userns_restricted() {
                assert!(!status.success() && is_userns_refusal(&err), "{restricted}: not a user namespace's refusal: {err}");
                eprintln!("ran nothing confined: {restricted}; refused at its user namespace, as it must: {err}");
                return;
            }
            panic!("{why} {status:?}: {err}");
        }
    };
    let mut g = G::over(r);
    g.getattr(ROOT, None).unwrap();
    let (status, err) = g.s.finish();
    assert!(status.success(), "{status:?}: {err}");
    assert!(err.contains("no Landlock"), "{err}");
    assert!(err.contains("confined (namespaces, pivot_root, no capabilities, no_new_privs, seccomp)"), "{err}");
}

/// The refusal of a host that restricts user namespaces names what the
/// host says (design-fs row 20), one sysctl at a time, and nothing where it
/// says nothing: as root, the test gives the server a mount namespace in
/// which `/proc/sys/kernel` and `/proc/sys/user` are stand-ins holding that
/// sysctl alone, starts it as 65534 (so it makes a user namespace) under the
/// simulated restriction (its setgroups write refused, EACCES), and reads
/// the refusal. The server is started from a link or copy in the temporary
/// directory: 65534 execs it, and execve needs search permission on every directory of
/// the path (path_resolution(7)), which a runner's home may not give others
/// (run 44244968658: the spawn refused, EACCES, on GitHub's Ubuntu runners,
/// where the build is beneath /home/runner; the sudo step records that path
/// with `namei -l`).
#[test]
fn test_the_refusal_names_the_restriction_it_reads() {
    if sys_euid() != 0 {
        eprintln!("ran nothing: a stand-in for a sysctl is bound over /proc/sys as root (the sudo step runs it)");
        return;
    }
    const NAMES: [&str; 3] =
        ["kernel.apparmor_restrict_unprivileged_userns", "user.max_user_namespaces", "kernel.unprivileged_userns_clone"];
    // The program 65534 execs, in a directory every user can search: a hard
    // link to the built one where the two share a filesystem (no write, so
    // no other test's child can hold it open for writing at the exec,
    // ETXTBSY), a copy otherwise.
    let bin = scratch("srv-names-bin");
    let program = bin.join("wick-fsd");
    if std::fs::hard_link(env!("CARGO_BIN_EXE_wick-fsd"), &program).is_err() {
        std::fs::copy(env!("CARGO_BIN_EXE_wick-fsd"), &program).unwrap();
    }
    for (tag, file, value) in [
        ("srv-names-apparmor", "kernel/apparmor_restrict_unprivileged_userns", "1"),
        ("srv-names-max", "user/max_user_namespaces", "0"),
        ("srv-names-clone", "kernel/unprivileged_userns_clone", "0"),
        ("srv-names-none", "user/max_user_namespaces", "58304"),
    ] {
        let s = setup(tag);
        // The server, 65534, binds its socket here: the directory is its
        // own, as wick-fsd requires of a socket's directory that no group or
        // other can write (main.rs socket_dir_is_private).
        std::os::unix::fs::chown(&s.base, Some(65534), Some(65534)).unwrap();
        let stand_in = s.base.join("proc-sys");
        for d in ["kernel", "user"] {
            std::fs::create_dir_all(stand_in.join(d)).unwrap();
        }
        std::fs::write(stand_in.join(file), format!("{value}\n")).unwrap();
        // The server is not root here: no --uid/--gid, and the test (root)
        // is its peer.
        let mut args = base_args(&s.share, &s.socket);
        let at = args.iter().position(|a| a == "--uid").unwrap();
        args.drain(at..at + 4);
        args.extend(["--peer-uid", "0"].map(String::from));
        let (kernel, user) = (stand_in.join("kernel"), stand_in.join("user"));
        let server = Server::start_from(&program, &args, |cmd| {
            c::command_as_user_with_binds(
                cmd,
                65534,
                65534,
                &[(&kernel, std::path::Path::new("/proc/sys/kernel")), (&user, std::path::Path::new("/proc/sys/user"))],
            );
            c::command_with_filter(cmd, c::simulated_userns_restriction());
        });
        let Err((mut server, _)) = Remote::connect(server) else {
            panic!("{tag}: served with its setgroups write refused");
        };
        let (status, err) = server.wait();
        assert!(!status.success() && is_userns_refusal(&err), "{tag}: {err}");
        let named = NAMES.iter().find(|n| file.replace('/', ".") == **n).unwrap();
        if tag == "srv-names-none" {
            // Nothing beneath /proc/sys says so; the AppArmor label may
            // (a host whose restriction is real, as CI's sudo step's).
            assert!(NAMES.iter().all(|n| !err.contains(n)), "{tag}: {err}");
        } else {
            assert!(err.contains(&format!("This host restricts unprivileged user namespaces ({named} = {value}")), "{tag}: {err}");
            assert!(err.contains("start wick-fsd as root with --uid and --gid"), "{tag}: {err}");
        }
    }
    remove(&bin);
}

/// The tests' helpers name a step of theirs that fails before the exec, on
/// the child's stderr (std's spawn would carry back only an errno, the same
/// as the exec's): an empty seccomp program (EINVAL) as any user, and as
/// root a bind mount of a source that does not exist (ENOENT).
#[test]
fn test_a_helper_step_that_fails_names_itself() {
    let run = |prepare: &dyn Fn(&mut std::process::Command)| {
        let mut cmd = std::process::Command::new("/bin/true");
        prepare(&mut cmd);
        let out = cmd.output().expect("the spawn succeeds: the step ends the child");
        (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    let (code, err) = run(&|cmd| c::command_with_filter(cmd, Vec::new()));
    assert_eq!((code, err.as_str()), (Some(127), "pre_exec: seccomp(SECCOMP_SET_MODE_FILTER) failed (errno 22)\n"));
    if sys_euid() != 0 {
        eprintln!("ran nothing for the bind mount: it needs root (the sudo step runs it)");
        return;
    }
    let missing = std::path::Path::new("/nonexistent-wick-stand-in");
    let (code, err) = run(&|cmd| c::command_as_user_with_binds(cmd, 65534, 65534, &[(missing, std::path::Path::new("/proc/sys/user"))]));
    assert_eq!(
        (code, err.as_str()),
        (Some(127), "pre_exec: bind mount of /nonexistent-wick-stand-in onto /proc/sys/user failed (errno 2)\n")
    );
}

/// A host that restricts user namespaces refuses a server that is not root,
/// naming the restriction's settings (design-fs row 20).
#[test]
fn test_userns_restricted_refused() {
    let Some(restricted) = userns_restricted() else {
        eprintln!("ran nothing: user namespaces are not restricted here (or this is root)");
        return;
    };
    let s = setup("srv-userns");
    let args = base_args(&s.share, &s.socket);
    let Err((mut server, _)) = Remote::connect(Server::start(&args, |_| {})) else {
        panic!("served although {restricted}");
    };
    let (status, err) = server.wait();
    assert!(!status.success());
    assert!(is_userns_refusal(&err), "{restricted}: not a user namespace's refusal: {err}");
    // What the host says is named in the refusal: here, as the test reads
    // it, each sysctl that restricts (a simulated restriction has none).
    for (file, name, restricted) in [
        ("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "kernel.apparmor_restrict_unprivileged_userns", "1"),
        ("/proc/sys/user/max_user_namespaces", "user.max_user_namespaces", "0"),
        ("/proc/sys/kernel/unprivileged_userns_clone", "kernel.unprivileged_userns_clone", "0"),
    ] {
        if std::fs::read_to_string(file).is_ok_and(|v| v.trim() == restricted) {
            assert!(err.contains(&format!("{name} = {restricted}")), "{restricted}: {err}");
            assert!(err.contains("start wick-fsd as root with --uid and --gid"), "{err}");
        }
    }
    // One line, for the CI unit step's record.
    eprintln!("refused as it must: {}", err.trim().replace('\n', " | "));
}
