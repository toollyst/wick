// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The wick-fsd binary on Linux (docs/design-fs.md §4.2, §6.1): stage 0's
//! one connection and peer check, the confined process's state as the
//! kernel reports it, and one refusal per confinement step. Each refusal is
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

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use common::drive::G;
use common::remote::{Remote, Server, base_args, give_share, userns_restricted};
use common::*;
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
                assert!(!status.success() && err.contains("confinement"), "{status:?}: {err}");
                eprintln!("ran nothing confined: {restricted}; the server refused as it must: {err}");
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

#[test]
fn test_second_connection_refused() {
    let s = setup("srv-second");
    let Some(mut r) = confined(&s, &[]) else { return };
    assert!(!s.socket.exists(), "the listener is unlinked after the one accept");
    UnixStream::connect(&s.socket).unwrap_err();
    let (status, err) = r.finish();
    assert!(status.success(), "{status:?}: {err}");
}

#[test]
fn test_wrong_peer_refused() {
    let s = setup("srv-peer");
    let mut args = base_args(&s.share, &s.socket);
    let other = (sys_euid() + 1).to_string();
    args.extend(["--peer-uid".to_string(), other]);
    let server = Server::start(&args, |_| {});
    let Err((mut server, _)) = Remote::connect(server) else {
        panic!("a peer of another uid was served");
    };
    let (status, err) = server.wait();
    assert!(!status.success(), "{status:?}");
    assert!(err.contains("not --peer-uid"), "{err}");
    assert!(!s.socket.exists());
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
                assert!(err.contains("confinement"), "{err}");
                eprintln!("{restricted}: refused before {step}: {err}");
                return;
            }
            assert!(err.contains(step), "expected a refusal naming {step:?}: {err}");
            assert!(err.contains("does not serve unconfined"), "{err}");
        }
    }
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
    if !served && let Some(restricted) = userns_restricted() && err.contains("unshare of the namespaces") {
        eprintln!("ran nothing confined: {restricted}: {err}");
        return None;
    }
    let child_calls = calls.iter().filter(|c| c.nested).count();
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
            if userns_restricted().is_none() || err.contains("Landlock") {
                assert!(err.contains("Landlock failed"), "{err}");
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
                eprintln!("ran nothing confined: {restricted}: {err}");
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
    assert!(err.contains("confinement") && err.contains("does not serve unconfined"), "{err}");
}
