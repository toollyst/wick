// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Linux's confinement (docs/design-fs.md §6.1), in two calls:
//!
//! [`enter`], after stage 0 has accepted the one connection:
//! 1. `unshare` a mount, pid, network and IPC namespace; a server that is
//!    not root makes a user namespace in the same call, with its own uid and
//!    gid mapped 1:1 and `setgroups` denied;
//! 2. `fork`: the child is pid 1 of the new pid namespace and goes on; the
//!    parent drops everything it holds, confines itself (the same ids as the
//!    child, no capabilities, not dumpable, `no_new_privs`, and a seccomp
//!    filter of waiting and exiting only, `PARENT_SYSCALLS`), waits, and
//!    exits as the child did (it never returns);
//! 3. the child dies with its parent, is not dumpable, makes every mount
//!    private, bind-mounts the share onto itself (not what is mounted
//!    beneath it), remounts the bind `nosuid,nodev,noexec` (and read-only
//!    for a read-only share), lists its descriptors (`/proc/self/fd`, the
//!    kernel's whole list, the last point it can be read) and requires them
//!    to be exactly the standard streams, the caller's (the connection),
//!    its end of the parent's pipe and stage 0's root, and makes the share
//!    the root with `pivot_root`, the old root detached;
//! 4. opens `/` and checks it is the object stage 0 checked.
//!
//! [`lock`], once the backend holds the new root:
//! 5. empties the bounding set (while it holds `CAP_SETPCAP`), then, as
//!    root, drops to the operator's `--uid`/`--gid` with no supplementary
//!    groups;
//! 6. drops every other capability (ambient, effective, permitted,
//!    inheritable), the bounding set checked empty; dies with its parent and is not dumpable
//!    again (a change of ids clears both, `commit_creds`);
//! 7. `no_new_privs`;
//! 8. Landlock where the kernel has it (an added layer, never the only one;
//!    without it the server logs so and goes on, decision Q11): file rights
//!    beneath the root only, no execute and no special files, no TCP, and
//!    abstract sockets and signals scoped;
//! 9. the seccomp filter of `wick_fs_sys::confine::SERVER_SYSCALLS`, which
//!    kills the process on anything else;
//! 10. reads back what must hold, in one place ([`check`]): the ids, the
//!     groups, every capability set, `SECBIT_KEEP_CAPS`, `no_new_privs`, the
//!     parent-death signal, dumpable, and the filter by its own effect; and,
//!     before the filter, that the descriptors open below the soft
//!     `RLIMIT_NOFILE` (every one it opened itself is) are exactly the
//!     standard streams and what the caller holds ([`held_exactly`]).
//!
//! Every step is required, and a failure is a [`Refusal`] naming it; no flag
//! skips one.

use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::path::Path;

use wick_fs_sys as sys;
use wick_fs_sys::confine as c;

use crate::host::unix::Refusal;
use crate::stage0::Checked;

/// What `enter` needs besides the share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Serve the share read-only: the bind mount is read-only too.
    pub read_only: bool,
    /// The uid and gid to drop to; required when running as root, refused
    /// otherwise.
    pub drop_to: Option<(u32, u32)>,
}

fn refuse(step: &str, e: sys::HostErrno) -> Refusal {
    Refusal(format!("confinement: {step} failed ({e:?}); wick-fsd does not serve unconfined"))
}

/// The child's end of the pipe its parent holds: [`lock`] arms the
/// parent-death signal again with it after the ids change.
#[derive(Debug)]
pub struct ParentWatch(std::os::fd::OwnedFd);

/// Steps 1 to 4. Returns, in the confined child only, the new root, `keep`
/// (the connection) and the [`ParentWatch`] for [`lock`]. `keep` is dropped
/// in the parent before it waits.
/// `kept`: the descriptors of `keep` (the connection), which the child
/// goes on holding.
pub fn enter<T>(
    checked: Checked,
    plan: Plan,
    keep: T,
    kept: &[RawFd],
) -> Result<(std::os::fd::OwnedFd, T, ParentWatch), Refusal> {
    let root_user = sys::euid() == 0;
    match (root_user, plan.drop_to) {
        (true, None) => {
            return Err(Refusal(
                "running as root needs --uid and --gid, the unprivileged ids to serve as".into(),
            ));
        }
        (true, Some((0, _) | (_, 0))) => {
            return Err(Refusal("--uid and --gid must not be 0".into()));
        }
        (false, Some(_)) => {
            return Err(Refusal("--uid and --gid need root (the server drops to them)".into()));
        }
        _ => {}
    }
    let (uid, gid) = (sys::euid(), sys::gid());
    c::unshare(!root_user).map_err(|e| {
        let mut r = refuse("unshare of the namespaces", e);
        if !root_user {
            r.0.push_str(
                ". Unprivileged user namespaces may be disabled on this host (user.max_user_namespaces, or \
                 Ubuntu's kernel.apparmor_restrict_unprivileged_userns); run wick-fsd as root with --uid/--gid \
                 instead",
            );
        }
        r
    })?;
    if !root_user {
        let write = |file: &str, what: String| {
            std::fs::write(file, what).map_err(|e| refuse(file, sys::HostErrno(e.raw_os_error().unwrap_or(5))))
        };
        write("/proc/self/setgroups", "deny".into())?;
        write("/proc/self/uid_map", format!("{uid} {uid} 1"))?;
        write("/proc/self/gid_map", format!("{gid} {gid} 1"))?;
    }
    let (watch, alive) = c::parent_watch().map_err(|e| refuse("the parent's pipe", e))?;
    match c::fork().map_err(|e| refuse("fork into the pid namespace", e))? {
        c::Forked::Parent(child) => {
            drop(keep);
            drop(checked);
            drop(watch);
            // Held open until this process ends: the child's sign that its
            // parent lives.
            let _alive = alive;
            // It takes no input but lives as long as the share: nothing it
            // does not need. Failing, it ends, and so does the child (the
            // pipe, then the parent-death signal).
            if let Err(r) = confine_parent(plan) {
                eprintln!("wick-fsd: {}", r.0);
                c::exit_now(1);
            }
            let code = match c::wait(child) {
                Ok(c::Ended::Exited(code)) => code,
                Ok(c::Ended::Signaled(sig)) => {
                    let why = if sig == 31 {
                        " (SIGSYS: a system call outside its seccomp list)"
                    } else {
                        ""
                    };
                    eprintln!("wick-fsd: the confined server was killed by signal {sig}{why}");
                    128 + sig
                }
                Err(e) => {
                    eprintln!("wick-fsd: waiting for the confined server failed: {e:?}");
                    1
                }
            };
            // `_exit`: under its filter the parent makes no other call.
            c::exit_now(code);
        }
        c::Forked::Child => {}
    }
    drop(alive);
    c::die_with_parent(watch.as_fd()).map_err(|e| refuse("PR_SET_PDEATHSIG", e))?;
    c::not_dumpable().map_err(|e| refuse("PR_SET_DUMPABLE", e))?;
    let share = checked.canonical.as_path();
    c::mounts_private().map_err(|e| refuse("making the mounts private", e))?;
    let locked = c::locked_flags(share).map_err(|e| refuse("statvfs of the share", e))?;
    c::bind_self(share).map_err(|e| refuse("the share's bind mount", e))?;
    let mut flags = locked | c::ms::NOSUID | c::ms::NODEV | c::ms::NOEXEC;
    if plan.read_only {
        flags |= c::ms::RDONLY;
    }
    c::remount_bind(share, flags).map_err(|e| refuse("the bind mount's remount (nosuid, nodev, noexec)", e))?;
    // The kernel's whole list, read while `/proc` is still in the root:
    // what the first step closed (main.rs) and every descriptor opened
    // since, closed again or one of these.
    let open = sys::open_descriptors().map_err(|e| refuse("listing the descriptors (/proc/self/fd)", e))?;
    let mut expected = kept.to_vec();
    expected.extend([watch.as_raw_fd(), checked.root.as_raw_fd()]);
    held_exactly("before pivot_root", &open, &expected)?;
    c::pivot_to(share).map_err(|e| refuse("pivot_root to the share", e))?;
    let root = sys::open_root(Path::new("/")).map_err(|e| refuse("opening the new root", e))?;
    let st = sys::fstat(root.as_fd()).map_err(|e| refuse("fstat of the new root", e))?;
    if (st.dev, st.ino) != checked.id {
        return Err(Refusal(format!(
            "confinement: the new root is not the share stage 0 checked ({} changed meanwhile)",
            checked.canonical.display()
        )));
    }
    drop(checked);
    Ok((root, keep, ParentWatch(watch)))
}

/// The waiting parent's own confinement (step 2): the child's ids, no
/// capabilities, not dumpable, `no_new_privs`, and [`c::parent_program`].
/// It needs no signal to the child (the child dies with it), no descriptor
/// but its end of the pipe and the standard streams, and no file.
fn confine_parent(plan: Plan) -> Result<(), Refusal> {
    // The child's step names: a refusal names the step whichever process
    // met it first.
    let refuse = |step: &str, e| refuse(&format!("the waiting parent: {step}"), e);
    c::drop_bounding().map_err(|e| refuse("dropping the bounding set", e))?;
    if let Some((uid, gid)) = plan.drop_to {
        c::drop_ids(uid, gid).map_err(|e| refuse("dropping to --uid/--gid", e))?;
    }
    c::drop_capabilities().map_err(|e| refuse("dropping the capabilities", e))?;
    c::not_dumpable().map_err(|e| refuse("PR_SET_DUMPABLE", e))?;
    c::no_new_privs().map_err(|e| refuse("PR_SET_NO_NEW_PRIVS", e))?;
    c::seccomp_install(&c::parent_program()).map_err(|e| refuse("the seccomp filter", e))
}

/// What [`lock`] put in place beyond the required steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Locked {
    /// The Landlock ABI applied; `None`: this kernel has no Landlock.
    pub landlock: Option<u32>,
}

/// Steps 5 to 10, in the confined child after the backend holds its root.
/// `held`: the descriptors the caller holds and serves with (the
/// connection, the backend's root).
pub fn lock(plan: Plan, watch: ParentWatch, held: &[RawFd]) -> Result<Locked, Refusal> {
    // Before the ids: the drop from root takes CAP_SETPCAP, which each
    // bounding drop needs.
    c::drop_bounding().map_err(|e| refuse("dropping the bounding set", e))?;
    if let Some((uid, gid)) = plan.drop_to {
        c::drop_ids(uid, gid).map_err(|e| refuse("dropping to --uid/--gid", e))?;
    }
    c::drop_capabilities().map_err(|e| refuse("dropping the capabilities", e))?;
    // The id change cleared these (`commit_creds`): armed again, and the
    // parent checked to be alive still.
    c::die_with_parent(watch.0.as_fd()).map_err(|e| refuse("PR_SET_PDEATHSIG after the id drop", e))?;
    drop(watch);
    c::not_dumpable().map_err(|e| refuse("PR_SET_DUMPABLE after the id drop", e))?;
    c::no_new_privs().map_err(|e| refuse("PR_SET_NO_NEW_PRIVS", e))?;
    let abi = c::landlock_abi().map_err(|e| refuse("asking for Landlock's ABI", e))?;
    if let Some(abi) = abi {
        let root = sys::open_root(Path::new("/")).map_err(|e| refuse("opening the root for Landlock", e))?;
        let (handled, allowed) = landlock_rights(abi);
        c::landlock_restrict(abi, root.as_fd(), handled, allowed).map_err(|e| refuse("Landlock", e))?;
    } else {
        eprintln!(
            "wick-fsd: this kernel has no Landlock (an added layer only): serving with namespaces, seccomp and \
             no_new_privs"
        );
    }
    // Its descriptors, every one it opened itself: below the soft limit
    // (main.rs sets it to what the share's limits may hold open), where the
    // kernel gives each new one the lowest free number. Above it nothing was
    // open before pivot_root (listed there).
    let (soft, _) = sys::nofile().map_err(|e| refuse("reading RLIMIT_NOFILE", e))?;
    held_exactly("when it serves", &sys::descriptors_below(soft), held)?;
    // What holds, read back in one place (step 10): the calls above said
    // they were done; this is what the kernel holds. Nothing after the read
    // changes credentials (the filter's install does not: kernel/seccomp.c,
    // v6.12, `seccomp_set_mode_filter` :1990 to :1996), and the filter's
    // own effect is read after it.
    let state = c::state().map_err(|e| refuse("reading the confinement back", e))?;
    c::seccomp_install(&c::server_program()).map_err(|e| refuse("the seccomp filter", e))?;
    check(plan, &state, c::filter_in_place())?;
    Ok(Locked { landlock: abi })
}

/// Step 10: what must hold once every step said it was done, each read
/// back from the kernel ([`c::state`], [`c::filter_in_place`]); one refusal
/// naming everything that did not. The ids are `--uid`/`--gid` for a server
/// started as root, its real ids otherwise (no saved or effective id
/// apart). A server that is not root keeps its user's supplementary groups:
/// its user namespace denies `setgroups` (user_namespaces(7)), and they
/// grant nothing its user does not have; as root it has none. Landlock is
/// not read back: the kernel has no call that reads a domain
/// (security/landlock/syscalls.c, v6.12: create_ruleset, add_rule and
/// restrict_self only), and `landlock_restrict_self` returns 0 only from
/// `commit_creds` of the new domain (:524).
pub fn check(plan: Plan, state: &c::State, filtered: bool) -> Result<(), Refusal> {
    let mut not = Vec::new();
    let (uid, gid) = plan.drop_to.unwrap_or((state.uids[0], state.gids[0]));
    if state.uids != [uid; 4] {
        not.push(format!("the uids (real, effective, saved, file system) are {:?}, not {uid}", state.uids));
    }
    if state.gids != [gid; 4] {
        not.push(format!("the gids (real, effective, saved, file system) are {:?}, not {gid}", state.gids));
    }
    if plan.drop_to.is_some() && state.groups != 0 {
        not.push(format!("{} supplementary groups are left", state.groups));
    }
    if state.caps != [0; 6] {
        not.push(format!("capabilities (effective, permitted, inheritable) are left: {:x?}", state.caps));
    }
    if !state.bounding.is_empty() {
        not.push(format!("the bounding set holds {:?}", state.bounding));
    }
    if !state.ambient.is_empty() {
        not.push(format!("the ambient set holds {:?}", state.ambient));
    }
    if state.securebits & c::SECBIT_KEEP_CAPS != 0 {
        not.push("SECBIT_KEEP_CAPS is set".into());
    }
    if !state.no_new_privs {
        not.push("no_new_privs is not set".into());
    }
    if state.death_signal != c::SIGKILL {
        not.push(format!("the parent-death signal is {}, not SIGKILL", state.death_signal));
    }
    if state.dumpable {
        not.push("the process is dumpable".into());
    }
    if !filtered {
        not.push("the seccomp filter is not in place (its probe call was not refused as it refuses it)".into());
    }
    if not.is_empty() {
        return Ok(());
    }
    Err(Refusal(format!(
        "confinement: read back after the steps, what did not hold: {}; wick-fsd does not serve unconfined",
        not.join("; ")
    )))
}

/// The descriptors `open` are exactly the standard streams and `expected`:
/// one refusal naming each other one (what it is, `descriptor_described`)
/// and each expected one not open, `when`.
pub fn held_exactly(when: &str, open: &[RawFd], expected: &[RawFd]) -> Result<(), Refusal> {
    let expected: Vec<RawFd> = [0, 1, 2].iter().chain(expected).copied().collect();
    let other: Vec<String> = open.iter().filter(|fd| !expected.contains(fd)).map(|&fd| sys::descriptor_described(fd)).collect();
    let missing: Vec<RawFd> = expected.iter().filter(|fd| !open.contains(fd)).copied().collect();
    let mut not = Vec::new();
    if !other.is_empty() {
        not.push(format!("descriptors open that wick-fsd did not open or keep: {}", other.join(", ")));
    }
    if !missing.is_empty() {
        not.push(format!("descriptors it holds that are not open: {missing:?}"));
    }
    if not.is_empty() {
        return Ok(());
    }
    Err(Refusal(format!("confinement: {when}, {}; wick-fsd does not serve unconfined", not.join("; "))))
}

/// Landlock's file rights for `abi`: (handled, allowed beneath the root).
/// Never allowed: execute, and making devices, sockets, FIFOs and symlinks
/// (the server emulates those as regular files; design-fs row 12).
pub fn landlock_rights(abi: u32) -> (u64, u64) {
    use c::landlock::*;
    let mut handled = EXECUTE
        | WRITE_FILE
        | READ_FILE
        | READ_DIR
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM;
    if abi >= 2 {
        handled |= REFER;
    }
    if abi >= 3 {
        handled |= TRUNCATE;
    }
    if abi >= 5 {
        handled |= IOCTL_DEV;
    }
    let allowed = handled & !(EXECUTE | MAKE_CHAR | MAKE_SOCK | MAKE_FIFO | MAKE_BLOCK | MAKE_SYM | IOCTL_DEV);
    (handled, allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held() -> c::State {
        c::State {
            uids: [65534; 4],
            gids: [65534; 4],
            groups: 0,
            caps: [0; 6],
            bounding: Vec::new(),
            ambient: Vec::new(),
            securebits: 0,
            no_new_privs: true,
            death_signal: c::SIGKILL,
            dumpable: false,
        }
    }

    const ROOT: Plan = Plan {
        read_only: false,
        drop_to: Some((65534, 65534)),
    };

    const USER: Plan = Plan {
        read_only: false,
        drop_to: None,
    };

    #[test]
    fn test_descriptors_held_exactly() {
        held_exactly("t", &[0, 1, 2, 5, 9], &[9, 5]).unwrap();
        let r = held_exactly("before pivot_root", &[0, 1, 2, 5, 9, 131], &[5, 9]).unwrap_err().0;
        assert!(r.contains("before pivot_root, descriptors open that wick-fsd did not open or keep: 131: "), "{r}");
        assert!(r.contains("does not serve unconfined") && !r.contains("not open: ["), "{r}");
        let r = held_exactly("t", &[0, 1, 2, 7], &[5]).unwrap_err().0;
        assert!(r.contains("7: ") && r.contains("descriptors it holds that are not open: [5]"), "{r}");
        let r = held_exactly("t", &[0, 2, 5], &[5]).unwrap_err().0;
        assert!(r.contains("not open: [1]"), "{r}");
    }

    #[test]
    fn test_what_held_is_served() {
        check(ROOT, &held(), true).unwrap();
        // A server that is not root: its own ids, its user's groups.
        let mut s = held();
        s.uids = [1000; 4];
        s.gids = [1000; 4];
        s.groups = 3;
        check(USER, &s, true).unwrap();
    }

    #[test]
    fn test_each_thing_that_did_not_hold_is_named_in_one_refusal() {
        for case in 0..13 {
            let mut s = held();
            let (mut plan, mut filtered) = (ROOT, true);
            let named = match case {
                0 => {
                    s.uids[2] = 0;
                    "the uids (real, effective, saved, file system) are [65534, 65534, 0, 65534], not 65534"
                }
                1 => {
                    s.uids[3] = 0;
                    "not 65534"
                }
                2 => {
                    s.gids[1] = 0;
                    "the gids"
                }
                3 => {
                    s.groups = 1;
                    "1 supplementary groups are left"
                }
                4 => {
                    plan = USER;
                    s.uids[1] = 0;
                    "the uids"
                }
                5 => {
                    s.caps[2] = 1;
                    "capabilities (effective, permitted, inheritable) are left"
                }
                6 => {
                    s.bounding = vec![21];
                    "the bounding set holds [21]"
                }
                7 => {
                    s.ambient = vec![0];
                    "the ambient set holds [0]"
                }
                8 => {
                    s.securebits = c::SECBIT_KEEP_CAPS;
                    "SECBIT_KEEP_CAPS is set"
                }
                9 => {
                    s.no_new_privs = false;
                    "no_new_privs is not set"
                }
                10 => {
                    s.death_signal = 0;
                    "the parent-death signal is 0, not SIGKILL"
                }
                11 => {
                    s.dumpable = true;
                    "the process is dumpable"
                }
                _ => {
                    filtered = false;
                    "the seccomp filter is not in place"
                }
            };
            let r = check(plan, &s, filtered).unwrap_err().0;
            assert!(r.contains(named) && r.contains("does not serve unconfined"), "{named}: {r}");
        }
        // Several at once: every one named, in one refusal.
        let mut s = held();
        s.dumpable = true;
        s.death_signal = 0;
        let r = check(ROOT, &s, false).unwrap_err().0;
        assert!(r.contains("dumpable") && r.contains("parent-death") && r.contains("seccomp"), "{r}");
    }
}
