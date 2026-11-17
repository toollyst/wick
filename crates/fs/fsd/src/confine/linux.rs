// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Linux's confinement (docs/design-fs.md §6.1), in two calls:
//!
//! [`enter`], after stage 0 has accepted the one connection:
//! 1. `unshare` a mount, pid, network and IPC namespace; a server that is
//!    not root makes a user namespace in the same call, with its own uid and
//!    gid mapped 1:1 and `setgroups` denied;
//! 2. `fork`: the child is pid 1 of the new pid namespace and goes on; the
//!    parent drops everything it holds, waits, and exits as the child did
//!    (it never returns);
//! 3. the child dies with its parent, is not dumpable, makes every mount
//!    private, bind-mounts the share onto itself (not what is mounted
//!    beneath it), remounts the bind `nosuid,nodev,noexec` (and read-only
//!    for a read-only share), and makes it the root with `pivot_root`, the
//!    old root detached;
//! 4. opens `/` and checks it is the object stage 0 checked.
//!
//! [`lock`], once the backend holds the new root:
//! 5. as root, drops to the operator's `--uid`/`--gid` with no
//!    supplementary groups;
//! 6. drops every capability;
//! 7. `no_new_privs`;
//! 8. Landlock where the kernel has it (an added layer, never the only one;
//!    without it the server logs so and goes on, decision Q11): file rights
//!    beneath the root only, no execute and no special files, no TCP, and
//!    abstract sockets and signals scoped;
//! 9. the seccomp filter of `wick_fs_sys::confine::SERVER_SYSCALLS`, which
//!    kills the process on anything else.
//!
//! Every step is required, and a failure is a [`Refusal`] naming it; no flag
//! skips one.

use std::os::fd::AsFd;
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

/// Steps 1 to 4. Returns, in the confined child only, the new root and
/// `keep` (the connection). `keep` is dropped in the parent before it waits.
pub fn enter<T>(checked: Checked, plan: Plan, keep: T) -> Result<(std::os::fd::OwnedFd, T), Refusal> {
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
            #[allow(clippy::exit, reason = "the parent's only job is to end as its child did")]
            std::process::exit(code);
        }
        c::Forked::Child => {}
    }
    drop(alive);
    c::die_with_parent(watch).map_err(|e| refuse("PR_SET_PDEATHSIG", e))?;
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
    Ok((root, keep))
}

/// What [`lock`] put in place beyond the required steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Locked {
    /// The Landlock ABI applied; `None`: this kernel has no Landlock.
    pub landlock: Option<u32>,
}

/// Steps 5 to 9, in the confined child after the backend holds its root.
pub fn lock(plan: Plan) -> Result<Locked, Refusal> {
    if let Some((uid, gid)) = plan.drop_to {
        c::drop_ids(uid, gid).map_err(|e| refuse("dropping to --uid/--gid", e))?;
    }
    c::drop_capabilities().map_err(|e| refuse("dropping the capabilities", e))?;
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
    c::seccomp_install(&c::server_program()).map_err(|e| refuse("the seccomp filter", e))?;
    Ok(Locked { landlock: abi })
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
