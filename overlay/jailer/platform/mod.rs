// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The jailer's host primitives outside Linux. Not part of upstream Firecracker.
//!
//! The jailer itself is upstream's: its command line, `Env::new` and `Env::run`
//! (the order of the steps, the jail's folders, resource limits, daemonizing,
//! the pid file) run unchanged on every host. What upstream does with
//! Linux-only primitives goes through an interface with one backend per host;
//! on Linux the backend is upstream's own code.
//!
//! | Interface (upstream)                       | Linux (upstream)              | macOS                                                        |
//! |--------------------------------------------|-------------------------------|--------------------------------------------------------------|
//! | `chroot::chroot`                           | mount namespace + `pivot_root`| `chroot(2)`, left again for the exec only (below)            |
//! | `cgroup::CgroupConfigurationBuilder`       | cgroup v1/v2 files            | `memory.max` / `memory.limit_in_bytes` → jetsam limit at exec; `cpu.max` / `cpu.cfs_*` → a CPU limit Firecracker applies to itself; the freezer → upstream's files next to the jail, kept by a supervisor (`freezer`); other controllers refused; an empty hierarchy (no parent cgroup to join) |
//! | `Env::join_netns` → [`join_netns`]         | `setns(CLONE_NEWNET)`         | a directory of endpoints, granted to the jail's uid and named to Firecracker at the exec (`WICK_NETNS`); the sandbox denies all IP networking |
//! | `Env::exec_into_new_pid_ns` → [`new_pid_ns`] | `clone(CLONE_NEWPID)`       | a fork; the jail holds what the namespace would (`new_pid_ns`) |
//! | `Env::mknod_and_own_dev` → [`mknod_and_own_dev`] | device nodes in the jail | none needed: Hypervisor.framework, vmnet, `getentropy` and wick's userfaultfd use no device node |
//! | `Env::copy_midr_el1_info` → [`copy_midr_el1_info`] | sysfs file in the jail | nothing to copy: macOS has no sysfs, the same inside the jail as outside |
//! | `Env::exec_command` → [`exec_command`]     | exec as `uid:gid`             | exec with the jail handed over to Firecracker (`vmm::ext::jail`), after the jail's freezer supervisor is started |
//! | `close_fds_by_close_range` → [`close_fds_by_close_range`] | `close_range` | descriptors listed with `proc_pidinfo` and closed      |
//!
//! No program can start inside a chroot on macOS: dyld maps the system
//! libraries from the shared cache, which is outside any jail (the kernel keeps
//! one shared region per root directory). So the macOS backend chroots the
//! jailer as upstream does, and for the exec alone leaves the chroot again
//! (the jailer is still root) and starts Firecracker with `WICK_JAIL` set; the
//! first thing Firecracker does is chroot into the same jail and drop to
//! `uid:gid`. The binary it execs as root is a root-owned copy next to the
//! jail, never one the jailed user could have written, and must carry the
//! hand-over mark (any other binary would run unjailed as root).
//!
//! Windows has no chroot, no user switch for a non-elevated jailer and no
//! exec; its backend ([`windows`]) makes the jail's root a drive of its own
//! (upstream's absolute paths resolve inside it), confines Firecracker with a
//! restricted low integrity token in place of `uid:gid` and with a Job Object
//! in place of cgroups, and starts it, waits for it and exits with its
//! status. Upstream's Unix-only steps around those (file modes and owners,
//! resource limits, daemonizing) go through the same backend on Windows
//! (patch 0019).

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

// What the freezer files hold, the same on the hosts that keep them
// (Windows; macOS's freezer moves to it).
#[cfg(windows)]
pub(crate) mod freezer_values;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
