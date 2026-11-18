// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! macOS's confinement (docs/design-fs.md §6.2), once stage 0 has accepted
//! the one connection, checked its peer, and the backend holds the share's
//! root:
//! 0. libc's first uses that read what the profile denies, made before it
//!    ([`first_uses`]): its value kept for the process's life, so the
//!    confined server never makes the call; [`confine`] takes their proof;
//! 1. the profile ([`profile`]) built for the share's canonical path and
//!    compiled, with the operator's rights;
//! 2. as root, the drop to the operator's `--uid`/`--gid` (required, never
//!    0), its one group the gid's;
//! 3. the ids read back ([`sys::seatbelt::ids`]) and that no profile is in
//!    force yet, then the profile applied for good;
//! 4. checked, in one place ([`check`]): the ids, no saved id to go back
//!    to, and the profile in force: none was before it (read before the
//!    apply, since the profile kills the call that reads it), and after it
//!    a second apply is killed at its mac-syscall, so no other replaces it.
//!
//! The profile kills: whatever it does not allow ends the process inside the
//! call (SIGKILL), files outside the share included. A denial means the
//! server's own checks let a request through, so it must die loudly; the VMM
//! then sees the connection close. Every step is required, and a failure is
//! a [`Refusal`] naming it; no flag skips one. There is no fork and so no
//! parent to confine: the process that accepted the connection serves it.

use std::os::fd::{BorrowedFd, RawFd};
use std::path::Path;

use wick_fs_sys as sys;
use wick_fs_sys::seatbelt as sb;

use super::{held_exactly, held_exactly_named};
use crate::host::unix::Refusal;

/// What [`confine`] needs besides the share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Serve the share read-only: the profile allows no write.
    pub read_only: bool,
    /// The uid and gid to drop to; required when running as root, refused
    /// otherwise.
    pub drop_to: Option<(u32, u32)>,
}

fn refuse(step: &str, e: impl std::fmt::Debug) -> Refusal {
    Refusal(format!("confinement: {step} failed ({e:?}); wick-fsd does not serve unconfined"))
}

/// The profile's fixed part (docs/design-fs.md §6.2). Everything no rule
/// allows is a denial that kills the process (SIGKILL) inside the call: the
/// default, files outside the share, generated code, and any system call,
/// Mach trap, MIG routine or mac-syscall not listed ([`profile`] adds the
/// share's rules and the lists). Two rules are not kills:
/// - the host's privileged port, refused with an error: libsandbox asks for
///   it inside `sandbox_apply`, once the profile is in force (measured on
///   macOS 27.2: with the kill the process ends in `sandbox_apply`;
///   Firecracker's profile, `overlay/vmm/ext/sandbox.rs`, has the same rule
///   for the same reason). The server asking for the port later is killed
///   at the Mach trap, before the rule is consulted (confine_probe);
/// - the free space of the share's volume, allowed exactly (`system-info`
///   `vfs.disk-space`, which `fstatfs` asks): denied, the free blocks are
///   rounded (measured: 5945470 shown as 5940000), where Linux's STATFS
///   answers exactly. The guest learns the share volume's free space, as on
///   Linux.
pub const BASE: &str = r#"(version 1)
(deny default (with send-signal SIGKILL))
(deny mach-priv-host-port)
(allow system-info (info-type "vfs.disk-space"))
(deny dynamic-code-generation (with send-signal SIGKILL))
(deny syscall-unix (with send-signal SIGKILL))
(deny syscall-mach (with send-signal SIGKILL))
(deny syscall-mig (with send-signal SIGKILL))
(deny system-mac-syscall (with send-signal SIGKILL))
(deny generic-issue-extension (with send-signal SIGKILL))
"#;

/// The system calls the server makes once confined, by number
/// (<sys/syscall.h>; xnu's numbers do not change between majors, and a
/// `SYS_` name a major's libsandbox does not know fails the whole profile),
/// each with its name and why. Measured with the discovery build over the
/// confined tests (docs/design-fs.md §6.2: each one reported unlisted in a
/// discovery run), but for the two whose reason says otherwise.
pub const SYSCALLS: &[(u16, &str, &str)] = &[
    (29, "recvfrom", "frames from the VMM (std's read of a stream socket)"),
    (53, "sigaltstack", "at exit: std takes down the main thread's stack-overflow handler"),
    (73, "munmap", "at exit: std unmaps that handler's stack"),
    (
        75,
        "madvise",
        "libmalloc clears a large block it hands out again zeroed (READ's reply buffer, `vec![0; n]`: xzone's \
         `_xzm_segment_group_clear_chunk`, MADV_ZERO) and gives a freed one's pages back (MADV_FREE_REUSABLE, \
         as macOS 15's magazine does for a medium region's freed pages, vm.c `mvm_madvise_free`): measured on \
         macOS 27.2, killed `deny(1) syscall-unix 75` in `Session::read` (requests.rs \
         `test_a_confined_server_answers_large_reads_again_and_again`, crash report) and reported by confine_probe's allocator shapes; the advice cannot be filtered (no such Seatbelt filter), and \
         xnu's madvise acts on the caller's own map only (bsd/kern/kern_mman.c, `current_map()`)",
    ),
    (92, "fcntl", "the commands of FCNTL_COMMANDS, each checked (`system-fcntl`)"),
    (
        95,
        "fsync",
        "FSYNC on a file system without F_FULLFSYNC (its ENOTSUP); from the code, never run: every volume a share \
         can be on that the tests make (APFS) has F_FULLFSYNC",
    ),
    (
        116,
        "gettimeofday",
        "SETATTR of a time to now (`Session`'s `now()`, `SystemTime::now`): libc's `clock_gettime(CLOCK_REALTIME)` \
         reads the commpage's time and makes this call when it cannot (libsyscall \
         `__commpage_gettimeofday_internal`: the kernel updating that time, `TimeStamp_tick` 0, or the time a \
         second old; xnu-11417); measured on macOS 27.2, 13 calls in 20,000,000 back-to-back reads (reported \
         `allow syscall-unix 116`), so about one SETATTR-to-now in a million; confine_probe makes it by number. \
         It only reads the time",
    ),
    (133, "sendto", "replies to the VMM (std's write to a stream socket)"),
    (153, "pread", "READ"),
    (199, "lseek", "READDIR from an offset (the directory stream's seek), FALLOCATE's walk over holes (SEEK_HOLE/SEEK_DATA)"),
    (201, "ftruncate", "SETATTR of the size, FALLOCATE past the end"),
    (229, "fsetattrlist", "SETATTR of the times (libc's futimens)"),
    (235, "fgetxattr", "the metadata record and GETXATTR"),
    (241, "flistxattr", "LISTXATTR"),
    (339, "fstat64", "a held descriptor's attributes and identity (GETATTR, a node found again)"),
    (344, "getdirentries64", "READDIR and READDIRPLUS (libc's readdir)"),
    (346, "fstatfs64", "STATFS (fstatvfs), FALLOCATE's hole punching (the block size)"),
    (406, "fcntl_nocancel", "libc's fdopendir (the directory stream READDIR reads through): a command of FCNTL_COMMANDS"),
    (470, "fstatat64", "LOOKUP and GETATTR beneath a held directory, never following a link"),
    (475, "mkdirat", "MKDIR"),
    (
        473,
        "readlinkat",
        "READLINK of a symlink the host made in the share (the guest's own are kept as files); never reported in a \
         discovery run: measured by a run of requests.rs without it, killed `deny(1) syscall-unix 473` in readlinkat",
    ),
    (476, "getattrlistat", "a name as stored on disk (`stored_name`: LOOKUP's exact-name check)"),
    (488, "renameatx_np", "RENAME, with RENAME_EXCHANGE and RENAME_NOREPLACE"),
];

/// The `fcntl` commands the server makes once confined (`F_<name>`,
/// <sys/fcntl.h>), each with why. Seatbelt checks the command of every
/// `fcntl` and `fcntl_nocancel` (`system-fcntl`, filter `fcntl-command`), so
/// any other command is killed, as Linux's filter allows `fcntl` with
/// `F_GETFL` and `F_GETFD` only. Taken from the code and measured: the
/// confined tests (requests, corpus, links) pass with exactly these, and
/// each is needed, a run without it killed (docs/design-fs.md §6.2).
pub const FCNTL_COMMANDS: &[(&str, &str)] = &[
    ("F_GETFD", "the read-back's walk over the descriptors under the profile (step 4)"),
    ("F_SETFD", "libc's fdopendir marks the directory stream's descriptor close-on-exec (READDIR)"),
    ("F_FULLFSYNC", "FSYNC"),
    ("F_PREALLOCATE", "FALLOCATE that allocates"),
    ("F_PUNCHHOLE", "FALLOCATE that punches a hole"),
];

/// The Mach traps the server makes once confined, by `MSC_` name, with why.
/// libmalloc's, measured on macOS 27.2 by a C program allocating, growing and
/// freeing small to 600 MB blocks under a profile that kills every other
/// trap (c15/sbx/alloc.c): each one named in the kill's report, then
/// allowed, until it ran; and on macOS 15 by confine_probe's allocator shapes
/// and the confined tests in CI (docs/design-fs.md §6.2, the table of each
/// major's allocator). wick-fsd makes them for a frame (up to 2 MiB) and
/// the node and handle tables (LINK's names beyond what a node keeps). Each
/// `MSC_` name is defined on every major the profile runs on (Firecracker's
/// profile lists the same names unconditionally, overlay/vmm/ext/sandbox.rs).
pub const MACH_TRAPS: &[(&str, &str)] = &[
    (
        "_kernelrpc_mach_vm_deallocate_trap",
        "macOS 15's magazine gives back a new medium region's mapping that landed above its entropic limit and maps \
         it again lower (libmalloc-715.140.5 vm.c :245, `mvm_allocate_plat`; a medium region, magazine_medium.c :2448, \
         holds every block of 32 KiB to 8 MiB on arm64): measured on macOS 15.8.2 in CI run 44362564244, killed \
         `deny(1) syscall-mach 12` in `Session::read`'s `vec![0u8; want]` (a confined server of requests.rs, crash \
         report: `mach_vm_deallocate` ← `mvm_allocate_pages_plat` ← `medium_malloc_should_clear`) and in four of \
         confine_probe's allocator shapes, reported by all five; the trap acts on the caller's own task only (xnu-11417 osfmk/ipc/mach_kernelrpc.c :77, \
         `port_name_to_current_task_noref`)",
    ),
    ("_kernelrpc_mach_vm_map_trap", "libmalloc maps a large block (trap 15)"),
    ("mach_msg2_trap", "libmalloc's MIG call to grow a large block in place (trap 47; the routine is below)"),
];

/// The kernel MIG routines the server makes once confined, with why.
pub const MIG_ROUTINES: &[(&str, &str)] = &[];

/// MIG routines allowed where the kernel defines them: `mach_vm_reallocate`
/// is in xnu's osfmk/mach/mach_vm.defs from xnu-12377.101.15 (a macOS 26
/// release) on, and a profile naming it does not compile on an older kernel
/// (macOS 15, as Firecracker's profile found, and macOS 26 before that
/// release). Where it is not defined libmalloc cannot call it; there
/// (libmalloc-715.140.5, macOS 15) the server's blocks of 32 KiB to 8 MiB
/// are medium on Apple silicon, wick's only macOS host (the medium allocator
/// is always engaged on arm64, malloc.c :357), and grow within their region
/// or move; a large block (past 8 MiB, which the server never asks) grows in
/// place with `vm_allocate` at a fixed address (magazine_large.c
/// `large_try_realloc_in_place`, trap 10, not in the profile: no run has
/// reported it) or moves with `memcpy` (`vm_copy` only past 2 MiB of data,
/// magazine_malloc.c :592, which no buffer of the server holds: a frame is
/// at most 1 MiB + 4 KiB, and the node and handle tables are hash tables
/// that grow by a new allocation, never by realloc).
/// confine_probe's allocator shapes (a frame's block, a buffer grown to it,
/// a realloc to it, the node tables at their cap, many large blocks freed)
/// check each major's way, and report on record what each calls.
pub const MIG_ROUTINES_IF_DEFINED: &[(&str, &str)] =
    &[("mach_vm_reallocate", "libmalloc grows a large block (realloc), measured as the traps are")];

/// libmalloc's deferred reclamation: the kernel's accounting trap, allowed
/// where this macOS defines it (`MSC_` name). xnu-12377 (macOS 26) on has it
/// (osfmk/kern/syscall_sw.c :173, trap 63; `kern_invalid` in xnu-11417,
/// macOS 15), and from that release libmalloc's xzone allocator defers the
/// reclamation of the spans it frees by default on macOS (libmalloc-792.80.2
/// and 812.100.31 xzone_malloc.h `XZM_DEFERRED_RECLAIM_ENABLED_DEFAULT`; its
/// ring is allocated at malloc's start, before the profile, 1016 entries
/// measured). macOS 15's libmalloc (715.140.5) has no deferred reclamation
/// on macOS (platform.h `CONFIG_MAGAZINE_DEFERRED_RECLAIM` 0, its xzone none).
pub const MACH_TRAPS_IF_DEFINED: &[(&str, &str)] = &[(
    RECLAMATION_TRAP,
    "measured: on macOS 27.2 a confined server was killed at its first READ 10 s or more after it started \
     (`deny(1) syscall-mach 63`; crash report: the trap ← `mach_vm_reclaim_update_kernel_accounting` ← \
     `_xzm_reclaim_mark_free` ← `xzm_segment_group_free_chunk` ← the reply frame's buffer dropped in \
     `Session::handle`): each span libmalloc frees goes into the ring (`mach_vm_reclaim_try_enter`), which asks \
     for this trap once the ring's sampling period has passed since its last sample (xnu-12377.1.9 \
     libsyscall/mach/vm_reclaim.c :265, :417), and that period is 10 s on every macOS (osfmk/vm/vm_reclaim.c \
     :79, `vm_reclaim_sampling_period_ns` under `CONFIG_WORKING_SET_ESTIMATION`); a timer, not a chance. The \
     trap acts on the caller's own task only (osfmk/ipc/mach_kernelrpc.c :784, \
     `port_name_to_current_task_noref`)",
)];

/// The accounting trap of [`MACH_TRAPS_IF_DEFINED`], whose definition the
/// rules of [`MIG_ROUTINES_WITH_RECLAMATION`] also wait on.
pub const RECLAMATION_TRAP: &str = "mach_vm_reclaim_update_kernel_accounting_trap";

/// The MIG routines of the same ring, allowed where the kernel defines the
/// accounting trap above (the releases whose libmalloc makes a ring) and
/// the routine: xnu-11417.101.15 (macOS 15.4) on defines both routines, but
/// no allocator of macOS 15 makes a ring, so there the rule is not emitted.
pub const MIG_ROUTINES_WITH_RECLAMATION: &[(&str, &str)] = &[
    (
        "mach_vm_deferred_reclamation_buffer_resize",
        "reachable by source, not measured: libmalloc's xzone resizes a full ring when it frees a span \
         (libmalloc-812.100.31 xzone_segment.c :345 `_xzm_reclaim_sync_and_resize` when \
         `mach_vm_reclaim_try_enter` finds the ring full, :300 `mach_vm_reclaim_ring_resize`); the ring's head moves \
         only as the kernel reclaims it, so a server that frees more than its 1016 entries' worth of spans between the \
         kernel's passes makes it (not reached by up to 12,000 frees of 64 KiB to 1 MiB in one run, each under a rule \
         killing it by name); the routine acts on the caller's own task only (xnu-12377.1.9 osfmk/vm/vm_user.c \
         `mach_vm_deferred_reclamation_buffer_resize`: `task != current_task()` is KERN_INVALID_TASK)",
    ),
    (
        "mach_vm_deferred_reclamation_buffer_flush",
        "reachable by source, not measured: libmalloc's xzone flushes the ring when its resize fails \
         (xzone_segment.c :305, `_xzm_reclaim_force_sync`, :260) and when taking back a span loses a race with the \
         kernel reclaiming it (xzone_malloc.c :447, :612, :689, :6904, each `xzm_reclaim_force_sync`, on the \
         allocation path); not reached as the resize was not; the routine acts on the caller's own task only \
         (osfmk/vm/vm_user.c `mach_vm_deferred_reclamation_buffer_flush`: `task != current_task()` is \
         KERN_INVALID_TASK)",
    ),
];

/// The file operations allowed in the share, each with the requests that
/// make it; the rest of the share's file operations are below.
pub const FILE_READ_OPS: &[(&str, &str)] = &[
    ("file-read-data", "READ, READDIR, opening for reading"),
    ("file-read-metadata", "LOOKUP, GETATTR and every node found again by its name"),
    ("file-read-xattr", "the metadata record and GETXATTR, LISTXATTR"),
    ("file-test-existence", "LOOKUP of a name that is not there, and LINK's check of its new name"),
];

/// Allowed in a share served read-write, with the requests that make them.
pub const FILE_WRITE_OPS: &[(&str, &str)] = &[
    ("file-write-create", "CREATE, MKDIR, MKNOD, SYMLINK (kept as files), RENAME's new name"),
    ("file-write-data", "WRITE, SETATTR of the size, FALLOCATE"),
    ("file-write-mode", "SETATTR of the mode (the host's permission bits)"),
    ("file-write-times", "SETATTR of the times"),
    ("file-write-unlink", "UNLINK, RMDIR, RENAME's old name"),
    ("file-write-xattr", "the metadata record (CREATE, SETATTR of ids), SETXATTR, REMOVEXATTR"),
    ("file-link", "LINK"),
];

/// Refused in the share with an error, not the kill (outside it the default
/// kills them). Seatbelt evaluates each of these for both names when the
/// server makes a hard link, and with the kill action that evaluation ends
/// the process although the link is made (measured on macOS 27.2, one
/// operation at a time: each one killed in the share alone ends LINK; the
/// composite operations need a rule of their own, a leaf rule does not
/// cover them). Each is still a denial: what it guards is refused.
pub const ERROR_IN_SHARE: &[&str] = &[
    "file*",
    "fs-snapshot*",
    "network*",
    "process-exec",
    "system-automount",
    "file-chroot",
    "file-clone",
    "file-ioctl",
    "file-issue-extension",
    "file-lock",
    "file-map-executable",
    "file-mknod",
    "file-revoke",
    "file-search",
    "file-write-acl",
    "file-write-finderinfo",
    "file-write-flags",
    "file-write-owner",
    "file-write-setugid",
];

/// Refused in the share with an error as [`ERROR_IN_SHARE`], where this
/// macOS defines the operation (`(when (defined? '<op>) ...)`), with why it
/// may be absent. Every other name the profile uses is required on every
/// major: a missing one fails the compile and the share is refused, naming
/// it (`test_every_name_of_the_profile_is_defined_on_this_macos`).
pub const ERROR_IN_SHARE_IF_DEFINED: &[(&str, &str)] = &[
    (
        "file-graft",
        "macOS 26's MAC check of graftdmg (xnu-12377 mpo_graft_check_graft); macOS 15 (xnu-11417) has no such check and \
         no such operation: there graftdmg (549) is decided at its number, unlisted, and the kernel refuses it without \
         the com.apple.private.vfs.graftdmg entitlement first (bsd/vfs/vfs_syscalls.c)",
    ),
    ("file-ungraft", "as file-graft, for ungraftdmg (555; mpo_graft_check_ungraft)"),
];

/// The share's file operations LINK's evaluation does not reach, killed
/// there as everywhere (a leaf rule: the share's `file*` rule is an error).
pub const KILLED_IN_SHARE: &[&str] = &["file-mount", "file-mount-update", "file-unmount"];

/// The profile for the share at `canonical` (stage 0's canonical path, which
/// Seatbelt matches at each access). A rule on one operation decides over a
/// rule on a composite one (`file*`, `file-read*`) whatever their order
/// (measured), so each file operation of the share has its own.
pub fn profile(canonical: &Path, read_only: bool) -> Result<String, Refusal> {
    let share = sb::quoted(canonical)
        .ok_or_else(|| Refusal(format!("confinement: the share's path {canonical:?} cannot be named in a profile")))?;
    let within = format!("(subpath \"{share}\")");
    let names = |ops: &mut dyn Iterator<Item = &str>| ops.collect::<Vec<_>>().join(" ");
    let mut p = String::from(BASE);
    p.push_str(&format!("(deny {} {within})\n", names(&mut ERROR_IN_SHARE.iter().copied())));
    for (op, _) in ERROR_IN_SHARE_IF_DEFINED {
        p.push_str(&format!("(when (defined? '{op}) (deny {op} {within}))\n"));
    }
    // The composite operations too: a call can be checked as one (measured:
    // futimens's fsetattrlist asks `file-write*`, denied as `file*` is).
    p.push_str(&format!("(allow file-read* {} {within})\n", names(&mut FILE_READ_OPS.iter().map(|(o, _)| *o))));
    let mut killed: Vec<&str> = KILLED_IN_SHARE.to_vec();
    if read_only {
        killed.push("file-write*");
        killed.extend(FILE_WRITE_OPS.iter().map(|(o, _)| *o));
    } else {
        p.push_str(&format!("(allow file-write* {} {within})\n", names(&mut FILE_WRITE_OPS.iter().map(|(o, _)| *o))));
    }
    p.push_str(&format!("(deny {} {within} (with send-signal SIGKILL))\n", killed.join(" ")));
    p.push_str(&list("syscall-unix", "syscall-number", SYSCALLS.iter().map(|(n, ..)| n.to_string())));
    p.push_str(&list("syscall-mach", "machtrap-number", MACH_TRAPS.iter().map(|(n, _)| format!("MSC_{n}"))));
    p.push_str(&list("syscall-mig", "kernel-mig-routine", MIG_ROUTINES.iter().map(|(n, _)| (*n).to_string())));
    for (name, _) in MIG_ROUTINES_IF_DEFINED {
        p.push_str(&format!("(when (defined? '{name}) (allow syscall-mig (kernel-mig-routine {name})))\n"));
    }
    for (name, _) in MACH_TRAPS_IF_DEFINED {
        p.push_str(&format!("(when (defined? 'MSC_{name}) (allow syscall-mach (machtrap-number MSC_{name})))\n"));
    }
    for (name, _) in MIG_ROUTINES_WITH_RECLAMATION {
        p.push_str(&format!(
            "(when (defined? 'MSC_{RECLAMATION_TRAP}) (when (defined? '{name}) (allow syscall-mig (kernel-mig-routine {name}))))\n"
        ));
    }
    // Not covered by the default rule (measured: the server's commands ran
    // under it before this rule), so denied here.
    let commands: Vec<String> = FCNTL_COMMANDS.iter().map(|(c, _)| (*c).to_string()).collect();
    p.push_str("(deny system-fcntl (with send-signal SIGKILL))\n");
    p.push_str(&list("system-fcntl", "fcntl-command", commands.iter().cloned()));
    p.push_str(&fcntl_discovery_rule(&commands));
    p.push_str(&discovery_rule());
    Ok(p)
}

/// `(allow <op> (<filter> <items>...))`, or nothing for none.
fn list(op: &str, filter: &str, items: impl Iterator<Item = String>) -> String {
    let items: Vec<String> = items.collect();
    if items.is_empty() {
        return String::new();
    }
    format!("(allow {op} ({filter} {}))\n", items.join(" "))
}

/// The discovery build's rule (`--cfg wick_fsd_discovery`, never released):
/// allowed and reported instead of killed are a system call, Mach trap or
/// MIG routine no list names, and an operation no rule names (the default).
/// Not reported: a listed call (the list's rule, which has a filter, decides
/// over this one, whatever their order: measured, discovery run 4), and an
/// operation the share's rules or the plain denials name. Seatbelt does not
/// check the number of some calls at all (Firecracker's
/// `UNFILTERED_SYSCALLS`), so a run reports only what the tests reach of the
/// rest; the lists are completed from the code, each request kind's calls
/// named (docs/design-fs.md §6.2), and requests.rs makes every kind.
#[allow(unexpected_cfgs)]
fn discovery_rule() -> String {
    #[cfg(wick_fsd_discovery)]
    return "(allow default (with report))\n(allow syscall-unix syscall-mach syscall-mig (with report))\n".into();
    #[allow(unreachable_code)]
    String::new()
}

/// The discovery build's rule for `fcntl`: a command outside `commands` is
/// allowed and reported (a rule with a filter, which decides over the
/// plain deny, as Firecracker's discovery rule for its commands does).
#[allow(unexpected_cfgs, unused_variables)]
fn fcntl_discovery_rule(commands: &[String]) -> String {
    #[cfg(wick_fsd_discovery)]
    return format!("(allow system-fcntl (require-not (fcntl-command {})) (with report))\n", commands.join(" "));
    #[allow(unreachable_code)]
    String::new()
}

/// Step 0's proof: libc's first uses are made ([`first_uses`]). Only that
/// function makes one, and [`confine`] takes it, so no profile is applied
/// before them.
#[derive(Debug)]
pub struct FirstUses(());

/// Step 0: libc's first uses on the server's paths that read what the
/// profile denies, each made once before it, on the share's `root`, and
/// kept by libc for the process's life. One so far:
/// - `fdopendir` (READDIR, and the search of a directory for a name a node
///   no longer keeps): Libc's `__opendir_common` asks
///   `__kernel_supports_unionfs()`, which reads `kern.secure_kernel` with
///   `sysctlbyname` (`sysctl`, system call 202, which the profile kills) on
///   its first use in a process and keeps the answer in a static
///   (gen/FreeBSD/opendir.c in Libc-1669 to Libc-1725: macOS 15 and macOS
///   26.0 to 26.3; Libc-1752, macOS 26.4 on, no longer asks). Measured on
///   macOS 15.8.2 in CI run 44362564244: a confined server killed `deny(1)
///   syscall-unix 202` in `fdopendir`. One `fdopendir` of the root, closed
///   again, fills the static; confine_probe records, on each major, whether
///   a fresh process confined without it is killed there.
///
/// A failure is a refusal naming it: the root that cannot be read as a
/// directory here could not be served.
pub fn first_uses(root: BorrowedFd<'_>) -> Result<FirstUses, Refusal> {
    let again = sys::reopen_dir(root).map_err(|e| refuse("opening the share's root again (libc's first fdopendir)", e))?;
    let stream = sys::DirReader::new(again).map_err(|e| refuse("libc's first fdopendir, of the share's root", e))?;
    drop(stream);
    Ok(FirstUses(()))
}

/// Steps 1 to 4, after step 0 ([`first_uses`], its proof `_first`). `held`:
/// the descriptors the caller holds and serves with (the connection, the
/// backend's root).
pub fn confine(plan: Plan, canonical: &Path, _first: FirstUses, held: &[RawFd]) -> Result<(), Refusal> {
    let root_user = sys::euid() == 0;
    match (root_user, plan.drop_to) {
        (true, None) => {
            return Err(Refusal(
                "running as root needs --uid and --gid, the unprivileged ids to serve as".into(),
            ));
        }
        (true, Some((0, _) | (_, 0))) => return Err(Refusal("--uid and --gid must not be 0".into())),
        (false, Some(_)) => return Err(Refusal("--uid and --gid need root (the server drops to them)".into())),
        _ => {}
    }
    let compiled = sb::compile(&profile(canonical, plan.read_only)?).map_err(|e| refuse("compiling the profile", e))?;
    if let Some((uid, gid)) = plan.drop_to {
        sb::drop_ids(uid, gid).map_err(|e| refuse("dropping to --uid/--gid", e))?;
    }
    let ids = sb::ids().map_err(|e| refuse("reading the ids back", e))?;
    // Its descriptors, the file table's whole list (proc_pidinfo, which the
    // profile does not allow): exactly the standard streams and what it
    // serves with. Everything opened since the first step (main.rs) is one
    // of these or closed again.
    let open = sys::open_descriptors().map_err(|e| refuse("listing the descriptors (proc_pidinfo)", e))?;
    held_exactly("before the profile", &open, held)?;
    // The soft limit (main.rs set it to what the share may hold), read
    // before the profile, which allows no sysctl.
    let (soft, _) = sys::nofile().map_err(|e| refuse("reading RLIMIT_NOFILE", e))?;
    // No profile before ours, read now (sandbox_check is a Sandbox
    // mac-syscall, which the profile kills); afterwards a second apply is
    // that mac-syscall too, killed, so the profile in force is the one
    // applied. (Seatbelt refuses a second profile over one with any denial,
    // EPERM, measured; over `(allow default)` alone it takes it.)
    let ours = !sb::sandboxed();
    if ours {
        sb::apply(&compiled).map_err(|e| refuse("applying the profile", e))?;
    }
    // Under the profile, by number (fcntl F_GETFD): nothing the apply opened
    // is left, and every descriptor it could have opened is below the soft
    // limit. One that is left is named by its kind: the profile kills the
    // fcntl that asks for its path.
    held_exactly_named("under the profile", &sys::descriptors_below(soft), held, sys::descriptor_kind)?;
    check(plan, &ids, ours)
}

/// Step 4: what must hold once every step said it was done, read back from
/// the kernel; one refusal naming everything that did not. The ids are
/// `--uid`/`--gid` for a server started as root, its real ids otherwise
/// (none apart); as root its one group is the gid. A server that is not root
/// keeps its user's groups, which grant nothing its user does not have.
/// `ours`: no profile was in force before this one was applied.
pub fn check(plan: Plan, ids: &sb::Ids, ours: bool) -> Result<(), Refusal> {
    let mut not = Vec::new();
    let (uid, gid) = plan.drop_to.unwrap_or((ids.uids[0], ids.gids[0]));
    if ids.uids != [uid; 2] {
        not.push(format!("the uids (real, effective) are {:?}, not {uid}", ids.uids));
    }
    if ids.gids != [gid; 2] {
        not.push(format!("the gids (real, effective) are {:?}, not {gid}", ids.gids));
    }
    if plan.drop_to.is_some() && ids.groups.iter().any(|&g| g != gid) {
        not.push(format!("the groups are {:?}, not {gid} alone", ids.groups));
    }
    if !ids.saved_uid_gone || !ids.saved_gid_gone {
        not.push("a saved id of 0 is left (seteuid(0) or setegid(0) was not refused)".into());
    }
    if !ours {
        not.push(
            "the profile is not in force: another Seatbelt profile was (sandbox_check), and a process takes one".into(),
        );
    }
    if not.is_empty() {
        return Ok(());
    }
    Err(Refusal(format!(
        "confinement: read back after the steps, what did not hold: {}; wick-fsd does not serve unconfined",
        not.join("; ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held() -> sb::Ids {
        sb::Ids {
            uids: [65534; 2],
            gids: [65534; 2],
            groups: vec![65534],
            saved_uid_gone: true,
            saved_gid_gone: true,
        }
    }

    const ROOT: Plan = Plan {
        read_only: false,
        drop_to: Some((65534, 65534)),
    };

    #[test]
    fn test_first_uses_refused_by_name_where_the_root_is_no_directory() {
        let file = std::fs::File::open("/etc/hosts").unwrap();
        let e = first_uses(std::os::fd::AsFd::as_fd(&file)).unwrap_err().0;
        assert!(e.starts_with("confinement: opening the share's root again (libc's first fdopendir) failed"), "{e}");
        assert!(e.ends_with("wick-fsd does not serve unconfined"), "{e}");
        let dir = std::fs::File::open("/").unwrap();
        first_uses(std::os::fd::AsFd::as_fd(&dir)).unwrap();
    }

    #[test]
    fn test_what_held_is_served_and_what_did_not_is_named() {
        check(ROOT, &held(), true).unwrap();
        for case in 0..6 {
            let mut ids = held();
            let mut ours = true;
            let named = match case {
                0 => {
                    ids.uids[1] = 0;
                    "the uids"
                }
                1 => {
                    ids.gids[0] = 0;
                    "the gids"
                }
                2 => {
                    ids.groups.push(80);
                    "the groups are [65534, 80]"
                }
                3 => {
                    ids.saved_uid_gone = false;
                    "a saved id of 0 is left"
                }
                4 => {
                    ids.saved_gid_gone = false;
                    "a saved id of 0 is left"
                }
                _ => {
                    ours = false;
                    "the profile is not in force"
                }
            };
            let r = check(ROOT, &ids, ours).unwrap_err().0;
            assert!(r.contains(named) && r.contains("does not serve unconfined"), "{named}: {r}");
        }
    }

    #[test]
    fn test_the_profile_names_the_share_and_compiles() {
        let rw = profile(Path::new("/private/tmp/a \"b\""), false).unwrap();
        let within = "(subpath \"/private/tmp/a \\\"b\\\"\")";
        let allowed = |p: &str, op: &str| p.lines().any(|l| l.starts_with(&format!("(allow {op} ")) && l.ends_with(&format!("{within})")));
        assert!(allowed(&rw, "file-read*") && allowed(&rw, "file-write*"), "{rw}");
        // Read-only: no write allowed, each write killed in the share.
        let ro = profile(Path::new("/private/tmp/a \"b\""), true).unwrap();
        assert!(allowed(&ro, "file-read*") && !ro.contains("(allow file-write"), "{ro}");
        let killed = ro.lines().find(|l| l.ends_with(&format!("{within} (with send-signal SIGKILL))"))).unwrap();
        assert!(FILE_WRITE_OPS.iter().all(|(o, _)| killed.contains(&format!(" {o} "))) && killed.contains(" file-write* "), "{ro}");
        // Executable mappings stay denied in the share, both ways.
        for p in [&rw, &ro] {
            let denied = p.lines().find(|l| l.starts_with("(deny file* ")).unwrap();
            assert!(denied.contains(" file-map-executable ") && denied.ends_with(&format!("{within})")), "{p}");
        }
        profile(Path::new("relative"), false).unwrap_err();
        sb::compile(&rw).unwrap();
        sb::compile(&ro).unwrap();
    }

    /// The first xnu release (`xnu-A.B`) that defines each name the profile
    /// emits only where it is defined, from the source
    /// (apple-oss-distributions/xnu): the graft checks
    /// `mpo_graft_check_graft` and `mpo_graft_check_ungraft` are in
    /// security/mac_policy.h from xnu-12377.1.9 (macOS 26.0), not in
    /// xnu-11417.140.69 (macOS 15); the routine `mach_vm_reallocate` is in
    /// osfmk/mach/mach_vm.defs from xnu-12377.101.15, not in xnu-12377.81.4
    /// or any earlier release; the trap `mach_vm_reclaim_update_kernel_accounting_trap`
    /// is osfmk/kern/syscall_sw.c's trap 63 from xnu-12377.1.9, `kern_invalid`
    /// in xnu-11417.140.69; the routines `mach_vm_deferred_reclamation_buffer_flush`
    /// and `_resize` are in mach_vm.defs from xnu-11417.101.15 (macOS 15.4),
    /// not in xnu-11215.81.4 (whose routines of the ring are `_init`,
    /// `_synchronize` and `_update_reclaimable_bytes`).
    const DEFINED_SINCE_XNU: &[(&str, (u32, u32))] = &[
        ("file-graft", (12377, 1)),
        ("file-ungraft", (12377, 1)),
        ("mach_vm_reallocate", (12377, 101)),
        ("MSC_mach_vm_reclaim_update_kernel_accounting_trap", (12377, 1)),
        ("mach_vm_deferred_reclamation_buffer_flush", (11417, 101)),
        ("mach_vm_deferred_reclamation_buffer_resize", (11417, 101)),
    ];

    /// This kernel's `xnu-A.B` (`uname -v`, `root:xnu-A.B.C~...`).
    fn xnu() -> (u32, u32) {
        let out = std::process::Command::new("/usr/bin/uname").arg("-v").output().unwrap();
        let version = String::from_utf8(out.stdout).unwrap();
        let rest = version.split("xnu-").nth(1).unwrap_or_else(|| panic!("no xnu- in {version:?}"));
        let mut parts = rest.split(['.', '~', '/']).map(|p| p.parse::<u32>());
        match (parts.next(), parts.next()) {
            (Some(Ok(a)), Some(Ok(b))) => (a, b),
            _ => panic!("no xnu-A.B in {version:?}"),
        }
    }

    /// Every symbol the profile names (operations, filters, actions, trap and
    /// MIG names, fcntl commands) is bound in this macOS's libsandbox, each
    /// checked on its own (`(define wick-probe-symbol <symbol>)`), so that
    /// one run names every missing one where the profile's compile stops at
    /// the first. The names a rule emits only where they are defined (every
    /// `(when (defined? '...))` of the profile, read from its text) are bound
    /// exactly from the xnu release that defines each
    /// ([`DEFINED_SINCE_XNU`]), so none of them is dropped where it exists.
    #[test]
    fn test_every_name_of_the_profile_is_defined_on_this_macos() {
        let xnu = xnu();
        let bound = |sym: &str| sb::compile(&format!("(version 1)\n(define wick-probe-symbol {sym})\n")).is_ok();
        let mut symbols = std::collections::BTreeSet::new();
        let mut optional = std::collections::BTreeSet::new();
        for text in [profile(Path::new("/private/tmp/share"), false).unwrap(), profile(Path::new("/private/tmp/share"), true).unwrap()] {
            // Each name a rule waits on, nested ones too.
            for piece in text.split("(defined? '").skip(1) {
                optional.insert(piece.split(')').next().unwrap().to_string());
            }
            // Strings out (the share's path, the info type), then each token
            // that is not a number or a quoted symbol.
            let mut plain = String::new();
            let mut in_string = false;
            for ch in text.chars() {
                match ch {
                    '"' => in_string = !in_string,
                    '(' | ')' if !in_string => plain.push(' '),
                    _ if !in_string => plain.push(ch),
                    _ => {}
                }
            }
            for token in plain.split_whitespace() {
                if !token.starts_with('\'') && token.parse::<u64>().is_err() {
                    symbols.insert(token.to_string());
                }
            }
        }
        let unbound: Vec<&String> = symbols.iter().filter(|s| !optional.contains(*s) && !bound(s)).collect();
        let optional_unbound: Vec<&String> = optional.iter().filter(|o| !bound(o)).collect();
        println!(
            "xnu-{}.{}: {} symbols of the profile, unbound: {unbound:?}; emitted where defined: {optional:?}, unbound: \
             {optional_unbound:?}",
            xnu.0,
            xnu.1,
            symbols.len()
        );
        assert!(unbound.is_empty(), "the profile names symbols this macOS (xnu-{}.{}) does not define: {unbound:?}", xnu.0, xnu.1);
        let since: std::collections::BTreeMap<&str, (u32, u32)> = DEFINED_SINCE_XNU.iter().copied().collect();
        for name in &optional {
            let first = since
                .get(name.as_str())
                .unwrap_or_else(|| panic!("{name} is emitted where defined: DEFINED_SINCE_XNU must say from which xnu"));
            let expected = xnu >= *first;
            assert_eq!(
                bound(name),
                expected,
                "{name} on xnu-{}.{}: defined since xnu-{}.{}, so expected {}",
                xnu.0,
                xnu.1,
                first.0,
                first.1,
                if expected { "bound" } else { "unbound (its rule dropped)" }
            );
        }
        assert_eq!(since.len(), optional.len(), "DEFINED_SINCE_XNU names one the profile does not emit");
    }

    /// The whole text, pinned for a read-write and a read-only share
    /// (printed with `--nocapture`, and in full on a difference).
    #[test]
    fn test_the_profile_text_is_pinned() {
        let rw = profile(Path::new("/private/tmp/share"), false).unwrap();
        let ro = profile(Path::new("/private/tmp/share"), true).unwrap();
        println!("read-write:\n{rw}\nread-only:\n{ro}");
        assert_eq!(rw, PINNED_RW, "read-write:\n{rw}");
        assert_eq!(ro, PINNED_RO, "read-only:\n{ro}");
    }

    const PINNED_RW: &str = r#"(version 1)
(deny default (with send-signal SIGKILL))
(deny mach-priv-host-port)
(allow system-info (info-type "vfs.disk-space"))
(deny dynamic-code-generation (with send-signal SIGKILL))
(deny syscall-unix (with send-signal SIGKILL))
(deny syscall-mach (with send-signal SIGKILL))
(deny syscall-mig (with send-signal SIGKILL))
(deny system-mac-syscall (with send-signal SIGKILL))
(deny generic-issue-extension (with send-signal SIGKILL))
(deny file* fs-snapshot* network* process-exec system-automount file-chroot file-clone file-ioctl file-issue-extension file-lock file-map-executable file-mknod file-revoke file-search file-write-acl file-write-finderinfo file-write-flags file-write-owner file-write-setugid (subpath "/private/tmp/share"))
(when (defined? 'file-graft) (deny file-graft (subpath "/private/tmp/share")))
(when (defined? 'file-ungraft) (deny file-ungraft (subpath "/private/tmp/share")))
(allow file-read* file-read-data file-read-metadata file-read-xattr file-test-existence (subpath "/private/tmp/share"))
(allow file-write* file-write-create file-write-data file-write-mode file-write-times file-write-unlink file-write-xattr file-link (subpath "/private/tmp/share"))
(deny file-mount file-mount-update file-unmount (subpath "/private/tmp/share") (with send-signal SIGKILL))
(allow syscall-unix (syscall-number 29 53 73 75 92 95 116 133 153 199 201 229 235 241 339 344 346 406 470 475 473 476 488))
(allow syscall-mach (machtrap-number MSC__kernelrpc_mach_vm_deallocate_trap MSC__kernelrpc_mach_vm_map_trap MSC_mach_msg2_trap))
(when (defined? 'mach_vm_reallocate) (allow syscall-mig (kernel-mig-routine mach_vm_reallocate)))
(when (defined? 'MSC_mach_vm_reclaim_update_kernel_accounting_trap) (allow syscall-mach (machtrap-number MSC_mach_vm_reclaim_update_kernel_accounting_trap)))
(when (defined? 'MSC_mach_vm_reclaim_update_kernel_accounting_trap) (when (defined? 'mach_vm_deferred_reclamation_buffer_resize) (allow syscall-mig (kernel-mig-routine mach_vm_deferred_reclamation_buffer_resize))))
(when (defined? 'MSC_mach_vm_reclaim_update_kernel_accounting_trap) (when (defined? 'mach_vm_deferred_reclamation_buffer_flush) (allow syscall-mig (kernel-mig-routine mach_vm_deferred_reclamation_buffer_flush))))
(deny system-fcntl (with send-signal SIGKILL))
(allow system-fcntl (fcntl-command F_GETFD F_SETFD F_FULLFSYNC F_PREALLOCATE F_PUNCHHOLE))
"#;

    const PINNED_RO: &str = r#"(version 1)
(deny default (with send-signal SIGKILL))
(deny mach-priv-host-port)
(allow system-info (info-type "vfs.disk-space"))
(deny dynamic-code-generation (with send-signal SIGKILL))
(deny syscall-unix (with send-signal SIGKILL))
(deny syscall-mach (with send-signal SIGKILL))
(deny syscall-mig (with send-signal SIGKILL))
(deny system-mac-syscall (with send-signal SIGKILL))
(deny generic-issue-extension (with send-signal SIGKILL))
(deny file* fs-snapshot* network* process-exec system-automount file-chroot file-clone file-ioctl file-issue-extension file-lock file-map-executable file-mknod file-revoke file-search file-write-acl file-write-finderinfo file-write-flags file-write-owner file-write-setugid (subpath "/private/tmp/share"))
(when (defined? 'file-graft) (deny file-graft (subpath "/private/tmp/share")))
(when (defined? 'file-ungraft) (deny file-ungraft (subpath "/private/tmp/share")))
(allow file-read* file-read-data file-read-metadata file-read-xattr file-test-existence (subpath "/private/tmp/share"))
(deny file-mount file-mount-update file-unmount file-write* file-write-create file-write-data file-write-mode file-write-times file-write-unlink file-write-xattr file-link (subpath "/private/tmp/share") (with send-signal SIGKILL))
(allow syscall-unix (syscall-number 29 53 73 75 92 95 116 133 153 199 201 229 235 241 339 344 346 406 470 475 473 476 488))
(allow syscall-mach (machtrap-number MSC__kernelrpc_mach_vm_deallocate_trap MSC__kernelrpc_mach_vm_map_trap MSC_mach_msg2_trap))
(when (defined? 'mach_vm_reallocate) (allow syscall-mig (kernel-mig-routine mach_vm_reallocate)))
(when (defined? 'MSC_mach_vm_reclaim_update_kernel_accounting_trap) (allow syscall-mach (machtrap-number MSC_mach_vm_reclaim_update_kernel_accounting_trap)))
(when (defined? 'MSC_mach_vm_reclaim_update_kernel_accounting_trap) (when (defined? 'mach_vm_deferred_reclamation_buffer_resize) (allow syscall-mig (kernel-mig-routine mach_vm_deferred_reclamation_buffer_resize))))
(when (defined? 'MSC_mach_vm_reclaim_update_kernel_accounting_trap) (when (defined? 'mach_vm_deferred_reclamation_buffer_flush) (allow syscall-mig (kernel-mig-routine mach_vm_deferred_reclamation_buffer_flush))))
(deny system-fcntl (with send-signal SIGKILL))
(allow system-fcntl (fcntl-command F_GETFD F_SETFD F_FULLFSYNC F_PREALLOCATE F_PUNCHHOLE))
"#;

    /// Every file operation this macOS's libsandbox knows has a rule of its
    /// own in the share (`FILE_READ_OPS`, `FILE_WRITE_OPS`,
    /// `ERROR_IN_SHARE`, `KILLED_IN_SHARE`), the composites `file-read*` and
    /// `file-write*` apart: a leaf a later macOS adds under a composite the
    /// share allows would otherwise be allowed with it, silently. The
    /// operations are read from the loaded libsandbox, on each macOS CI runs.
    #[test]
    fn test_every_file_operation_of_this_macos_has_a_rule_in_the_share() {
        let ops = sb::probe::operations("file").unwrap();
        println!("file operations of this macOS: {ops:?}");
        // The table was found: the operations every major has.
        for known in ["file*", "file-read*", "file-write*", "file-read-data", "file-write-data", "file-link"] {
            assert!(ops.iter().any(|o| o == known), "{known} not found in {ops:?}");
        }
        let named: Vec<&str> = FILE_READ_OPS
            .iter()
            .chain(FILE_WRITE_OPS)
            .map(|(o, _)| *o)
            .chain(ERROR_IN_SHARE.iter().copied())
            .chain(ERROR_IN_SHARE_IF_DEFINED.iter().map(|(o, _)| *o))
            .chain(KILLED_IN_SHARE.iter().copied())
            .collect();
        let missing: Vec<&String> =
            ops.iter().filter(|o| !named.contains(&o.as_str()) && !["file-read*", "file-write*"].contains(&o.as_str())).collect();
        assert!(missing.is_empty(), "file operations of this macOS with no rule of their own in the share: {missing:?}");
    }
}
