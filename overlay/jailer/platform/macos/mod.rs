// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! macOS backend of the jailer's host primitives (see `platform`).

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::JailerError;

mod freezer;
pub(crate) use super::freezer_values::{State as FreezerState, Version as FreezerVersion, parse_start as parse_freezer_start};

/// Environment variable through which Firecracker takes the jail over
/// (`vmm::ext::jail::ENV`).
const JAIL_ENV: &str = "WICK_JAIL";
/// Environment variable with the CPU limit for Firecracker to apply to itself
/// (`vmm::ext::jail::CPU_ENV`).
const JAIL_CPU_ENV: &str = "WICK_JAIL_CPU";
/// Environment variable through which Firecracker learns the jail's memory
/// limit in MiB (`vmm::ext::jail::MEMORY_ENV`), to share it with its API
/// process.
const JAIL_MEMORY_ENV: &str = "WICK_JAIL_MEMORY";
/// `vmm::ext::jail::PID_NS_ENV`.
const JAIL_PID_NS_ENV: &str = "WICK_JAIL_PID_NS";
/// Firecracker's temporary directory in the jail. On macOS eventfds are
/// unlinked FIFOs and memfds unlinked files (crates/compat), made in the
/// temporary directory; on Linux both are kernel objects, so upstream's jail
/// has none.
const JAIL_TMP: &CStr = c"/tmp";
/// Bytes every binary that takes the jail over carries
/// (`vmm::ext::jail::HANDOVER_MARK`).
const HANDOVER_MARK: &[u8] = b"wick-jail-handover:v1\0";

// <spawn.h> and <sys/kern_memorystatus.h>; not in the libc crate.
const POSIX_SPAWN_JETSAM_MEMLIMIT_ACTIVE_FATAL: libc::c_short = 0x04;
const POSIX_SPAWN_JETSAM_MEMLIMIT_INACTIVE_FATAL: libc::c_short = 0x08;
const MEMORYSTATUS_CMD_GET_PRIORITY_LIST: u32 = 1;

#[repr(C)]
#[derive(Default)]
struct MemorystatusPriorityEntry {
    pid: libc::pid_t,
    priority: i32,
    user_data: u64,
    limit: i32,
    state: u32,
}

unsafe extern "C" {
    fn posix_spawnattr_setjetsam_ext(
        attr: *mut libc::posix_spawnattr_t,
        flags: libc::c_short,
        priority: libc::c_int,
        memlimit_active: libc::c_int,
        memlimit_inactive: libc::c_int,
    ) -> libc::c_int;
    fn posix_spawn_file_actions_addinherit_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        fd: libc::c_int,
    ) -> libc::c_int;
    fn memorystatus_control(
        command: u32,
        pid: i32,
        flags: u32,
        buffer: *mut libc::c_void,
        buffersize: libc::size_t,
    ) -> libc::c_int;
}

/// What the macOS backend refuses, or a macOS step that failed.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error(
        "--cgroup {0} is not supported on macOS: {1} (supported: memory.max and cpu.max with \
         --cgroup-version 2, memory.limit_in_bytes, cpu.cfs_quota_us, cpu.cfs_period_us and \
         freezer.state with --cgroup-version 1, and cpuset.cpus and cpuset.mems naming every CPU and memory node). \
         The jailer never accepts a limit it cannot enforce."
    )]
    UnsupportedCgroup(String, &'static str),
    #[error(
        "--{0} is not supported on macOS: {1}. The jailer never accepts an isolation option it \
         cannot enforce."
    )]
    Unsupported(&'static str, &'static str),
    #[error("--cgroup {0}: {1}")]
    CgroupValue(String, &'static str),
    #[error("No macOS equivalent for the device {0:?} in the jail")]
    UnsupportedDevice(String),
    #[error("Failed to chroot: {0}")]
    Chroot(io::Error),
    #[error("Failed to leave the chroot for the exec: {0}")]
    LeaveChroot(io::Error),
    #[error(
        "{0:?} cannot take the jail over (it is not a wick Firecracker build), so it would run \
         unjailed as root"
    )]
    NoHandover(PathBuf),
    #[error("The jail's freezer: {0}")]
    Freezer(String),
    #[error("Failed to copy {0:?} to {1:?} for the exec: {2}")]
    CopyExec(PathBuf, PathBuf, io::Error),
    #[error("Failed to make the jail's temporary directory: {0}")]
    JailTmp(io::Error),
    #[error("Failed to read the jailer's memory priority: {0}")]
    JetsamPriority(io::Error),
    #[error("Failed to prepare the exec: {0}: {1}")]
    Spawn(&'static str, io::Error),
    #[error("The jail's network {0:?} (--netns): {1}")]
    Netns(PathBuf, io::Error),
}

impl From<HostError> for JailerError {
    fn from(err: HostError) -> Self {
        JailerError::Host(err)
    }
}

/// The root directory before the chroot, to leave it again for the exec.
static OLD_ROOT: OnceLock<OwnedFd> = OnceLock::new();
/// The jetsam memory limit in MiB, from the memory cgroup.
static MEMORY_LIMIT_MIB: Mutex<Option<i32>> = Mutex::new(None);
/// The CPU limit in percent of one CPU, from the CPU cgroup.
static CPU_LIMIT_PERCENT: Mutex<Option<u8>> = Mutex::new(None);

pub(crate) fn set_old_root(fd: OwnedFd) -> Result<(), HostError> {
    OLD_ROOT
        .set(fd)
        .map_err(|_| HostError::Chroot(io::Error::other("the jailer chroots once")))
}

pub(crate) fn set_memory_limit_mib(limit: Option<i32>) {
    *MEMORY_LIMIT_MIB.lock().unwrap() = limit;
}

pub(crate) fn set_cpu_limit_percent(limit: Option<u8>) {
    *CPU_LIMIT_PERCENT.lock().unwrap() = limit;
}

/// The jail's cgroup version, whose freezer files it gets (`freezer`).
pub(crate) fn set_cgroup_version(version: FreezerVersion) {
    freezer::set_version(version);
}

/// `--cgroup freezer.state=<state>` (v1), at the cgroup step: the freezer's
/// files are made now and, for `FROZEN`, the jailer stops here until they
/// say `THAWED`, as on Linux the jailer freezes itself at this step
/// (`freezer`).
pub(crate) fn freezer_at_cgroup_step(state: FreezerState) -> Result<(), JailerError> {
    let dir = jail_dir_from_args()?;
    freezer::at_cgroup_step(&dir, state).map_err(|e| HostError::Freezer(e.to_string()).into())
}

/// The jail's directory (`<chroot-base>/<exec file name>/<id>`), as
/// `Env::new` makes it from the same command line (the cgroup step is not
/// given it; upstream's `main` has made it already).
fn jail_dir_from_args() -> Result<PathBuf, JailerError> {
    let mut parser = crate::build_arg_parser();
    parser.parse_from_cmdline().map_err(JailerError::ArgumentParsing)?;
    let args = parser.arguments();
    let value = |name: &'static str| {
        args.single_value(name)
            .cloned()
            .ok_or_else(|| HostError::Freezer(format!("no --{name} on the command line")))
    };
    let base = value("chroot-base-dir")?;
    let exec = value("exec-file")?;
    let base = std::fs::canonicalize(&base).map_err(|e| JailerError::Canonicalize(PathBuf::from(&base), e))?;
    let exec = std::fs::canonicalize(&exec).map_err(|e| JailerError::Canonicalize(PathBuf::from(&exec), e))?;
    let name = exec.file_name().ok_or_else(|| JailerError::ExtractFileName(exec.clone()))?;
    Ok(base.join(name).join(value("id")?))
}

/// `--netns`: the jail's network.
///
/// macOS has no network namespaces. As on Windows, a jail's network is a
/// directory of endpoints the operator made (it must exist, as the
/// namespace file must on Linux): Firecracker makes its network endpoints
/// there (`vmm::platform::net`) instead of in its temporary directory. A
/// jail given its own directory reaches no other's. Two jails given one
/// directory are not separated from each other's endpoints, unlike two
/// Firecrackers in one namespace, whose TAPs are each their own
/// (drivers/net/tun.c tun_not_capable, tun_attach): each is granted
/// write and delete on the other's endpoint, and an endpoint takes
/// whoever sends to it as a peer. Not done yet: being closed. The
/// jail's uid is granted the directory and what is made in it at the exec
/// ([`grant_to_jail`]); Firecracker opens it before its chroot
/// (`WICK_NETNS`, `vmm::ext::jail::netns_dir`), and its sandbox lets it
/// reach Unix sockets only there and in the jail, and no IP network.
pub fn join_netns(path: &str) -> Result<(), JailerError> {
    let dir = std::fs::canonicalize(path).map_err(|e| HostError::Netns(PathBuf::from(path), e))?;
    if !dir.is_dir() {
        return Err(HostError::Netns(
            dir,
            io::Error::new(io::ErrorKind::NotADirectory, "a network is a directory of endpoints"),
        )
        .into());
    }
    let mut netns = NETNS.lock().unwrap();
    if netns.is_some() {
        return Err(HostError::Netns(dir, io::Error::other("a jail has one network")).into());
    }
    *netns = Some(dir);
    Ok(())
}

/// The jail's network directory (`--netns`), by its canonical path.
static NETNS: Mutex<Option<PathBuf>> = Mutex::new(None);
/// The variable that names it to Firecracker (`vmm::ext::jail::NETNS_ENV`).
const NETNS_ENV: &str = "WICK_NETNS";

/// sys/acl.h and membership.h.
mod acl {
    use std::os::raw::{c_char, c_int, c_void};

    pub type Acl = *mut c_void;
    pub type Entry = *mut c_void;
    pub type Set = *mut c_void;
    pub const TYPE_EXTENDED: c_int = 0x100;
    pub const EXTENDED_ALLOW: c_int = 1;
    pub const FIRST_ENTRY: c_int = 0;
    pub const NEXT_ENTRY: c_int = -1;
    pub const LIST_DIRECTORY: c_int = 1 << 1;
    pub const READ_DATA: c_int = 1 << 1;
    pub const ADD_FILE: c_int = 1 << 2;
    pub const WRITE_DATA: c_int = 1 << 2;
    pub const SEARCH: c_int = 1 << 3;
    pub const DELETE: c_int = 1 << 4;
    pub const APPEND_DATA: c_int = 1 << 5;
    pub const DELETE_CHILD: c_int = 1 << 6;
    pub const READ_ATTRIBUTES: c_int = 1 << 7;
    pub const WRITE_ATTRIBUTES: c_int = 1 << 8;
    pub const READ_EXTATTRIBUTES: c_int = 1 << 9;
    pub const WRITE_EXTATTRIBUTES: c_int = 1 << 10;
    pub const READ_SECURITY: c_int = 1 << 11;
    pub const ENTRY_FILE_INHERIT: c_int = 1 << 5;
    pub const ENTRY_ONLY_INHERIT: c_int = 1 << 8;

    unsafe extern "C" {
        pub fn acl_get_file(path: *const c_char, kind: c_int) -> Acl;
        pub fn acl_set_file(path: *const c_char, kind: c_int, acl: Acl) -> c_int;
        pub fn acl_init(count: c_int) -> Acl;
        pub fn acl_free(obj: *mut c_void) -> c_int;
        pub fn acl_get_entry(acl: Acl, id: c_int, entry: *mut Entry) -> c_int;
        pub fn acl_create_entry(acl: *mut Acl, entry: *mut Entry) -> c_int;
        pub fn acl_get_tag_type(entry: Entry, tag: *mut c_int) -> c_int;
        pub fn acl_set_tag_type(entry: Entry, tag: c_int) -> c_int;
        pub fn acl_get_qualifier(entry: Entry) -> *mut c_void;
        pub fn acl_set_qualifier(entry: Entry, qualifier: *const c_void) -> c_int;
        pub fn acl_get_permset(entry: Entry, set: *mut Set) -> c_int;
        pub fn acl_add_perm(set: Set, perm: c_int) -> c_int;
        pub fn acl_get_perm_np(set: Set, perm: c_int) -> c_int;
        pub fn acl_set_permset(entry: Entry, set: Set) -> c_int;
        pub fn acl_get_flagset_np(obj: *mut c_void, set: *mut Set) -> c_int;
        pub fn acl_add_flag_np(set: Set, flag: c_int) -> c_int;
        pub fn acl_get_flag_np(set: Set, flag: c_int) -> c_int;
        pub fn acl_set_flagset_np(obj: *mut c_void, set: Set) -> c_int;
        pub fn mbr_uid_to_uuid(uid: u32, uuid: *mut u8) -> c_int;
    }
}

/// What the jail's uid is granted on its network directory, and on what is
/// made in it (inherited) or already there.
const NETNS_DIR_PERMS: &[i32] = &[
    acl::LIST_DIRECTORY,
    acl::SEARCH,
    acl::ADD_FILE,
    acl::DELETE_CHILD,
    acl::READ_ATTRIBUTES,
    acl::READ_EXTATTRIBUTES,
    acl::READ_SECURITY,
];
const NETNS_ENTRY_PERMS: &[i32] = &[
    acl::READ_DATA,
    acl::WRITE_DATA,
    acl::APPEND_DATA,
    acl::DELETE,
    acl::READ_ATTRIBUTES,
    acl::WRITE_ATTRIBUTES,
    acl::READ_EXTATTRIBUTES,
    acl::WRITE_EXTATTRIBUTES,
    acl::READ_SECURITY,
];

/// Grants `uid` its network directory `dir`: an entry for the directory
/// itself (list, search, make and remove entries), one that what is made
/// in it inherits (read and write: a socket is reached by writing to it),
/// and the same on the entries already there, keeping every other entry
/// (another jail given the same directory keeps its own, and so reaches
/// this jail's endpoints: see [`join_netns`]). An entry already
/// granted is not added twice. As the Windows jailer grants the jail's SID.
pub(crate) fn grant_to_jail(dir: &Path, uid: u32) -> io::Result<()> {
    grant(dir, uid, NETNS_DIR_PERMS, &[])?;
    grant(dir, uid, NETNS_ENTRY_PERMS, &[acl::ENTRY_FILE_INHERIT, acl::ENTRY_ONLY_INHERIT])?;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink() {
            continue;
        }
        grant(&entry.path(), uid, NETNS_ENTRY_PERMS, &[])?;
    }
    Ok(())
}

/// Adds an allow entry for `uid` with `perms` and `flags` to `path`'s ACL,
/// unless one with at least those is there.
fn grant(path: &Path, uid: u32, perms: &[i32], flags: &[i32]) -> io::Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let mut uuid = [0u8; 16];
    // SAFETY: a 16-byte uuid_t.
    if unsafe { acl::mbr_uid_to_uuid(uid, uuid.as_mut_ptr()) } != 0 {
        return Err(io::Error::other(format!("no UUID for uid {uid}")));
    }
    let check = |ret: i32| if ret == 0 { Ok(()) } else { Err(io::Error::last_os_error()) };
    // SAFETY: a NUL-terminated path; a null ACL is no ACL yet.
    let mut list = unsafe { acl::acl_get_file(c_path.as_ptr(), acl::TYPE_EXTENDED) };
    if list.is_null() {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOENT) {
            return Err(err);
        }
        // SAFETY: a new, empty ACL.
        list = unsafe { acl::acl_init(1) };
        if list.is_null() {
            return Err(io::Error::last_os_error());
        }
    }
    let result = (|| {
        // Already granted?
        let mut entry: acl::Entry = std::ptr::null_mut();
        let mut id = acl::FIRST_ENTRY;
        // SAFETY: entries of a valid ACL, read only; the qualifier is freed.
        while unsafe { acl::acl_get_entry(list, id, &mut entry) } == 0 {
            id = acl::NEXT_ENTRY;
            let mut tag = 0;
            // SAFETY: as above.
            unsafe { acl::acl_get_tag_type(entry, &mut tag) };
            if tag != acl::EXTENDED_ALLOW {
                continue;
            }
            // SAFETY: as above.
            let qualifier = unsafe { acl::acl_get_qualifier(entry) };
            if qualifier.is_null() {
                continue;
            }
            // SAFETY: a guid_t (16 bytes), freed after.
            let same = unsafe { std::slice::from_raw_parts(qualifier.cast::<u8>(), 16) } == uuid;
            // SAFETY: allocated by acl_get_qualifier.
            unsafe { acl::acl_free(qualifier) };
            let (mut pset, mut fset): (acl::Set, acl::Set) = (std::ptr::null_mut(), std::ptr::null_mut());
            // SAFETY: as above.
            unsafe {
                acl::acl_get_permset(entry, &mut pset);
                acl::acl_get_flagset_np(entry, &mut fset);
            }
            let has = |set: acl::Set, all: &[i32], get: unsafe extern "C" fn(acl::Set, i32) -> i32| {
                // SAFETY: a set of the entry, and a bit of its kind.
                all.iter().all(|&b| unsafe { get(set, b) } == 1)
            };
            let all_flags = [acl::ENTRY_FILE_INHERIT, acl::ENTRY_ONLY_INHERIT];
            let flags_match = all_flags
                .iter()
                // SAFETY: the entry's flag set.
                .all(|&f| (unsafe { acl::acl_get_flag_np(fset, f) } == 1) == flags.contains(&f));
            if same && flags_match && has(pset, perms, acl::acl_get_perm_np) {
                return Ok(());
            }
        }
        let mut entry: acl::Entry = std::ptr::null_mut();
        // SAFETY: a new entry of the ACL, filled in below.
        check(unsafe { acl::acl_create_entry(&mut list, &mut entry) })?;
        // SAFETY: the new entry.
        check(unsafe { acl::acl_set_tag_type(entry, acl::EXTENDED_ALLOW) })?;
        // SAFETY: a guid_t.
        check(unsafe { acl::acl_set_qualifier(entry, uuid.as_ptr().cast()) })?;
        let mut pset: acl::Set = std::ptr::null_mut();
        // SAFETY: the new entry's permission set.
        check(unsafe { acl::acl_get_permset(entry, &mut pset) })?;
        for &perm in perms {
            // SAFETY: as above.
            check(unsafe { acl::acl_add_perm(pset, perm) })?;
        }
        // SAFETY: as above.
        check(unsafe { acl::acl_set_permset(entry, pset) })?;
        let mut fset: acl::Set = std::ptr::null_mut();
        // SAFETY: the new entry's flag set.
        check(unsafe { acl::acl_get_flagset_np(entry, &mut fset) })?;
        for &flag in flags {
            // SAFETY: as above.
            check(unsafe { acl::acl_add_flag_np(fset, flag) })?;
        }
        // SAFETY: as above.
        check(unsafe { acl::acl_set_flagset_np(entry, fset) })?;
        // SAFETY: a NUL-terminated path and a valid ACL.
        check(unsafe { acl::acl_set_file(c_path.as_ptr(), acl::TYPE_EXTENDED, list) })
    })();
    // SAFETY: allocated above.
    unsafe { acl::acl_free(list) };
    result
}

/// Whether Firecracker runs in a PID namespace of its own (`--new-pid-ns`).
static NEW_PID_NS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `--new-pid-ns`, where upstream clones Firecracker into a new PID
/// namespace: macOS has none, so Firecracker is a child, as the clone makes
/// it, and its jail holds it as the namespace would. It sees and signals no
/// process but itself: its sandbox allows process information and signals
/// for itself only (`vmm::ext::sandbox::PROFILE`), so it cannot find another
/// pid or reach one. Processes outside reach it only with the signals it
/// handles, and SIGKILL and SIGSTOP: it ignores the others
/// (`vmm::ext::jail::DROPPED_IN_PID_NS`), as the kernel drops them for a
/// namespace's init. Its pid is the host's (upstream writes that pid, the
/// one the jailer's namespace sees, to the pid file too): macOS has one pid
/// space. The rest is upstream's: the jailer writes the child's pid to the
/// pid file and exits 0. Returns the child's pid in the jailer, 0 in the
/// child.
pub fn new_pid_ns() -> Result<i32, JailerError> {
    NEW_PID_NS.store(true, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: the jailer has one thread.
    match unsafe { libc::fork() } {
        -1 => Err(HostError::Spawn("new-pid-ns", io::Error::last_os_error()).into()),
        pid => Ok(pid),
    }
}

/// The device nodes upstream creates in the jail. None is needed on macOS;
/// any other device is refused.
pub fn mknod_and_own_dev(dev_path: &CStr) -> Result<(), JailerError> {
    match dev_path.to_bytes() {
        // Hypervisor.framework is a system framework, not a device.
        b"/dev/kvm"
        // vmnet is a framework; the Unix datagram endpoint is a socket.
        | b"/dev/net/tun"
        // Random bytes come from getentropy(2).
        | b"/dev/urandom"
        // wick's userfaultfd is a socket protocol (crates/compat/userfaultfd).
        | b"/dev/userfaultfd" => Ok(()),
        other => Err(HostError::UnsupportedDevice(String::from_utf8_lossy(other).into_owned()).into()),
    }
}

/// Upstream copies sysfs's MIDR_EL1 file into the jail; macOS has no sysfs,
/// so Firecracker sees the same inside the jail as outside it.
pub fn copy_midr_el1_info() -> Result<(), JailerError> {
    Ok(())
}

/// Execs Firecracker as upstream's `exec_command` does, with the jail handed
/// over: leaves the chroot, copies the binary next to the jail (root-owned,
/// so the jailed user never had a chance to write the binary run as root),
/// checks it takes the jail over, and replaces the jailer with it
/// (`POSIX_SPAWN_SETEXEC`: same PID) with only the standard descriptors,
/// `WICK_JAIL` (and `WICK_JAIL_CPU`, `WICK_JAIL_MEMORY` for the limits,
/// `WICK_NETNS` for the jail's network) as its whole environment
/// and the jetsam memory limit. Just before, it starts the jail's freezer
/// supervisor (`freezer`), which holds the exec back while the jail is
/// frozen. Returns only on failure.
pub fn exec_command(
    exec_file_path: &Path,
    chroot_dir: &Path,
    uid: u32,
    gid: u32,
    args: &[String],
) -> io::Error {
    match exec(exec_file_path, chroot_dir, uid, gid, args) {
        Ok(err) => err,
        Err(err) => io::Error::other(err),
    }
}

fn exec(
    exec_file_path: &Path,
    chroot_dir: &Path,
    uid: u32,
    gid: u32,
    args: &[String],
) -> Result<io::Error, HostError> {
    jail_tmp(uid, gid)?;
    leave_chroot()?;
    let exec_file = copy_for_exec(exec_file_path, chroot_dir)?;
    let jail_dir = chroot_dir.parent().unwrap_or(chroot_dir);
    let freezer = freezer::files_for_exec(jail_dir).map_err(|e| HostError::Freezer(e.to_string()))?;

    let mut argv = vec![CString::new(exec_file.as_os_str().as_bytes()).expect("path has no NUL")];
    for arg in args {
        argv.push(
            CString::new(arg.as_bytes())
                .map_err(|e| HostError::Spawn("argument", io::Error::other(e)))?,
        );
    }
    let mut env_var = format!("{JAIL_ENV}={uid}:{gid}:").into_bytes();
    env_var.extend_from_slice(chroot_dir.as_os_str().as_bytes());
    let mut tmp_var = b"TMPDIR=".to_vec();
    tmp_var.extend_from_slice(JAIL_TMP.to_bytes());
    let mut env = vec![
        CString::new(env_var).map_err(|e| HostError::Spawn("WICK_JAIL", io::Error::other(e)))?,
        CString::new(tmp_var).expect("no NUL"),
    ];
    if let Some(percent) = *CPU_LIMIT_PERCENT.lock().unwrap() {
        env.push(CString::new(format!("{JAIL_CPU_ENV}={percent}")).expect("no NUL"));
    }
    if let Some(mib) = *MEMORY_LIMIT_MIB.lock().unwrap() {
        env.push(CString::new(format!("{JAIL_MEMORY_ENV}={mib}")).expect("no NUL"));
    }
    if NEW_PID_NS.load(std::sync::atomic::Ordering::Relaxed) {
        env.push(CString::new(format!("{JAIL_PID_NS_ENV}=1")).expect("no NUL"));
    }
    if let Some(dir) = NETNS.lock().unwrap().as_ref() {
        grant_to_jail(dir, uid).map_err(|e| HostError::Netns(dir.clone(), e))?;
        let mut var = format!("{NETNS_ENV}=").into_bytes();
        var.extend_from_slice(dir.as_os_str().as_bytes());
        env.push(CString::new(var).map_err(|e| HostError::Spawn("WICK_NETNS", io::Error::other(e)))?);
    }
    let mut argv_ptrs: Vec<*mut libc::c_char> = argv.iter().map(|a| a.as_ptr().cast_mut()).collect();
    argv_ptrs.push(std::ptr::null_mut());
    let mut envp_ptrs: Vec<*mut libc::c_char> = env.iter().map(|a| a.as_ptr().cast_mut()).collect();
    envp_ptrs.push(std::ptr::null_mut());

    let fail = |what, ret: libc::c_int| HostError::Spawn(what, io::Error::from_raw_os_error(ret));
    let mut attr = std::mem::MaybeUninit::<libc::posix_spawnattr_t>::uninit();
    let mut actions = std::mem::MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
    // SAFETY: initialises the attribute and file action objects; they are not
    // destroyed, as the process is replaced or exits on failure.
    let ret = unsafe { libc::posix_spawnattr_init(attr.as_mut_ptr()) };
    if ret != 0 {
        return Err(fail("posix_spawnattr_init", ret));
    }
    // SAFETY: as above.
    let ret = unsafe { libc::posix_spawn_file_actions_init(actions.as_mut_ptr()) };
    if ret != 0 {
        return Err(fail("posix_spawn_file_actions_init", ret));
    }
    let flags = libc::POSIX_SPAWN_SETEXEC | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
    // SAFETY: initialised above.
    let ret = unsafe {
        libc::posix_spawnattr_setflags(
            attr.as_mut_ptr(),
            libc::c_short::try_from(flags).expect("spawn flags fit"),
        )
    };
    if ret != 0 {
        return Err(fail("posix_spawnattr_setflags", ret));
    }
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: initialised above.
        let ret = unsafe { posix_spawn_file_actions_addinherit_np(actions.as_mut_ptr(), fd) };
        if ret != 0 {
            return Err(fail("posix_spawn_file_actions_addinherit_np", ret));
        }
    }
    if let Some(limit) = *MEMORY_LIMIT_MIB.lock().unwrap() {
        let priority = jetsam_priority()?;
        // SAFETY: initialised above.
        let ret = unsafe {
            posix_spawnattr_setjetsam_ext(
                attr.as_mut_ptr(),
                POSIX_SPAWN_JETSAM_MEMLIMIT_ACTIVE_FATAL | POSIX_SPAWN_JETSAM_MEMLIMIT_INACTIVE_FATAL,
                priority,
                limit,
                limit,
            )
        };
        if ret != 0 {
            return Err(fail("posix_spawnattr_setjetsam_ext", ret));
        }
    }
    // Last before the exec: the jail's supervisor, which may hold the exec
    // back while the jail is frozen.
    freezer::start_supervisor(freezer).map_err(HostError::Freezer)?;
    // SAFETY: NUL-terminated path, argument and environment vectors that
    // outlive the call; attributes initialised above.
    let ret = unsafe {
        libc::posix_spawn(
            std::ptr::null_mut(),
            argv[0].as_ptr(),
            actions.as_ptr(),
            attr.as_ptr(),
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
        )
    };
    Ok(io::Error::from_raw_os_error(ret))
}

/// Makes the jail's temporary directory (still inside the chroot), given to
/// the jailed user as upstream's jail folders are. One the operator made is
/// kept, if it is a directory and not a link.
fn jail_tmp(uid: u32, gid: u32) -> Result<(), HostError> {
    let err = |_| HostError::JailTmp(io::Error::last_os_error());
    // SAFETY: NUL-terminated path.
    let created = unsafe { libc::mkdir(JAIL_TMP.as_ptr(), 0o700) } == 0;
    if !created && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
        return Err(HostError::JailTmp(io::Error::last_os_error()));
    }
    // SAFETY: NUL-terminated path.
    let fd = unsafe { libc::open(JAIL_TMP.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW) };
    if fd < 0 {
        return Err(HostError::JailTmp(io::Error::last_os_error()));
    }
    // SAFETY: a descriptor we own.
    let dir = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    if created {
        // SAFETY: a directory descriptor.
        let ok = unsafe { libc::fchown(dir.as_raw_fd(), uid, gid) == 0 && libc::fchmod(dir.as_raw_fd(), 0o700) == 0 };
        if !ok {
            return Err(err(()));
        }
    }
    Ok(())
}

/// Back to the root directory the jailer had before its chroot.
fn leave_chroot() -> Result<(), HostError> {
    let fd = OLD_ROOT
        .get()
        .ok_or_else(|| HostError::LeaveChroot(io::Error::other("the jailer did not chroot")))?;
    let check = |ret: libc::c_int| {
        if ret == 0 { Ok(()) } else { Err(HostError::LeaveChroot(io::Error::last_os_error())) }
    };
    // SAFETY: a directory descriptor opened by `chroot::chroot`.
    check(unsafe { libc::fchdir(fd.as_raw_fd()) })?;
    // SAFETY: NUL-terminated paths.
    check(unsafe { libc::chroot(c".".as_ptr()) })?;
    // SAFETY: as above.
    check(unsafe { libc::chdir(c"/".as_ptr()) })
}

/// Copies the operator's binary next to the jail (`<id>/<name>`, beside
/// `<id>/root`), root-owned and read-only, and checks it takes the jail over.
/// A copy as upstream's: two Firecracker processes never share the binary's
/// memory.
fn copy_for_exec(exec_file_path: &Path, chroot_dir: &Path) -> Result<PathBuf, HostError> {
    let name = exec_file_path.file_name().unwrap_or_default();
    let dst = chroot_dir.parent().unwrap_or(chroot_dir).join(name);
    let copy_err = |e| HostError::CopyExec(exec_file_path.to_owned(), dst.clone(), e);
    let mut src = File::open(exec_file_path).map_err(copy_err)?;
    let mode = src.metadata().map_err(copy_err)?.mode();
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode & 0o555)
        .open(&dst)
        .map_err(copy_err)?;
    io::copy(&mut src, &mut out).map_err(copy_err)?;
    drop(out);
    let mut copied = Vec::new();
    File::open(&dst)
        .and_then(|mut f| f.read_to_end(&mut copied))
        .map_err(copy_err)?;
    if !copied.windows(HANDOVER_MARK.len()).any(|w| w == HANDOVER_MARK) {
        return Err(HostError::NoHandover(exec_file_path.to_owned()));
    }
    Ok(dst)
}

/// The jailer's own jetsam priority, which Firecracker keeps: the limit
/// attribute sets a priority too, and only the limit is meant to change.
fn jetsam_priority() -> Result<i32, HostError> {
    let mut entry = MemorystatusPriorityEntry::default();
    // SAFETY: no arguments.
    let pid = unsafe { libc::getpid() };
    // SAFETY: the buffer is one entry of the size passed.
    let ret = unsafe {
        memorystatus_control(
            MEMORYSTATUS_CMD_GET_PRIORITY_LIST,
            pid,
            0,
            std::ptr::from_mut(&mut entry).cast(),
            std::mem::size_of::<MemorystatusPriorityEntry>(),
        )
    };
    if ret < 0 {
        return Err(HostError::JetsamPriority(io::Error::last_os_error()));
    }
    if entry.pid != pid {
        return Err(HostError::JetsamPriority(io::Error::other(format!(
            "entry for pid {} instead of {pid}",
            entry.pid
        ))));
    }
    Ok(entry.priority)
}

/// `close_range(3, ~0)`: macOS has no `close_range`, so the descriptors are
/// listed with `proc_pidinfo` and closed, and the list is checked to be empty.
pub fn close_fds_by_close_range() -> Result<(), JailerError> {
    for fd in open_fds().map_err(JailerError::CloseRange)? {
        // SAFETY: closing a descriptor; the jailer is single-threaded here.
        unsafe { libc::close(fd) };
    }
    let left = open_fds().map_err(JailerError::CloseRange)?;
    if left.is_empty() {
        Ok(())
    } else {
        Err(JailerError::CloseRange(io::Error::other(format!(
            "descriptors {left:?} are still open"
        ))))
    }
}

/// The open descriptors above the standard ones.
fn open_fds() -> io::Result<Vec<i32>> {
    // SAFETY: no arguments.
    let pid = unsafe { libc::getpid() };
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    let mut cap = 64;
    loop {
        let mut buf: Vec<libc::proc_fdinfo> = Vec::with_capacity(cap);
        let bytes = libc::c_int::try_from(cap * entry).map_err(io::Error::other)?;
        // SAFETY: the buffer has room for `cap` entries.
        let n = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, buf.as_mut_ptr().cast(), bytes)
        };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        let count = usize::try_from(n).map_err(io::Error::other)? / entry;
        if count < cap {
            // SAFETY: the kernel filled `count` entries.
            unsafe { buf.set_len(count) };
            return Ok(buf
                .iter()
                .map(|f| f.proc_fd)
                .filter(|&fd| fd > libc::STDERR_FILENO)
                .collect());
        }
        cap *= 4;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netns_needs_an_existing_directory() {
        // Nothing there, or not a directory: the jailer fails, as setns on a
        // file that is not a network namespace does.
        assert!(matches!(
            join_netns("/var/run/netns/x").unwrap_err(),
            JailerError::Host(HostError::Netns(_, _))
        ));
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let file = dir.as_path().join("file");
        std::fs::write(&file, b"").unwrap();
        let err = join_netns(file.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("a network is a directory of endpoints"), "{err}");
        assert!(NETNS.lock().unwrap().is_none());
        // A directory, by a path with a link in it: kept by its real path.
        let net = dir.as_path().join("net");
        std::fs::create_dir(&net).unwrap();
        std::os::unix::fs::symlink(&net, dir.as_path().join("link")).unwrap();
        join_netns(dir.as_path().join("link").to_str().unwrap()).unwrap();
        assert_eq!(NETNS.lock().unwrap().as_deref(), Some(net.canonicalize().unwrap().as_path()));
        // One network per jail.
        join_netns(net.to_str().unwrap()).unwrap_err();
        *NETNS.lock().unwrap() = None;
    }

    /// The `ls -le` lines of `path`'s ACL.
    fn acl_lines(path: &Path) -> Vec<String> {
        let out = std::process::Command::new("/bin/ls").arg("-lde").arg(path).output().unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .skip(1)
            .map(|l| l.trim().split_once(' ').map_or("", |(_, rest)| rest).to_owned())
            .collect()
    }

    #[test]
    fn test_grant_to_jail_keeps_other_entries() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let net = dir.as_path().to_owned();
        // A socket made before the grant, another jail's entry.
        let before = std::os::unix::net::UnixDatagram::bind(net.join("before")).unwrap();
        grant_to_jail(&net, 54321).unwrap();
        let first = acl_lines(&net);
        grant_to_jail(&net, 54320).unwrap();
        // Granted again: no entry added twice.
        grant_to_jail(&net, 54321).unwrap();
        let lines = acl_lines(&net);
        let uuid = |uid: u32| format!("{uid:X}");
        let theirs: Vec<_> = lines.iter().filter(|l| l.contains(&uuid(54321))).collect();
        assert_eq!(theirs.len(), 2, "{lines:?}");
        assert!(theirs[0].contains("allow list,add_file,search,delete_child"), "{lines:?}");
        assert!(theirs[1].contains("file_inherit,only_inherit"), "{lines:?}");
        // (ls names a directory's entry's rights as a directory's: read,
        // write, append are list, add_file, add_subdirectory.)
        assert!(theirs[1].contains("allow list,add_file,delete,add_subdirectory"), "{lines:?}");
        assert_eq!(lines.iter().filter(|l| l.contains(&uuid(54320))).count(), 2, "{lines:?}");
        assert_eq!(&lines[..2], &first[..], "{lines:?}");
        // The socket already there, and one made after: reachable by the jail.
        let after = std::os::unix::net::UnixDatagram::bind(net.join("after")).unwrap();
        for name in ["before", "after"] {
            let entry = acl_lines(&net.join(name));
            assert!(
                entry.iter().any(|l| l.contains(&uuid(54321)) && l.contains("allow read,write")),
                "{name}: {entry:?}"
            );
        }
        drop((before, after));
    }

    // --new-pid-ns: a child, as upstream's clone, and Firecracker is told
    // it runs in a namespace of its own (its exec's environment).
    #[test]
    fn test_new_pid_ns_forks() {
        let pid = new_pid_ns().unwrap();
        if pid == 0 {
            // SAFETY: the child ends at once.
            unsafe { libc::_exit(7) };
        }
        let mut status = 0;
        // SAFETY: our child; an out-pointer.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 7, "{status:#x}");
        assert!(NEW_PID_NS.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_devices() {
        for dev in [c"/dev/kvm", c"/dev/net/tun", c"/dev/urandom", c"/dev/userfaultfd"] {
            mknod_and_own_dev(dev).unwrap();
        }
        assert!(matches!(
            mknod_and_own_dev(c"/dev/nitro_enclaves").unwrap_err(),
            JailerError::Host(HostError::UnsupportedDevice(_))
        ));
    }

    #[test]
    fn test_copy_for_exec() {
        let tmp = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let root = tmp.as_path().join("id").join("root");
        std::fs::create_dir_all(&root).unwrap();
        // A binary without the mark is refused.
        assert!(matches!(
            copy_for_exec(Path::new("/bin/ls"), &root).unwrap_err(),
            HostError::NoHandover(_)
        ));
        // This test binary carries it (HANDOVER_MARK is in its data); the
        // copy is next to the jail and not writable.
        let exe = std::env::current_exe().unwrap();
        let copy = copy_for_exec(&exe, &root).unwrap();
        assert_eq!(copy.parent().unwrap(), root.parent().unwrap());
        assert_eq!(std::fs::metadata(&copy).unwrap().mode() & 0o222, 0);
        // Never over an existing file (or a link planted there).
        copy_for_exec(&exe, &root).unwrap_err();
    }

    #[test]
    fn test_leave_chroot_needs_a_chroot() {
        if OLD_ROOT.get().is_none() {
            assert!(matches!(leave_chroot().unwrap_err(), HostError::LeaveChroot(_)));
        }
    }
}
