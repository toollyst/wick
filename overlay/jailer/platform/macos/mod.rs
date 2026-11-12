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
/// macOS has no network namespaces. As on Windows, a network is a
/// directory the operator made (it must exist, as the namespace file must
/// on Linux), where the operator's switch binds its sockets. Each jail
/// given it has a directory of its own inside, `<dir>/<id>`, made at the
/// exec ([`network_for_jail`]): Firecracker makes its network endpoints
/// there (`vmm::platform::net`), `<dir>/<id>/<host_dev_name>`, instead of
/// in its temporary directory. So jails given one directory are in one
/// network, as Firecrackers in one namespace are, and each one's endpoints
/// are its own, as a TAP is its owner's (drivers/net/tun.c
/// tun_not_capable, tun_attach). Firecracker opens its directory before
/// its chroot (`WICK_NETNS`, `vmm::ext::jail::netns_dir`), and its sandbox
/// lets it reach Unix sockets only there, directly in the network (the
/// switch's) and in the jail, and no IP network.
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
        pub fn acl_delete_entry(acl: Acl, entry: Entry) -> c_int;
        pub fn acl_set_tag_type(entry: Entry, tag: c_int) -> c_int;
        pub fn acl_get_qualifier(entry: Entry) -> *mut c_void;
        pub fn acl_set_qualifier(entry: Entry, qualifier: *const c_void) -> c_int;
        pub fn acl_get_permset(entry: Entry, set: *mut Set) -> c_int;
        pub fn acl_add_perm(set: Set, perm: c_int) -> c_int;
        pub fn acl_set_permset(entry: Entry, set: Set) -> c_int;
        pub fn acl_get_flagset_np(obj: *mut c_void, set: *mut Set) -> c_int;
        pub fn acl_add_flag_np(set: Set, flag: c_int) -> c_int;
        pub fn acl_set_flagset_np(obj: *mut c_void, set: Set) -> c_int;
        pub fn mbr_uid_to_uuid(uid: u32, uuid: *mut u8) -> c_int;
    }
}

/// What a jail's uid, and the network's owner, are granted on the jail's
/// own directory in the network: to list it and to make and remove entries.
const NETNS_DIR_PERMS: &[i32] = &[
    acl::LIST_DIRECTORY,
    acl::SEARCH,
    acl::ADD_FILE,
    acl::DELETE_CHILD,
    acl::READ_ATTRIBUTES,
    acl::READ_EXTATTRIBUTES,
    acl::READ_SECURITY,
];
/// What the network's owner is granted on what a jail makes in its
/// directory (inherited): a socket is reached by writing to it.
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
/// What a jail's uid is granted on the network directory itself: to pass
/// through it, to its own directory and to the switch's sockets.
const NETNS_PASS_PERMS: &[i32] = &[acl::SEARCH];
/// What a jail's uid is granted on the switch's sockets, those directly in
/// the network directory: to send to them.
const NETNS_SWITCH_PERMS: &[i32] = &[acl::WRITE_DATA];

/// An entry of an ACL to write: who, what, and the inheritance flags.
type AclEntry<'a> = (u32, &'a [i32], &'a [i32]);

/// The jail `id`'s own directory in the network `dir`, for the jail's
/// `uid`: `<dir>/<id>`, returned with the lock that says a jail lives
/// there, which Firecracker holds for its life (the descriptor is its
/// inheritance; a lock goes with its last descriptor, so it frees itself
/// however the jail ends).
///
/// - The network directory lets the jail's uid pass through
///   ([`NETNS_PASS_PERMS`]) and send to the sockets directly in it, the
///   operator's switch's, made before or after ([`NETNS_SWITCH_PERMS`]):
///   it cannot list the directory, nor make, remove or replace anything
///   in it. Whatever else an earlier jailer granted that uid there is
///   taken back. (The grant for what is made after is inherited by any
///   file made directly there, not sockets alone: the directory is for
///   the switch's sockets, and the docs say to keep nothing else in it.
///   A switch started or restarted after the jail must be reachable.)
/// - `<dir>/<id>` is the jailer's (mode 0700) and grants the jail's uid
///   and the network's owner only: the uid makes and removes its endpoints
///   there, the owner's switch reaches them. No other uid has an entry, so
///   another jail gets nothing there from the kernel's file checks. Two
///   jails of one uid are told apart by nothing a file has: each
///   Firecracker's sandbox profile names its own directory only
///   (`vmm::ext::sandbox::files_in_jail`).
/// - A jail of this id that lives keeps its directory: the second start
///   fails with `EBUSY` and nothing of the first's is touched, as a TAP
///   with a queue attached refuses a second attach (drivers/net/tun.c
///   tun_attach). With the lock free the directory is a dead jail's: its
///   sockets are removed (each one logged), by name on the directory's
///   own descriptor, no link followed; nothing that is not a socket is.
/// - A link at `<dir>/<id>`, or anything that is not a directory of the
///   jailer's own user, is refused. The path's length is not: Firecracker
///   names its endpoints and the switch's sockets relative to its
///   directory, and a switch for which `<dir>/<id>/<name>` is too long for
///   a socket address (104 bytes) names it relative to `<dir>`.
pub(crate) fn network_for_jail(dir: &Path, id: &str, uid: u32) -> io::Result<(PathBuf, OwnedFd)> {
    if id.is_empty() || id == "." || id == ".." || id.contains(['/', '\0']) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{id:?} names no directory")));
    }
    let sub = dir.join(id);
    let c_sub = CString::new(sub.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: a NUL-terminated path.
    if unsafe { libc::mkdir(c_sub.as_ptr(), 0o700) } != 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::AlreadyExists {
            return Err(err);
        }
    }
    // SAFETY: a NUL-terminated path; no link followed at its last name.
    let fd = unsafe {
        libc::open(c_sub.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor we own.
    let lock = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let meta = File::from(lock.try_clone()?).metadata()?;
    // SAFETY: no arguments.
    let me = unsafe { libc::geteuid() };
    if meta.uid() != me {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{sub:?} is uid {}'s, not the jailer's ({me}): remove it", meta.uid()),
        ));
    }
    // SAFETY: a descriptor we own; does not block.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = io::Error::last_os_error();
        return Err(if err.kind() == io::ErrorKind::WouldBlock {
            io::Error::from_raw_os_error(libc::EBUSY)
        } else {
            err
        });
    }
    // From here the directory is this jail's and no other's.
    remove_dead_sockets(&lock, &sub)?;
    // SAFETY: a descriptor we own.
    if unsafe { libc::fchmod(lock.as_raw_fd(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let owner = std::fs::metadata(dir)?.uid();
    let mut entries: Vec<AclEntry> = vec![(uid, NETNS_DIR_PERMS, &[])];
    if owner != 0 {
        entries.push((owner, NETNS_DIR_PERMS, &[]));
        entries.push((owner, NETNS_ENTRY_PERMS, &[acl::ENTRY_FILE_INHERIT, acl::ENTRY_ONLY_INHERIT]));
    }
    write_acl(&sub, None, &entries)?;
    write_acl(
        dir,
        Some(uid),
        &[
            (uid, NETNS_PASS_PERMS, &[]),
            (uid, NETNS_SWITCH_PERMS, &[acl::ENTRY_FILE_INHERIT, acl::ENTRY_ONLY_INHERIT]),
        ],
    )?;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = std::fs::symlink_metadata(entry.path())?;
        if std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()) && (meta.uid() == owner || meta.uid() == 0) {
            write_acl(&entry.path(), Some(uid), &[(uid, NETNS_SWITCH_PERMS, &[])])?;
        }
    }
    Ok((sub, lock))
}

/// Removes the sockets in the directory `dir` is open on (`path`, for the
/// log): what a jail that is gone left there. Each name is looked at and
/// removed on the descriptor, without following a link.
fn remove_dead_sockets(dir: &OwnedFd, path: &Path) -> io::Result<()> {
    // readdir on a descriptor of its own: closedir closes it.
    let list = dir.try_clone()?;
    // SAFETY: a directory descriptor, owned by the stream from here.
    let stream = unsafe { libc::fdopendir(std::os::fd::IntoRawFd::into_raw_fd(list)) };
    if stream.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: a valid stream; the entry is read before the next call.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: a NUL-terminated name in the entry.
        names.push(unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_owned());
    }
    // SAFETY: the stream opened above.
    unsafe { libc::closedir(stream) };
    for name in names {
        // SAFETY: plain data, filled by fstatat.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a name in the directory; no link followed.
        if unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0
            || st.st_mode & libc::S_IFMT != libc::S_IFSOCK
        {
            continue;
        }
        // SAFETY: as above; removes that name only.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        eprintln!(
            "jailer: removed the socket {:?} a jail that is gone left in {path:?}",
            std::ffi::OsStr::from_bytes(name.to_bytes())
        );
    }
    Ok(())
}

/// Writes `path`'s ACL: `add`'s allow entries, after the entries it has
/// that are not `without`'s uid's (`Some`), or after none (`None`: the ACL
/// is `add` alone).
fn write_acl(path: &Path, without: Option<u32>, add: &[AclEntry]) -> io::Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let uuid_of = |uid: u32| {
        let mut uuid = [0u8; 16];
        // SAFETY: a 16-byte uuid_t.
        if unsafe { acl::mbr_uid_to_uuid(uid, uuid.as_mut_ptr()) } != 0 {
            return Err(io::Error::other(format!("no UUID for uid {uid}")));
        }
        Ok(uuid)
    };
    let check = |ret: i32| if ret == 0 { Ok(()) } else { Err(io::Error::last_os_error()) };
    let mut list = match without {
        // SAFETY: a NUL-terminated path; a null ACL is no ACL yet.
        Some(_) => unsafe { acl::acl_get_file(c_path.as_ptr(), acl::TYPE_EXTENDED) },
        None => std::ptr::null_mut(),
    };
    if list.is_null() {
        if without.is_some() {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(err);
            }
        }
        // SAFETY: a new, empty ACL.
        list = unsafe { acl::acl_init(1) };
        if list.is_null() {
            return Err(io::Error::last_os_error());
        }
    }
    let result = (|| {
        if let Some(uid) = without {
            let uuid = uuid_of(uid)?;
            // One entry of that uid's removed per pass: an entry's place is
            // not kept across a removal.
            loop {
                let mut found = None;
                let mut entry: acl::Entry = std::ptr::null_mut();
                let mut id = acl::FIRST_ENTRY;
                // SAFETY: entries of a valid ACL, read only; the qualifier is freed.
                while unsafe { acl::acl_get_entry(list, id, &mut entry) } == 0 {
                    id = acl::NEXT_ENTRY;
                    // SAFETY: as above.
                    let qualifier = unsafe { acl::acl_get_qualifier(entry) };
                    if qualifier.is_null() {
                        continue;
                    }
                    // SAFETY: a guid_t (16 bytes), freed after.
                    let same = unsafe { std::slice::from_raw_parts(qualifier.cast::<u8>(), 16) } == uuid;
                    // SAFETY: allocated by acl_get_qualifier.
                    unsafe { acl::acl_free(qualifier) };
                    if same {
                        found = Some(entry);
                        break;
                    }
                }
                match found {
                    // SAFETY: an entry of this ACL.
                    Some(entry) => check(unsafe { acl::acl_delete_entry(list, entry) })?,
                    None => break,
                }
            }
        }
        for &(uid, perms, flags) in add {
            let uuid = uuid_of(uid)?;
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
        }
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
    // The jail's own directory in its network, and the lock on it, which
    // Firecracker inherits and holds for its life.
    let mut network_lock = None;
    if let Some(dir) = NETNS.lock().unwrap().as_ref() {
        let id = jail_dir.file_name().and_then(|id| id.to_str()).unwrap_or("");
        let (sub, lock) = network_for_jail(dir, id, uid).map_err(|e| HostError::Netns(dir.join(id), e))?;
        let mut var = format!("{NETNS_ENV}=").into_bytes();
        var.extend_from_slice(sub.as_os_str().as_bytes());
        env.push(CString::new(var).map_err(|e| HostError::Spawn("WICK_NETNS", io::Error::other(e)))?);
        network_lock = Some(lock);
    }
    let memory = match *MEMORY_LIMIT_MIB.lock().unwrap() {
        Some(limit) => Some((jetsam_priority()?, limit)),
        None => None,
    };
    // Last before the exec: the jail's supervisor, which may hold the exec
    // back while the jail is frozen.
    replace_process(&argv, &env, network_lock.as_ref(), memory, || {
        freezer::start_supervisor(freezer).map_err(HostError::Freezer)
    })
}

/// Replaces this process with `argv[0]` (`posix_spawn` with
/// `POSIX_SPAWN_SETEXEC`), given `argv`, `env` as its whole environment, the
/// standard descriptors and `network_lock` and no other descriptor, and
/// `memory`'s jetsam priority and limit (MiB). `last` runs when all else
/// is ready, just before. Returns only on failure.
///
/// `network_lock` is close-on-exec until here (a descriptor of the
/// jailer's that must reach nothing but Firecracker), and an inherit action
/// alone does not carry such a descriptor over when the spawn replaces the
/// caller: the kernel makes the new process's descriptor table first,
/// without the close-on-exec ones (xnu bsd/kern/kern_exec.c posix_spawn:
/// cloneproc(CLONEPROC_EXEC); kern_descrip.c fdt_fork with in_exec), and
/// runs the file actions on that table after, where the inherit action
/// finds no such descriptor: EBADF (exec_handle_file_actions,
/// PSFA_INHERIT). So the flag is cleared here, last, and the inherit
/// action keeps the descriptor through POSIX_SPAWN_CLOEXEC_DEFAULT.
fn replace_process(
    argv: &[CString],
    env: &[CString],
    network_lock: Option<&OwnedFd>,
    memory: Option<(i32, i32)>,
    last: impl FnOnce() -> Result<(), HostError>,
) -> Result<io::Error, HostError> {
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
    let inherited = [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]
        .into_iter()
        .chain(network_lock.map(AsRawFd::as_raw_fd));
    for fd in inherited {
        // SAFETY: initialised above.
        let ret = unsafe { posix_spawn_file_actions_addinherit_np(actions.as_mut_ptr(), fd) };
        if ret != 0 {
            return Err(fail("posix_spawn_file_actions_addinherit_np", ret));
        }
    }
    if let Some((priority, limit)) = memory {
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
    last()?;
    if let Some(lock) = network_lock {
        // SAFETY: a descriptor we own; the jailer has one thread and
        // nothing is started between this and the exec.
        if unsafe { libc::fcntl(lock.as_raw_fd(), libc::F_SETFD, 0) } != 0 {
            return Err(HostError::Spawn("fcntl(F_SETFD) on the network's lock", io::Error::last_os_error()));
        }
    }
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

    /// `ls`'s name for a uid nobody has.
    fn who(uid: u32) -> String {
        format!("{uid:X}")
    }

    // The exec itself, with a stand-in for Firecracker: the lock reaches the
    // new program (and nothing else of the jailer's does), and is held for
    // as long as that program lives. The stand-in is a shell that fails
    // unless the lock's descriptor is open and another of the jailer's,
    // not close-on-exec, is not; it says so and waits for its stdin to end.
    #[test]
    fn test_the_network_lock_is_held_by_the_program_the_jailer_becomes() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let net = dir.as_path().canonicalize().unwrap();
        let (_sub, lock) = network_for_jail(&net, "a", 54321).unwrap();
        let other = File::open(&net).unwrap();
        let script = format!(
            ": <&{} || exit 9; if (: <&{}) 2>/dev/null; then exit 8; fi; echo ok; read line; exit 0",
            lock.as_raw_fd(),
            other.as_raw_fd()
        );
        let argv = ["/bin/sh", "-c", &script].map(|a| CString::new(a).unwrap());
        let (mut pipe, mut out) = ([-1; 2], [-1; 2]);
        // SAFETY: arrays of two descriptors.
        assert_eq!(unsafe { (libc::pipe(pipe.as_mut_ptr()), libc::pipe(out.as_mut_ptr())) }, (0, 0));
        // SAFETY: the child only calls replace_process and _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: descriptors of ours; ends the child.
            unsafe {
                libc::dup2(pipe[0], 0);
                libc::dup2(out[1], 1);
                libc::fcntl(other.as_raw_fd(), libc::F_SETFD, 0);
                let code = match replace_process(&argv, &[], Some(&lock), None, || Ok(())) {
                    Ok(err) => 100 + err.raw_os_error().unwrap_or(0),
                    Err(_) => 99,
                };
                libc::_exit(code)
            }
        }
        // SAFETY: the child's ends; the other is ours from here.
        let mut said = unsafe {
            libc::close(pipe[0]);
            libc::close(out[1]);
            <File as std::os::fd::FromRawFd>::from_raw_fd(out[0])
        };
        // The jailer's own descriptor is gone with the jailer.
        drop(lock);
        let wait = |flags| {
            let mut status = 0;
            // SAFETY: our child; an out-pointer.
            let got = unsafe { libc::waitpid(pid, &mut status, flags) };
            (got, status)
        };
        let mut word = [0u8; 3];
        if said.read_exact(&mut word).is_err() {
            let (_, status) = wait(0);
            panic!("the stand-in did not start with the lock: exit {}", libc::WEXITSTATUS(status));
        }
        assert_eq!(&word, b"ok\n");
        let err = network_for_jail(&net, "a", 54321).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EBUSY), "{err}");
        // SAFETY: ends the stand-in's stdin.
        unsafe { libc::close(pipe[1]) };
        let (got, status) = wait(0);
        assert_eq!(got, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "status {status:#x}");
        network_for_jail(&net, "a", 54321).unwrap();
    }

    // Linux: a TAP that has a queue attached refuses a second attach with
    // EBUSY and the first keeps it (drivers/net/tun.c tun_attach). Here: a
    // second jail of the same id, whatever its uid, is refused while the
    // first lives, and the first's endpoint is neither removed nor
    // regranted; once the first is gone its leftover sockets go, and
    // nothing else does.
    #[test]
    fn test_a_second_jail_of_one_id_is_refused_and_the_first_keeps_its_endpoint() {
        use std::os::unix::net::UnixDatagram;
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let net = dir.as_path().canonicalize().unwrap();
        let (sub, lock) = network_for_jail(&net, "a", 54321).unwrap();
        assert_eq!(sub, net.join("a"));
        let ep = UnixDatagram::bind(sub.join("tap0")).unwrap();
        for uid in [54321, 54320] {
            let err = network_for_jail(&net, "a", uid).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EBUSY), "uid {uid}: {err}");
        }
        UnixDatagram::unbound().unwrap().send_to(b"frame", sub.join("tap0")).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(ep.recv(&mut buf).unwrap(), 5);
        let lines = acl_lines(&sub);
        assert!(lines.iter().any(|l| l.contains(&who(54321))), "{lines:?}");
        assert!(!lines.iter().any(|l| l.contains(&who(54320))), "{lines:?}");
        // The first jail is gone (its descriptors closed with it).
        drop((lock, ep));
        std::fs::write(sub.join("note"), b"x").unwrap();
        let (again, _lock) = network_for_jail(&net, "a", 54320).unwrap();
        assert_eq!(again, sub);
        assert!(!sub.join("tap0").exists(), "the leftover socket stayed");
        assert!(sub.join("note").exists(), "a file that is no socket was removed");
        let lines = acl_lines(&sub);
        assert!(lines.iter().any(|l| l.contains(&who(54320))), "{lines:?}");
        assert!(!lines.iter().any(|l| l.contains(&who(54321))), "{lines:?}");
    }

    // Two jails given one network: each has a directory of its own in it,
    // which grants the other's uid nothing, and the network directory
    // itself lets a jail pass through and write to the switch's sockets,
    // no more (what an earlier jailer granted there is taken back).
    #[test]
    fn test_each_jail_has_a_network_directory_of_its_own() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixDatagram;
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let net = dir.as_path().canonicalize().unwrap();
        // As a jailer before this one left it.
        let old = [acl::LIST_DIRECTORY, acl::SEARCH, acl::ADD_FILE, acl::DELETE_CHILD];
        write_acl(&net, None, &[(54321, &old, &[]), (54321, NETNS_ENTRY_PERMS, &[acl::ENTRY_FILE_INHERIT, acl::ENTRY_ONLY_INHERIT])])
            .unwrap();
        let switch = UnixDatagram::bind(net.join("switch")).unwrap();
        let (a, _la) = network_for_jail(&net, "a", 54321).unwrap();
        let (b, _lb) = network_for_jail(&net, "b", 54320).unwrap();
        let later = UnixDatagram::bind(net.join("later")).unwrap();
        let lines = acl_lines(&net);
        for uid in [54321, 54320] {
            let theirs: Vec<_> = lines.iter().filter(|l| l.contains(&who(uid))).collect();
            assert_eq!(theirs.len(), 2, "{lines:?}");
            assert!(theirs.iter().any(|l| l.ends_with("allow search")), "{lines:?}");
            // (ls names a directory's entry's write right add_file.)
            assert!(theirs.iter().any(|l| l.ends_with("allow add_file,file_inherit,only_inherit")), "{lines:?}");
            for name in ["switch", "later"] {
                let entry = acl_lines(&net.join(name));
                assert!(
                    entry.iter().any(|l| l.contains(&who(uid)) && l.ends_with("allow write")),
                    "{name}: {entry:?}"
                );
            }
        }
        for (sub, own, other) in [(&a, 54321, 54320), (&b, 54320, 54321)] {
            assert_eq!(sub.parent(), Some(net.as_path()));
            assert_eq!(std::fs::metadata(sub).unwrap().permissions().mode() & 0o7777, 0o700);
            let lines = acl_lines(sub);
            assert!(
                lines.iter().any(|l| l.contains(&who(own)) && l.contains("allow list,add_file,search,delete_child")),
                "{lines:?}"
            );
            assert!(!lines.iter().any(|l| l.contains(&who(other))), "{lines:?}");
            // SAFETY: no arguments.
            let me = unsafe { libc::geteuid() };
            if me != 0 {
                // The network's owner, who is not root, reaches the endpoints made there.
                assert!(lines.iter().any(|l| !l.contains(&who(own)) && l.contains("file_inherit")), "{lines:?}");
            }
        }
        drop((switch, later));
    }

    // What stands at <network>/<id> is the jailer's own directory or
    // nothing: a link is refused before the jail starts, and so is an id
    // that names no directory there. An id of the longest kind is taken
    // (upstream's tests use 36-character ones).
    #[test]
    fn test_a_network_directory_that_cannot_hold_the_jail_is_refused() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let net = dir.as_path().canonicalize().unwrap();
        std::fs::create_dir(net.join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(net.join("elsewhere"), net.join("linked")).unwrap();
        let err = network_for_jail(&net, "linked", 54321).unwrap_err();
        // (O_DIRECTORY with O_NOFOLLOW on a link: ENOTDIR on macOS.)
        assert_eq!(err.raw_os_error(), Some(libc::ENOTDIR), "{err}");
        assert!(acl_lines(&net.join("elsewhere")).is_empty());
        let long = "i".repeat(64);
        let (sub, _lock) = network_for_jail(&net, &long, 54321).unwrap();
        assert_eq!(sub, net.join(&long));
        for bad in ["", ".", "..", "a/b"] {
            network_for_jail(&net, bad, 54321).unwrap_err();
        }
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
