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

/// Environment variable through which Firecracker takes the jail over
/// (`vmm::ext::jail::ENV`).
const JAIL_ENV: &str = "WICK_JAIL";
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
        "--{0} is not supported on macOS: {1}. The jailer never accepts an isolation option it \
         cannot enforce."
    )]
    Unsupported(&'static str, &'static str),
    #[error(
        "--cgroup {0} is not supported on macOS (supported: memory.max with --cgroup-version 2, \
         memory.limit_in_bytes with --cgroup-version 1). The jailer never accepts a limit it \
         cannot enforce."
    )]
    UnsupportedCgroup(String),
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
    #[error("Failed to copy {0:?} to {1:?} for the exec: {2}")]
    CopyExec(PathBuf, PathBuf, io::Error),
    #[error("Failed to make the jail's temporary directory: {0}")]
    JailTmp(io::Error),
    #[error("Failed to read the jailer's memory priority: {0}")]
    JetsamPriority(io::Error),
    #[error("Failed to prepare the exec: {0}: {1}")]
    Spawn(&'static str, io::Error),
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

pub(crate) fn set_old_root(fd: OwnedFd) -> Result<(), HostError> {
    OLD_ROOT
        .set(fd)
        .map_err(|_| HostError::Chroot(io::Error::other("the jailer chroots once")))
}

pub(crate) fn set_memory_limit_mib(limit: Option<i32>) {
    *MEMORY_LIMIT_MIB.lock().unwrap() = limit;
}

/// `--netns`: macOS has no network namespaces.
pub fn join_netns(_path: &str) -> Result<(), JailerError> {
    Err(HostError::Unsupported(
        "netns",
        "macOS has no network namespaces; the sandbox denies all IP networking to a jailed \
         Firecracker, so give it a Unix datagram network endpoint inside the jail",
    )
    .into())
}

/// `--new-pid-ns`: macOS has no PID namespaces.
pub fn new_pid_ns() -> Result<(), JailerError> {
    Err(HostError::Unsupported("new-pid-ns", "macOS has no PID namespaces").into())
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
/// `WICK_JAIL` as its whole environment and the jetsam memory limit. Returns
/// only on failure.
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
    let env = [
        CString::new(env_var).map_err(|e| HostError::Spawn("WICK_JAIL", io::Error::other(e)))?,
        CString::new(tmp_var).expect("no NUL"),
    ];
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
    fn test_unsupported_isolation_is_refused() {
        assert!(matches!(
            join_netns("/var/run/netns/x").unwrap_err(),
            JailerError::Host(HostError::Unsupported("netns", _))
        ));
        assert!(matches!(
            new_pid_ns().unwrap_err(),
            JailerError::Host(HostError::Unsupported("new-pid-ns", _))
        ));
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
