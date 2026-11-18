// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! macOS's confinement calls for wick-fsd's stage 0 → stage 1 step
//! (docs/design-fs.md §6.2): the peer's credentials, the drop to the
//! operator's ids, and a Seatbelt profile compiled and applied with
//! libsandbox's calls, as Firecracker's own sandbox does
//! (`overlay/vmm/ext/sandbox.rs`; design-fs Q5: a module of its own for now).
//! `wick_fsd::confine::macos` calls them in order; each failure is the
//! caller's refusal to serve.

use std::ffi::{CStr, CString, c_char};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;

use libc::{c_int, c_void};

use super::{HostErrno, Result, check, last};

/// The uid and pid of the peer of a connected Unix socket
/// (`LOCAL_PEERCRED`, `LOCAL_PEERPID`): who connected, as the kernel
/// recorded it at `connect`.
pub fn peer(sock: BorrowedFd<'_>) -> Result<(u32, i32)> {
    // SAFETY: a zeroed xucred is valid; getsockopt fills it.
    let mut cred: libc::xucred = unsafe { std::mem::zeroed() };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::xucred>()).unwrap_or(0);
    // SAFETY: the buffer and its length, which the call updates.
    check(unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            std::ptr::from_mut(&mut cred).cast::<c_void>(),
            &mut len,
        )
    })?;
    if cred.cr_version != libc::XUCRED_VERSION {
        return Err(HostErrno(libc::EPROTO));
    }
    let mut pid: libc::pid_t = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::pid_t>()).unwrap_or(0);
    // SAFETY: as above.
    check(unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::from_mut(&mut pid).cast::<c_void>(),
            &mut len,
        )
    })?;
    Ok((cred.cr_uid, pid))
}

/// Drops to `uid`/`gid` with no supplementary group but `gid`: as root,
/// `setgid` and `setuid` set the real, effective and saved ids together
/// (setuid(2)), and the ids are read back; that the saved ids are gone is
/// read back by its effect, `seteuid(0)` and `setegid(0)` refused.
pub fn drop_ids(uid: u32, gid: u32) -> Result<()> {
    let groups = [gid];
    // SAFETY: one group, read by the call.
    check(unsafe { libc::setgroups(1, groups.as_ptr()) })?;
    // SAFETY: integer arguments only.
    check(unsafe { libc::setgid(gid) })?;
    // SAFETY: as above.
    check(unsafe { libc::setuid(uid) })?;
    Ok(())
}

/// What the kernel holds for this process's ids, read back (docs/design-fs.md
/// §6.2, the read-back).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ids {
    /// Real and effective uid.
    pub uids: [u32; 2],
    /// Real and effective gid.
    pub gids: [u32; 2],
    /// The supplementary groups.
    pub groups: Vec<u32>,
    /// `seteuid(0)` was refused: no saved uid 0 to go back to.
    pub saved_uid_gone: bool,
    /// `setegid(0)` was refused.
    pub saved_gid_gone: bool,
}

/// Reads [`Ids`] back. For a process that is root, the two probes succeed
/// and change nothing (the effective ids are 0 already).
pub fn ids() -> Result<Ids> {
    // SAFETY: these take no arguments and cannot fail.
    let (uids, gids) = unsafe { ([libc::getuid(), libc::geteuid()], [libc::getgid(), libc::getegid()]) };
    // SAFETY: size 0 asks for the count only.
    let n = check(unsafe { libc::getgroups(0, std::ptr::null_mut()) })?;
    let mut groups = vec![0; usize::try_from(n).unwrap_or(0)];
    // SAFETY: room for `n` groups.
    let n = check(unsafe { libc::getgroups(n, groups.as_mut_ptr()) })?;
    groups.truncate(usize::try_from(n).unwrap_or(0));
    // SAFETY: integer arguments only; an unprivileged process is refused.
    let saved_uid_gone = unsafe { libc::seteuid(0) } < 0 && last().0 == libc::EPERM;
    // SAFETY: as above.
    let saved_gid_gone = unsafe { libc::setegid(0) } < 0 && last().0 == libc::EPERM;
    Ok(Ids {
        uids,
        gids,
        groups,
        saved_uid_gone,
        saved_gid_gone,
    })
}

/// A path for a profile, quoted for a Seatbelt string: absolute, with no
/// NUL or newline. `None` for one a profile cannot name.
pub fn quoted(path: &Path) -> Option<String> {
    let path = path.to_str().filter(|r| r.starts_with('/') && !r.contains(['\0', '\n']))?;
    Some(path.replace('\\', "\\\\").replace('"', "\\\""))
}

/// libsandbox's compiled profile (`sandbox_compile_string`).
#[repr(C)]
struct SandboxProfile {
    builtin: *const c_char,
    data: *const u8,
    size: usize,
}

// libsandbox: compiling apart from applying, which sandbox_init does in one
// call. Not in the SDK's headers, exported by libsandbox (its .tbd lists
// them); Firecracker's sandbox and Chromium's use the same calls.
unsafe extern "C" {
    // <os/log.h> (libSystem).
    fn os_log_create(subsystem: *const c_char, category: *const c_char) -> *mut c_void;
}

#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_compile_string(profile: *const c_char, params: *mut c_void, error: *mut *mut c_char) -> *mut SandboxProfile;
    fn sandbox_apply(profile: *const SandboxProfile) -> c_int;
    fn sandbox_free_profile(profile: *mut SandboxProfile);
    fn sandbox_free_error(error: *mut c_char);
    fn sandbox_check(pid: libc::pid_t, operation: *const c_char, kind: c_int, ...) -> c_int;
}

/// Compiles `profile` to libsandbox's bytecode; the error is libsandbox's
/// message.
pub fn compile(profile: &str) -> std::result::Result<Vec<u8>, String> {
    let profile = CString::new(profile).map_err(|_| "the profile holds a NUL".to_string())?;
    let mut err: *mut c_char = std::ptr::null_mut();
    // SAFETY: a NUL-terminated profile, no parameters, an out-pointer.
    let compiled = unsafe { sandbox_compile_string(profile.as_ptr(), std::ptr::null_mut(), &mut err) };
    if compiled.is_null() {
        if err.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: libsandbox's NUL-terminated message, freed after the copy.
        let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
        // SAFETY: as above.
        unsafe { sandbox_free_error(err) };
        return Err(msg);
    }
    // SAFETY: libsandbox's profile: `size` bytes at `data`, freed once
    // copied.
    let bytes = unsafe {
        let p = &*compiled;
        let bytes = std::slice::from_raw_parts(p.data, p.size).to_vec();
        sandbox_free_profile(compiled);
        bytes
    };
    Ok(bytes)
}

/// Applies a compiled profile to this process, for good: Seatbelt cannot
/// be applied twice, nor taken off.
pub fn apply(compiled: &[u8]) -> Result<()> {
    // libsystem_trace sets itself up at the process's first os_log use and
    // asks the sandbox then; sandbox_init logs before it applies a profile,
    // a compiled profile is applied without that, so the log is set up here
    // first, as Firecracker's sandbox does.
    // SAFETY: NUL-terminated subsystem and category; the log object is kept
    // for the process's life, as os_log's are.
    unsafe { os_log_create(c"com.toollyst.wick".as_ptr(), c"fsd".as_ptr()) };
    let profile = SandboxProfile {
        builtin: std::ptr::null(),
        data: compiled.as_ptr(),
        size: compiled.len(),
    };
    // SAFETY: a profile of libsandbox's bytecode, which it only reads.
    if unsafe { sandbox_apply(&profile) } != 0 {
        return Err(last());
    }
    Ok(())
}

/// Whether this process runs under a Seatbelt profile: `sandbox_check`
/// with no operation answers that and carries out no rule.
pub fn sandboxed() -> bool {
    // SAFETY: no operation, no further arguments; getpid cannot fail.
    unsafe { sandbox_check(libc::getpid(), std::ptr::null(), 0) == 1 }
}

/// What a test's confined child does, and its process calls (the tests'
/// `confine_probe`: each case forks a child that confines itself as
/// wick-fsd does, then tries one thing the server must never do).
pub mod probe {
    use super::*;

    /// Which process [`fork`] returned in.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Forked {
        /// The child.
        Child,
        /// The parent, with the child's pid.
        Parent(libc::pid_t),
    }

    /// `fork`; the caller has one thread.
    pub fn fork() -> Result<Forked> {
        // SAFETY: the caller's process has one thread (harness = false).
        match check(unsafe { libc::fork() })? {
            0 => Ok(Forked::Child),
            pid => Ok(Forked::Parent(pid)),
        }
    }

    /// How a child ended.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Ended {
        /// With this exit code.
        Exited(i32),
        /// By this signal.
        Signaled(i32),
    }

    /// Waits for `pid` to end.
    pub fn wait(pid: libc::pid_t) -> Result<Ended> {
        let mut status = 0;
        loop {
            // SAFETY: a valid status out-pointer.
            if unsafe { libc::waitpid(pid, &mut status, 0) } >= 0 {
                break;
            }
            if last().0 != libc::EINTR {
                return Err(last());
            }
        }
        if libc::WIFSIGNALED(status) {
            return Ok(Ended::Signaled(libc::WTERMSIG(status)));
        }
        Ok(Ended::Exited(libc::WEXITSTATUS(status)))
    }

    /// Ends this process now with `code` (`_exit`).
    pub fn exit_now(code: i32) -> ! {
        // SAFETY: _exit never returns.
        unsafe { libc::_exit(code) }
    }

    /// `ptrace(PT_TRACE_ME)`.
    pub fn ptrace_traceme() -> Result<()> {
        // SAFETY: PT_TRACE_ME takes no address.
        check(unsafe { libc::ptrace(libc::PT_TRACE_ME, 0, std::ptr::null_mut(), 0) }).map(drop)
    }

    /// `kill(pid, 0)`: a signal's check to another process.
    pub fn signal_check(pid: libc::pid_t) -> Result<()> {
        // SAFETY: integer arguments only.
        check(unsafe { libc::kill(pid, 0) }).map(drop)
    }

    /// The parent's pid.
    pub fn parent() -> libc::pid_t {
        // SAFETY: getppid cannot fail.
        unsafe { libc::getppid() }
    }

    /// `mmap` of one anonymous executable page (no `MAP_JIT`).
    pub fn mmap_exec() -> Result<()> {
        // SAFETY: an anonymous mapping at no fixed address; unmapped at once.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                16384,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(last());
        }
        // SAFETY: p is the page just mapped.
        unsafe { libc::munmap(p, 16384) };
        Ok(())
    }

    /// `mmap` of the start of the file `fd` readable and executable.
    pub fn mmap_file_exec(fd: BorrowedFd<'_>) -> Result<()> {
        // SAFETY: a shared mapping of a descriptor the caller holds, at no
        // fixed address; unmapped at once.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                16384,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(last());
        }
        // SAFETY: p is the mapping just made.
        unsafe { libc::munmap(p, 16384) };
        Ok(())
    }

    /// `mmap` with `MAP_JIT` (dynamic code generation).
    pub fn mmap_jit() -> Result<()> {
        // SAFETY: as above.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                16384,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(last());
        }
        // SAFETY: as above.
        unsafe { libc::munmap(p, 16384) };
        Ok(())
    }

    /// `sysctlbyname("kern.hostname")`: a sysctl read.
    /// Asks for the host's privileged port (<mach/host_special_ports.h>'s
    /// `host_get_host_priv_port`: `host_get_special_port` of
    /// `HOST_PRIV_PORT` on `HOST_LOCAL_NODE`, a MIG routine sent by
    /// `mach_msg2_trap`): `Ok` only when the port came back.
    pub fn host_priv_port() -> Result<()> {
        const HOST_LOCAL_NODE: c_int = -1;
        const HOST_PRIV_PORT: c_int = 1;
        unsafe extern "C" {
            fn mach_host_self() -> u32;
            fn host_get_special_port(host: u32, node: c_int, which: c_int, port: *mut u32) -> c_int;
        }
        let mut port = 0u32;
        // SAFETY: the calling task's host name port, and an out-port.
        let kr = unsafe { host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, HOST_PRIV_PORT, &mut port) };
        if kr == 0 && port != 0 { Ok(()) } else { Err(HostErrno(libc::EPERM)) }
    }

    /// `task_info(MACH_TASK_BASIC_INFO)` of this task: a kernel MIG
    /// routine (3409) sent by `mach_msg2_trap` to the task's own port
    /// (`mach_task_self_`, a variable: no trap to get it). `Ok` when the
    /// kernel answered.
    pub fn task_info() -> Result<()> {
        const MACH_TASK_BASIC_INFO: c_int = 20;
        unsafe extern "C" {
            static mach_task_self_: u32;
            fn task_info(task: u32, flavor: c_int, info: *mut c_int, count: *mut u32) -> c_int;
        }
        let mut info = [0 as c_int; 32];
        let mut count = 12u32;
        // SAFETY: this task's port, a buffer of 32 words and its count.
        let kr = unsafe { task_info(mach_task_self_, MACH_TASK_BASIC_INFO, info.as_mut_ptr(), &mut count) };
        if kr == 0 { Ok(()) } else { Err(HostErrno(kr)) }
    }

    /// `bootstrap_look_up` of `service` from launchd: a message to the
    /// bootstrap port (a variable) by `mach_msg2_trap`, which Seatbelt
    /// checks as `mach-lookup`. `Ok` when a port came back.
    pub fn bootstrap_look_up(service: &str) -> Result<()> {
        unsafe extern "C" {
            static bootstrap_port: u32;
            fn bootstrap_look_up(bp: u32, name: *const c_char, sp: *mut u32) -> c_int;
        }
        let name = CString::new(service).map_err(|_| HostErrno(libc::EINVAL))?;
        let mut port = 0u32;
        // SAFETY: the bootstrap port, a NUL-terminated name and an out-port.
        let kr = unsafe { bootstrap_look_up(bootstrap_port, name.as_ptr(), &mut port) };
        if kr == 0 && port != 0 { Ok(()) } else { Err(HostErrno(kr)) }
    }

    /// Every Seatbelt operation this macOS's libsandbox knows whose name
    /// starts with `prefix`: each string of the loaded libsandbox's
    /// `__TEXT,__cstring` section (its operation table's names are there)
    /// that compiles as `(allow NAME)`, which a filter's or another string
    /// does not. Aliases kept elsewhere in the library (`file-write-mount`
    /// for `file-mount`, measured on macOS 27.2) name an operation listed
    /// here.
    pub fn operations(prefix: &str) -> std::result::Result<Vec<String>, String> {
        unsafe extern "C" {
            fn getsectiondata(header: *const c_void, segment: *const c_char, section: *const c_char, size: *mut libc::c_ulong) -> *const u8;
        }
        // SAFETY: plain data, filled by dladdr.
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        // SAFETY: an address in libsandbox, and the info to fill.
        if unsafe { libc::dladdr((sandbox_compile_string as *const ()).cast::<c_void>(), &mut info) } == 0 || info.dli_fbase.is_null() {
            return Err("dladdr found no image for sandbox_compile_string".into());
        }
        let mut size: libc::c_ulong = 0;
        // SAFETY: the image's header as dyld loaded it, and NUL-terminated names.
        let data = unsafe { getsectiondata(info.dli_fbase, c"__TEXT".as_ptr(), c"__cstring".as_ptr(), &mut size) };
        if data.is_null() || size == 0 {
            return Err("libsandbox has no __TEXT,__cstring section".into());
        }
        // SAFETY: the section dyld mapped, of the size it gave, read-only for the process's life.
        let bytes = unsafe { std::slice::from_raw_parts(data, usize::try_from(size).unwrap_or(0)) };
        let mut found: Vec<String> = bytes
            .split(|&b| b == 0)
            .filter_map(|s| std::str::from_utf8(s).ok())
            .filter(|n| n.starts_with(prefix) && n.bytes().all(|b| b.is_ascii_lowercase() || b == b'-' || b == b'*'))
            .filter(|n| compile(&format!("(version 1)\n(allow {n})\n")).is_ok())
            .map(String::from)
            .collect();
        found.sort();
        found.dedup();
        Ok(found)
    }

    /// The metadata of `path`, not following a last link: `fstatat` from
    /// the working directory, the call the server makes beneath its held
    /// directories.
    pub fn fstatat_path(path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| HostErrno(libc::EINVAL))?;
        // SAFETY: plain data, filled by fstatat.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated path and a stat to fill.
        check(unsafe { libc::fstatat(libc::AT_FDCWD, path.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) }).map(drop)
    }

    /// The calls by which the share's operations that are refused with an
    /// error there (`confine::macos::ERROR_IN_SHARE`) are made, on a file or
    /// directory of the share: `Ok` only when the call did what it asks.
    pub fn in_share(form: InShare, root: BorrowedFd<'_>, file: BorrowedFd<'_>, file_path: &Path) -> Result<()> {
        unsafe extern "C" {
            fn revoke(path: *const c_char) -> c_int;
            fn fs_snapshot_create(dirfd: c_int, name: *const c_char, flags: u32) -> c_int;
        }
        let (r, f) = (root.as_raw_fd(), file.as_raw_fd());
        let path = CString::new(file_path.as_os_str().as_encoded_bytes()).map_err(|_| HostErrno(libc::EINVAL))?;
        let dir = CString::new(file_path.parent().unwrap_or(file_path).as_os_str().as_encoded_bytes())
            .map_err(|_| HostErrno(libc::EINVAL))?;
        // SAFETY: each call takes descriptors the caller holds and
        // NUL-terminated names; none keeps a pointer.
        let ret = unsafe {
            match form {
                InShare::Flags => libc::fchflags(f, libc::UF_NODUMP),
                // No change of either id (-1): the operation alone.
                InShare::Owner => libc::fchown(f, u32::MAX, u32::MAX),
                InShare::SetUgid => {
                    let r = libc::fchmod(f, 0o4644);
                    let mut st: libc::stat = std::mem::zeroed();
                    if r == 0 && libc::fstat(f, &mut st) == 0 && st.st_mode & libc::S_ISUID == 0 {
                        // Not kept: refused without an error.
                        return Err(HostErrno(0));
                    }
                    r
                }
                InShare::Clone => libc::clonefileat(r, c"inside".as_ptr(), r, c"clone".as_ptr(), 0),
                InShare::Ioctl => {
                    // DKIOCGETBLOCKSIZE, _IOR('d', 24, uint32_t): one the file
                    // system's own ioctl handles (FIONREAD is the descriptor
                    // layer's, which file-ioctl does not see; measured).
                    let mut n: u32 = 0;
                    libc::ioctl(f, 0x4004_6418, &mut n)
                }
                InShare::Snapshot => fs_snapshot_create(r, c"wick-probe".as_ptr(), 0),
                InShare::Chroot => libc::chroot(dir.as_ptr()),
                InShare::Revoke => revoke(path.as_ptr()),
                InShare::Lock => libc::flock(f, libc::LOCK_SH | libc::LOCK_NB),
                InShare::Fifo => libc::mkfifoat(r, c"fifo".as_ptr(), 0o644),
                InShare::FcntlLock => {
                    // fcntl is a listed call: this reaches file-lock's rule.
                    let mut l: libc::flock = std::mem::zeroed();
                    l.l_type = libc::F_RDLCK;
                    // SEEK_SET, 0: the lock from the file's start.
                    l.l_whence = 0;
                    libc::fcntl(f, libc::F_SETLK, &l)
                }
                InShare::FinderInfo => {
                    // fsetattrlist is a listed call (SETATTR of the times):
                    // this reaches the share's file-write-finderinfo rule.
                    let mut list = libc::attrlist {
                        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
                        reserved: 0,
                        commonattr: libc::ATTR_CMN_FNDRINFO,
                        volattr: 0,
                        dirattr: 0,
                        fileattr: 0,
                        forkattr: 0,
                    };
                    let mut info = [0u8; 32];
                    info[..4].copy_from_slice(b"TEXT");
                    libc::fsetattrlist(f, (&raw mut list).cast(), info.as_mut_ptr().cast(), info.len(), 0)
                }
            }
        };
        check(ret).map(drop)
    }

    /// A form of [`in_share`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum InShare {
        /// `fchflags` (`file-write-flags`).
        Flags,
        /// `fchown` changing neither id (`file-write-owner`).
        Owner,
        /// `fchmod` with the set-user-id bit (`file-write-setugid`); an
        /// error of 0 when the call returned but the bit was not kept.
        SetUgid,
        /// `clonefileat` (`file-clone`).
        Clone,
        /// `ioctl(DKIOCGETBLOCKSIZE)` (`file-ioctl`).
        Ioctl,
        /// `fs_snapshot_create` (`fs-snapshot-create`).
        Snapshot,
        /// `chroot` to the share's root (`file-chroot`).
        Chroot,
        /// `revoke` (`file-revoke`).
        Revoke,
        /// `flock` (`file-lock`).
        Lock,
        /// `mkfifoat` (`file-mknod`).
        Fifo,
        /// `fcntl(F_SETLK)` of a read lock (`file-lock`, by a listed call).
        FcntlLock,
        /// `fsetattrlist` of the Finder information
        /// (`file-write-finderinfo`).
        FinderInfo,
    }

    pub fn sysctl_hostname() -> Result<()> {
        let mut buf = [0u8; 256];
        let mut len = buf.len();
        // SAFETY: a NUL-terminated name and a buffer of the length passed.
        check(unsafe {
            libc::sysctlbyname(
                c"kern.hostname".as_ptr(),
                buf.as_mut_ptr().cast::<c_void>(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        })
        .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quoted_refuses_what_a_profile_cannot_name() {
        assert_eq!(quoted(Path::new("/a/b")).as_deref(), Some("/a/b"));
        assert_eq!(quoted(Path::new("/a\"b\\c")).as_deref(), Some("/a\\\"b\\\\c"));
        assert_eq!(quoted(Path::new("a/b")), None);
        assert_eq!(quoted(Path::new("/a\nb")), None);
    }

    #[test]
    fn test_a_profile_compiles_and_a_bad_one_names_its_error() {
        assert!(!compile("(version 1)\n(allow default)\n").unwrap().is_empty());
        let e = compile("(version 1)\n(allow no-such-operation)\n").unwrap_err();
        assert!(e.contains("no-such-operation"), "{e}");
        assert!(!sandboxed(), "the test process runs under no profile");
    }
}
