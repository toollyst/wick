// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Host folder sharing under the jailer (docs/design-fs.md §8): one
//! wick-fsd per `--fs-share`, started by the jailer as root before it jails
//! Firecracker. Not part of upstream Firecracker.
//!
//! - `--fs-server PATH` (once, absolute) names wick-fsd's binary;
//!   `--fs-share id=ID,dir=DIR,uid=U,gid=G[,ro]` (repeatable) one share.
//!   Everything is checked before anything is started: the id is wick-fsd's
//!   (1 to 64 of `[a-z0-9_-]`, `wick_fs_frame`'s rule) and its socket's path,
//!   `<jail root>/fs-<id>.sock`, fits a Unix socket's; ids and directories
//!   are not given twice; `U` and `G` are not 0 and not the jail's (the
//!   server's own ids, so that the kernel's checks by id separate it from the
//!   VMM as well as the two sandboxes do); and neither `--daemonize` nor
//!   `--new-pid-ns` is given, since each leaves the process that would be
//!   wick-fsd's parent behind (a limit of this version; the next item lifts
//!   it, ROADMAP M7).
//! - Each server is started just before the chroot, after the cgroup is
//!   set (it shares the jail's), from the process that execs Firecracker,
//!   which so becomes its parent: as root, with `--uid U --gid G --peer-uid
//!   <jail uid> --ready-fd 3 --parent-pid <this pid>`, so it ends with
//!   Firecracker, before its connection too; standard input `/dev/null`, its output the
//!   jailer's, and the `RLIMIT_NOFILE` and `RLIMIT_FSIZE` the jailer was
//!   started with ([`HostLimits`]), not the jail's: `--resource-limit` is
//!   Firecracker's (its `no-file`, 2048 by default, is below the 2112
//!   descriptors a share holds by default, which wick-fsd sets for itself and
//!   checks, and its `fsize` would end the server with SIGXFSZ on a guest's
//!   write past it). It binds its socket 0600 and its
//!   own (`listen_private` in wick-fs-sys), checks the socket's directory,
//!   says ready, and accepts one connection whose peer is the jail's uid.
//! - The jailer waits for the ready byte ([`READY_TIMEOUT`]), checks the
//!   socket (a socket, mode 0600, root's) and gives it to the jail's
//!   `uid:gid` without following a link, so that the jailed Firecracker,
//!   and only a process of its uid, can connect.
//! - Any failure of the jailer's after a server started kills every server
//!   it started, and waits for each ([`Started`]'s drop): none is left
//!   behind. Once Firecracker runs, a server ends when its connection does.

use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::JailerError;

/// How long the jailer waits for a server's ready byte.
pub const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// One `--fs-share`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// The share's id (the socket's name and the VMM's `extensions.fs`).
    pub id: String,
    /// The host directory, as given (wick-fsd's stage 0 resolves and checks
    /// it).
    pub dir: PathBuf,
    /// The server's ids.
    pub uid: u32,
    pub gid: u32,
    pub read_only: bool,
}

/// `--fs-server` and the `--fs-share`s, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsShares {
    pub server: PathBuf,
    pub shares: Vec<Share>,
}

fn refused(what: String) -> JailerError {
    JailerError::FsShare(what)
}

/// An id as wick-fsd and the VMM take it (`wick_fs_frame`'s rule): 1 to 64
/// characters of `[a-z0-9_-]`, no capitals (it names a file in the jail, on
/// file systems that ignore case too).
fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// The share's socket: `<jail root>/fs-<id>.sock`, the path the VMM takes
/// when its `socket` is not given (`/fs-<id>.sock` in the jail).
pub fn socket_path(chroot_dir: &Path, id: &str) -> PathBuf {
    chroot_dir.join(format!("fs-{id}.sock"))
}

/// The bytes a Unix socket's path may take, its terminating NUL apart.
fn max_socket_path() -> usize {
    // SAFETY: plain data.
    let addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_path.len() - 1
}

fn parse_share(spec: &str) -> Result<Share, JailerError> {
    let (mut id, mut dir, mut uid, mut gid, mut read_only) = (None, None, None, None, false);
    for part in spec.split(',') {
        let (key, value) = part.split_once('=').map_or((part, None), |(k, v)| (k, Some(v)));
        let twice = || refused(format!("--fs-share {spec}: `{key}` given twice"));
        let number = |v: Option<&str>| -> Result<u32, JailerError> {
            v.and_then(|v| v.parse().ok())
                .ok_or_else(|| refused(format!("--fs-share {spec}: `{key}` takes a number")))
        };
        match (key, value) {
            ("id", Some(v)) => {
                if id.replace(v.to_string()).is_some() {
                    return Err(twice());
                }
            }
            ("dir", Some(v)) => {
                if dir.replace(PathBuf::from(v)).is_some() {
                    return Err(twice());
                }
            }
            ("uid", v) => {
                if uid.replace(number(v)?).is_some() {
                    return Err(twice());
                }
            }
            ("gid", v) => {
                if gid.replace(number(v)?).is_some() {
                    return Err(twice());
                }
            }
            ("ro", None) => {
                if read_only {
                    return Err(twice());
                }
                read_only = true;
            }
            _ => {
                return Err(refused(format!(
                    "--fs-share {spec}: `{part}` is not one of id=ID, dir=DIR, uid=U, gid=G, ro"
                )));
            }
        }
    }
    let missing = |what: &str| refused(format!("--fs-share {spec}: `{what}` is required"));
    Ok(Share {
        id: id.ok_or_else(|| missing("id"))?,
        dir: dir.ok_or_else(|| missing("dir"))?,
        uid: uid.ok_or_else(|| missing("uid"))?,
        gid: gid.ok_or_else(|| missing("gid"))?,
        read_only,
    })
}

/// The jail's settings the shares are checked against.
#[derive(Clone, Copy, Debug)]
pub struct Jail<'a> {
    pub chroot_dir: &'a Path,
    pub uid: u32,
    pub gid: u32,
    pub daemonize: bool,
    pub new_pid_ns: bool,
}

/// `--fs-server` and `--fs-share`, checked: `None` when neither is given.
pub fn parse(server: Option<&str>, specs: &[String], jail: Jail<'_>) -> Result<Option<FsShares>, JailerError> {
    let server = match (server, specs.is_empty()) {
        (None, true) => return Ok(None),
        (None, false) => return Err(refused("--fs-share needs --fs-server, the path of wick-fsd".into())),
        (Some(s), true) => return Err(refused(format!("--fs-server {s} without any --fs-share"))),
        (Some(s), false) => PathBuf::from(s),
    };
    if !server.is_absolute() {
        return Err(refused(format!("--fs-server {}: an absolute path is required", server.display())));
    }
    if jail.daemonize || jail.new_pid_ns {
        return Err(refused(format!(
            "--fs-share with {}: not in this version (each leaves the process that would be wick-fsd's parent \
             behind; docs/design-fs.md §8, ROADMAP M7)",
            if jail.daemonize { "--daemonize" } else { "--new-pid-ns" }
        )));
    }
    let mut shares: Vec<Share> = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();
    for spec in specs {
        let share = parse_share(spec)?;
        if !valid_id(&share.id) {
            return Err(refused(format!("--fs-share {spec}: the id must be 1 to 64 characters of [a-z0-9_-]")));
        }
        let socket = socket_path(jail.chroot_dir, &share.id);
        if socket.as_os_str().len() > max_socket_path() {
            return Err(refused(format!(
                "--fs-share {spec}: the socket {} is longer than a Unix socket's path ({} bytes); use a shorter id \
                 or --chroot-base-dir",
                socket.display(),
                max_socket_path()
            )));
        }
        if !share.dir.is_absolute() {
            return Err(refused(format!("--fs-share {spec}: dir must be an absolute path")));
        }
        if share.uid == 0 || share.gid == 0 {
            return Err(refused(format!("--fs-share {spec}: uid and gid must not be 0 (the server drops to them)")));
        }
        if share.uid == jail.uid || share.gid == jail.gid {
            return Err(refused(format!(
                "--fs-share {spec}: uid and gid must not be the jail's ({}:{}): the server runs as ids of its own",
                jail.uid, jail.gid
            )));
        }
        if shares.iter().any(|s| s.id == share.id) {
            return Err(refused(format!("--fs-share {spec}: the id {} is given twice", share.id)));
        }
        let canonical = std::fs::canonicalize(&share.dir)
            .map_err(|e| refused(format!("--fs-share {spec}: {}: {e}", share.dir.display())))?;
        if dirs.contains(&canonical) {
            return Err(refused(format!("--fs-share {spec}: {} is shared twice", canonical.display())));
        }
        dirs.push(canonical);
        shares.push(share);
    }
    Ok(Some(FsShares { server, shares }))
}

/// The resource limits the jailer was started with, read before it sets the
/// jail's (`ResourceLimits::install`), and set back in each server's process
/// before its exec: (soft, hard) of `RLIMIT_NOFILE` and `RLIMIT_FSIZE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostLimits {
    pub nofile: (libc::rlim_t, libc::rlim_t),
    pub fsize: (libc::rlim_t, libc::rlim_t),
}

impl HostLimits {
    /// This process's.
    pub fn read() -> Result<HostLimits, JailerError> {
        let get = |resource, name: &str| {
            let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            // SAFETY: a known resource and an rlimit to fill.
            if unsafe { libc::getrlimit(resource, &mut r) } != 0 {
                return Err(refused(format!("getrlimit({name}): {}", std::io::Error::last_os_error())));
            }
            Ok((r.rlim_cur, r.rlim_max))
        };
        Ok(HostLimits {
            nofile: get(libc::RLIMIT_NOFILE, "RLIMIT_NOFILE")?,
            fsize: get(libc::RLIMIT_FSIZE, "RLIMIT_FSIZE")?,
        })
    }
}

/// What a server's process says on the ready pipe instead of being ready
/// when a step of the jailer's between the fork and the exec fails.
const CHILD_STDIN: u8 = b'0';
const CHILD_FD3: u8 = b'3';
const CHILD_LIMITS: u8 = b'L';
const CHILD_EXEC: u8 = b'X';

fn child_failure(b: u8) -> Option<&'static str> {
    match b {
        CHILD_STDIN => Some("making /dev/null its standard input failed"),
        CHILD_FD3 => Some("putting the ready pipe at descriptor 3 failed"),
        CHILD_LIMITS => Some("setting back the jailer's RLIMIT_NOFILE and RLIMIT_FSIZE failed"),
        CHILD_EXEC => Some("the exec of --fs-server failed"),
        _ => None,
    }
}

/// Servers started and not yet handed to Firecracker: each is killed and
/// waited for when this is dropped. The caller holds it to the exec: an exec
/// that works runs no destructor and leaves the servers to Firecracker, their
/// parent from then on; any failure before it, the exec's own included,
/// returns and drops it.
#[derive(Debug, Default)]
pub struct Started {
    pids: Vec<libc::pid_t>,
}

impl Started {
    /// The servers' pids, in start order.
    #[cfg(test)]
    pub fn pids(&self) -> &[libc::pid_t] {
        &self.pids
    }
}

impl Drop for Started {
    fn drop(&mut self) {
        for &pid in &self.pids {
            // SAFETY: a child this process started and has not waited for.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                let mut status = 0;
                while libc::waitpid(pid, &mut status, 0) < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {}
            }
        }
    }
}

/// A pipe, both ends close-on-exec: (read, write).
fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: two descriptors to fill.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the descriptors just made, this function's.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&r, &w] {
        // SAFETY: a descriptor this function owns.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok((r, w))
}

/// Waits up to `timeout` for one byte on `fd`: `Ok(Some(b))`, `Ok(None)` at
/// its end (the writer closed it, the server ended), `Err` on timeout.
fn read_ready(fd: &OwnedFd, timeout: Duration) -> Result<Option<u8>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!("no ready byte in {} s", timeout.as_secs()));
        }
        let mut p = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ms = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX).max(1);
        // SAFETY: one pollfd.
        let n = unsafe { libc::poll(&mut p, 1, ms) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("poll: {e}"));
        }
        if n == 0 {
            continue;
        }
        let mut byte = [0u8; 1];
        // SAFETY: a descriptor the caller holds; this borrows it for one read.
        let mut file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) });
        return match file.read(&mut byte) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(byte[0])),
            Err(e) => Err(format!("reading the ready byte: {e}")),
        };
    }
}

/// The socket wick-fsd made, checked and given to the jail: a socket, mode
/// 0600, this process's (root's), then `uid:gid`, never following a link.
fn give_socket(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let m = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: geteuid cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !m.file_type().is_socket() || m.mode() & 0o7777 != 0o600 || m.uid() != euid {
        return Err(format!(
            "{}: {}mode {:o}, owner {}, where wick-fsd makes a socket of mode 600 owned by uid {euid}",
            path.display(),
            if m.file_type().is_socket() { "" } else { "not a socket, " },
            m.mode() & 0o7777,
            m.uid()
        ));
    }
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| format!("{}: a NUL in the path", path.display()))?;
    // SAFETY: a NUL-terminated path; AT_SYMLINK_NOFOLLOW changes a link
    // itself, never what it names (and the lstat above found a socket).
    if unsafe { libc::fchownat(libc::AT_FDCWD, c.as_ptr(), uid, gid, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(format!("{}: chown to {uid}:{gid}: {}", path.display(), std::io::Error::last_os_error()));
    }
    Ok(())
}

impl FsShares {
    /// The arguments wick-fsd is started with for `share`.
    pub fn server_args(&self, share: &Share, jail: Jail<'_>) -> Vec<std::ffi::OsString> {
        let mut a: Vec<std::ffi::OsString> = vec![
            "--share-dir".into(),
            share.dir.clone().into(),
            "--socket".into(),
            socket_path(jail.chroot_dir, &share.id).into(),
            "--id".into(),
            share.id.clone().into(),
            "--peer-uid".into(),
            jail.uid.to_string().into(),
            "--uid".into(),
            share.uid.to_string().into(),
            "--gid".into(),
            share.gid.to_string().into(),
            "--ready-fd".into(),
            "3".into(),
            // The process that forks the server and then execs Firecracker
            // (the same pid): the server watches it and ends with it, also
            // before the VMM connected (wick-fsd's parent watch).
            "--parent-pid".into(),
            std::process::id().to_string().into(),
        ];
        if share.read_only {
            a.push("--read-only".into());
        }
        a
    }

    /// Starts one server per share into `started`, each ready and its socket
    /// given to the jail before the next. On a failure the error names the
    /// share; `started`, dropped, kills and waits for every server in it.
    pub fn start(
        &self,
        jail: Jail<'_>,
        limits: HostLimits,
        timeout: Duration,
        started: &mut Started,
    ) -> Result<(), JailerError> {
        for share in &self.shares {
            let fail = |what: String| refused(format!("--fs-share id={}: {what}", share.id));
            let (read, write) = pipe().map_err(|e| fail(format!("a pipe: {e}")))?;
            let pid = spawn(&self.server, &self.server_args(share, jail), &write, limits).map_err(&fail)?;
            started.pids.push(pid);
            // Only the server holds the write end now: its end means it ended.
            drop(write);
            match read_ready(&read, timeout) {
                Ok(Some(b'R')) => {}
                Ok(Some(b)) => match child_failure(b) {
                    Some(what) => return Err(fail(format!("in wick-fsd's process, before its exec: {what}"))),
                    None => return Err(fail(format!("wick-fsd said {b:#x}, not ready"))),
                },
                Ok(None) => return Err(fail("wick-fsd ended before it was ready (its error is above)".into())),
                Err(e) => return Err(fail(format!("{e}: wick-fsd killed"))),
            }
            give_socket(&socket_path(jail.chroot_dir, &share.id), jail.uid, jail.gid).map_err(fail)?;
        }
        Ok(())
    }
}

/// `fork` and `execv` of `server` with `args`: standard input `/dev/null`,
/// `ready` as descriptor 3, `limits` set, the rest as this process's (the
/// jailer closed everything above 2 when it started). The jailer has one
/// thread here, as its own forks need (upstream's daemonize,
/// `platform::fork_alone`). A step that fails writes its byte
/// ([`child_failure`]) on `ready` and ends the child with 127.
fn spawn(
    server: &Path,
    args: &[std::ffi::OsString],
    ready: &OwnedFd,
    limits: HostLimits,
) -> Result<libc::pid_t, String> {
    let path = CString::new(server.as_os_str().as_bytes()).map_err(|_| "a NUL in --fs-server".to_string())?;
    let mut argv: Vec<CString> = vec![path.clone()];
    for a in args {
        argv.push(CString::new(a.as_bytes()).map_err(|_| format!("a NUL in {a:?}"))?);
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let null = c"/dev/null";
    let ready = ready.as_raw_fd();
    let nofile = libc::rlimit { rlim_cur: limits.nofile.0, rlim_max: limits.nofile.1 };
    let fsize = libc::rlimit { rlim_cur: limits.fsize.0, rlim_max: limits.fsize.1 };
    // SAFETY: one thread (above); the child makes only async-signal-safe
    // calls (open, dup2, fcntl, setrlimit, write, execv, _exit) on data made
    // before the fork.
    match unsafe { libc::fork() } {
        -1 => Err(format!("fork: {}", std::io::Error::last_os_error())),
        // SAFETY: the child, as above: system calls on descriptors and data
        // made before the fork, then the exec or _exit.
        0 => unsafe {
            let fail = |fd: libc::c_int, b: u8| -> ! {
                libc::write(fd, (&raw const b).cast(), 1);
                libc::_exit(127)
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &nofile) != 0 || libc::setrlimit(libc::RLIMIT_FSIZE, &fsize) != 0 {
                fail(ready, CHILD_LIMITS);
            }
            let n = libc::open(null.as_ptr(), libc::O_RDONLY);
            if n < 0 || libc::dup2(n, 0) != 0 {
                fail(ready, CHILD_STDIN);
            }
            // Not left open beside 0 (3 is replaced below, or is `ready`,
            // which the pipe holds open).
            if n > 3 && n != ready {
                libc::close(n);
            }
            if ready == 3 {
                // dup2 onto itself keeps close-on-exec: clear it.
                if libc::fcntl(3, libc::F_SETFD, 0) != 0 {
                    fail(3, CHILD_FD3);
                }
            } else if libc::dup2(ready, 3) != 3 {
                fail(ready, CHILD_FD3);
            }
            libc::execv(path.as_ptr(), argv_ptrs.as_ptr());
            fail(3, CHILD_EXEC)
        },
        pid => Ok(pid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jail(dir: &Path) -> Jail<'_> {
        Jail { chroot_dir: dir, uid: 123, gid: 100, daemonize: false, new_pid_ns: false }
    }

    fn err(r: Result<Option<FsShares>, JailerError>) -> String {
        r.unwrap_err().to_string()
    }

    #[test]
    fn test_fs_share_parse() {
        let tmp = std::env::temp_dir();
        let d = tmp.to_str().unwrap();
        let root = Path::new("/srv/jailer/firecracker/a/root");
        let spec = format!("id=data,dir={d},uid=500,gid=500,ro");
        let got = parse(Some("/usr/local/bin/wick-fsd"), &[spec], jail(root)).unwrap().unwrap();
        assert_eq!(got.server, Path::new("/usr/local/bin/wick-fsd"));
        assert_eq!(
            got.shares,
            vec![Share { id: "data".into(), dir: tmp.clone(), uid: 500, gid: 500, read_only: true }]
        );
        let args: Vec<String> =
            got.server_args(&got.shares[0], jail(root)).iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(
            args.join(" "),
            format!(
                "--share-dir {d} --socket /srv/jailer/firecracker/a/root/fs-data.sock --id data --peer-uid 123 \
                 --uid 500 --gid 500 --ready-fd 3 --parent-pid {} --read-only",
                std::process::id()
            )
        );
        // Neither flag: nothing to start.
        assert_eq!(parse(None, &[], jail(root)).unwrap(), None);
    }

    #[test]
    fn test_fs_share_refusals_name_what() {
        let d = std::env::temp_dir().to_str().unwrap().to_string();
        let root = Path::new("/srv/jailer/firecracker/a/root");
        let server = Some("/usr/local/bin/wick-fsd");
        let one = |s: &str| vec![s.to_string()];
        let ok = format!("id=data,dir={d},uid=500,gid=500");
        let cases: Vec<(Option<&str>, Vec<String>, Jail<'_>, &str)> = vec![
            (None, one(&ok), jail(root), "needs --fs-server"),
            (server, vec![], jail(root), "without any --fs-share"),
            (Some("wick-fsd"), one(&ok), jail(root), "absolute path is required"),
            (server, one(&ok), Jail { daemonize: true, ..jail(root) }, "--daemonize"),
            (server, one(&ok), Jail { new_pid_ns: true, ..jail(root) }, "--new-pid-ns"),
            (server, one(&format!("id=Data,dir={d},uid=500,gid=500")), jail(root), "[a-z0-9_-]"),
            (server, one(&format!("id=,dir={d},uid=500,gid=500")), jail(root), "[a-z0-9_-]"),
            (server, one(&format!("id={},dir={d},uid=500,gid=500", "a".repeat(65))), jail(root), "[a-z0-9_-]"),
            (server, one(&format!("dir={d},uid=500,gid=500")), jail(root), "`id` is required"),
            (server, one("id=data,uid=500,gid=500"), jail(root), "`dir` is required"),
            (server, one(&format!("id=data,dir={d},gid=500")), jail(root), "`uid` is required"),
            (server, one(&format!("id=data,dir={d},uid=500")), jail(root), "`gid` is required"),
            (server, one(&format!("id=data,id=b,dir={d},uid=500,gid=500")), jail(root), "given twice"),
            (server, one(&format!("{ok},ro,ro")), jail(root), "given twice"),
            (server, one(&format!("{ok},cache=never")), jail(root), "is not one of"),
            (server, one(&format!("id=data,dir={d},uid=x,gid=500")), jail(root), "takes a number"),
            (server, one("id=data,dir=relative,uid=500,gid=500"), jail(root), "absolute path"),
            (server, one(&format!("id=data,dir={d},uid=0,gid=500")), jail(root), "must not be 0"),
            (server, one(&format!("id=data,dir={d},uid=500,gid=0")), jail(root), "must not be 0"),
            (server, one(&format!("id=data,dir={d},uid=123,gid=500")), jail(root), "must not be the jail's"),
            (server, one(&format!("id=data,dir={d},uid=500,gid=100")), jail(root), "must not be the jail's"),
            (server, vec![ok.clone(), ok.clone()], jail(root), "the id data is given twice"),
            (server, vec![ok.clone(), format!("id=other,dir={d}/.,uid=500,gid=500")], jail(root), "shared twice"),
            (server, one("id=data,dir=/no/such/dir,uid=500,gid=500"), jail(root), "/no/such/dir"),
        ];
        for (server, specs, jail, want) in cases {
            let e = err(parse(server, &specs, jail));
            assert!(e.contains(want), "{specs:?}: {e}");
        }
        // An id that does not fit the socket's path.
        let deep = PathBuf::from(format!("/{}", "j".repeat(90)));
        let e = err(parse(server, &one(&format!("id={},dir={d},uid=500,gid=500", "a".repeat(20))), jail(&deep)));
        assert!(e.contains("longer than a Unix socket's path"), "{e}");
    }

    /// A server that is never ready is killed at the timeout, one that ends
    /// first is named, one ready without its socket is killed at the
    /// socket's check; each time every server started is gone after (its
    /// pid no longer exists once `Started` is dropped).
    #[test]
    fn test_fs_share_start_kills_what_it_started() {
        let tmp = std::env::temp_dir().join(format!("wick-jailer-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir(&tmp).unwrap();
        let script = |name: &str, body: &str| {
            use std::os::unix::fs::PermissionsExt;
            let p = tmp.join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let never = script("never", "exec sleep 30");
        let ends = script("ends", "exit 3");
        let no_socket = script("no-socket", "printf R >&3; exec sleep 30");
        for (server, timeout, want) in [
            (never, Duration::from_millis(300), "no ready byte in"),
            (ends, Duration::from_secs(10), "ended before it was ready"),
            (no_socket, Duration::from_secs(10), "fs-a.sock"),
        ] {
            let shares = FsShares {
                server: server.clone(),
                shares: vec![Share { id: "a".into(), dir: tmp.clone(), uid: 500, gid: 500, read_only: false }],
            };
            let mut started = Started::default();
            let e = shares.start(jail(&tmp), HostLimits::read().unwrap(), timeout, &mut started).unwrap_err().to_string();
            assert!(e.contains(want) && e.contains("id=a"), "{}: {e}", server.display());
            let pids = started.pids().to_vec();
            assert_eq!(pids.len(), 1);
            drop(started);
            for pid in pids {
                // SAFETY: a signal check only.
                let gone = unsafe { libc::kill(pid, 0) } != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
                assert!(gone, "{}: pid {pid} left", server.display());
            }
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The server's process gets the limits it is given (the jailer's own,
    /// read before it sets the jail's), not the ones in force when it is
    /// started: here a soft no-file of 200 and a file size of 1 MiB, lower
    /// than the test's, which a script records.
    #[test]
    fn test_fs_share_server_gets_the_jailer_s_limits() {
        let tmp = std::env::temp_dir().join(format!("wick-jailer-fs-limits-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir(&tmp).unwrap();
        let record = tmp.join("record");
        let server = tmp.join("server");
        std::fs::write(
            &server,
            format!(
                "#!/bin/sh\n{{ ulimit -Sn; ulimit -Hn; ulimit -Sf; }} > {}\nprintf R >&3\nexec sleep 30\n",
                record.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&server, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mine = HostLimits::read().unwrap();
        let given = HostLimits { nofile: (200, mine.nofile.1), fsize: (1 << 20, mine.fsize.1) };
        assert!(mine.nofile.0 > 200 && mine.fsize.0 > 1 << 20, "{mine:?}");
        let shares = FsShares {
            server,
            shares: vec![Share { id: "a".into(), dir: tmp.clone(), uid: 500, gid: 500, read_only: false }],
        };
        let mut started = Started::default();
        // Ready, then refused at the socket's check (the script makes none).
        let e = shares.start(jail(&tmp), given, Duration::from_secs(10), &mut started).unwrap_err().to_string();
        assert!(e.contains("fs-a.sock"), "{e}");
        drop(started);
        let hard = if mine.nofile.1 == libc::RLIM_INFINITY { "unlimited".to_string() } else { mine.nofile.1.to_string() };
        // `ulimit -f` counts 512-byte blocks in dash (Linux's /bin/sh) and
        // 1024-byte ones in bash (macOS's /bin/sh, measured).
        let blocks = if cfg!(target_os = "macos") { 1024 } else { 2048 };
        assert_eq!(std::fs::read_to_string(&record).unwrap(), format!("200\n{hard}\n{blocks}\n"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A step between the fork and the exec that fails is named: the
    /// limits (a soft no-file above the hard one, which setrlimit refuses)
    /// and the exec (a server that does not exist).
    #[test]
    fn test_fs_share_a_failure_before_the_exec_is_named() {
        let tmp = std::env::temp_dir().join(format!("wick-jailer-fs-named-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir(&tmp).unwrap();
        let mine = HostLimits::read().unwrap();
        for (server, limits, want) in [
            (
                PathBuf::from("/bin/sh"),
                HostLimits { nofile: (100, 50), ..mine },
                "before its exec: setting back the jailer's RLIMIT_NOFILE and RLIMIT_FSIZE failed",
            ),
            (tmp.join("missing"), mine, "before its exec: the exec of --fs-server failed"),
        ] {
            let shares = FsShares {
                server,
                shares: vec![Share { id: "a".into(), dir: tmp.clone(), uid: 500, gid: 500, read_only: false }],
            };
            let mut started = Started::default();
            let e = shares.start(jail(&tmp), limits, Duration::from_secs(10), &mut started).unwrap_err().to_string();
            assert!(e.contains(want), "{e}");
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
