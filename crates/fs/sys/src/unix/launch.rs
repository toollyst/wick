// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Starting a program with descriptors set up beyond std's standard streams,
//! for the tests of what a process was started with (a descriptor at a
//! number, a closed standard stream, nothing but the standard streams).
//!
//! On macOS without a fork in this process: `posix_spawn` with file actions
//! and `POSIX_SPAWN_CLOEXEC_DEFAULT`, one system call. std's `Command` forks
//! in user space when it is given a `pre_exec` closure, and a fork made
//! while another thread of the process is inside a first-time `os_once` (a
//! test process's threads run other tests: libsandbox's first `os_log`
//! registers with libnotify) leaves the child a gate held by a thread it
//! does not have, and libSystem's fork child handler `_notify_fork_child`
//! aborts the child before it can exec ("os_once_t is corrupt", "crashed on
//! child side of fork pre-exec": CI run 44375259298, macOS 15.8.2; 1117 of
//! 1500 children in a C program on macOS 27.2, docs/design-fs.md §4.2).
//! On Linux std's `Command` with `pre_exec`, whose fork has no such handler.

use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Output};

use libc::c_int;

/// What the started program finds beyond its standard streams.
#[derive(Debug, Default)]
pub struct Descriptors {
    /// Each descriptor at that number (not close-on-exec), as a launcher
    /// that leaves descriptors open does.
    pub inherited: Vec<(OwnedFd, c_int)>,
    /// Each of these closed, as a launcher that runs it with `>&-` does
    /// (standard streams among them).
    pub closed: Vec<c_int>,
    /// Nothing but the standard streams and `inherited`, whatever this
    /// process holds without close-on-exec (macOS: always so, by
    /// `POSIX_SPAWN_CLOEXEC_DEFAULT`; Linux: every descriptor above 2 is
    /// marked close-on-exec in the child).
    pub only_stdio: bool,
}

/// A standard stream of the started program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Io {
    /// This process's own.
    Inherit,
    /// `/dev/null`.
    Null,
    /// A pipe to this process ([`Launched`]'s `stdout` or `stderr`).
    Piped,
}

/// A started program.
#[derive(Debug)]
pub struct Launched {
    pid: libc::pid_t,
    /// Its standard output, when [`Io::Piped`].
    pub stdout: Option<File>,
    /// Its standard error, when [`Io::Piped`].
    pub stderr: Option<File>,
    ended: Option<ExitStatus>,
    #[cfg(target_os = "linux")]
    child: std::process::Child,
}

impl Launched {
    /// Its pid.
    pub fn id(&self) -> u32 {
        u32::try_from(self.pid).unwrap_or(0)
    }

    /// How it ended, if it has.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.reap(libc::WNOHANG)
    }

    /// Waits for it to end.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.reap(0).map(|s| s.unwrap_or_else(|| ExitStatus::from_raw(0)))
    }

    /// SIGKILL, unless it has ended (and been waited for).
    pub fn kill(&mut self) -> std::io::Result<()> {
        if self.ended.is_some() {
            return Ok(());
        }
        // SAFETY: a signal to this process's own child, not yet reaped.
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Reads its piped output and error to their end (the error on a thread
    /// of its own, so that neither pipe fills while the other is read),
    /// then waits for it.
    pub fn wait_with_output(mut self) -> std::io::Result<Output> {
        let err = self.stderr.take().map(|mut f| {
            std::thread::spawn(move || {
                let mut v = Vec::new();
                f.read_to_end(&mut v).map(|_| v)
            })
        });
        let mut stdout = Vec::new();
        if let Some(mut f) = self.stdout.take() {
            f.read_to_end(&mut stdout)?;
        }
        let stderr = match err {
            Some(t) => t.join().map_err(|_| std::io::Error::other("the reader of standard error panicked"))??,
            None => Vec::new(),
        };
        let status = self.wait()?;
        Ok(Output { status, stdout, stderr })
    }

    fn reap(&mut self, flags: c_int) -> std::io::Result<Option<ExitStatus>> {
        if let Some(s) = self.ended {
            return Ok(Some(s));
        }
        #[cfg(target_os = "linux")]
        {
            let s = if flags == 0 { Some(self.child.wait()?) } else { self.child.try_wait()? };
            self.ended = s;
            Ok(s)
        }
        #[cfg(target_os = "macos")]
        loop {
            let mut status: c_int = 0;
            // SAFETY: this process's own child; status is an out-parameter.
            let r = unsafe { libc::waitpid(self.pid, &mut status, flags) };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(e);
            }
            if r == 0 {
                return Ok(None);
            }
            let s = ExitStatus::from_raw(status);
            self.ended = Some(s);
            return Ok(Some(s));
        }
    }
}

impl Drop for Launched {
    /// Reaps it if it ended, as std's `Child` leaves that to the caller but
    /// a test that forgot must not leave a zombie per run.
    fn drop(&mut self) {
        let _ = self.try_wait();
    }
}

/// `cmd`'s program, arguments and environment (this process's, with
/// `cmd`'s changes; `env_clear` and a working directory are not carried:
/// refused), started with `stdio` and `fds`.
pub fn launch(cmd: &Command, stdio: [Io; 3], fds: Descriptors) -> std::io::Result<Launched> {
    if cmd.get_current_dir().is_some() {
        return Err(std::io::Error::other("launch: a working directory is not carried over"));
    }
    #[cfg(target_os = "linux")]
    {
        linux::launch(cmd, stdio, fds)
    }
    #[cfg(target_os = "macos")]
    {
        macos::launch(cmd, stdio, fds)
    }
}

/// [`launch`] with standard input `/dev/null` and the output and error
/// captured, as std's `Command::output`, then waited for.
pub fn output(cmd: &Command, fds: Descriptors) -> std::io::Result<Output> {
    launch(cmd, [Io::Null, Io::Piped, Io::Piped], fds)?.wait_with_output()
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CString, OsStr, OsString};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    use super::*;

    fn c_string(s: &OsStr) -> std::io::Result<CString> {
        CString::new(s.as_bytes()).map_err(|_| std::io::Error::other(format!("launch: {s:?} holds a NUL")))
    }

    /// This process's environment with `cmd`'s changes, as `NAME=value`.
    fn environment(cmd: &Command) -> std::io::Result<Vec<CString>> {
        let mut env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        for (k, v) in cmd.get_envs() {
            env.retain(|(name, _)| name.as_os_str() != k);
            if let Some(v) = v {
                env.push((k.to_os_string(), v.to_os_string()));
            }
        }
        env.into_iter()
            .map(|(k, v)| {
                let mut kv = k;
                kv.push("=");
                kv.push(v);
                c_string(&kv)
            })
            .collect()
    }

    /// A pipe, both ends close-on-exec: (read, write).
    fn pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
        let (r, w) = std::io::pipe()?;
        Ok((r.into(), w.into()))
    }

    struct Actions(libc::posix_spawn_file_actions_t);

    impl Actions {
        fn new() -> std::io::Result<Self> {
            let mut a = std::mem::MaybeUninit::uninit();
            // SAFETY: initialises the object it is given.
            check(unsafe { libc::posix_spawn_file_actions_init(a.as_mut_ptr()) })?;
            // SAFETY: initialised just above.
            Ok(Actions(unsafe { a.assume_init() }))
        }
    }

    impl Drop for Actions {
        fn drop(&mut self) {
            // SAFETY: initialised in new.
            unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
        }
    }

    struct Attr(libc::posix_spawnattr_t);

    impl Drop for Attr {
        fn drop(&mut self) {
            // SAFETY: initialised in launch.
            unsafe { libc::posix_spawnattr_destroy(&mut self.0) };
        }
    }

    unsafe extern "C" {
        fn posix_spawn_file_actions_addinherit_np(actions: *mut libc::posix_spawn_file_actions_t, fd: c_int) -> c_int;
    }

    /// posix_spawn's calls return the error, not -1 and errno.
    fn check(r: c_int) -> std::io::Result<()> {
        if r == 0 { Ok(()) } else { Err(std::io::Error::from_raw_os_error(r)) }
    }

    pub(super) fn launch(cmd: &Command, stdio: [Io; 3], fds: Descriptors) -> std::io::Result<Launched> {
        let program = c_string(cmd.get_program())?;
        let args: Vec<CString> =
            std::iter::once(Ok(program.clone())).chain(cmd.get_args().map(c_string)).collect::<std::io::Result<_>>()?;
        let env = environment(cmd)?;
        let mut a = Actions::new()?;
        // The parent's ends of the pipes, and the child's (closed here once
        // it has started).
        let mut ours: [Option<File>; 3] = [None, None, None];
        let mut theirs = Vec::new();
        for (fd, io) in (0..3).zip(stdio) {
            match io {
                // SAFETY: an initialised object and descriptor numbers.
                Io::Inherit => check(unsafe { posix_spawn_file_actions_addinherit_np(&mut a.0, fd) })?,
                Io::Null => check(unsafe {
                    // SAFETY: as above, and a NUL-terminated path.
                    libc::posix_spawn_file_actions_addopen(&mut a.0, fd, c"/dev/null".as_ptr(), libc::O_RDWR, 0)
                })?,
                Io::Piped => {
                    let (r, w) = pipe()?;
                    let (parent, child) = if fd == 0 { (w, r) } else { (r, w) };
                    // SAFETY: as above; the child's end is open here.
                    check(unsafe { libc::posix_spawn_file_actions_adddup2(&mut a.0, child.as_raw_fd(), fd) })?;
                    ours[usize::try_from(fd).unwrap_or(0)] = Some(File::from(parent));
                    theirs.push(child);
                }
            }
        }
        for (fd, at) in &fds.inherited {
            if fd.as_raw_fd() == *at {
                // dup2 onto itself would leave it close-on-exec.
                // SAFETY: as above.
                check(unsafe { posix_spawn_file_actions_addinherit_np(&mut a.0, *at) })?;
            } else {
                // SAFETY: as above; fd is open here.
                check(unsafe { libc::posix_spawn_file_actions_adddup2(&mut a.0, fd.as_raw_fd(), *at) })?;
            }
        }
        for &fd in &fds.closed {
            // SAFETY: as above.
            check(unsafe { libc::posix_spawn_file_actions_addclose(&mut a.0, fd) })?;
        }
        let mut attr = std::mem::MaybeUninit::uninit();
        // SAFETY: initialises the object it is given.
        check(unsafe { libc::posix_spawnattr_init(attr.as_mut_ptr()) })?;
        // SAFETY: initialised just above.
        let mut attr = Attr(unsafe { attr.assume_init() });
        // As std's spawn: no signal blocked, SIGPIPE at its default; and
        // only what the file actions name is open in the child.
        let flags = libc::POSIX_SPAWN_SETSIGMASK | libc::POSIX_SPAWN_SETSIGDEF | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        // SAFETY: plain sigset_t values and an initialised attribute object.
        unsafe {
            let mut none: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut none);
            check(libc::posix_spawnattr_setsigmask(&mut attr.0, &none))?;
            let mut pipe: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut pipe);
            libc::sigaddset(&mut pipe, libc::SIGPIPE);
            check(libc::posix_spawnattr_setsigdefault(&mut attr.0, &pipe))?;
            check(libc::posix_spawnattr_setflags(&mut attr.0, libc::c_short::try_from(flags).map_err(std::io::Error::other)?))?;
        }
        let mut argv: Vec<*mut libc::c_char> = args.iter().map(|s| s.as_ptr().cast_mut()).collect();
        argv.push(std::ptr::null_mut());
        let mut envp: Vec<*mut libc::c_char> = env.iter().map(|s| s.as_ptr().cast_mut()).collect();
        envp.push(std::ptr::null_mut());
        let mut pid: libc::pid_t = 0;
        // SAFETY: NUL-terminated strings and arrays that outlive the call,
        // initialised file actions and attributes.
        check(unsafe { libc::posix_spawnp(&mut pid, program.as_ptr(), &a.0, &attr.0, argv.as_ptr(), envp.as_ptr()) })?;
        drop(theirs);
        drop(fds);
        let [_, stdout, stderr] = ours;
        Ok(Launched { pid, stdout, stderr, ended: None })
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    pub(super) fn launch(cmd: &Command, stdio: [Io; 3], fds: Descriptors) -> std::io::Result<Launched> {
        let mut c = Command::new(cmd.get_program());
        c.args(cmd.get_args());
        for (k, v) in cmd.get_envs() {
            match v {
                Some(v) => c.env(k, v),
                None => c.env_remove(k),
            };
        }
        let as_std = |io: Io| match io {
            Io::Inherit => std::process::Stdio::inherit(),
            Io::Null => std::process::Stdio::null(),
            Io::Piped => std::process::Stdio::piped(),
        };
        c.stdin(as_std(stdio[0])).stdout(as_std(stdio[1])).stderr(as_std(stdio[2]));
        let Descriptors { inherited, closed, only_stdio } = fds;
        // In the child, in this order: everything above 2 close-on-exec,
        // then the inherited ones placed (dup2 leaves them inheritable),
        // then the closed ones closed.
        if only_stdio {
            crate::command_with_only_stdio(&mut c);
        }
        crate::command_with_inherited(&mut c, inherited);
        crate::command_with_closed(&mut c, closed);
        let mut child = c.spawn()?;
        let stdout = child.stdout.take().map(|o| File::from(OwnedFd::from(o)));
        let stderr = child.stderr.take().map(|e| File::from(OwnedFd::from(e)));
        let pid = libc::pid_t::try_from(child.id()).unwrap_or(0);
        Ok(Launched { pid, stdout, stderr, ended: None, child })
    }
}
