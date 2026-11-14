// Copyright 2026 toollyst contributors.
// Copyright 2019 Intel Corporation. All Rights Reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! `terminal` for macOS: vmm-sys-util 0.15.0's `unix/terminal.rs`, the same
//! API and code, but for one case of `set_non_block` that XNU's `fcntl`
//! reports differently from Linux's.
//!
//! A terminal is revoked when the session leader it is the controlling
//! terminal of exits (xnu-12377.121.6 bsd/kern/kern_exit.c :2436 to :2476,
//! `VNOP_REVOKE(ttyvp, REVOKEALL)`; `vn_revoke` makes the vnode `VBAD`,
//! bsd/vfs/vfs_subr.c :3270 and :6918), for every descriptor on it, also
//! those of processes of other sessions, such as a Firecracker the jailer
//! started without `--daemonize` (the jailer is then the leader, and exits
//! once it has forked Firecracker). XNU's `F_SETFL` sets the descriptor's
//! flags and then tells the file of `O_NONBLOCK` with an `FIONBIO` ioctl
//! (bsd/kern/kern_descrip.c :2998 to :3003), which a `VBAD` vnode refuses
//! with `ENOTTY` (bsd/vfs/vfs_vnops.c :1782), the flag left set. Linux hangs
//! a pty up when its master is closed (v6.1 drivers/tty/pty.c :69 to :79;
//! not on the leader's exit, drivers/tty/tty_jobctrl.c :274), and its
//! `F_SETFL` makes no call to the driver for `O_NONBLOCK` (fs/fcntl.c `setfl`,
//! :36 to :80), so it succeeds there, live or hung up. So an `ENOTTY` from
//! `F_SETFL` with `F_GETFL` then showing the flags asked for is Linux's
//! success; any other error, or flags not as asked, is returned.
//!
//! After that the revoked terminal behaves as Linux's hung-up one: `isatty`
//! is false (Linux: `TCGETS` fails with `EIO`, drivers/tty/tty_io.c :440 to
//! :444), so the mode calls do nothing; a read gives 0 (:424 to :427), a
//! write fails with `EIO` (:429 to :432). Firecracker's serial device then
//! takes no input on either host (it registers its input only if `isatty`
//! or a FIFO, devices/legacy/serial.rs `init`).
//!
//! What differs: a terminal whose master stays open after the leader exits
//! is still live on Linux, and Firecracker keeps it; on macOS it is revoked
//! all the same, which no process can undo.

use std::io::StdinLock;
use std::mem::zeroed;
use std::os::unix::io::RawFd;

use libc::{
    c_int, fcntl, isatty, read, tcgetattr, tcsetattr, termios, ECHO, F_GETFL, F_SETFL, ICANON, ISIG, O_NONBLOCK,
    STDIN_FILENO, TCSANOW,
};

use crate::errno::{errno_result, Result};

fn modify_mode<F: FnOnce(&mut termios)>(fd: RawFd, f: F) -> Result<()> {
    // SAFETY: Safe because we check the return value of isatty.
    if unsafe { isatty(fd) } != 1 {
        return Ok(());
    }

    // SAFETY: The following pair are safe because termios gets totally overwritten by tcgetattr
    // and we check the return result.
    let mut termios: termios = unsafe { zeroed() };
    // SAFETY: The parameter is valid and we check the result.
    let ret = unsafe { tcgetattr(fd, &mut termios as *mut _) };
    if ret < 0 {
        return errno_result();
    }
    let mut new_termios = termios;
    f(&mut new_termios);
    // SAFETY: Safe because the syscall will only read the extent of termios and we check the
    // return result.
    let ret = unsafe { tcsetattr(fd, TCSANOW, &new_termios as *const _) };
    if ret < 0 {
        return errno_result();
    }

    Ok(())
}

fn get_flags(fd: RawFd) -> Result<c_int> {
    // SAFETY: Safe because no third parameter is expected and we check the return result.
    let ret = unsafe { fcntl(fd, F_GETFL) };
    if ret < 0 {
        return errno_result();
    }
    Ok(ret)
}

fn set_flags(fd: RawFd, flags: c_int) -> Result<()> {
    set_flags_by(fd, flags, |fd, flags| {
        // SAFETY: Safe because we supply the third parameter and we check the return result.
        let ret = unsafe { fcntl(fd, F_SETFL, flags) };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    })
}

/// `set_flags` with its `F_SETFL` call given, so that the tests can make it
/// fail. An `ENOTTY` with `F_GETFL` then giving `flags` is a revoked
/// terminal's, where Linux's `F_SETFL` succeeds (the module's
/// documentation); every other outcome is the call's.
fn set_flags_by(fd: RawFd, flags: c_int, setfl: impl FnOnce(RawFd, c_int) -> Result<()>) -> Result<()> {
    match setfl(fd, flags) {
        Err(err) if err.errno() == libc::ENOTTY && get_flags(fd).ok() == Some(flags) => Ok(()),
        outcome => outcome,
    }
}

/// Trait for file descriptors that are TTYs, according to
/// [`isatty`](http://man7.org/linux/man-pages/man3/isatty.3.html).
///
/// # Safety
///
/// This is marked unsafe because the implementation must ensure that the returned
/// RawFd is a valid fd and that the lifetime of the returned fd is at least that
/// of the trait object.
pub unsafe trait Terminal {
    /// Get the file descriptor of the TTY.
    fn tty_fd(&self) -> RawFd;

    /// Set this terminal to canonical mode (`ICANON | ECHO | ISIG`).
    fn set_canon_mode(&self) -> Result<()> {
        modify_mode(self.tty_fd(), |t| t.c_lflag |= ICANON | ECHO | ISIG)
    }

    /// Set this terminal to raw mode (`!(ICANON | ECHO | ISIG)`).
    fn set_raw_mode(&self) -> Result<()> {
        modify_mode(self.tty_fd(), |t| t.c_lflag &= !(ICANON | ECHO | ISIG))
    }

    /// Set this terminal to non-blocking mode.
    ///
    /// If `non_block` is `true`, then `read_raw` will not block.
    /// If `non_block` is `false`, then `read_raw` may block if
    /// there is nothing to read. On a revoked terminal it succeeds as on
    /// Linux's hung-up one (the module's documentation).
    fn set_non_block(&self, non_block: bool) -> Result<()> {
        let old_flags = get_flags(self.tty_fd())?;
        let new_flags = if non_block {
            old_flags | O_NONBLOCK
        } else {
            old_flags & !O_NONBLOCK
        };
        if new_flags != old_flags {
            set_flags(self.tty_fd(), new_flags)?
        }
        Ok(())
    }

    /// Read from a [`Terminal`] without any buffering. This may block,
    /// depending on if non-blocking was enabled with `set_non_block` or if
    /// there are any bytes to read.
    fn read_raw(&self, out: &mut [u8]) -> Result<usize> {
        // SAFETY: Safe because read will only modify the pointer up to the length we give it and
        // we check the return result.
        let ret = unsafe { read(self.tty_fd(), out.as_mut_ptr() as *mut _, out.len()) };
        if ret < 0 {
            return errno_result();
        }

        Ok(ret as usize)
    }
}

// SAFETY: Safe because we return a genuine terminal fd that never changes and shares our lifetime.
unsafe impl Terminal for StdinLock<'_> {
    fn tty_fd(&self) -> RawFd {
        STDIN_FILENO
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::fs::File;
    use std::io;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::path::Path;

    use super::*;
    use crate::errno::Error;

    unsafe impl Terminal for File {
        fn tty_fd(&self) -> RawFd {
            self.as_raw_fd()
        }
    }

    // Upstream's two tests.
    #[test]
    fn test_a_tty() {
        let stdin_handle = io::stdin();
        let stdin = stdin_handle.lock();

        assert!(stdin.set_canon_mode().is_ok());
        assert!(stdin.set_raw_mode().is_ok());
        assert!(stdin.set_raw_mode().is_ok());
        assert!(stdin.set_canon_mode().is_ok());
        assert!(stdin.set_non_block(true).is_ok());
        let mut out = [0u8; 0];
        assert!(stdin.read_raw(&mut out[..]).is_ok());
    }

    #[test]
    fn test_a_non_tty() {
        let file = File::open(Path::new("/dev/zero")).unwrap();
        assert!(file.set_canon_mode().is_ok());
    }

    /// A pty's replica (master, replica), revoked: a child makes it the
    /// controlling terminal of a session it leads, then exits.
    fn revoked_pty() -> (File, File) {
        let (mut master, mut replica) = (-1, -1);
        let ret = unsafe {
            libc::openpty(&mut master, &mut replica, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(ret, 0, "openpty: {}", io::Error::last_os_error());
        let (master, replica) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(replica)) };
        assert_eq!(unsafe { isatty(replica.as_raw_fd()) }, 1);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            // The child: async-signal-safe calls only.
            unsafe {
                let ok = libc::setsid() >= 0 && libc::ioctl(replica.as_raw_fd(), libc::TIOCSCTTY.into(), 0) == 0;
                libc::_exit(if ok { 0 } else { 1 });
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "the child's setsid or TIOCSCTTY failed");
        (master, replica)
    }

    // On a revoked terminal, as on Linux's hung-up one: set_non_block both
    // ways succeeds and leaves the flag as asked, the mode calls do nothing,
    // a read gives 0 and a write fails with EIO.
    #[test]
    fn test_a_revoked_tty_is_linux_s_hung_up_one() {
        let (_master, replica) = revoked_pty();
        let fd = replica.as_raw_fd();
        assert_eq!(unsafe { isatty(fd) }, 0);
        // XNU's F_SETFL itself still fails here (the module's documentation).
        let flags = get_flags(fd).unwrap();
        assert_eq!(unsafe { fcntl(fd, F_SETFL, flags) }, -1);
        assert_eq!(Error::last().errno(), libc::ENOTTY);

        replica.set_non_block(true).unwrap();
        assert_ne!(get_flags(fd).unwrap() & O_NONBLOCK, 0);
        replica.set_non_block(false).unwrap();
        assert_eq!(get_flags(fd).unwrap() & O_NONBLOCK, 0);
        replica.set_non_block(true).unwrap();
        assert_ne!(get_flags(fd).unwrap() & O_NONBLOCK, 0);

        replica.set_raw_mode().unwrap();
        replica.set_canon_mode().unwrap();
        let mut out = [0u8; 8];
        assert_eq!(replica.read_raw(&mut out).unwrap(), 0);
        let ret = unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
        assert_eq!(ret, -1);
        assert_eq!(Error::last().errno(), libc::EIO);
    }

    // An ENOTTY from F_SETFL with the flags not as asked is returned, and so
    // is any other error with the flags as asked: on a pipe, with F_SETFL
    // made to fail.
    #[test]
    fn test_only_enotty_with_the_flags_as_asked_succeeds() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_end, _write_end) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
        let fd = read_end.as_raw_fd();
        let old = get_flags(fd).unwrap();
        assert_eq!(old & O_NONBLOCK, 0);

        // ENOTTY, the flag not set: returned.
        let err = set_flags_by(fd, old | O_NONBLOCK, |_, _| Err(Error::new(libc::ENOTTY))).unwrap_err();
        assert_eq!(err.errno(), libc::ENOTTY);
        assert_eq!(get_flags(fd).unwrap(), old);

        // EBADF with the flag set (by a call that then fails): returned.
        let err = set_flags_by(fd, old | O_NONBLOCK, |fd, flags| {
            assert_eq!(unsafe { fcntl(fd, F_SETFL, flags) }, 0);
            Err(Error::new(libc::EBADF))
        })
        .unwrap_err();
        assert_eq!(err.errno(), libc::EBADF);

        // ENOTTY with the flag set: Linux's success.
        set_flags_by(fd, old | O_NONBLOCK, |_, _| Err(Error::new(libc::ENOTTY))).unwrap();

        // ENOTTY with the flag cleared as asked: success; with it left set: returned.
        let err = set_flags_by(fd, old, |_, _| Err(Error::new(libc::ENOTTY))).unwrap_err();
        assert_eq!(err.errno(), libc::ENOTTY);
        set_flags_by(fd, old, |fd, flags| {
            assert_eq!(unsafe { fcntl(fd, F_SETFL, flags) }, 0);
            Err(Error::new(libc::ENOTTY))
        })
        .unwrap();
        assert_eq!(get_flags(fd).unwrap(), old);

        // And the real call on the pipe works both ways.
        read_end.set_non_block(true).unwrap();
        assert_ne!(get_flags(fd).unwrap() & O_NONBLOCK, 0);
        read_end.set_non_block(false).unwrap();
        assert_eq!(get_flags(fd).unwrap(), old);
    }
}
