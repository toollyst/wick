// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `libc` 0.2.189 for wick.
//!
//! - Linux: the original crate, re-exported as is.
//! - macOS: the original crate plus the Linux-only items Firecracker uses, with
//!   the same names and signatures. Each item documents how it behaves.
//! - Windows: the original crate plus the POSIX items Firecracker uses, with
//!   their Linux layout, on Win32.

#![no_std]
#![allow(non_camel_case_types, non_upper_case_globals)]

#[cfg(target_os = "macos")]
extern crate std;

pub use upstream::*;

#[cfg(target_os = "macos")]
mod linux_items;
#[cfg(target_os = "macos")]
pub use linux_items::*;
// Items that exist on macOS with a different signature: the explicit re-export
// takes precedence over the glob re-export of `upstream`.
#[cfg(target_os = "macos")]
pub use linux_items::{getsockopt, madvise, mincore, mmap, mprotect, munmap, syscall};
/// The name prefix of a huge page memfd's shared memory object on macOS
/// (`/fcmH.<pid>.<n>`, made by the compatibility `memfd` crate), by which
/// `mmap` knows to map it in huge pages (docs/PORTING.md row 10).
#[cfg(target_os = "macos")]
pub const HUGE_MEMFD_PREFIX: &str = "/fcmH.";
/// The kernel side of userfaultfd (a wick API, not part of `libc`).
#[cfg(target_os = "macos")]
pub mod wick_uffd;
/// The hypervisor backend's hooks on guest memory (a wick API, not part of `libc`).
#[cfg(target_os = "macos")]
pub mod wick_guest;
// CLOCK_MONOTONIC as Linux has it: the explicit re-export takes precedence
// over the glob re-export of `upstream`.
#[cfg(target_os = "macos")]
mod macos_time;
#[cfg(target_os = "macos")]
pub use macos_time::clock_gettime;
#[cfg(target_os = "macos")]
mod timerfd;
// AF_UNIX streams start with Linux's send buffer (`socket`, `socketpair`).
#[cfg(target_os = "macos")]
mod unix_stream_buffer;
#[cfg(target_os = "macos")]
pub use unix_stream_buffer::LINUX_WMEM_DEFAULT;
// System calls on user memory wait for userfaultfd pages, as on Linux.
#[cfg(target_os = "macos")]
pub use wick_uffd::syscalls::{
    pread, preadv, pwrite, pwritev, read, readv, recv, recvfrom, recvmsg, send, sendmsg, sendto,
    write, writev,
};
#[cfg(target_os = "macos")]
pub use timerfd::*;

#[cfg(windows)]
extern crate std;
/// The kernel side of userfaultfd (a wick API, not part of `libc`).
#[cfg(windows)]
#[path = "windows_uffd.rs"]
pub mod wick_uffd;
/// The jailer's `--resource-limit no-file=`: descriptors past it fail with
/// `EMFILE` (a wick API, not part of `libc`).
#[cfg(windows)]
#[path = "windows_nofile.rs"]
pub mod wick_nofile;
#[cfg(windows)]
mod windows_errno;
// Explicit, so they take precedence over the CRT values of `upstream`.
#[cfg(windows)]
#[rustfmt::skip]
pub use windows_errno::{
    wick_errno_from_win32, EPERM, ENOENT, ESRCH, EINTR, EIO, ENXIO, E2BIG, ENOEXEC, EBADF, ECHILD, EAGAIN, EWOULDBLOCK, ENOMEM, EACCES, EFAULT, EBUSY, EEXIST, EXDEV, ENODEV, ENOTDIR, EISDIR, EINVAL, ENFILE, EMFILE, ENOTTY, EFBIG, ENOSPC, ESPIPE, EROFS, EMLINK, EPIPE, ERANGE, EDEADLK, ENAMETOOLONG, ENOSYS, ENOTEMPTY, EOVERFLOW, ECANCELED, EOPNOTSUPP, ENOTSUP, EPROTO, ETIMEDOUT, EADDRINUSE, EADDRNOTAVAIL, ECONNREFUSED, ECONNRESET, ECONNABORTED, ENOTCONN, EISCONN, ENOBUFS, EMSGSIZE, EINPROGRESS, EALREADY, ENOTSOCK, EAFNOSUPPORT, ENETUNREACH, EHOSTUNREACH, EPROTONOSUPPORT, ENOPROTOOPT,
};
#[cfg(windows)]
mod windows_time;
// Explicit: Linux layouts that replace the CRT ones of `upstream`.
#[cfg(windows)]
pub use windows_time::{timespec, tm};
#[cfg(windows)]
pub use windows_time::{
    CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_RAW,
    CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME, CLOCK_REALTIME_COARSE, CLOCK_THREAD_CPUTIME_ID,
    TFD_CLOEXEC, TFD_NONBLOCK, TFD_TIMER_ABSTIME, clock_gettime, clockid_t, itimerspec,
    localtime_r, timerfd_create, timerfd_gettime, timerfd_settime,
};
#[cfg(windows)]
mod windows_fd;
// Explicit: Linux layouts, values and handle-based calls that replace the CRT
// ones of `upstream`.
#[cfg(windows)]
#[rustfmt::skip]
pub use windows_fd::{
    close, dup, dup2, fcntl, fstat, isatty, lseek, off_t, pipe, read, stat, write, O_APPEND,
    O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, S_IFCHR, S_IFDIR, S_IFMT, S_IFREG,
};
#[cfg(windows)]
pub use windows_fd::{
    F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD, F_SETFL, FD_CLOEXEC, O_CLOEXEC,
    O_NOFOLLOW, O_NONBLOCK, RLIM_INFINITY, RLIMIT_FSIZE, RLIMIT_NOFILE, S_IFIFO, S_IFSOCK, SEEK_CUR, SEEK_DATA, SEEK_END, SEEK_HOLE,
    SEEK_SET, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO, _SC_CLK_TCK, _SC_NPROCESSORS_CONF, _SC_NPROCESSORS_ONLN, _SC_OPEN_MAX,
    _SC_PAGE_SIZE, _SC_PAGESIZE, _SC_PHYS_PAGES, wick_fd, wick_signal, fdatasync, fsync, ftruncate, getrlimit,
    pread, pwrite, readv, rlim_t, rlimit, sysconf, uname, utsname, writev,
};
#[cfg(windows)]
mod windows_linux;
// Explicit, so they take precedence over the CRT types and Winsock functions
// of `upstream`.
#[cfg(windows)]
#[rustfmt::skip]
pub use windows_linux::{
    accept, bind, c_long, c_ulong, connect, fallocate, getpeername, getsockname, ioctl, listen,
    memfd_create, off64_t, prctl, sa_family_t, sendfile64, sockaddr_ll, sockaddr_storage, sockaddr_un, socket, syscall,
    Ioctl, AF_PACKET, BLKIOMIN, BLKIOOPT, BLKPBSZGET, BLKSSZGET, EFD_CLOEXEC, EFD_NONBLOCK,
    EFD_SEMAPHORE, FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE,
    MFD_ALLOW_SEALING, MFD_CLOEXEC, PR_GET_SECCOMP, PR_SET_NO_NEW_PRIVS, SECCOMP_SET_MODE_FILTER,
    SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_RAW, SYS_arch_prctl, SYS_io_uring_enter,
    SYS_io_uring_register, SYS_io_uring_setup, SYS_seccomp,
};
#[cfg(windows)]
mod windows_socket;
#[cfg(windows)]
pub use windows_socket::{
    getsockopt, nfds_t, poll, pollfd, setsockopt, socklen_t, ucred, POLLERR, POLLHUP, POLLIN, POLLNVAL,
    POLLOUT, POLLPRI, SO_PEERCRED, AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC, SOCK_DGRAM,
    SOCK_SEQPACKET, SOCK_STREAM, SOL_SOCKET, SO_DOMAIN, SO_ERROR, SO_KEEPALIVE, SO_RCVBUF,
    SO_REUSEADDR, SO_SNDBUF, SO_TYPE,
};
#[cfg(windows)]
mod windows_mm;
// The records for section memory charged against memory.max (SECTREC).
#[cfg(all(windows, test))]
mod windows_sectrec;
#[cfg(windows)]
#[rustfmt::skip]
pub use windows_mm::{
    wick_mm, madvise, mincore, mmap, mprotect, msync, munmap, MADV_DODUMP, MADV_DOFORK,
    MADV_DONTDUMP, MADV_DONTFORK, MADV_DONTNEED, MADV_FREE, MADV_HUGEPAGE, MADV_MERGEABLE,
    MADV_NOHUGEPAGE, MADV_NORMAL, MADV_RANDOM, MADV_REMOVE, MADV_SEQUENTIAL, MADV_UNMERGEABLE,
    MADV_WILLNEED, MAP_ANON, MAP_ANONYMOUS, MAP_FAILED, MAP_FIXED, MAP_HUGETLB, MAP_HUGE_1GB,
    MAP_HUGE_2MB, MAP_HUGE_SHIFT, MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, MS_ASYNC,
    MS_INVALIDATE, MS_SYNC, PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE,
};
#[cfg(windows)]
mod windows_items;
#[cfg(windows)]
pub use windows_items::*;
