// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Linux-only `libc` items Firecracker and the rust-vmm crates use, on
//! Windows. As on macOS (`linux_items`), each item does what it does on
//! Linux with Windows means, or fails with the error Linux gives when the
//! facility is missing; none reports success for something it did not do:
//! - `c_long`/`c_ulong` are 64 bits, the Linux LP64 types (ioctl requests,
//!   `arch_prctl` arguments); upstream's CRT declarations keep their own;
//! - `syscall`: Windows has no Linux system calls. `arch_prctl` fails with
//!   `EINVAL`, as on kernels without the XSTATE permission interface (WHP
//!   sets guest XSTATE features on the partition); everything else fails
//!   with `ENOSYS`;
//! - `prctl`: `PR_GET_SECCOMP` is 0 (no seccomp filter); other options fail
//!   with `EINVAL`, as unknown options do on Linux;
//! - `ioctl` fails with `ENOTTY`: Windows paths use `DeviceIoControl`;
//! - `fallocate`: punching holes and zeroing ranges with sparse files and
//!   `FSCTL_SET_ZERO_DATA`, allocation by writing zeros into holes;
//! - sockets take descriptors and Linux numbers (`AF_INET6` is 10), over
//!   Winsock; address families Windows lacks (`AF_PACKET`) are -1, so
//!   `socket` fails.

use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::Networking::WinSock::{
    self as ws, INVALID_SOCKET, SOCKET_ERROR, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
    WSAGetLastError, WSASocketW,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_END_OF_FILE_INFO, FileEndOfFileInfo, GetFileSizeEx, SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    FILE_ALLOCATED_RANGE_BUFFER, FILE_SET_SPARSE_BUFFER, FILE_ZERO_DATA_INFORMATION,
    FSCTL_QUERY_ALLOCATED_RANGES, FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA,
};

use crate::windows_fd::{wick_wsa_startup, handle, set_errno};
use crate::windows_socket::{AF_INET, AF_INET6, AF_UNIX};
use crate::{c_char, c_int, c_void, off_t};

/// `long` of the Linux LP64 ABI.
#[allow(non_camel_case_types)]
pub type c_long = i64;
/// `unsigned long` of the Linux LP64 ABI.
#[allow(non_camel_case_types)]
pub type c_ulong = u64;

// ---- eventfd (implemented by vmm-sys-util's Windows eventfd) ----

/// `eventfd` flag: close on exec.
pub const EFD_CLOEXEC: c_int = 0o2_000_000;
/// `eventfd` flag: non-blocking.
pub const EFD_NONBLOCK: c_int = 0o4000;
/// `eventfd` flag: semaphore semantics.
pub const EFD_SEMAPHORE: c_int = 1;

// ---- system calls ----

#[cfg(target_arch = "x86_64")]
mod nr {
    use super::c_long;
    pub const ARCH_PRCTL: c_long = 158;
    pub const SECCOMP: c_long = 317;
}
#[cfg(target_arch = "aarch64")]
mod nr {
    use super::c_long;
    // No arch_prctl on arm64: a number no call has.
    pub const ARCH_PRCTL: c_long = -1;
    pub const SECCOMP: c_long = 277;
}

/// `arch_prctl` (x86_64 Linux number).
pub const SYS_arch_prctl: c_long = nr::ARCH_PRCTL;
/// `seccomp`.
pub const SYS_seccomp: c_long = nr::SECCOMP;
/// `io_uring_setup`.
pub const SYS_io_uring_setup: c_long = 425;
/// `io_uring_enter`.
pub const SYS_io_uring_enter: c_long = 426;
/// `io_uring_register`.
pub const SYS_io_uring_register: c_long = 427;
/// `seccomp` operation.
pub const SECCOMP_SET_MODE_FILTER: core::ffi::c_uint = 1;

// Windows passes variadic arguments like fixed ones on x86_64 and arm64, so
// the variadic entry points bind to fixed-argument functions.
#[unsafe(no_mangle)]
extern "C" fn wick_compat_syscall(num: c_long) -> c_long {
    set_errno(if num == SYS_arch_prctl && num >= 0 {
        crate::EINVAL
    } else {
        crate::ENOSYS
    });
    -1
}

/// `prctl` option.
pub const PR_GET_SECCOMP: c_int = 21;
/// `prctl` option.
pub const PR_SET_NO_NEW_PRIVS: c_int = 38;

#[unsafe(no_mangle)]
extern "C" fn wick_compat_prctl(option: c_int) -> c_int {
    if option == PR_GET_SECCOMP {
        return 0;
    }
    set_errno(crate::EINVAL);
    -1
}

/// The `ioctl` request type (glibc's).
pub type Ioctl = c_ulong;

#[unsafe(no_mangle)]
extern "C" fn wick_compat_ioctl(_fd: c_int, _request: Ioctl) -> c_int {
    set_errno(crate::ENOTTY);
    -1
}

unsafe extern "C" {
    /// `syscall`: see the module documentation.
    #[link_name = "wick_compat_syscall"]
    pub fn syscall(num: c_long, ...) -> c_long;
    /// `prctl`: see the module documentation.
    #[link_name = "wick_compat_prctl"]
    pub fn prctl(option: c_int, ...) -> c_int;
    /// `ioctl`: fails with `ENOTTY` (see the module documentation).
    #[link_name = "wick_compat_ioctl"]
    pub fn ioctl(fd: c_int, request: Ioctl, ...) -> c_int;
}

/// Block device ioctl: logical sector size.
pub const BLKSSZGET: Ioctl = 0x1268;
/// Block device ioctl: physical sector size.
pub const BLKPBSZGET: Ioctl = 0x127b;
/// Block device ioctl: minimum I/O size.
pub const BLKIOMIN: Ioctl = 0x1278;
/// Block device ioctl: optimal I/O size.
pub const BLKIOOPT: Ioctl = 0x1279;

// ---- fallocate ----

/// Keep the file size.
pub const FALLOC_FL_KEEP_SIZE: c_int = 0x01;
/// Deallocate the range (with `FALLOC_FL_KEEP_SIZE`).
pub const FALLOC_FL_PUNCH_HOLE: c_int = 0x02;
/// Zero the range.
pub const FALLOC_FL_ZERO_RANGE: c_int = 0x10;

fn ioctl_in<T>(h: HANDLE, code: u32, input: &T) -> bool {
    let mut n = 0u32;
    // SAFETY: `input` is valid for its size; no output.
    unsafe {
        DeviceIoControl(
            h,
            code,
            (&raw const *input).cast(),
            u32::try_from(std::mem::size_of::<T>()).unwrap(),
            std::ptr::null_mut(),
            0,
            &mut n,
            std::ptr::null_mut(),
        ) != 0
    }
}

fn file_size(h: HANDLE) -> Option<i64> {
    let mut size = 0i64;
    // SAFETY: valid out-parameter.
    (unsafe { GetFileSizeEx(h, &mut size) } != 0).then_some(size)
}

fn set_size(h: HANDLE, size: i64) -> bool {
    let info = FILE_END_OF_FILE_INFO { EndOfFile: size };
    // SAFETY: valid information of the right class and size.
    unsafe {
        SetFileInformationByHandle(
            h,
            FileEndOfFileInfo,
            (&raw const info).cast(),
            u32::try_from(std::mem::size_of_val(&info)).unwrap(),
        ) != 0
    }
}

fn zero_data(h: HANDLE, from: i64, to: i64) -> bool {
    from >= to
        || ioctl_in(
            h,
            FSCTL_SET_ZERO_DATA,
            &FILE_ZERO_DATA_INFORMATION {
                FileOffset: from,
                BeyondFinalZero: to,
            },
        )
}

/// Writes zeros into the holes of [from, to), so the range is allocated.
fn fill_holes(fd: c_int, h: HANDLE, from: i64, to: i64) -> bool {
    let zeros = [0u8; 64 * 1024];
    let mut at = from;
    while at < to {
        let query = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: at,
            Length: to - at,
        };
        let mut out = [FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: 0,
            Length: 0,
        }; 32];
        let mut n = 0u32;
        // SAFETY: valid input and output buffers.
        let ok = unsafe {
            DeviceIoControl(
                h,
                FSCTL_QUERY_ALLOCATED_RANGES,
                (&raw const query).cast(),
                u32::try_from(std::mem::size_of_val(&query)).unwrap(),
                out.as_mut_ptr().cast(),
                u32::try_from(std::mem::size_of_val(&out)).unwrap(),
                &mut n,
                std::ptr::null_mut(),
            )
        };
        // More ranges than fit: process these, then ask again.
        // SAFETY: plain call.
        if ok == 0 && unsafe { GetLastError() } != windows_sys::Win32::Foundation::ERROR_MORE_DATA {
            return false;
        }
        let count = n as usize / std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        let mut hole = at;
        let mut next = to;
        for r in &out[..count] {
            if r.FileOffset > hole && !write_zeros(fd, &zeros, hole, r.FileOffset.min(to)) {
                return false;
            }
            hole = r.FileOffset + r.Length;
            next = hole;
        }
        if ok != 0 {
            // Every range reported: the rest is a hole.
            return hole >= to || write_zeros(fd, &zeros, hole, to);
        }
        at = next;
    }
    true
}

fn write_zeros(fd: c_int, zeros: &[u8], mut from: i64, to: i64) -> bool {
    while from < to {
        let n = usize::try_from(to - from)
            .unwrap_or(usize::MAX)
            .min(zeros.len());
        // SAFETY: `zeros` is valid for `n` bytes.
        let w = unsafe { crate::windows_fd::pwrite(fd, zeros.as_ptr().cast(), n, from) };
        if w <= 0 {
            return false;
        }
        from += i64::try_from(w).unwrap();
    }
    true
}

/// `fallocate`:
/// - `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`: the file is made sparse
///   and the range deallocated; file systems without sparse files fail with
///   `EOPNOTSUPP`, as Linux does;
/// - `FALLOC_FL_ZERO_RANGE`: the range reads as zeros (and the file grows to
///   cover it without `FALLOC_FL_KEEP_SIZE`);
/// - 0: the range is allocated (holes are filled with zeros) and the file
///   grows to cover it without `FALLOC_FL_KEEP_SIZE`.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn fallocate(fd: c_int, mode: c_int, offset: off_t, len: off_t) -> c_int {
    let fail = |e| {
        set_errno(e);
        -1
    };
    if offset < 0 || len <= 0 {
        return fail(crate::EINVAL);
    }
    let Some(end) = offset.checked_add(len) else {
        return fail(crate::EFBIG);
    };
    let keep = mode & FALLOC_FL_KEEP_SIZE != 0;
    let h = handle(fd);
    let Some(size) = file_size(h) else {
        return fail(crate::EBADF);
    };
    match mode & !FALLOC_FL_KEEP_SIZE {
        FALLOC_FL_PUNCH_HOLE => {
            if !keep {
                return fail(crate::EOPNOTSUPP);
            }
            let sparse = FILE_SET_SPARSE_BUFFER { SetSparse: true };
            if !ioctl_in(h, FSCTL_SET_SPARSE, &sparse) {
                return fail(crate::EOPNOTSUPP);
            }
            if !zero_data(h, offset, end.min(size)) {
                return -1;
            }
        }
        FALLOC_FL_ZERO_RANGE => {
            if !zero_data(h, offset, end.min(size)) {
                return -1;
            }
            if !keep && end > size && !set_size(h, end) {
                return -1;
            }
        }
        0 => {
            if !keep && end > size && !set_size(h, end) {
                return -1;
            }
            if !fill_holes(fd, h, offset, if keep { end.min(size) } else { end }) {
                return -1;
            }
        }
        _ => return fail(crate::EOPNOTSUPP),
    }
    0
}

// ---- sockets ----

/// Address family type.
#[allow(non_camel_case_types)]
pub type sa_family_t = u16;
/// Packet sockets: not on Windows (-1, so `socket` fails).
pub const AF_PACKET: c_int = -1;
/// Raw sockets.
pub const SOCK_RAW: c_int = 3;
/// `socket` type flag: non-blocking.
pub const SOCK_NONBLOCK: c_int = 0o4000;
/// `socket` type flag: close on exec.
pub const SOCK_CLOEXEC: c_int = 0o2_000_000;

/// A Unix domain socket address (the Linux and Winsock layouts agree).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub struct sockaddr_un {
    /// `AF_UNIX`.
    pub sun_family: sa_family_t,
    /// The path, NUL-terminated unless it fills the array.
    pub sun_path: [c_char; 108],
}

/// Storage for any socket address (Linux layout).
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub struct sockaddr_storage {
    /// The family.
    pub ss_family: sa_family_t,
    __ss_pad: [u8; 126],
}

/// A packet socket address (Linux layout; packet sockets do not exist on
/// Windows).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub struct sockaddr_ll {
    /// `AF_PACKET`.
    pub sll_family: u16,
    /// Protocol.
    pub sll_protocol: u16,
    /// Interface index.
    pub sll_ifindex: c_int,
    /// ARP hardware type.
    pub sll_hatype: u16,
    /// Packet type.
    pub sll_pkttype: u8,
    /// Address length.
    pub sll_halen: u8,
    /// Address.
    pub sll_addr: [u8; 8],
}

const WS_AF_INET6: u16 = ws::AF_INET6;

fn to_winsock_family(f: c_int) -> Option<c_int> {
    match f {
        AF_UNIX | AF_INET => Some(f),
        AF_INET6 => Some(c_int::from(WS_AF_INET6)),
        _ => None,
    }
}

/// Copies a Linux address, with the Winsock family number.
///
/// # Safety
/// `addr` must be valid for `len` bytes.
unsafe fn winsock_addr(addr: *const c_void, len: u32) -> Option<(sockaddr_storage, c_int)> {
    let n = usize::try_from(len).ok()?;
    if n < 2 || n > std::mem::size_of::<sockaddr_storage>() {
        return None;
    }
    // SAFETY: an all-zero storage is valid.
    let mut s: sockaddr_storage = unsafe { std::mem::zeroed() };
    // SAFETY: the caller's contract; `n` fits.
    unsafe { std::ptr::copy_nonoverlapping(addr.cast::<u8>(), (&raw mut s).cast::<u8>(), n) };
    let family = to_winsock_family(c_int::from(s.ss_family))?;
    s.ss_family = u16::try_from(family).ok()?;
    Some((s, c_int::try_from(n).ok()?))
}

/// Copies a Winsock address out, with the Linux family number.
///
/// # Safety
/// `addr` and `len` as for `getsockname(2)`.
unsafe fn linux_addr(s: &mut sockaddr_storage, n: c_int, addr: *mut c_void, len: *mut u32) {
    if s.ss_family == WS_AF_INET6 {
        s.ss_family = u16::try_from(AF_INET6).unwrap();
    }
    let n = u32::try_from(n).unwrap_or(0);
    // SAFETY: the caller's contract.
    unsafe {
        let room = *len;
        std::ptr::copy_nonoverlapping(
            (&raw const *s).cast::<u8>(),
            addr.cast::<u8>(),
            usize::try_from(room.min(n)).unwrap(),
        );
        *len = n;
    }
}

fn sock(fd: c_int) -> usize {
    handle(fd) as usize
}

fn wsa_fail() -> c_int {
    // SAFETY: plain call.
    set_errno(unsafe { WSAGetLastError() });
    -1
}

/// `socket`, with Linux families and the `SOCK_NONBLOCK`/`SOCK_CLOEXEC`
/// flags. Returns a descriptor.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    wick_wsa_startup();
    let Some(family) = to_winsock_family(domain) else {
        set_errno(crate::EAFNOSUPPORT);
        return -1;
    };
    let base = ty & !(SOCK_NONBLOCK | SOCK_CLOEXEC);
    let mut flags = WSA_FLAG_OVERLAPPED;
    if ty & SOCK_CLOEXEC != 0 {
        flags |= WSA_FLAG_NO_HANDLE_INHERIT;
    }
    // SAFETY: plain call.
    let s = unsafe { WSASocketW(family, base, protocol, std::ptr::null(), 0, flags) };
    if s == INVALID_SOCKET {
        return wsa_fail();
    }
    #[allow(clippy::cast_possible_truncation)]
    let fd = s as c_int;
    // SAFETY: our new descriptor.
    if ty & SOCK_NONBLOCK != 0
        && unsafe { crate::windows_fd::fcntl(fd, crate::F_SETFL, crate::O_NONBLOCK) } != 0
    {
        // SAFETY: closes our socket.
        unsafe { ws::closesocket(s) };
        return -1;
    }
    fd
}

/// `bind`.
///
/// # Safety
/// `addr` must be valid for `len` bytes.
pub unsafe fn bind(fd: c_int, addr: *const crate::sockaddr, len: u32) -> c_int {
    wick_wsa_startup();
    // SAFETY: the caller's contract.
    let Some((s, n)) = (unsafe { winsock_addr(addr.cast(), len) }) else {
        set_errno(crate::EINVAL);
        return -1;
    };
    // SAFETY: a valid address of `n` bytes.
    if unsafe { ws::bind(sock(fd), (&raw const s).cast(), n) } == SOCKET_ERROR {
        return wsa_fail();
    }
    0
}

/// `connect`.
///
/// # Safety
/// `addr` must be valid for `len` bytes.
pub unsafe fn connect(fd: c_int, addr: *const crate::sockaddr, len: u32) -> c_int {
    wick_wsa_startup();
    // SAFETY: the caller's contract.
    let Some((s, n)) = (unsafe { winsock_addr(addr.cast(), len) }) else {
        set_errno(crate::EINVAL);
        return -1;
    };
    // SAFETY: a valid address of `n` bytes.
    if unsafe { ws::connect(sock(fd), (&raw const s).cast(), n) } == SOCKET_ERROR {
        return wsa_fail();
    }
    0
}

/// `listen`.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn listen(fd: c_int, backlog: c_int) -> c_int {
    wick_wsa_startup();
    // SAFETY: plain call.
    if unsafe { ws::listen(sock(fd), backlog) } == SOCKET_ERROR {
        return wsa_fail();
    }
    0
}

/// `accept`. Returns a descriptor.
///
/// # Safety
/// `addr` and `len` may be null; otherwise as for `accept(2)`.
pub unsafe fn accept(fd: c_int, addr: *mut crate::sockaddr, len: *mut u32) -> c_int {
    wick_wsa_startup();
    // SAFETY: an all-zero storage is valid.
    let mut s: sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut n = c_int::try_from(std::mem::size_of_val(&s)).unwrap();
    // SAFETY: valid output buffers.
    let a = unsafe { ws::accept(sock(fd), (&raw mut s).cast(), &mut n) };
    if a == INVALID_SOCKET {
        return wsa_fail();
    }
    if !addr.is_null() && !len.is_null() {
        // SAFETY: the caller's contract.
        unsafe { linux_addr(&mut s, n, addr.cast(), len) };
    }
    #[allow(clippy::cast_possible_truncation)]
    let fd = a as c_int;
    fd
}

macro_rules! name_call {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        ///
        /// # Safety
        /// As for the libc function.
        pub unsafe fn $name(fd: c_int, addr: *mut crate::sockaddr, len: *mut u32) -> c_int {
            wick_wsa_startup();
            // SAFETY: an all-zero storage is valid.
            let mut s: sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut n = c_int::try_from(std::mem::size_of_val(&s)).unwrap();
            // SAFETY: valid output buffers.
            if unsafe { ws::$name(sock(fd), (&raw mut s).cast(), &mut n) } == SOCKET_ERROR {
                return wsa_fail();
            }
            // SAFETY: the caller's contract.
            unsafe { linux_addr(&mut s, n, addr.cast(), len) };
            0
        }
    };
}
name_call!(
    /// `getsockname`, with the Linux family number.
    getsockname
);
name_call!(
    /// `getpeername`, with the Linux family number.
    getpeername
);

// ---- memfd ----

/// `memfd_create` flag: close on exec (not inherited by children).
pub const MFD_CLOEXEC: core::ffi::c_uint = 1;
/// `memfd_create` flag: allow seals.
pub const MFD_ALLOW_SEALING: core::ffi::c_uint = 2;

/// `memfd_create`: a temporary file with no name that goes away with its
/// last handle, as the `memfd` crate's Windows backend creates (created
/// with `FILE_FLAG_DELETE_ON_CLOSE`, no sharing, marked temporary, and
/// unlinked at once with POSIX delete semantics), so the descriptor
/// supports `read`, `write`, `ftruncate` and `mmap` like a memfd.
///
/// `flags` may hold `MFD_CLOEXEC` and `MFD_ALLOW_SEALING`; seals are added
/// through the `memfd` crate (`fcntl(F_ADD_SEALS)` does not exist here and
/// fails). Other flags (`MFD_HUGETLB` and its sizes, `MFD_NOEXEC_SEAL`, ...)
/// ask for what this cannot give and fail with `EINVAL`. On other failures
/// the Windows error is the thread's last error.
///
/// # Safety
/// `name` must be a valid C string (it is not used).
pub unsafe fn memfd_create(_name: *const c_char, flags: core::ffi::c_uint) -> c_int {
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    use windows_sys::Win32::Foundation::{
        ERROR_FILE_EXISTS, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, DELETE, FILE_ATTRIBUTE_TEMPORARY, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_FLAG_DELETE_ON_CLOSE,
        FileDispositionInfoEx,
    };

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    if flags & !(MFD_CLOEXEC | MFD_ALLOW_SEALING) != 0 {
        set_errno(crate::EINVAL);
        return -1;
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(core::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
        lpSecurityDescriptor: core::ptr::null_mut(),
        bInheritHandle: i32::from(flags & MFD_CLOEXEC == 0),
    };
    let h = loop {
        let path = std::env::temp_dir().join(std::format!(
            "wick-memfd-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let wide: std::vec::Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: a valid path and attributes; the result is checked.
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE,
                0,
                &sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                core::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            break h;
        }
        // SAFETY: plain call.
        if unsafe { GetLastError() } != ERROR_FILE_EXISTS {
            return -1;
        }
    };
    // Unlink the name now. File systems without POSIX delete (FAT) keep it
    // until the last handle goes, which deletes it.
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: valid information of the right class and size.
    unsafe {
        SetFileInformationByHandle(
            h,
            FileDispositionInfoEx,
            (&raw const info).cast(),
            u32::try_from(core::mem::size_of_val(&info)).unwrap(),
        )
    };
    #[allow(clippy::cast_possible_truncation)]
    let fd = h as isize as c_int;
    fd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memfd_create() {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::windows::io::FromRawHandle;

        // SAFETY: a valid C string.
        let fd = unsafe { memfd_create(c"t".as_ptr(), MFD_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: a fresh handle we own.
        let mut f = unsafe { std::fs::File::from_raw_handle(handle(fd)) };
        f.write_all(b"wick").unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut s = std::string::String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "wick");
        // No name left in the temporary directory once created.
        let pid = std::format!("wick-memfd-{}-", std::process::id());
        let left = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(&pid))
            .count();
        assert_eq!(left, 0);
        // MFD_HUGETLB: not available.
        // SAFETY: as above.
        assert_eq!(unsafe { memfd_create(c"t".as_ptr(), 4) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(crate::EINVAL)
        );
    }

    #[test]
    fn test_syscall_prctl_ioctl() {
        // SAFETY: calls that fail or only read.
        unsafe {
            assert_eq!(syscall(SYS_io_uring_setup, 1, 0), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(crate::ENOSYS)
            );
            #[cfg(target_arch = "x86_64")]
            {
                assert_eq!(syscall(SYS_arch_prctl, 0x1022, 0), -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(crate::EINVAL)
                );
            }
            assert_eq!(prctl(PR_GET_SECCOMP), 0);
            assert_eq!(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), -1);
            assert_eq!(ioctl(0, BLKSSZGET, 0), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(crate::ENOTTY)
            );
        }
    }

    #[test]
    fn test_fallocate() {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::windows::io::AsRawHandle;
        let path = std::env::temp_dir().join(std::format!("wick-falloc-{}", std::process::id()));
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.write_all(&std::vec![0xaa; 1 << 20]).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let fd = f.as_raw_handle() as isize as c_int;
        // SAFETY: our descriptor.
        unsafe {
            assert_eq!(
                fallocate(
                    fd,
                    FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                    64 << 10,
                    128 << 10
                ),
                0
            );
            assert_eq!(
                fallocate(fd, FALLOC_FL_PUNCH_HOLE, 0, 4096),
                -1,
                "needs KEEP_SIZE"
            );
            assert_eq!(fallocate(fd, 0, 0, 2 << 20), 0);
            assert_eq!(fallocate(fd, FALLOC_FL_ZERO_RANGE, 0, 4096), 0);
        }
        assert_eq!(f.metadata().unwrap().len(), 2 << 20);
        let mut b = std::vec![0u8; 1 << 20];
        f.seek(SeekFrom::Start(0)).unwrap();
        f.read_exact(&mut b).unwrap();
        assert!(b[..4096].iter().all(|&x| x == 0));
        assert!(b[4096..64 << 10].iter().all(|&x| x == 0xaa));
        assert!(b[64 << 10..192 << 10].iter().all(|&x| x == 0), "punched");
        assert!(b[192 << 10..].iter().all(|&x| x == 0xaa));
        drop(f);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_socket_with_linux_families() {
        // SAFETY: socket calls on our descriptors and buffers.
        unsafe {
            let fd = socket(AF_INET6, crate::SOCK_STREAM | SOCK_CLOEXEC, 0);
            assert!(fd >= 0, "{}", std::io::Error::last_os_error());
            let mut a: sockaddr_storage = std::mem::zeroed();
            a.ss_family = u16::try_from(AF_INET6).unwrap();
            // [::1]:0
            let p = (&raw mut a).cast::<u8>();
            *p.add(8 + 15) = 1;
            assert_eq!(
                bind(fd, (&raw const a).cast(), 28),
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            assert_eq!(listen(fd, 1), 0);
            let mut out: sockaddr_storage = std::mem::zeroed();
            let mut n = 128u32;
            assert_eq!(getsockname(fd, (&raw mut out).cast(), &mut n), 0);
            assert_eq!(c_int::from(out.ss_family), AF_INET6);
            assert_eq!(n, 28);
            assert_eq!(socket(AF_PACKET, SOCK_RAW, 0), -1);
            assert_eq!(crate::close(fd), 0);
        }
    }
}
