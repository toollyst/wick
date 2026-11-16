// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The macOS backend: an unlinked POSIX shared memory object.
//!
//! macOS sizes a POSIX shared memory object once and never resizes it, so the
//! size seals hold as soon as the object has a size (also `SealShrink` alone
//! forbids growing).
//!
//! A huge page memfd (`MFD_HUGETLB`, 2 MiB) is an object named
//! `libc::HUGE_MEMFD_PREFIX` (`/fcmH.<pid>.<random>`): the compatibility `libc`'s
//! `mmap` reads the name back (`proc_pidfdinfo`) and maps it in 2 MiB pages
//! as hugetlbfs does, with or without `MAP_HUGETLB`, refusing an offset off
//! a huge page and a size that is not whole huge pages (which hugetlbfs
//! refuses at `ftruncate`; here it is caught at the mapping). Other huge
//! page sizes have no pool here (`ENODEV`, as Linux without one).
//!
//! An object maps shared only. Linux maps a memfd private copy-on-write, as
//! any file. macOS refuses a shared memory object's mapping without
//! `MAP_SHARED` (xnu-12377.1.9 bsd/kern/posix_shm.c `pshm_mmap` :763 to
//! :765), and a copy of it would not follow the object until its own write
//! as Linux's mapping does. So the compatibility `libc`'s `mmap` refuses a
//! private mapping of one with `EINVAL` before it changes anything
//! (`test_a_private_mapping_of_a_shared_memory_object_is_refused`).
//! Firecracker maps its memfds shared only (`memfd_backed` in
//! vstate/memory.rs, `IovDeque`).

use std::ffi::CString;
use std::fs::File;
use std::io;
pub(crate) use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

/// The mode an object is made with: none, so that while it has its name
/// no process but root opens it again; its maker's descriptor, opened by
/// the call that made it, reads, writes and maps it all the same (an open
/// of an existing object asks the mode, its making does not: xnu-12377.121.6
/// bsd/kern/posix_shm.c :534, `pshm_access` :781 to :791).
const MODE: libc::c_uint = 0;

/// How many fresh names a creation tries when the name it drew is taken.
/// One taken is already a draw of 64 random bits matching another's; a
/// second in a row says something else is wrong.
const NAME_TRIES: u32 = 8;

/// A name of `prefix`, this process's pid and 64 random bits from
/// `getentropy` (16 hex digits): at most 28 bytes, under macOS's 31
/// (`PSHMNAMLEN`), and under the sandbox profile's prefixes for this
/// process (`/fcm.<pid>.`, `/fcmH.<pid>.`, vmm's sandbox.rs `shm_rule`).
/// No predictable name stands in when `getentropy` fails: the error is
/// returned.
fn random_name(prefix: &str) -> io::Result<CString> {
    let mut bits = [0u8; 8];
    // SAFETY: a buffer of 8 bytes, under getentropy's 256.
    if unsafe { libc::getentropy(bits.as_mut_ptr().cast(), bits.len()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let name = format!("{prefix}{}.{:016x}", std::process::id(), u64::from_ne_bytes(bits));
    CString::new(name).map_err(io::Error::other)
}

/// A test's look at an object's name ([`NAMED`]).
#[cfg(test)]
type Hook = Box<dyn FnMut(&std::ffi::CStr)>;

#[cfg(test)]
std::thread_local! {
    /// Run between the object's making and its unlink, with its name, on
    /// the thread that makes it (tests only: a product build keeps no name).
    static NAMED: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) };
}

/// A new, unlinked object; a huge page one if `huge` (2 MiB).
///
/// It has a name from its `shm_open` to its `shm_unlink`, the next call:
/// random, so that no process can take it first or guess it, and of mode
/// 0, so that no process but root can open it meanwhile (SECURITY.md,
/// Fixed defects, "macOS: a memfd and a waiter mirror had a name anyone
/// could guess while they were made"). A huge page object's name is its
/// mark, kept after the unlink (the compatibility `libc`'s `mmap` reads it).
pub(crate) fn create(cloexec: bool, huge: Option<crate::HugetlbSize>) -> io::Result<File> {
    let prefix = match huge {
        None => "/fcm.",
        Some(crate::HugetlbSize::Huge2MB) => libc::HUGE_MEMFD_PREFIX,
        Some(size) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("no {size:?} huge pages on this host (ENODEV on Linux without such a pool)"),
            ));
        }
    };
    let mut tries = 0;
    let (fd, cname) = loop {
        let cname = random_name(prefix)?;
        // SAFETY: valid C string; the result is checked.
        let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, MODE) };
        if fd >= 0 {
            break (fd, cname);
        }
        let e = io::Error::last_os_error();
        tries += 1;
        if e.raw_os_error() != Some(libc::EEXIST) || tries == NAME_TRIES {
            return Err(e);
        }
    };
    #[cfg(test)]
    NAMED.with_borrow_mut(|hook| {
        if let Some(hook) = hook {
            hook(&cname);
        }
    });
    // SAFETY: valid C string. Unlinking keeps the object alive through `fd` only.
    if unsafe { libc::shm_unlink(cname.as_ptr()) } != 0 {
        let e = io::Error::last_os_error();
        // SAFETY: the descriptor opened above.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if !cloexec {
        // SAFETY: descriptor we own.
        unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    }
    // SAFETY: fresh descriptor we own.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The OS already refuses to resize a sized object.
pub(crate) fn seal_size(_file: &File, _grow: bool) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) fn check_size_sealed(file: &File, size: u64) {
    file.set_len(size * 2).unwrap_err();
    file.set_len(size / 2).unwrap_err();
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    /// Names that `create` gave before its names were random:
    /// `<prefix><pid>.<n>` for a counter `n` from 0, shared by both prefixes.
    /// Every test of this crate makes fewer memfds than this.
    const OLD_NAMES: u32 = 512;

    /// Makes `name` (mode 0600, as any process could) and closes it, the
    /// name keeping the object; false if it exists.
    fn take(name: &CStr) -> bool {
        // SAFETY: a NUL-terminated name; the result is checked.
        let fd = unsafe { libc::shm_open(name.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600) };
        if fd >= 0 {
            // SAFETY: the descriptor just opened.
            unsafe { libc::close(fd) };
        }
        fd >= 0
    }

    /// Unlinks what [`take`] made.
    fn give_back(taken: Vec<CString>) {
        for name in taken {
            // SAFETY: a name `take` made.
            unsafe { libc::shm_unlink(name.as_ptr()) };
        }
    }

    /// Another process (of any uid: the names are one namespace, xnu-12377.121.6
    /// bsd/kern/posix_shm.c `pshm_cache_search` :223, and `O_EXCL` fails on an
    /// existing name whoever made it, :492 to :495; here the same uid, which
    /// shows the same refusal) that makes the names a memfd of this process
    /// would take does not stop its creation: the name is random. With the
    /// counter's names (`/fcm.<pid>.<n>`, `/fcmH.<pid>.<n>`) the creation
    /// failed with `EEXIST`. The names taken are given back before any check.
    #[test]
    fn test_a_memfds_name_cannot_be_taken_first() {
        let pid = std::process::id();
        println!("SWEEP-PID {pid}");
        let mut taken = Vec::new();
        for prefix in ["/fcm.", libc::HUGE_MEMFD_PREFIX] {
            for n in 0..OLD_NAMES {
                let name = CString::new(format!("{prefix}{pid}.{n}")).unwrap();
                if take(&name) {
                    taken.push(name);
                }
            }
        }
        let made = [None, Some(crate::HugetlbSize::Huge2MB)].map(|huge| create(true, huge).map(drop));
        let count = taken.len();
        give_back(taken);
        assert_eq!(count, 2 * OLD_NAMES as usize, "names this process's memfds had taken");
        for (made, huge) in made.into_iter().zip(["plain", "huge page"]) {
            made.unwrap_or_else(|e| panic!("a {huge} memfd with its old names taken: {e}"));
        }
    }

    /// While a memfd's object has its name, between `create`'s `shm_open`
    /// and its `shm_unlink`, a second `shm_open` of that name by the same
    /// uid is `EACCES`, for reading and writing and for reading (mode 0;
    /// root alone opens it: `pshm_access`, posix_shm.c :781 to :791), and
    /// its maker's descriptor reads, writes and maps it; the name is
    /// `<prefix><pid>.` and 16 hex digits, and opens nothing after. With mode
    /// 0600 the second open read and wrote the guest's memory.
    #[test]
    fn test_a_memfd_opens_for_no_one_else_while_it_has_its_name() {
        // SAFETY: no arguments.
        assert_ne!(unsafe { libc::geteuid() }, 0, "root opens any object; run as a user");
        for (prefix, huge) in [("/fcm.", None), (libc::HUGE_MEMFD_PREFIX, Some(crate::HugetlbSize::Huge2MB))] {
            let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let into = seen.clone();
            NAMED.set(Some(Box::new(move |name: &CStr| {
                let mut opens = Vec::new();
                for flags in [libc::O_RDWR, libc::O_RDONLY] {
                    // SAFETY: a NUL-terminated name; a descriptor opened is closed.
                    let fd = unsafe { libc::shm_open(name.as_ptr(), flags, 0) };
                    opens.push(if fd >= 0 {
                        // SAFETY: as above.
                        unsafe { libc::close(fd) };
                        Ok(())
                    } else {
                        Err(io::Error::last_os_error().raw_os_error())
                    });
                }
                into.borrow_mut().push((name.to_owned(), opens));
            })));
            let file = create(true, huge);
            NAMED.set(None);
            let file = file.unwrap();
            let seen = seen.take();
            assert_eq!(seen.len(), 1, "{prefix}: one object made");
            let (name, opens) = &seen[0];
            assert_eq!(opens, &[Err(Some(libc::EACCES)), Err(Some(libc::EACCES))], "{prefix}: {name:?} opened again");
            let name = name.to_str().unwrap();
            let rest = name.strip_prefix(&format!("{prefix}{}.", std::process::id())).unwrap_or_else(|| panic!("{name}"));
            assert!(rest.len() == 16 && rest.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
            // SAFETY: as above; nothing is made (no O_CREAT).
            assert_eq!(unsafe { libc::shm_open(seen[0].0.as_ptr(), libc::O_RDONLY, 0) }, -1, "{name} after the unlink");
            let size = if huge.is_some() { 2 << 20 } else { 16384 };
            file.set_len(size).unwrap();
            // SAFETY: a shared mapping of the object just sized; unmapped below.
            let p = unsafe {
                libc::mmap(std::ptr::null_mut(), size as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, file.as_raw_fd(), 0)
            };
            assert_ne!(p, libc::MAP_FAILED, "{}", io::Error::last_os_error());
            // SAFETY: the mapping just made.
            unsafe {
                p.cast::<u8>().write(7);
                assert_eq!(p.cast::<u8>().read(), 7);
                libc::munmap(p, size as usize);
            }
        }
    }
}
