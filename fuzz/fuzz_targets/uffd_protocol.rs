// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The kernel side of userfaultfd on macOS (`libc::wick_uffd`), driven as a
//! page fault handler process drives it: requests on a channel sent over the
//! userfaultfd with `HELLO`, and any records on the userfaultfd itself.
//!
//! The requests name pages of an arena (some of them `PROT_NONE` guard
//! pages) or any address. After each reply the arena must be in the state
//! Linux's `UFFDIO_*` would leave it in: a copy or zeropage fills exactly the
//! missing pages it reports, with the data sent, and touches nothing else;
//! a register makes the pages that were not resident missing; an unregister
//! makes them ordinary zero pages. When the handler closes its descriptors,
//! the userfaultfd is released and no descriptor it was sent stays open.
//!
//! Registering memory outside the arena would make the fuzzer's own memory
//! fault, so registers name the arena, or lengths past the address space
//! (as Linux's, a register takes what is mapped in a range and leaves its
//! holes out).

#![no_main]

#[cfg(not(target_os = "macos"))]
libfuzzer_sys::fuzz_target!(|_data: &[u8]| {});

#[cfg(target_os = "macos")]
libfuzzer_sys::fuzz_target!(|input: imp::Input| imp::run(input));

#[cfg(target_os = "macos")]
mod imp {
    use std::os::raw::c_int;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use arbitrary::Arbitrary;
    use libc::wick_uffd::{self, proto};

    /// Pages of the arena that are readable and writable, then `PROT_NONE`.
    const DATA_PAGES: usize = 6;
    const GUARD_PAGES: usize = 2;
    const PAGES: usize = DATA_PAGES + GUARD_PAGES;

    #[derive(Arbitrary, Debug)]
    pub enum Addr {
        /// A page of the arena (or just past it), maybe plus some bytes.
        Page(u8, bool),
        Raw(u64),
    }

    #[derive(Arbitrary, Debug)]
    pub enum Len {
        Pages(u8),
        Bytes(u16),
        Raw(u64),
    }

    #[derive(Arbitrary, Debug)]
    pub enum Op {
        Register {
            page: u8,
            len: Len,
        },
        Unregister {
            at: Addr,
            len: Len,
        },
        /// The data sent is `fill`; its length is `len` if that is below a
        /// MiB, else nothing is sent and the channel is closed.
        Copy {
            at: Addr,
            len: Len,
            dontwake: bool,
            fill: u8,
        },
        Zeropage {
            at: Addr,
            len: Len,
            dontwake: bool,
        },
        Wake {
            at: Addr,
            len: Len,
        },
        Other {
            op: u64,
            a: u64,
            b: u64,
            c: u64,
        },
        /// Records on the userfaultfd, with `fds` descriptors attached.
        Records {
            words: Vec<[u64; 4]>,
            fds: u8,
        },
        /// Bytes on the channel that are not a whole request; the channel is
        /// closed after them.
        Partial {
            bytes: Vec<u8>,
        },
    }

    #[derive(Arbitrary, Debug)]
    pub struct Input {
        ops: Vec<Op>,
    }

    struct Arena {
        base: u64,
        ps: u64,
    }

    fn arena() -> &'static Arena {
        static ARENA: OnceLock<Arena> = OnceLock::new();
        ARENA.get_or_init(|| {
            // SAFETY: plain calls.
            let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
            // SAFETY: a new anonymous mapping.
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    PAGES * ps as usize,
                    libc::PROT_NONE,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                    -1,
                    0,
                )
            };
            assert_ne!(base, libc::MAP_FAILED);
            Arena {
                base: base as u64,
                ps,
            }
        })
    }

    fn open_fds() -> usize {
        std::fs::read_dir("/dev/fd").unwrap().count()
    }

    impl Arena {
        /// Fresh pages: none resident, none registered.
        fn reset(&self) {
            // SAFETY: replaces the arena mapping, which only this target uses.
            unsafe {
                let p = libc::mmap(
                    self.base as *mut _,
                    PAGES * self.ps as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                    -1,
                    0,
                );
                assert_eq!(p as u64, self.base);
                let guard = self.base + (DATA_PAGES as u64) * self.ps;
                let r = libc::mprotect(
                    guard as *mut _,
                    GUARD_PAGES * self.ps as usize,
                    libc::PROT_NONE,
                );
                assert_eq!(r, 0);
            }
        }

        fn page(&self, i: usize) -> u64 {
            self.base + i as u64 * self.ps
        }

        fn addr(&self, a: &Addr) -> u64 {
            match a {
                Addr::Page(i, off) => {
                    self.page(usize::from(*i) % (PAGES + 2)) + if *off { 8 } else { 0 }
                }
                Addr::Raw(v) => *v,
            }
        }

        fn len(&self, l: &Len) -> u64 {
            match l {
                Len::Pages(n) => u64::from(*n % (PAGES as u8 + 2)) * self.ps,
                Len::Bytes(b) => u64::from(*b),
                Len::Raw(v) => *v,
            }
        }

        /// The data pages: missing, or their contents. Pages that are not
        /// resident are not read, which would make them resident.
        fn snapshot(&self) -> Vec<Option<Vec<u8>>> {
            (0..DATA_PAGES)
                .map(|i| {
                    let p = self.page(i);
                    if wick_uffd::is_missing(p) {
                        return None;
                    }
                    if !self.resident(i) {
                        return Some(vec![0; self.ps as usize]);
                    }
                    // SAFETY: a data page of the arena that is not missing.
                    Some(
                        unsafe { std::slice::from_raw_parts(p as *const u8, self.ps as usize) }
                            .to_vec(),
                    )
                })
                .collect()
        }

        /// Whether data page `i` is resident.
        fn resident(&self, i: usize) -> bool {
            let mut v = 0u8;
            // SAFETY: one page of the arena, one byte of output.
            let r = unsafe { libc::mincore(self.page(i) as *mut _, self.ps as usize, &mut v) };
            assert_eq!(r, 0);
            v & 1 != 0
        }

        /// The data pages in `[start, start + len)`.
        fn pages_in(&self, start: u64, len: u64) -> impl Iterator<Item = usize> + '_ {
            let end = start.saturating_add(len);
            (0..DATA_PAGES).filter(move |&i| self.page(i) >= start && self.page(i) < end)
        }
    }

    fn record(w: [u64; 4]) -> Vec<u8> {
        w.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    /// libFuzzer's `-timeout` is a `SIGALRM` every second.
    fn interrupted() -> bool {
        std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
    }

    fn write_all(fd: c_int, buf: &[u8]) -> bool {
        let mut done = 0;
        while done < buf.len() {
            // SAFETY: writes from a valid buffer.
            let n = unsafe { libc::write(fd, buf[done..].as_ptr().cast(), buf.len() - done) };
            if n < 0 && interrupted() {
                continue;
            }
            if n <= 0 {
                return false;
            }
            done += n as usize;
        }
        true
    }

    fn read_reply(fd: c_int) -> (i64, u64) {
        let mut buf = [0u8; proto::RECORD];
        let mut done = 0;
        while done < buf.len() {
            // SAFETY: reads into a valid buffer.
            let n = unsafe { libc::read(fd, buf[done..].as_mut_ptr().cast(), buf.len() - done) };
            if n < 0 && interrupted() {
                continue;
            }
            assert!(n > 0, "no reply to a request");
            done += n as usize;
        }
        let w = |i: usize| u64::from_le_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap());
        (w(0) as i64, w(1))
    }

    fn socketpair() -> [c_int; 2] {
        let mut fds = [0; 2];
        // SAFETY: creates two descriptors.
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let one: c_int = 1;
        for fd in fds {
            // SAFETY: a plain socket option.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&one as *const c_int).cast(),
                    4,
                )
            };
        }
        fds
    }

    /// Sends `bytes` on `fd` with descriptors `fds` attached.
    fn send_with_fds(fd: c_int, bytes: &[u8], fds: &[c_int]) {
        let space = if fds.is_empty() {
            0
        } else {
            // SAFETY: a size computation.
            unsafe { libc::CMSG_SPACE((fds.len() * 4) as u32) as usize }
        };
        let mut control = vec![0u8; space];
        // SAFETY: a msghdr with one buffer and the descriptors.
        let n = unsafe {
            let mut iov = libc::iovec {
                iov_base: bytes.as_ptr() as *mut _,
                iov_len: bytes.len(),
            };
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if !fds.is_empty() {
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = space as _;
                let c = libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN((fds.len() * 4) as u32) as _;
                std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c).cast(), fds.len());
            }
            loop {
                let n = libc::sendmsg(fd, &msg, 0);
                if n >= 0 || !interrupted() {
                    break n;
                }
            }
        };
        assert_eq!(n, bytes.len() as isize);
    }

    pub fn run(input: Input) {
        let arena = arena();
        let ps = arena.ps;
        arena.reset();
        // libFuzzer opens descriptors of its own between runs (a symbolizer).
        let fds = open_fds();
        let (_, user) = wick_uffd::create(wick_uffd::FEATURE_EVENT_REMOVE, false, true).unwrap();
        let [chan, theirs] = socketpair();
        send_with_fds(user, &record([proto::HELLO, 0, 0, 0]), &[theirs]);
        // Kept open until the serving thread certainly holds its copy (see
        // the userfaultfd crate's `Channel`).
        let mut sent = vec![theirs];

        for op in input.ops.iter().take(48) {
            let before = arena.snapshot();
            let resident: Vec<bool> = (0..DATA_PAGES).map(|i| arena.resident(i)).collect();
            // Pages this request may fill, with what.
            let mut fill: Option<(u64, u64, u8)> = None;
            let head = match op {
                Op::Register { page, len } => {
                    let start = arena.page(usize::from(*page) % PAGES);
                    let len = match len {
                        // Within the arena.
                        Len::Pages(n) => {
                            u64::from(*n) % (PAGES as u64 - (start - arena.base) / ps + 1) * ps
                        }
                        Len::Bytes(b) => u64::from(*b),
                        // Past the address space (128 TiB less 32 MiB).
                        Len::Raw(v) => (v | 1 << 47) & !(ps - 1),
                    };
                    [proto::OP_REGISTER, start, len, 0]
                }
                Op::Unregister { at, len } => {
                    [proto::OP_UNREGISTER, arena.addr(at), arena.len(len), 0]
                }
                Op::Copy {
                    at,
                    len,
                    dontwake,
                    fill: f,
                } => {
                    let (a, l) = (arena.addr(at), arena.len(len));
                    fill = Some((a, l, *f));
                    [proto::OP_COPY, a, l, u64::from(*dontwake)]
                }
                Op::Zeropage { at, len, dontwake } => {
                    let (a, l) = (arena.addr(at), arena.len(len));
                    fill = Some((a, l, 0));
                    [proto::OP_ZEROPAGE, a, l, u64::from(*dontwake)]
                }
                Op::Wake { at, len } => [proto::OP_WAKE, arena.addr(at), arena.len(len), 0],
                Op::Other { op, a, b, c } => {
                    if (1..=5).contains(op) {
                        continue;
                    }
                    [*op, *a, *b, *c]
                }
                Op::Records { words, fds } => {
                    let words = &words[..words.len().min(4)];
                    let bytes: Vec<u8> = words.iter().flat_map(|w| record(*w)).collect();
                    if bytes.is_empty() {
                        continue;
                    }
                    // Fresh descriptors; ours are closed, so a channel the
                    // serving thread takes from them closes at once.
                    let mut theirs = Vec::new();
                    for _ in 0..*fds % 3 {
                        let [a, b] = socketpair();
                        // SAFETY: our end of the pair.
                        unsafe { libc::close(a) };
                        theirs.push(b);
                    }
                    send_with_fds(user, &bytes, &theirs);
                    sent.extend(theirs);
                    continue;
                }
                Op::Partial { bytes } => {
                    let n = bytes.len() % proto::RECORD;
                    write_all(chan, &bytes[..n]);
                    break;
                }
            };
            let mut msg = record(head);
            if head[0] == proto::OP_COPY {
                if head[2] >= 1 << 20 {
                    // More data than is sent: the serving thread must give up
                    // when the channel closes.
                    write_all(chan, &msg);
                    break;
                }
                msg.resize(msg.len() + head[2] as usize, fill.unwrap().2);
            }
            assert!(write_all(chan, &msg));
            let (result, count) = read_reply(chan);
            for fd in sent.drain(..) {
                // SAFETY: descriptors sent to the serving thread, which holds its copies.
                unsafe { libc::close(fd) };
            }
            check(arena, head, result, count, &before, &resident, fill);
        }

        // The handler goes away: the userfaultfd is released and every
        // descriptor it was sent is closed.
        // SAFETY: descriptors of this run.
        unsafe {
            libc::close(chan);
            libc::close(user);
            for fd in sent {
                libc::close(fd);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while open_fds() != fds {
            assert!(
                Instant::now() < deadline,
                "{} descriptors open after the userfaultfd was released, {} before",
                open_fds(),
                fds
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    const KNOWN: [i32; 7] = [
        libc::EINVAL,
        libc::ENOENT,
        libc::EEXIST,
        libc::EAGAIN,
        libc::EBUSY,
        libc::ENOMEM,
        libc::EPERM,
    ];

    #[allow(clippy::too_many_arguments)]
    fn check(
        arena: &Arena,
        head: [u64; 4],
        result: i64,
        count: u64,
        before: &[Option<Vec<u8>>],
        resident: &[bool],
        fill: Option<(u64, u64, u8)>,
    ) {
        let ps = arena.ps;
        let [op, a, b, _] = head;
        let after = arena.snapshot();
        let ok = result >= 0;
        if !ok {
            let e = (-result) as i32;
            assert!(KNOWN.contains(&e), "{head:x?}: errno {e}");
        }
        let aligned = a.is_multiple_of(ps) && b.is_multiple_of(ps) && b != 0;
        if ok || result == -(libc::EAGAIN as i64) {
            assert!(aligned, "{head:x?}: unaligned request accepted");
        }
        match op {
            proto::OP_COPY | proto::OP_ZEROPAGE => {
                let (dst, len, byte) = fill.unwrap();
                let filled = match result {
                    r if r >= 0 => {
                        assert_eq!(r as u64, len, "{head:x?}: count");
                        len
                    }
                    r if r == -(libc::EAGAIN as i64) => {
                        assert!(
                            count > 0 && count < len && count.is_multiple_of(ps),
                            "{head:x?}: partial count {count}"
                        );
                        count
                    }
                    _ => 0,
                };
                for i in 0..DATA_PAGES {
                    let p = arena.page(i);
                    if p >= dst && p < dst.saturating_add(filled) {
                        assert!(before[i].is_none(), "{head:x?}: page {i} was not missing");
                        let page = after[i].as_ref().expect("filled page still missing");
                        assert!(
                            page.iter().all(|&x| x == byte),
                            "{head:x?}: page {i} contents"
                        );
                    } else {
                        assert_eq!(before[i], after[i], "{head:x?}: page {i} changed");
                    }
                }
                // A partial fill stops at a page that was not missing.
                if result == -(libc::EAGAIN as i64)
                    && let Some(i) = arena.pages_in(dst.saturating_add(count), ps).next()
                {
                    assert!(before[i].is_some(), "{head:x?}: stopped at a missing page");
                }
                if result == -(libc::EEXIST as i64)
                    && let Some(i) = arena.pages_in(dst, ps).next()
                {
                    assert!(before[i].is_some(), "{head:x?}: EEXIST for a missing page");
                }
            }
            proto::OP_REGISTER => {
                for i in 0..DATA_PAGES {
                    let p = arena.page(i);
                    if ok && p >= a && p < a.saturating_add(b) {
                        // Pages not resident are missing from now on.
                        assert_eq!(
                            after[i].is_none(),
                            !resident[i],
                            "{head:x?}: page {i} after register"
                        );
                        if let (Some(x), Some(y)) = (&before[i], &after[i]) {
                            assert_eq!(x, y, "{head:x?}: page {i} changed");
                        }
                    } else {
                        assert_eq!(before[i], after[i], "{head:x?}: page {i} changed");
                    }
                }
            }
            proto::OP_UNREGISTER => {
                for i in 0..DATA_PAGES {
                    let p = arena.page(i);
                    if ok && p >= a && p < a.saturating_add(b) {
                        // Missing pages become zero pages.
                        let page = after[i].as_ref().expect("unregistered page still missing");
                        match &before[i] {
                            Some(x) => assert_eq!(x, page, "{head:x?}: page {i} changed"),
                            None => assert!(
                                page.iter().all(|&x| x == 0),
                                "{head:x?}: page {i} not zero"
                            ),
                        }
                    } else {
                        assert_eq!(before[i], after[i], "{head:x?}: page {i} changed");
                    }
                }
            }
            _ => {
                assert!(
                    op == proto::OP_WAKE || result == -(libc::EINVAL as i64),
                    "{head:x?}: unknown request accepted"
                );
                assert_eq!(before, &after[..], "{head:x?}: pages changed");
            }
        }
    }
}
