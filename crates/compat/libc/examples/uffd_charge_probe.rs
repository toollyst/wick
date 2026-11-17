// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! A program the jailer runs in Firecracker's place (tools/macos/jailer-test.py,
//! stage `uffd-charge`), under the jail's memory limit, a jetsam limit on the
//! process's phys_footprint. It prints its footprint after each step
//! (`UFFD-CHARGE` lines). It carries the jailer's hand-over mark
//! (vmm::ext::jail::HANDOVER_MARK), so the jailer runs it.
//!
//! - `uffd_charge_probe MIB`: registers `MIB` MiB with a userfaultfd, fills
//!   every page with `UFFDIO_COPY`, then reads every page through the memory,
//!   as a VMM reads guest memory a handler filled. Linux's memory cgroup
//!   charges each page once; a fill that left a second mapping of the pages
//!   behind (the alias `wick_uffd` filled through until its fills had views of
//!   their own) doubled it, and a limit of 1.5 times `MIB` killed the process
//!   at the read.
//! - `uffd_charge_probe MIB second-view`: the same, with the memory mapped a
//!   second time after the fill and read there too, as that alias did: the
//!   stage's control that the limit kills at that footprint.
//! - `uffd_charge_probe MIB purgeable`: the same as the first, on a purgeable
//!   (nonvolatile) object the process owns (mach_vm_allocate
//!   `VM_FLAGS_PURGABLE`), which is charged by the object, whatever maps its
//!   pages: each page counts at its fill, as on Linux, so `MIB` past the limit
//!   is killed during the fills (the design being made for guest memory).
//! - `uffd_charge_probe MIB views-only`: `MIB` MiB of anonymous memory
//!   (mach_vm_allocate) written only through mappings of it made for each
//!   16 MiB and removed after (mach_vm_remap, mach_vm_deallocate), never
//!   through its own mapping: the pages stay resident and are charged to no
//!   one, so a process can hold them past its limit (SECURITY.md, Not at
//!   parity yet; docs/macos-memory-limit.md). Also prints what the task's
//!   own reports count (task_info TASK_VM_INFO, proc_pidinfo
//!   PROC_PIDTASKINFO, proc_pid_rusage's resident size) and the host's
//!   internal pages before and after (host_statistics64), which do count
//!   them, host-wide. With a third argument `then-read`, the memory is then read
//!   through its own mapping, which counts it.
//! - `uffd_charge_probe MIB reusable`: `MIB` MiB of anonymous memory, each
//!   16 MiB written, made reusable (`MADV_FREE_REUSABLE`, which takes it out of
//!   the footprint) and written again (which does not count it again): the
//!   second way to hold pages that count nowhere.
//! - `uffd_charge_probe MIB views-only-purgeable`: the same on a purgeable
//!   (nonvolatile) object, which is charged by the object: past the limit the
//!   process is killed.

#[cfg(target_os = "macos")]
mod probe {
    use std::ptr;

    #[used]
    static HANDOVER_MARK: [u8; 24] = *b"wick-jail-handover:v1\0\0\0";

    const MIB: u64 = 1 << 20;
    const VM_FLAGS_ANYWHERE: i32 = 1;
    const VM_FLAGS_PURGABLE: i32 = 2;
    const VM_INHERIT_NONE: u32 = 2;
    const HOST_VM_INFO64: i32 = 4;
    /// `vm_statistics64`'s size in 32-bit words, and the word holding
    /// `internal_page_count` (mach/vm_statistics.h).
    const HOST_VM_INFO64_COUNT: u32 = 40;
    const INTERNAL_PAGE_COUNT_WORD: usize = 35;

    unsafe extern "C" {
        static mach_task_self_: u32;
        fn mach_host_self() -> u32;
        fn host_statistics64(host: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
        fn task_info(task: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
        fn mach_vm_allocate(target: u32, address: *mut u64, size: u64, flags: i32) -> i32;
        fn mach_vm_deallocate(target: u32, address: u64, size: u64) -> i32;
        fn mach_vm_remap(
            target: u32,
            address: *mut u64,
            size: u64,
            mask: u64,
            flags: i32,
            src_task: u32,
            src_address: u64,
            copy: i32,
            cur: *mut i32,
            max: *mut i32,
            inheritance: u32,
        ) -> i32;
    }

    /// proc_pid_rusage of this process.
    fn rusage() -> libc::rusage_info_v4 {
        // SAFETY: plain data filled by the call.
        let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        // SAFETY: a V4 buffer for the V4 flavour, of this process.
        let r = unsafe {
            libc::proc_pid_rusage(libc::getpid(), libc::RUSAGE_INFO_V4, ptr::from_mut(&mut info).cast())
        };
        assert_eq!(r, 0, "proc_pid_rusage: {}", std::io::Error::last_os_error());
        info
    }

    /// The process's phys_footprint, what a jetsam limit holds, in MiB.
    fn footprint_mib() -> u64 {
        rusage().ri_phys_footprint / MIB
    }

    /// The host's internal (anonymous) pages, in MiB.
    fn host_internal_mib(page: u64) -> u64 {
        let mut info = [0i32; HOST_VM_INFO64_COUNT as usize];
        let mut count = HOST_VM_INFO64_COUNT;
        // SAFETY: a buffer of `count` words for this flavour.
        let kr = unsafe { host_statistics64(mach_host_self(), HOST_VM_INFO64, info.as_mut_ptr(), &mut count) };
        assert_eq!(kr, 0, "host_statistics64");
        u64::from(info[INTERNAL_PAGE_COUNT_WORD] as u32) * page / MIB
    }

    /// What the task's own reports count, in MiB: task_info TASK_VM_INFO's
    /// phys_footprint, internal and resident_size (mach/task_info.h: the
    /// 64-bit words 18, 6 and 2), proc_pidinfo PROC_PIDTASKINFO's resident
    /// size and proc_pid_rusage's resident size.
    fn task_counts() -> String {
        const TASK_VM_INFO: i32 = 22;
        let mut info = [0u64; 64];
        let mut count = 128u32;
        // SAFETY: a buffer of `count` 32-bit words for this flavour, of this task.
        let kr = unsafe { task_info(mach_task_self_, TASK_VM_INFO, info.as_mut_ptr().cast(), &mut count) };
        assert_eq!(kr, 0, "task_info");
        // SAFETY: plain data filled by the call.
        let mut pti: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
        // SAFETY: a buffer of `size` bytes for this flavour, of this process.
        let n = unsafe { libc::proc_pidinfo(libc::getpid(), libc::PROC_PIDTASKINFO, 0, ptr::from_mut(&mut pti).cast(), size) };
        assert_eq!(n, size, "proc_pidinfo");
        format!(
            "task_vm_info phys_footprint {} internal {} resident {}, proc_pidinfo resident {}, rusage resident {}",
            info[18] / MIB,
            info[6] / MIB,
            info[2] / MIB,
            pti.pti_resident_size / MIB,
            rusage().ri_resident_size / MIB
        )
    }

    /// A second mapping of `[at, at + len)`, shared, anywhere.
    fn view(at: u64, len: u64) -> u64 {
        let (mut view, mut cur, mut max) = (0u64, 0, 0);
        // SAFETY: maps pages of this process's own a second time.
        let kr = unsafe {
            mach_vm_remap(mach_task_self_, &mut view, len, 0, VM_FLAGS_ANYWHERE, mach_task_self_, at, 0, &mut cur, &mut max, VM_INHERIT_NONE)
        };
        assert_eq!(kr, 0, "mach_vm_remap");
        view
    }

    fn read_all(mem: u64, len: u64, page: u64) -> u64 {
        // SAFETY: pages of a mapping of `len` bytes at `mem`.
        (0..len / page).map(|i| u64::from(unsafe { ptr::read_volatile((mem + i * page) as *const u8) })).sum()
    }

    fn fill_and_read(len: u64, page: u64, start: u64, second_view: bool, purgeable: bool) {
        let mem = if purgeable {
            let mut mem = 0u64;
            // SAFETY: allocates `len` bytes anywhere, kept to the end.
            let kr = unsafe { mach_vm_allocate(mach_task_self_, &mut mem, len, VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE) };
            assert_eq!(kr, 0, "mach_vm_allocate");
            mem
        } else {
            // SAFETY: a fresh anonymous mapping, kept to the end.
            let mem = unsafe {
                libc::mmap(ptr::null_mut(), len as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0)
            };
            assert_ne!(mem, libc::MAP_FAILED);
            mem as u64
        };
        let (ctx, _user) = libc::wick_uffd::create(0, false, true).unwrap();
        libc::wick_uffd::register(ctx, mem, len).unwrap();
        let data = vec![1u8; page as usize];
        for i in 0..len / page {
            // SAFETY: `data` holds a page.
            assert_eq!(unsafe { libc::wick_uffd::copy(ctx, data.as_ptr(), mem + i * page, page, false) }, Ok(page));
            if (i + 1) % (16 * MIB / page) == 0 {
                println!("UFFD-CHARGE filling: {} MiB filled, footprint {} MiB", (i + 1) * page / MIB, footprint_mib() - start);
            }
        }
        println!("UFFD-CHARGE filled {} MiB", footprint_mib() - start);
        if second_view {
            assert_eq!(read_all(view(mem, len), len, page), len / page);
            println!("UFFD-CHARGE second view read {} MiB", footprint_mib() - start);
        }
        assert_eq!(read_all(mem, len, page), len / page);
        println!("UFFD-CHARGE read {} MiB", footprint_mib() - start);
    }

    fn views_only(len: u64, page: u64, start: u64, purgeable: bool, then_read: bool) {
        let host_before = host_internal_mib(page);
        let mut mem = 0u64;
        let flags = VM_FLAGS_ANYWHERE | if purgeable { VM_FLAGS_PURGABLE } else { 0 };
        // SAFETY: allocates `len` bytes anywhere, kept to the end.
        assert_eq!(unsafe { mach_vm_allocate(mach_task_self_, &mut mem, len, flags) }, 0, "mach_vm_allocate");
        let chunk = 16 * MIB;
        let mut off = 0;
        while off < len {
            let n = chunk.min(len - off);
            let v = view(mem + off, n);
            // SAFETY: the view's `n` bytes.
            unsafe { ptr::write_bytes(v as *mut u8, 0x5a, n as usize) };
            // SAFETY: the view made above, used by no one else.
            assert_eq!(unsafe { mach_vm_deallocate(mach_task_self_, v, n) }, 0, "mach_vm_deallocate");
            off += n;
            println!("UFFD-CHARGE written through views {} MiB: footprint {} MiB", off / MIB, footprint_mib() - start);
        }
        let host_after = host_internal_mib(page);
        println!(
            "UFFD-CHARGE views gone: footprint {} MiB ({}), host internal pages {:+} MiB",
            footprint_mib() - start,
            task_counts(),
            host_after as i64 - host_before as i64
        );
        if !then_read {
            return;
        }
        assert_eq!(read_all(mem, len, page), 0x5a * (len / page));
        println!("UFFD-CHARGE then read through its own mapping: footprint {} MiB ({})", footprint_mib() - start, task_counts());
    }

    fn reusable(len: u64, start: u64) {
        // SAFETY: a fresh anonymous mapping, kept to the end.
        let mem = unsafe {
            libc::mmap(ptr::null_mut(), len as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0)
        };
        assert_ne!(mem, libc::MAP_FAILED);
        let chunk = 16 * MIB;
        let mut off = 0;
        while off < len {
            let n = chunk.min(len - off) as usize;
            let at = (mem as u64 + off) as *mut u8;
            // SAFETY: `n` bytes of the mapping above, then the same range.
            unsafe {
                ptr::write_bytes(at, 0x5a, n);
                assert_eq!(libc::madvise(at.cast(), n, libc::MADV_FREE_REUSABLE), 0, "madvise");
                ptr::write_bytes(at, 0xa5, n);
            }
            off += n as u64;
            println!("UFFD-CHARGE written, made reusable, written again {} MiB: footprint {} MiB", off / MIB, footprint_mib() - start);
        }
        println!("UFFD-CHARGE reusable: footprint {} MiB ({})", footprint_mib() - start, task_counts());
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        let mib: u64 = args.get(1).and_then(|a| a.parse().ok()).expect("usage: uffd_charge_probe MIB [MODE]");
        let mode = args.get(2).map(String::as_str).unwrap_or("");
        let then_read = args.get(3).map(String::as_str) == Some("then-read");
        // SAFETY: sysconf has no preconditions.
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let start = footprint_mib();
        println!("UFFD-CHARGE start {start} MiB");
        match mode {
            "" => fill_and_read(mib * MIB, page, start, false, false),
            "second-view" => fill_and_read(mib * MIB, page, start, true, false),
            "purgeable" => fill_and_read(mib * MIB, page, start, false, true),
            "views-only" => views_only(mib * MIB, page, start, false, then_read),
            "views-only-purgeable" => views_only(mib * MIB, page, start, true, then_read),
            "reusable" => reusable(mib * MIB, start),
            other => panic!("uffd_charge_probe: unknown mode {other}"),
        }
        println!("UFFD-CHARGE done");
    }
}

#[cfg(target_os = "macos")]
fn main() {
    probe::main();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("uffd_charge_probe: macOS only");
    std::process::exit(2);
}
