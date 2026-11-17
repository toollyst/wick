// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! A program the jailer runs in Firecracker's place (tools/macos/jailer-test.py,
//! stage `uffd-charge`): under the jail's memory limit, a jetsam limit on the
//! process's phys_footprint, it registers `MIB` MiB with a userfaultfd, fills
//! every page with `UFFDIO_COPY`, then reads every page through the memory, as
//! a VMM reads guest memory a handler filled, and prints its footprint after
//! each step (`UFFD-CHARGE` lines). Linux's memory cgroup charges each page
//! once; a fill that left a second mapping of the pages behind (the alias
//! `wick_uffd` filled through until its fills had views of their own) doubled
//! it, and a limit of 1.5 times `MIB` killed the process at the read. With
//! `second-view` the probe maps the memory a second time after the fill and
//! reads it there too, as that alias did: the stage's control that the limit
//! kills at that footprint. It carries the jailer's hand-over mark
//! (vmm::ext::jail::HANDOVER_MARK), so the jailer runs it.
//!
//! Usage: uffd_charge_probe MIB [second-view]

#[cfg(target_os = "macos")]
mod probe {
    use std::ptr;

    #[used]
    static HANDOVER_MARK: [u8; 24] = *b"wick-jail-handover:v1\0\0\0";

    extern "C" {
        static mach_task_self_: u32;
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

    /// The process's phys_footprint, what a jetsam limit holds, in MiB.
    fn footprint_mib() -> u64 {
        // SAFETY: plain data filled by the call.
        let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        // SAFETY: a V4 buffer for the V4 flavour, of this process.
        let r = unsafe {
            libc::proc_pid_rusage(libc::getpid(), libc::RUSAGE_INFO_V4, ptr::from_mut(&mut info).cast())
        };
        assert_eq!(r, 0, "proc_pid_rusage: {}", std::io::Error::last_os_error());
        info.ri_phys_footprint >> 20
    }

    fn read_all(mem: u64, len: u64, page: u64) -> u64 {
        // SAFETY: pages of a mapping of `len` bytes at `mem`.
        (0..len / page).map(|i| u64::from(unsafe { ptr::read_volatile((mem + i * page) as *const u8) })).sum()
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        let mib: u64 = args.get(1).and_then(|a| a.parse().ok()).expect("usage: uffd_charge_probe MIB [second-view]");
        let second_view = args.get(2).map(String::as_str) == Some("second-view");
        // SAFETY: sysconf has no preconditions.
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let len = mib << 20;
        let start = footprint_mib();
        println!("UFFD-CHARGE start {start} MiB");
        // SAFETY: a fresh anonymous mapping, kept to the end.
        let mem = unsafe {
            libc::mmap(ptr::null_mut(), len as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0)
        };
        assert_ne!(mem, libc::MAP_FAILED);
        let mem = mem as u64;
        let (ctx, _user) = libc::wick_uffd::create(0, false, true).unwrap();
        libc::wick_uffd::register(ctx, mem, len).unwrap();
        let data = vec![1u8; page as usize];
        for i in 0..len / page {
            // SAFETY: `data` holds a page.
            assert_eq!(unsafe { libc::wick_uffd::copy(ctx, data.as_ptr(), mem + i * page, page, false) }, Ok(page));
        }
        println!("UFFD-CHARGE filled {} MiB", footprint_mib() - start);
        if second_view {
            let (mut view, mut cur, mut max) = (0u64, 0, 0);
            // SAFETY: maps the same pages a second time, anywhere (VM_FLAGS_ANYWHERE, shared, VM_INHERIT_NONE).
            let kr = unsafe { mach_vm_remap(mach_task_self_, &mut view, len, 0, 1, mach_task_self_, mem, 0, &mut cur, &mut max, 1) };
            assert_eq!(kr, 0, "mach_vm_remap");
            assert_eq!(read_all(view, len, page), len / page);
            println!("UFFD-CHARGE second view read {} MiB", footprint_mib() - start);
        }
        assert_eq!(read_all(mem, len, page), len / page);
        println!("UFFD-CHARGE read {} MiB", footprint_mib() - start);
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
