# Architecture

wick makes Firecracker a **microVM runner controlled through the same API on
Linux, macOS (Apple silicon) and Windows**. The details live in code comments
and in the `wick:` comments of the patches; this document describes the
structure and how it is built.

## Boundary

```
sandbox manager ──(OCI-like spec)──▶ adapter (separate repository) ──(Firecracker API)──▶ wick
```

- **wick**: a runner binary whose Firecracker API (REST over a Unix socket,
  `--config-file`, the vsock UDS convention) means the same on all three hosts.
- **The adapter**: OCI interpretation, image → rootfs, lifecycle mapping, guest
  agent.
- Extensions added here are general features any user of a runner can use
  (host capability query, consistent errors for unsupported features, ...).

## Repository layout

```
lib/firecracker/      upstream Firecracker, a submodule pinned at patches/base
patches/              the patch series applied to it (series, base, *.patch)
                      and wick's release number (version)
overlay/vmm/          modules compiled into upstream's vmm crate
    ext/              extension point and host sandbox      (vmm::ext)
    platform/         host facility interfaces and backends (vmm::platform)
crates/compat/        compatibility builds of Linux-only dependencies
crates/ext/           wick-ext: wick's features behind vmm::ext
crates/version/       wick-version: the version the binaries report
crates/fs/            host folder sharing, a workspace of its own (docs/design-fs.md): the VMM↔server frames
tools/                setup, patch workflow, generators, Linux tests against upstream and boot test, macOS run/test/boot and jailer tests, vhost-user-blk test backend, Windows boot and jailer tests and probes, upstream's integration tests on macOS and Windows, release, fuzzing
fuzz/                 fuzz targets for wick's own code: a crate of its own, outside upstream's workspace
docs/                 the documentation (docs/README.md is the index)
```

`tools/setup.sh` checks out lib/firecracker at the release in `patches/base`
and applies the series as commits on a local branch `wick`. Cargo always runs
in lib/firecracker: it is the workspace, and its manifest (patched) lists
`crates/compat/*`, `crates/ext` and `crates/version` as members, so there is
one workspace, one `Cargo.lock` and one set of lints.

Code that is new rather than a change to an upstream file lives outside the
submodule. The overlay modules are declared from upstream's `vmm/src/lib.rs`
with `#[path = "../../../../../overlay/vmm/..."]`, so they are part of the vmm
crate (`crate::` paths work) while their files belong to wick. The patches
therefore only change existing upstream files: 55 feature patches touching 88
files.

## Layers

```
firecracker binary, vmm   (upstream source + patches/)
   │
   ├─ vmm::platform            host facility interfaces (overlay/vmm/platform)
   │    ├─ async_io, fs, net   interfaces: the semantics of the Linux API upstream used
   │    ├─ vnet                what the kernel did, OS-independent (TUN's virtio-net header handling)
   │    ├─ linux/              Linux backend = the kernel API upstream used (io_uring, ...)
   │    ├─ macos/              macOS backend = the same semantics on macOS facilities
   │    └─ windows/            Windows backend = the same semantics on Win32
   │
   ├─ vmm::ext ──▶ wick-ext    wick features (extension point)
   │
   └─ external crates ([patch.crates-io] in lib/firecracker/Cargo.toml; micro_http,
      a git dependency upstream, by path in the crates that use it)
        libc, vmm-sys-util, memfd, userfaultfd, kvm-ioctls, kvm-bindings,
        vm-memory, event-manager, vhost, micro_http → crates/compat/<crate>
            Linux : re-exports the original crate from the same git tag (micro_http:
                    a git revision), unchanged
            macOS : libc and vmm-sys-util are the original plus the Linux-only items
                    on macOS facilities (and vmm-sys-util's terminal, whose
                    set_non_block takes a revoked terminal as Linux's hung-up one); memfd, userfaultfd and kvm-ioctls are the same
                    API on macOS facilities (kvm-ioctls → Hypervisor.framework);
                    kvm-bindings, vm-memory, event-manager, vhost and micro_http are
                    the original crate
            Windows: the same API on Win32 (kvm-ioctls → Windows Hypervisor Platform)
        polling (by path from the Windows vmm-sys-util) → crates/compat/polling
            Linux, macOS: empty, with no dependency (nothing of wick's uses it there,
                and a build compiles upstream's units with upstream's features)
            Windows: polling 3.11.0's source, its waitable removal fixed and its
                waits registered again without an allocation (below)
```

## How it is built

1. **Find the Linux dependency and give it an interface.** Where upstream calls
   a Linux kernel facility directly, `vmm::platform` gets an interface (trait +
   backend types). Its semantics are those of the Linux API upstream used (for
   example `async_io` is io_uring's submission/completion model, its
   restrictions and its queue limits).
2. **One backend per OS.** The Linux backend is upstream's code (io_uring,
   holes in ext4/tmpfs); the macOS and Windows backends implement the same
   semantics with that OS's facilities. Interface tests live in
   `platform::<iface>::tests` and run against every host's backend.
3. **Upstream changes are patches.** Calling the interface from upstream code
   is a change to an upstream file, so it goes into a feature patch with a
   `wick:` comment (CONTRIBUTING.md).
4. **What can be solved below an external crate's API goes into a
   compatibility crate.** A crate API such as `kvm_ioctls::VcpuFd::run()` is
   implemented with the same semantics by the compatibility crate: what KVM
   did in the kernel (irqfd, MMIO decode, PSCI, GIC, timers, dirty tracking,
   handle lifetime and `EBADF`, error meanings such as `ENOEXEC`). Linux-only
   libc functions are implemented with the same names and semantics
   (`fallocate`, `madvise(DONTNEED)`), and so are kernel defaults a program
   relies on without asking: an AF_UNIX stream starts with Linux's send
   buffer (the compatibility `libc` defines `socket` and `socketpair`). What the kernel did stays where the
   kernel was (the compatibility `libc`). For example, the kernel side of
   userfaultfd (`libc::wick_uffd`) catches missing pages with `PROT_NONE` and
   a signal on the host and stage-2 protection in the guest, sleeps until the
   handler fills them, and fills a page before a system call (`read`, `pread`,
   `recv`, `write`, ...) touches it, as Linux's `copy_to_user` and `copy_from_user`
   would (their fault reaches `handle_userfault` through mm/memory.c
   `do_anonymous_page`, for a userfaultfd made with `user_mode_only(false)`,
   as upstream makes it; `test_system_calls_wait_for_missing_pages`). The HVF backend
   calls into it as KVM's `get_user_pages` would. And when the libc replaces
   the pages of a range (`madvise(DONTNEED)` of private memory, a `MAP_FIXED`
   mapping), the backend unmaps the range from stage 2 for the duration
   (`libc::wick_guest`), as Linux's MMU notifier zaps KVM's stage-2 entries
   (virt/kvm/kvm_main.c `kvm_mmu_notifier_invalidate_range_start`, arch/arm64/kvm/mmu.c
   `kvm_unmap_gfn_range`; `test_replaced_pages_are_reported_to_the_guest_hooks`):
   Hypervisor.framework maps physical pages, not host addresses, so the guest
   would otherwise keep the old pages.
5. **wick features go through the extension point.** Upstream calls `vmm::ext`
   from a few fixed places, and `wick-ext` implements the features
   (`PUT /extensions/{name}`, the config file's `extensions` section). It has
   none yet: every extension request is refused as unknown and nothing is
   attached at boot (`crates/ext`, `test_unknown_extension_is_rejected`).
6. **No pretending.** If a host lacks a facility, wick builds the same
   semantics itself: io_uring → worker-thread queues, seccomp-BPF → Seatbelt,
   SSBD → `PSTATE.SSBS`, holes APFS fills → restored with `F_PUNCHHOLE`, TAP →
   vmnet or Unix sockets with TUN's checksum/TSO/UFO done in user space, ITS →
   the GIC's GICv2m MSI frame, userfaultfd → the kernel side above. Only what
   the hardware or OS physically cannot do is an error, and the roadmap's
   status table says so.

### Memory calls on registered memory (macOS)

The compatibility `libc` keeps a userfaultfd's registration through the calls
that change memory as Linux keeps it (`libc::wick_uffd`). Each such call on memory a userfaultfd has registered,
against Linux v6.12:

| Call | Linux | wick on macOS | Test |
| --- | --- | --- | --- |
| `mprotect` | the vma's protection changes and its registration stays (mm/mprotect.c `mprotect_fixup` :603, `vma_modify_flags` :664 and `vm_flags_reset` :677, nothing of `vm_userfaultfd_ctx`); an access the protection refuses is a `SIGSEGV` with no event (arch/arm64/mm/fault.c `do_page_fault` :590 to :595), one it allows to a missing page faults to the userfaultfd | the same (`protecting`): present pages take the protection, missing ones stay `PROT_NONE` so that they still fault, and every registered page has the protection recorded as asked, which a missing page takes once it is filled, or unregistered, or its userfaultfd released; an access the asked protection refuses goes on to the process's own `SIGSEGV` or `SIGBUS` handler with no event (`asked_allows`; an instruction fetch needs `PROT_EXEC`, a write `PROT_WRITE`, a read any of the three, as on a processor without EPAN, :566) | `test_mprotect_of_registered_missing_pages_keeps_them_missing`, `test_a_filled_page_takes_the_protection_asked_while_it_was_missing`, `test_an_unregistered_page_takes_the_protection_asked_while_it_was_missing`, `test_a_released_page_takes_the_protection_asked_while_it_was_missing`, `test_a_registered_page_its_protection_denies_is_no_userfault`, `test_mprotect_of_a_filled_page_does_not_make_it_missing`, `test_plug_after_a_uffd_restore`, and in the VMM `test_a_slot_plugged_after_a_uffd_restore_still_faults_host_accesses` (patch 0053) |
| `madvise(MADV_DONTNEED)` | a remove event (`EVENT_REMOVE`) for each vma the walk reaches, then the pages are zapped and missing again (mm/madvise.c `madvise_walk_vmas` :1233, its call of each vma at :1274, `madvise_dontneed_free` :880, `userfaultfd_remove` :894); a page unregistered from the middle of a vma, or a protection asked of part of it, splits it, and a register next to a registered vma of the same userfaultfd merges with it | the same (`discarding`); the events follow the vmas Linux would have (`vmas`: runs of registered pages of one userfaultfd, page size and protection asked, across adjacent ranges), not the macOS map entries the discard went by; a fill writes through a view of the pages the memory has then (`fill_view`), read-write whatever their protection | `test_remove_event`, `test_a_discard_posts_one_remove_event_a_vma`, `test_a_slot_unplugged_and_plugged_again_is_filled` |
| `madvise(MADV_FREE)` | as `MADV_DONTNEED` for the userfaultfd: `madvise_vma_behavior` sends it to `madvise_dontneed_free` (mm/madvise.c :1046 to :1049), whose remove event (:894) comes first; then a hugetlb vma is `EINVAL` before that event (:864, checked at :888), and a vma that is not anonymous (shared memory, a file mapping) is `EINVAL` after it (`madvise_free_single_vma` :797); anonymous pages are freed lazily, and once freed they are missing | the same (`discarding_or_refusing`, `linux_items::madvise`), with the pieces taken in order and the events in address order; private anonymous pages are freed at once, the outcome Linux reaches once it frees them; macOS's own `MADV_FREE`, under which a freed registered page reads as zeros with no fault, is not used; Firecracker does not use `MADV_FREE` | `test_madv_free_of_registered_pages_makes_them_missing`, `test_madv_free_of_registered_pages_posts_a_remove_event`, `test_madv_free_of_registered_shared_memory_is_einval_after_its_remove_event`, `test_madv_free_of_a_huge_page_mapping_is_einval_with_no_remove_event`, `test_the_remove_events_of_one_discard_go_out_in_address_order`, `test_madv_free_frees_private_anonymous_memory_only` |
| `munmap`, `mmap(MAP_FIXED)` over registered memory | the registration goes with the vma in the same step (mm/vma.c `do_vmi_align_munmap` :1332; fs/userfaultfd.c `userfaultfd_unmap_prep` :811, called at mm/vma.c :1267; mm/mmap.c `__mmap_region` :1361 unmaps first, :1386); a cut of a hugetlb vma off its huge page boundaries is `EINVAL` before anything changes (mm/vma.c `__split_vma` :377 to :378); a thread waiting on such a page waits until its userfaultfd's `UFFDIO_WAKE`, which checks the range only (fs/userfaultfd.c `userfaultfd_wake` :1545 to :1575), or its release (:873), then runs its access again | the same (`unmapping`): `LOCK` is held from before the system call until the pages it reached are in no registration, so no fill or release runs in between; a range with no page left registered is freed; a fill of such a page is `ENOENT`; registered again, a fill writes in the new pages; a waiter as on Linux; a cut of a huge page is `EINVAL`. A change that touches no registered range runs without `LOCK`, so it and a register are ordered by two counts instead (`unlocked_change`): the change counts itself and then looks for a register under way, the register counts itself and then waits for the changes counted to end; of the two, at least one sees the other, so the register finds the memory as the change left it, as Linux's mm lock orders them (the same for `mprotect` and the discards). Firecracker unmaps its registered guest memory at teardown, while the VM's userfaultfd is still open (the guest regions' drop, lib/firecracker/src/vmm/src/vstate/memory.rs:308, before `uffd`, vstate/vm.rs:84 and :95), and the release after it changes nothing | `test_memory_unmapped_while_registered_leaves_no_registration_behind`, `test_a_release_after_the_memory_was_unmapped_leaves_a_new_mapping_as_it_is`, `test_an_unmapping_and_its_unregistration_are_one_step`, `test_memory_replaced_while_registered_is_in_no_registration`, `test_memory_replaced_while_registered_registers_anew`, `test_a_discard_of_memory_replaced_while_registered_is_ordinary`, `test_a_page_mapped_over_and_registered_again_is_filled_in_the_new_memory`, `test_a_waiter_on_memory_mapped_over_is_woken_by_its_userfaultfd`, `test_a_waiter_on_unmapped_memory_takes_its_own_fault_once_woken`, `test_a_cut_of_a_registered_huge_page_is_einval`, `test_a_register_racing_a_munmap_leaves_nothing_registered`, `test_a_register_racing_a_map_fixed_registers_the_new_memory`, `test_a_register_racing_an_mprotect_keeps_its_pages_missing`, `test_a_register_racing_a_discard_fills_the_new_pages` |
| `read`, `write`, `recv`, `send`, ... into or out of registered memory | the copy faults to the userfaultfd and waits (for a userfaultfd made with `user_mode_only(false)`) | the buffer's missing pages are faulted in first (`prefault`), and again on `EFAULT` | `test_system_calls_wait_for_missing_pages` |
| `UFFDIO_UNREGISTER` of part of a range | the vma is split and the rest stays registered (fs/userfaultfd.c `userfaultfd_unregister` :1413); the part unregistered is in no registration, and another userfaultfd registers it (`userfaultfd_register` refuses only a vma another context has, :1364 to :1366) | the same. A range stays one slot; each of its pages has an owner, the userfaultfd it is registered with or none (a byte a page: 64 KiB a GiB of 16 KiB pages), so an unregister takes no slot and cannot fail for want of one, however scattered (Firecracker's on-demand handler unregisters the range of every remove event and asserts it succeeds, examples/uffd/on_demand_handler.rs :93 to :94, many runs under a balloon). The part unregistered is in no registration, and any userfaultfd registers it; a register with a page of another userfaultfd anywhere in its range is `EBUSY` with nothing changed, as Linux checks every vma first (`userfaultfd_register` :1363 to :1366, before :1378); an unregister through any userfaultfd takes the pages and wakes their waiters, as 6.12's (`userfaultfd_unregister` :1500 to :1501, :1519; 6.17 refuses it with `EINVAL`). A fill whose destination holds a page that is not the caller's, unregistered or another userfaultfd's, is `ENOENT`, as Linux's destination must lie in one vma of the caller (mm/userfaultfd.c `validate_dst_vma` :23 to :37); one across pages the same userfaultfd registered again is one call, as over Linux's merged vma. The same userfaultfd registers its own range again, and part of a mapping is registered, as Linux's | `test_a_partial_unregister_keeps_the_rest_registered`, `test_a_fill_of_an_unregistered_page_is_enoent`, `test_the_same_userfaultfd_registers_its_range_again`, `test_part_of_a_mapping_is_registered`, `test_a_partial_unregister_frees_that_part_for_another_userfaultfd`, `test_more_scattered_unregisters_than_slots_all_succeed`, `test_a_register_ending_in_another_userfaultfds_page_changes_nothing`, `test_two_userfaultfds_in_one_slot_fill_discard_and_release_their_own`, `test_a_fill_lies_in_one_userfaultfds_pages`, `test_an_unregister_through_another_userfaultfd_wakes_and_takes_the_pages` |

**Events and their wakes.** On macOS a page fault's event is a record written into the userfaultfd's socket at the fault
(`wick_uffd::post`), and a socket cannot take a record back, where Linux's wake takes each waiting fault it wakes off
the queue, read or not (v6.12 fs/userfaultfd.c `userfaultfd_wake_function` :141). So each userfaultfd has a waiter
mirror: one 64-bit word per waiter slot (256) in a POSIX shared memory object of one page (a random name, mode `0400`,
unlinked once its two descriptors are open: SECURITY.md, Fixed defects), which the VMM maps
read-write and each reader maps read-only (`OP_MIRROR` on its request channel sends the read-only descriptor). A
waiter stores its tag (its slot, the slot's count of its waiters, a waiting bit) before it reads its page to validate
the fault, and its record carries the tag (event type 3; it was 1, so a reader from before fails on it loudly). Every
wake (an unregister, a fill with a wake, `UFFDIO_WAKE`, the release) clears the waiting bit of the exact tag it read,
and the waiter waits until its bit is clear. The `userfaultfd` crate returns a page fault only while the mirror's
word is still its tag, waiting, at one load of it: a record of a woken waiter is dropped however late it was written,
and a read with only such records reads again (a non-blocking one then returns none, as Linux's read may be `EAGAIN`
after poll said readable, :927 to :928 and :1069 to :1070). The tests are in SECURITY.md's entry. The mirror adds no system call: per fault a
slot count and two stores, per wake a load and a compare-and-swap, per read one load. Measured (a timed test kept out
of the tree: 8 threads read 512 registered pages each, a second object reads each event and fills its page; debug
build, the Mac in timing mode; three runs of 9 rounds, binaries from before and after the change and a control
interleaved in a rotated order): faults/s medians before 11895, 11865 and 11987, after 11768, 11612 and 11632, 1.1 to
3.0% lower and inside each run's spread (before 11218 to 12787, after 11063 to 12502). The control, the after binary
with 200 `getppid` calls added to each read, lowered the median to 9073 (22%), its range clear of the others: the
measurement resolves a cost of that size, not one of 1 to 3%.

On Windows (`windows_uffd`, `windows_mm`) the same, with the same test names, for the `munmap` and `MAP_FIXED` row:
`windows_mm`'s `munmap` and its `mmap` with `MAP_FIXED` go through `wick_uffd::unmapping`, which holds `LOCK` from
before the change until the pages it took (`windows_mm::uffd_pages_gone`: no longer in a view of the range's
sections: only the views `uffd_alias` made, or a move or swap put in their place, are marked a userfaultfd range's,
`Kind::View`'s `uffd`; `test_a_shared_mapping_over_registered_memory_is_in_no_registration`) are in no registration. A fill of
such a page is `ENOENT` with nothing filled, as is one whose destination holds an unregistered page (the last row);
a waiter waits on its userfaultfd, whose wake (the range checked as Linux's `validate_range` checks it, against
Windows' lowest and highest user addresses) or release ends the wait; a range is freed once all of its memory is
unmapped or mapped over. A change in no registration and a register are
ordered by the two counts as on macOS (`unlocked_change`; the register waits on `WaitOnAddress`, without a lock, and
no exception handler reaches it or any of the four changes). The register moves the memory into its sections
(`windows_mm::uffd_alias`), where Linux's moves nothing. While it does:
- it holds the memory against system calls copying into or out of it, waiting for those already in their copy, as
  the reclaim's move of a chunk does;
- the mapping is read-only for the copy, and the pages that hold memory (the working set) are read only after that,
  so none takes data unseen (`test_a_write_made_as_a_register_starts_its_move_is_kept`); a move that fails before
  the private allocation is given back gives the
  runs their protection back (`test_a_failed_registers_move_gives_the_memory_back_writable`), and a refusal of that
  ends the process at once, named (`test_a_refused_reopen_after_a_failed_move_ends_the_process`);
- the memory is marked moving until the register is done, so an access that faults on it meanwhile waits and runs
  again (`test_a_write_during_a_registers_move_lands_in_the_registered_memory`,
  `test_a_register_waits_for_a_call_copying_into_its_memory`). The mark is the reclaim's one (`MovingWindow`): a
  register opens it after taking `LOCK` and closes it before letting go, and the reclaim's thread opens it only
  while an asker holds `LOCK` for it, so two marks are never open at once (asserted in debug builds).

A register keeps each page's protection, as Linux's leaves the vma's, checks its range as Linux's `validate_range` does, and with nothing mapped in it is `ENOMEM` (nothing
at or above its start) or `EINVAL` (the first mapping past its end), as Linux's (fs/userfaultfd.c v6.1 :1323 to
:1330). For the `UFFDIO_UNREGISTER` row, the same (`windows_uffd::Range`): each page has an owner, the userfaultfd it is registered with or none, a byte a page in place of the registered bit (256 KiB a GiB of 4 KiB pages, against 32 KiB before), so an unregister takes no slot and cannot fail for want of one; a range's slot is kept, with its alias and record, until all of its memory is unmapped or mapped over, so its pages register again, with any userfaultfd: unregistered whole, released with their userfaultfd, or unregistered from a range's middle (`test_a_ranges_slot_is_kept_until_its_memory_is_unmapped`, `test_memory_unregistered_whole_registers_again`, `test_pages_of_a_released_userfaultfd_register_again`, `test_a_partial_unregister_frees_that_part_for_another_userfaultfd`, `test_register_and_unregister_as_linux`, `test_more_scattered_unregisters_than_slots_all_succeed`). A slot's per-page arrays belong to it and are taken again by the next range that fits, and a reader without the lock (the exception handler, the WHP run loop's fault) reads a slot whole by its sequence count (SECURITY.md, Fixed defects; `test_register_and_unmap_in_a_loop_keeps_the_array_count_flat`, `test_a_reader_between_its_generation_reads_starts_over`, `test_fault_reads_the_generation_after_the_page`). A page that left the registration while missing is missing again when registered again, its old content never shown (`test_a_page_pending_when_registered_again_is_missing_and_shows_nothing_old`, `test_a_swapped_chunk_registered_again_is_missing_and_filled`); a page touched since holds memory. In a process whose exception handler could not be added, a range is not on a reserved section and keeps no record: a page that left while missing was zeroed and opened, and holds memory when registered again; there the register closes the missing pages after it publishes the range, and a close that fails returns its error with the range unregistered whole, its slot kept so the memory registers again (`test_a_register_whose_close_fails_leaves_the_range_in_no_registration`), and a reopening that fails too ends the process with a line (`test_a_register_whose_reopening_fails_ends_the_process`). A register with a page of another userfaultfd anywhere in its range is `EBUSY` with nothing changed (`test_a_register_ending_in_another_userfaultfds_page_changes_nothing`); the same userfaultfd's register of its own pages changes nothing (`test_the_same_userfaultfd_registers_its_range_again`); an unregister through any userfaultfd takes the pages and wakes each owner's waiters, as 6.12's (6.17 refuses it with `EINVAL`; `test_an_unregister_through_another_userfaultfd_wakes_and_takes_the_pages`); a fill must lie in the caller's pages (`test_a_fill_lies_in_one_userfaultfds_pages`); a discard's remove event goes to each owner for its pages, and a release takes only its own (`test_two_userfaultfds_in_one_slot_fill_discard_and_release_their_own`). Windows Server 2022 20348 and 2025 26100; each failed on the code before, but `test_a_register_ending_in_another_userfaultfds_page_changes_nothing`, whose check the code before made too. Part of a
mapping is registered, as Linux's register splits the vma: the range is made over the whole private mapping that
holds it (`windows_mm::uffd_mapping_of`), which the register moves into its sections whole, under the guards above,
and only the part's pages get the userfaultfd as their owner and are missing if they hold no memory; every other page
is in no registration, as after an unregister of that part. A page holds memory if it is in the working set, or
committed, readable and not all zeros out of it (read once after the move closes the mapping, so a page trimmed to
the pagefile keeps its data, as a swapped page on Linux is not missing:
`test_a_written_page_out_of_the_working_set_is_not_missing_after_a_register`); such a page is copied, inside the part
and out. Outside the part any other page is pending in the range's record, so its
first access commits it, zeroed, and charges it, as a page Linux's split vma never faulted in. So a register of a part
charges what a register of the whole mapping charges (`test_part_of_a_mapping_is_registered`,
`test_memory_mapped_over_part_of_a_mapping_is_registered`,
`test_a_part_registered_is_charged_as_the_whole_mapping_would_be`,
`test_parts_of_a_mapping_register_with_two_userfaultfds`,
`test_an_munmap_of_a_registered_part_leaves_the_rest_of_the_mapping`,
`test_a_part_registered_keeps_the_rest_of_the_mapping_out_of_the_working_set`; first run: CI). Its cost: one copy of
each page of the mapping that holds memory, and one read of each committed page that is out of the working set. Not
as Linux on Windows (SECURITY.md, "Not at parity yet"): a page out of the working set that cannot be read
(`PROT_NONE`) or holds only zeros is taken as missing in the range; a range across two mappings is `EINVAL`; `MAP_FIXED` over part of a
registered mapping is `EINVAL`; a register that overlaps a registered range without lying inside it, or holds a page
of it that was unmapped or mapped over, is `EBUSY`; and a huge page mapping is not registered.

### The ioctls' checks (macOS)

Each `UFFDIO_*` request is checked as Linux v6.12 checks it, in its order, so that a handler sees the errno Linux
would give (`libc::wick_uffd`: `validate_range`, `register_ioctls`, `serve_copy`, `serve_request`, `fill`). A
request's data comes with it on the channel, so Linux's check of `UFFDIO_COPY`'s `src` has nothing to check here; a
refused copy's data is read all the same and the next request is answered as itself. The `uffd_protocol` fuzz target
holds every reply to these rules (CONTRIBUTING.md, "Fuzzing").

| Ioctl | Linux v6.12, in order (fs/userfaultfd.c unless named) | wick on macOS | Test |
| --- | --- | --- | --- |
| every range | the start on a page and not below `mmap_min_addr`, the length whole pages and not 0, the range below `task_size`, no wrap, else `EINVAL` (`validate_unaligned_range`, `validate_range` :1210 to :1237); `mmap_min_addr` is 64 KiB on arm64 and x86 hosts (security/Kconfig `LSM_MMAP_MIN_ADDR` :145 to :149, taken over the lower `DEFAULT_MMAP_MIN_ADDR` by security/min_addr.c :16 to :26) | the same, with `mmap_min_addr` 64 KiB and `task_size` `MACH_VM_MAX_ADDRESS` (macOS maps nothing below 64 KiB either; before, a range from one page up passed, a fill there was `ENOENT` and a wake took it) | `test_fill_modes_and_ranges_are_checked_as_linux`, `test_ranges_that_wrap`, `test_register_checks_the_range_as_linux` |
| `UFFDIO_REGISTER` | a mode of 0 or with an unknown bit `EINVAL`, `WP` and `MINOR` taken where the architecture has them (:1261 to :1280); the range; no vma `EINVAL`, a hugetlb start off its huge page `EINVAL`; then each vma: one that cannot be registered `EINVAL` (`vma_can_userfault`), one never writable `EPERM`, a hugetlb end off its huge page `EINVAL`, another context's `EBUSY` (:1364 to :1366); the reply's ioctls `UFFD_API_RANGE_IOCTLS`, without `UFFDIO_ZEROPAGE` where a vma is hugetlb (:1371 to :1372, :1387 to :1388), `WRITEPROTECT` and `CONTINUE` taken off a range registered for missing faults only | the mode is the `userfaultfd` crate's: missing faults only, `WP` and `MINOR` `EINVAL` (Firecracker registers for missing faults only); then Linux's order. The ioctls `WAKE`, `COPY` and `ZEROPAGE`, without `ZEROPAGE` where a `MAP_HUGETLB` mapping is in the range (before, `ZEROPAGE` for every range); Linux's `MOVE` and `POISON` are not here. Not Linux's: memory not readable and writable is `EPERM`, which fills would change (`register`), and a private file mapping is registered, as a memfd here is a file (`test_register_takes_a_private_file_mapping`) | `test_register_checks_the_range_as_linux`, `test_huge_page_ranges_fault_and_fill_whole_pages` |
| `UFFDIO_UNREGISTER` | the range; no vma `EINVAL`, a hugetlb start off its huge page `EINVAL`; each vma that cannot be registered `EINVAL`. Linux 6.17 also refuses a vma of another context, `EINVAL` ("userfaultfd: prevent unregistering VMAs through a different userfaultfd", an ABI change its author kept off the stable kernels) | 6.12's, wick's reference (the module documentation of `wick_uffd`) | `test_an_unregister_through_another_userfaultfd_wakes_and_takes_the_pages` |
| `UFFDIO_WAKE` | the range, nothing else (:1545) | the same | `test_fill_modes_and_ranges_are_checked_as_linux` |
| `UFFDIO_COPY` | a non-cooperative event not yet read (a remove event: `mmap_changing`) `EAGAIN` (:1588 to :1590); `src`; `dst` (:1602 to :1604); a mode bit other than `DONTWAKE` and `WP` `EINVAL` (:1606 to :1608); then mm/userfaultfd.c `mfill_atomic`: a destination not in one registered vma `ENOENT` (`uffd_mfill_lock` :733, `validate_dst_vma` :23 to :37), `mmap_changing` again, `WP` into a vma not registered for write-protect faults `EINVAL` (:762 to :763), a hugetlb range off its huge pages `EINVAL`; the first page present `EEXIST`, a later one `EAGAIN` with the count | the same order: a remove event under way and unread `EAGAIN`, its count `-EAGAIN` (`changing`), the range, an unknown mode bit `EINVAL` (before, ignored), `ENOENT`, `WP` `EINVAL`, as no range is registered for write-protect faults (before, ignored and the pages filled writable), huge page alignment, `EEXIST` and `EAGAIN`. A discard waits, without the lock, until each remove event it posts is read or the userfaultfd is released, as Linux's (`userfaultfd_remove` :783 to :793, `userfaultfd_event_wait_completion` :543 to :608): the kernel end sees what the reader has not read in its send space (XNU takes from a Unix stream sender's space what the peer has not read and gives it back as the peer reads, bsd/kern/uipc_usrreq.c `uipc_send` :670 to :676 and `uipc_rcvd` :469 to :470; a level kqueue `EVFILT_WRITE` reports the space, uipc_socket.c `filt_sowrite_common` :6741 and :6801, with both buffers 1 MiB and the low-water mark 1 byte), and each read wakes the wait (`EVFILT_WRITE` with `EV_CLEAR`). The two kqueues are made with the userfaultfd, as the run phase's sandbox allows `kevent` and makes no kqueue (`test_discards_run_under_the_run_phase_profile` discards under it). The pages go before the event here and after it on Linux, so fills are held from before the discard (`test_a_discard_waits_until_its_remove_event_is_read`, `test_a_discard_waiting_for_its_event_ends_at_the_release`; before, the discard posted and returned and fills went on). A discard the release ends returns only once the release has made the userfaultfd's ranges ordinary memory: the readers' close wakes its waiter, which then waits for the teardown (`destroy`, after it takes the mirror away), as Linux's release clears every vma's context under the mmap lock before it wakes the remove event's waiter (fs/userfaultfd.c, v6.12, `userfaultfd_release` :865 then :878), and the discard zaps ordinary memory after (`test_a_discard_woken_by_the_release_returns_after_its_teardown`, which holds the teardown back and fails on the earlier code with the page still missing; before, the waiter returned at the readers' close, and the page could still be missing for the VMM: 30 of 600 runs of the test above under load on an M1 Pro, and one failure of it on a CI macOS runner). Not Linux's, not done yet: (b) another userfaultfd's page is `ENOENT` where Linux fills it, as its `validate_dst_vma` asks only that the vma has a userfaultfd (`test_a_partial_unregister_frees_that_part_for_another_userfaultfd`); (c) two registers of adjacent memory are two ranges, and a fill across both `ENOENT`, where Linux merges the vmas (`test_two_adjacent_registers_are_two_ranges`) | `test_fill_modes_and_ranges_are_checked_as_linux`, `test_huge_page_ranges_fault_and_fill_whole_pages` |
| `UFFDIO_ZEROPAGE` | `mmap_changing` `EAGAIN` (:1644 to :1646); the range; a mode bit other than `DONTWAKE` `EINVAL` (:1654 to :1660); then as `UFFDIO_COPY`'s `mfill_atomic`, and a hugetlb vma `EINVAL`, there being no zero huge page (mm/userfaultfd.c :516 to :520) | the same: an unknown mode bit, `WP` among them, `EINVAL` (before, ignored); a `MAP_HUGETLB` range `EINVAL` (before, filled with zeros); the remove event's `EAGAIN` as `UFFDIO_COPY`'s; (b) and (c) as `UFFDIO_COPY`'s | `test_fill_modes_and_ranges_are_checked_as_linux`, `test_huge_page_ranges_fault_and_fill_whole_pages` |

### The ioctls' checks (Windows)

The same checks as macOS's table above, against Linux v6.12, in its order (`libc::wick_uffd` on Windows,
crates/compat/libc/src/windows_uffd.rs: `validate_range`, `range_of`, `register_ioctls`, `serve_copy`,
`serve_request`, `fill`). A copy's data comes with the request on the channel; it is checked before its data is read,
the data is read and copied a mebibyte at a time, and a refused copy's data is read and dropped, so the next request
is answered as itself (before, the whole length was allocated first). The checks of a request's mode, made where it
comes off a channel, are tested through one in the `userfaultfd` crate; the rest in the libc crate, under the same
test names.

| Ioctl | wick on Windows | Test |
| --- | --- | --- |
| every range | as Linux's: the start on a page and not below `mmap_min_addr`, the length whole pages and not 0, the range below `task_size`, else `EINVAL`. The bounds are Windows' own lowest and highest user addresses (`GetSystemInfo`); the lowest is 64 KiB, Linux's `mmap_min_addr` on arm64 and x86 hosts, and the test holds the two equal. Before, a fill checked only the alignment: below 64 KiB it was `ENOENT` | `test_fill_modes_and_ranges_are_checked_as_linux` (libc and `userfaultfd` crates), `test_register_errors` |
| `UFFDIO_REGISTER` | the mode is the `userfaultfd` crate's, missing faults only (`WP` and `MINOR` `EINVAL`), then Linux's order. The reply's ioctls `WAKE`, `COPY` and `ZEROPAGE` (`proto::RANGE_IOCTLS`), which the `userfaultfd` crate returns from the reply (before, it answered them whatever the reply said); Linux's hugetlb set never, as a huge page mapping is not registered here (`EINVAL`). Not Linux's (SECURITY.md, "Not at parity yet"): a range across two mappings is `EINVAL`, a register that overlaps a registered range without lying inside it is `EBUSY`; part of a mapping is registered, as Linux's | `test_fill_modes_and_ranges_are_checked_as_linux` (both crates), `test_register_errors`, `test_part_of_a_mapping_is_registered` |
| `UFFDIO_UNREGISTER` | 6.12's, as macOS's | `test_an_unregister_through_another_userfaultfd_wakes_and_takes_the_pages` |
| `UFFDIO_WAKE` | the range, nothing else, as Linux's | `test_fill_modes_and_ranges_are_checked_as_linux` (both crates) |
| `UFFDIO_COPY` | Linux's order: the range, a mode bit other than `DONTWAKE` and `WP` `EINVAL` (before, ignored), `ENOENT`, `WP` `EINVAL`, as no range is registered for write-protect faults (before, ignored and the pages filled writable), `EEXIST` and `EAGAIN` with the count, across the data's pieces as within one. A fill whose commit the job's limit refuses in part fills each page from its own bytes of the source (before, each part after the first was filled from the source's start: SECURITY.md, Fixed defects). Not Linux's, as on macOS: (a) no `EAGAIN` for an unread remove event, as `madvise` queues it and returns; (b) another userfaultfd's page is `ENOENT` where Linux fills it; (c) two registers of adjacent memory are two ranges, and a fill across both `ENOENT`, where Linux merges the vmas (here the two are two mappings, each a range of its own) | `test_fill_modes_and_ranges_are_checked_as_linux` (`userfaultfd` crate), `test_a_copy_of_many_pieces_fills_each_page_from_its_own_bytes`, `test_a_copy_whose_commit_is_refused_in_part_fills_each_page_from_its_own_bytes`; (a) `test_a_fill_while_a_remove_event_is_unread_fills`, (b) `test_a_partial_unregister_frees_that_part_for_another_userfaultfd`, (c) `test_two_adjacent_registers_are_two_ranges` |
| `UFFDIO_ZEROPAGE` | the range, then a mode bit other than `DONTWAKE`, `WP` among them, `EINVAL` (before, ignored); then as `UFFDIO_COPY`'s, with (a), (b) and (c). Linux's hugetlb `EINVAL` has nothing to refuse here, a huge page mapping not being registered | `test_fill_modes_and_ranges_are_checked_as_linux` (both crates), `test_two_adjacent_registers_are_two_ranges` |

## Hypervisors

| | Linux | macOS | Windows |
|---|---|---|---|
| Hypervisor | KVM | Hypervisor.framework (macOS 15+) | Windows Hypervisor Platform |
| Guest | x86_64, aarch64 | aarch64 | x86_64 |
| Interrupt controller | KVM vGIC / LAPIC | `hv_gic_*` GICv3 (GICv2m MSI frame instead of an ITS) | WHP LAPIC + user-space IOAPIC, 8259 PIC, 8254 PIT |
| Process hardening | seccomp-BPF, jailer | Seatbelt, upstream's jailer on macOS backends (`overlay/jailer/platform`) | a process mitigation profile, upstream's jailer on Windows backends: a jail drive, a restricted token, a Job Object |

Guest memory and the host's protection on macOS: KVM takes each stage-2 page through the host's vma (mm/gup.c,
v6.12, `check_vma_flags`), so a guest access follows the host's `mprotect`, `munmap` and `mmap` of slot memory, and
an `mprotect` or `munmap` invalidates stage 2 before it returns. Hypervisor.framework maps the physical pages behind
a host range at `hv_vm_map`, with the permissions given then, so the backend follows the host instead: every
`mprotect`, `munmap` and `mmap` of the compatibility libc calls the `protected` hook after it returned
(`crates/compat/libc/src/wick_guest.rs`), saying whether the range's mappings were replaced (`munmap`, a new
mapping: every slot page of it in stage 2 is then unmapped first, as a protection cannot tell a page from its
replacement), which reads the range's protection, with the userfaultfd's registrations,
under the VM's memory lock (`wick_uffd::host_protections`), brings each slot page to it (unmapped where the mapping
went, mapped with the new pages where one was made, the permissions changed otherwise; each run mapped with its final
permissions; one Hypervisor.framework call a run of pages, the lock held for the whole call: over 1 GiB about 4 ms
for an `mprotect` and 30 ms for an `munmap`, where Linux lets a waiting fault in between 32 MiB blocks, SECURITY.md), with no vCPU made to leave its run, as arm64 KVM makes none leave (its stage-2 change ends in a
broadcast TLB invalidation; relied on here is that `hv_vm_protect` and `hv_vm_unmap` have invalidated a running
vCPU's translations when they return, which hv_vm.h does not say and two tests measure: docs/PORTING.md); a guest abort is
checked against the page's host protection before a userfaultfd is asked (`VmInner::host_fault`). A stage-2
protect that takes a permission away and fails ends the process; one that gives a permission and fails is
`KVM_RUN`'s error (`protect_stage2`). Pages the libc
replaces (`MADV_DONTNEED`, `MAP_FIXED`) are unmapped for the change and mapped again after (`replace`). A call of the
system's own library on guest memory is not seen. The tests and what was measured before: SECURITY.md, "Fixed
defects".

PV steal time on macOS 27 (`crates/compat/kvm-ioctls/src/hvf/pvtime.rs`): KVM adds a vCPU thread's run delay to the
guest's stolen-time structure at the next entry after the scheduler runs the thread again. Hypervisor.framework
does not leave `hv_vcpu_run` when the host deschedules the thread, so the backend counts a vCPU's steal as the
time inside `run()` the thread was neither on a CPU nor waiting for an interrupt, and writes it at each entry; a
thread of each microVM reads its running vCPU threads' state every 2 ms (`thread_info`) and makes one kept off
its CPU for 1 ms leave the guest (`hv_vcpus_exit`), which the run loop enters again with the steal written. It
sleeps while no vCPU is in the guest and ends with the microVM. It is an ordinary thread: on a contended host it
waits for a CPU like the vCPUs, and the steal reaches the guest later by that wait (not closed). Cost and lateness:
docs/COMPATIBILITY.md, PV time.

A parked WHP partition (`crates/compat/kvm-ioctls/src/whp/park.rs`): a token whose only restricting SID is the
jail's own cannot open `\Device\VidExo`, so under it no partition can be made, while one made and set up before the
revert runs (docs/windows-jail-reach.md, option P). `park_partition` makes the process's partition early, with the
register probe that needs one of its own; `create_vm` takes it. Its properties that are fixed at set-up are the
host's, never a VM's (processor count `MAX_VCPUS`, features, XSAVE, the local APIC mode, the exit kinds); the four
WHP lets change after set-up are set by the VM as before. A dropped VM gives the partition back for the process's
next VM, as upstream lets a failed `InstanceStart` be tried again: its vCPUs deleted, its memory unmapped, time
running, the four properties written back, then every property and the mapped-page counters read back and compared
with the partition as parked. A difference, or a step that fails, deletes it, and the next VM is a named error
saying to start the process again, as is a second VM while the first holds it. The partition is never handed to
another process or jail. Firecracker does not park yet.

## The POSIX layer on Windows

Upstream and the external crates (`vmm-sys-util`, `event-manager`,
`micro_http`, `vm-memory`, `vhost`) stand on `RawFd`, epoll, eventfd,
`SCM_RIGHTS` and POSIX `libc`. On Windows the compatibility crates build those
semantics on Win32. The details are in the comments of each
`crates/compat/*/src/windows*` module.

- **fd = kernel handle value.** 64-bit Windows keeps handles in 32 bits: only
  the low 32 bits are significant, and a handle truncated to them sign-extends
  back (Microsoft, "Interprocess communication", 64-bit Windows programming).
  The system ignores a handle's low two bits, which ntdef.h leaves to
  applications as tag bits, and the kernel hands out handles that are
  multiples of 4 (Raymond Chen, The Old New Thing, 2005-01-21; Microsoft
  documents the tag bits, not the multiple). So `RawFd` (i32,
  sign-extended) is the `HANDLE` or `SOCKET` value itself, and 0, 1, 2 are the
  standard handles. Winsock promises neither for a `SOCKET` ("any value in the
  range 0 to INVALID_SOCKET-1", Socket Data Type): the system's providers
  return kernel handles (AFD), and a socket whose value does not fit in 32
  bits, or is 0, 1 or 2, is closed and refused with `EINVAL` where it is made
  or accepted, never truncated (`wick-os` and the compatibility libc,
  `test_a_socket_that_is_no_descriptor_is_refused_and_closed`; one std made
  panics when it becomes a descriptor, `test_socket_values_that_are_no_descriptor`).
  `wick-os` re-exports `std::os::{unix, fd}` on Unix and defines the same
  traits and types on handles on Windows (`AsRawFd`, `AsFd`, `OwnedFd`, ...;
  `unix::net`'s `UnixStream` and `UnixListener` are Winsock `AF_UNIX`).
  Upstream crate roots get `#[cfg(windows)] extern crate wick_std as std;` (a
  one-line patch), so `std::os::{unix, fd}` resolve to `wick-os`. `c_long` and
  `c_ulong` in `std::os::raw` are 64-bit on Windows too, to keep the layout of
  Linux kernel ABI bindings (`ifreq`, io_uring, ...). `std::io::stdin` and
  `Stdin` are `wick_os::stdio`'s on Windows: std's reads an empty
  non-blocking pipe as the end (`Ok(0)`), which the serial takes as its
  input closed; this one gives `EWOULDBLOCK` as Linux does, for a console
  with nothing typed too, and reads console input with std's console reader,
  a line typed in line input mode with one newline at its end
  (`test_a_pipe_reads_as_on_linux`,
  `test_a_console_without_characters_reads_as_eagain`,
  `test_serial_input_reads_an_emptied_pipe_as_eagain`,
  `test_a_line_ends_in_one_newline`). `lock()` is std's
  lock, for the terminal modes. `std::io::stdout` and `Stdout` are
  `wick_os::stdio`'s too: a non-blocking pipe takes 0 bytes of a write that
  does not fit in the room it has left, whatever the write's size (run
  43323860314), and std passes the 0 on (`WriteZero` from `write_all` and
  the buffer's flush); this one fails with `EWOULDBLOCK` as Linux does,
  after trying a write of more than 4096 bytes in pieces of 4096, which
  Linux takes as far as it fits
  (`test_a_write_that_does_not_fit_takes_nothing`,
  `test_a_large_write_is_taken_as_far_as_it_fits`; the compatibility
  `write` does the same; on a pipe made to hold less than 4096 bytes, which
  Linux has none of, the pieces are of what it holds:
  `test_a_write_larger_than_a_small_pipe_goes_in_pieces`), keeps std's
  1024-byte line buffer so a failed write leaves the same bytes buffered,
  reports a pipe with no reader as `BrokenPipe` with the `SIGPIPE` hook, and
  writes a console with std's writer (`test_a_full_pipe_writes_as_on_linux`,
  `test_the_serial_on_a_full_non_blocking_stdout`, which also runs on Linux
  and macOS). `print!`/`println!` keep std's own buffer, so they interleave
  with it by line; its buffer is not flushed at exit, where std's is. Libtest
  writes through std's, so the unit-test checker still gives tests a file.
  A named pipe given for the log, the metrics or a serial device's output
  is `wick_os::fifo`'s (`std::os::fifo`; overlay/vmm/ext/fifo.rs holds the
  type upstream's writers take): a Linux FIFO held read-write takes writes
  with no reader and holds 64 KiB, where a Windows pipe ends with its
  reader and holds what the reader gave it, so what the pipe does not take
  waits in the process, up to 64 KiB with the pipe's own, for that reader
  or the next of the name (`test_a_pipe_whose_reader_left_takes_writes_as_a_fifo_does`,
  `test_a_new_reader_of_the_name_gets_what_was_written_meanwhile`; its
  rules have no Windows call and their tests run on every host).
  `std::fs`'s opening calls (`OpenOptions::open`, `read`, `write`, `copy`,
  `read_dir`, ...) fail with `EMFILE` past the jail's `no-file` limit, as the
  compat libc's descriptor calls do (`libc::wick_nofile`: a count of the
  process's handles; std's own `File::open` is not shadowed).
- **errno = Win32/WSA codes**, chosen so that the `io::ErrorKind` mapping
  matches Linux (`EPERM`=`WSAEACCES`, `EAGAIN`=`EWOULDBLOCK`,
  `ENOTTY`=`ERROR_INVALID_FUNCTION`, ...). A code Windows gives beside one of
  them with the same meaning is mapped to it (`libc::wick_errno_from_win32`:
  `ERROR_PATH_NOT_FOUND` is `ENOENT`, `ERROR_OUTOFMEMORY` `ENOMEM`, ...), so
  upstream's comparisons with `libc::E*` match; the WHP backend's `HRESULT`s
  and every error the compat libc sets or leaves go through it. A code whose
  meaning depends on the call is mapped where it is made: `ERROR_NO_DATA`
  is `EPIPE` from a write and `EAGAIN` from a non-blocking read (std's own
  read of an empty non-blocking pipe returns `Ok(0)`, the end, as for a
  closed writer: std takes 232 as `BrokenPipe` and a read's `BrokenPipe` as
  the end, measured by the libc's `test_pipe`); `WSAESHUTDOWN` is `EPIPE`
  from a send and the end (0) from a recv, and `WSAECONNABORTED` (the peer
  gone) `EPIPE` from a send and `ECONNRESET` from a recv
  (`vmm-sys-util`'s `sock_ctrl_msg`); `ERROR_INVALID_FUNCTION` from
  `FSCTL_SET_ZERO_DATA` is `fallocate`'s `EOPNOTSUPP`.
- **Per-object state (`libc::wick_fd`).** State that belongs to the object a
  handle points to (eventfd counter, timer schedule, status flags such as
  `O_NONBLOCK`, memfd seal sections) is keyed by the fd value. A duplicate of
  the handle and `CompareObjectHandles` check that the fd still names the same
  object (`dup` copies the state, `close` removes it); state of fds that std
  closed is swept when the table grows. `ioctl(FIONBIO)` and
  `fcntl(F_SETFL)` set a socket's or pipe's wait mode and its `O_NONBLOCK`
  together, as Linux's set the open file's `f_flags` (v6.1
  fs/ioctl.c:341-361 `ioctl_fionbio`), and wick_os's `set_nonblocking` is
  that `ioctl`, as Linux's std's is, so `F_GETFL` shows it
  (`test_fionbio_sets_and_clears_o_nonblocking`,
  `test_a_socket_made_non_blocking_by_wick_os_is_o_nonblocking_to_the_libc`).
  The duplicate holds the object open, so whoever closes a descriptor that
  has state removes the state first: the libc's `close`, and wick_os's,
  which closes its own sockets; a socket wick_os made non-blocking stayed
  open past its `closesocket` otherwise, its peer never reading the end
  (CI run 43616040593: vsock's handshake and the network endpoint;
  `test_a_socket_made_non_blocking_and_closed_ends_its_peers_stream`). A
  descriptor with state that another library closes (Rust std's own
  sockets, which take no `ioctl` here) keeps its object until the sweep;
  a question makes no state: `F_GETFL` reads the flags without an entry
  (`test_f_getfl_makes_no_state_that_outlives_a_close_past_the_library`).
- **epoll = IOCP (the `polling` crate).** Sockets use AFD polls; eventfds,
  consoles and other waitable handles use wait packets that complete on the
  IOCP. A waitable's removal (`EPOLL_CTL_DEL`, and a dropped instance's
  sources) returns once the thread pool no longer waits on the handle nor
  runs that wait's callback (`UnregisterWaitEx` with `INVALID_HANDLE_VALUE`,
  which "waits for all callback functions to complete before returning",
  Learn), so the handle may be closed at once, as Linux's `EPOLL_CTL_DEL`
  leaves nothing behind (fs/eventpoll.c `ep_remove`). polling 3.11.0 returned
  at once, and a callback already running armed a new wait on the removed
  handle, which its owner then closed: a handle "closed while the wait is
  still pending" is undefined (Learn, `RegisterWaitForSingleObject`), and the
  pool ended the process with STATUS_THREADPOOL_HANDLE_EXCEPTION (0xc000070a;
  CI run 43676869163, the kvm-ioctls tests). wick builds polling with that
  fixed (`crates/compat/polling`, generated from 3.11.0 by
  `tools/gen-windows-sources.sh`, the change in
  `tools/gen-windows-sources-polling.py`;
  `test_a_removal_returns_once_a_running_callback_has_ended`,
  `test_a_source_removed_with_its_packet_posted_yields_nothing`,
  `test_a_modify_racing_the_callback_leaves_no_wait_behind`,
  `test_a_dropped_poller_leaves_no_wait_on_its_sources`, and vmm-sys-util's
  `test_an_eventfd_deleted_as_its_wait_fires_is_not_waited_on_once_closed`;
  on Windows Server 2022 20348 the four passed in 3 of 3 runs and each fails
  against upstream's code, the third with 0xc000070a; the vmm-sys-util test
  passed 5 of 5; a loop of add, signal, remove and close on polling alone,
  no wick code, ended with 0xc000070a in 5 of 5 runs on crates.io's 3.11.0
  and finished its 20000 rounds in 5 of 5 on wick's). The paths that remove a waitable and then close it: the irqfd watcher's
  reconcile (an irqfd unregistered, a guest's MSI-X vector masked or
  disabled), event-manager's removal of a subscriber's events (a device
  reset or unplugged), the serial input removed at its end, a pipe's
  watcher event and an epoll nested in another (vsock); each now waits for
  at most one callback, which only posts a packet. A waitable's wait is
  registered again by the `wait` after one that took its packet; polling
  3.11.0 boxed a new callback there each time (wick's first change kept that,
  in an `Arc`), so the VMM's event loop allocated once for each eventfd whose
  packet woke it. wick's polling keeps one callback context for each source,
  made when it is added, which holds the packet the callback posts
  (`test_a_wait_allocates_nothing`'s last part, a wait after one woken
  through the port by a waitable; first run: CI); the pool's registration
  itself (`RegisterWaitForSingleObject`) allocates in the system's heap, not
  counted there. Level-triggered is the default and `ONE_SHOT` is supported. Sockets
  also support `EDGE_TRIGGERED`: IOCP is level-triggered, so edges come from
  the edge contract that the reader reads until `EAGAIN` (the compatibility
  `libc`'s `read` and `recv` report `EAGAIN` through `wick_fd::drained`, which
  re-arms). `Redirect` makes a registered listening socket's readiness follow
  the connection it accepted, so a network endpoint keeps one fd for its
  lifetime. Regular files are `EPERM`, as on Linux (`test_regular_file_rejected`).
  The read end of a pipe is watched by a thread with `PeekNamedPipe`: a
  zero-byte `ReadFile` waits for data, but on a synchronous handle it holds up
  every other call on that handle until data comes
  (`test_a_pending_pipe_read_holds_up_the_handle`; the watcher:
  `test_pipe_in_and_hang_up`, `test_pipe_wakes_a_blocked_wait`).
  `EPOLLOUT` on a pipe fails with `ERROR_NOT_SUPPORTED`
  (`test_pipe_out_not_supported`): the write end's `WriteQuotaAvailable`
  (`FILE_PIPE_LOCAL_INFORMATION`) follows the room left, but reads 0 while
  the reader waits in a read, when a write completes at once
  (`test_pipe_write_room_reads_0_while_a_read_waits`).
  An epoll nested in another (the vsock muxer's) is readable while its own
  wait would report something: a completion port is not waitable, so a
  forwarder thread keeps the inner instance's packets and sets an event the
  outer one waits on, and the outer one, when it looks, checks those packets
  and the inner instance's level-triggered sources again, consuming nothing,
  as Linux's `__ep_eventpoll_poll` polls each ready item again
  (`ep_item_poll`, fs/eventpoll.c), and drops the packets that went stale
  (trusting the event made it report a drained inner instance ready in
  about 1 of 100 rounds: `test_nested_epoll_stale_packets_do_not_make_the_outer_ready`,
  one and two levels deep, `test_nested_epoll_two_levels`). An addition that
  would close a loop, or make a chain deeper than `EP_MAX_NESTS` (4), fails
  with `ELOOP`, as Linux's `ep_loop_check`
  (`test_nested_epoll_loops_fail_with_eloop`,
  `test_nested_epoll_deeper_than_linux_s_limit_fails_with_eloop`).
- **eventfd = counter + manual-reset event.** The event is signalled while the
  counter is above zero. Counter, flags and lock live in a 4 KiB paging-file
  section, with a space event (counter < MAX). Every change happens under a
  spin lock together with `SetEvent`/`ResetEvent`. Another process gets the
  section and events, so it shares the same counter.
- **fd passing (`SCM_RIGHTS`) = framing + `DuplicateHandle`.** An `AF_UNIX`
  stream carries a wire format of its own (header + KIND_HANDLE, EVENTFD,
  SOCKET and SECTION entries). Handles are duplicated into the peer process
  (`SIO_AF_UNIX_GETPEERPID`); an eventfd travels with its section and events,
  a sealed memfd with the section that fixes its size. Sockets travel as
  `WSADuplicateSocketW` protocol information. A plain peer (no wick framing)
  is read as Linux `recvmsg` reads it.
- **timerfd = high-resolution waitable timer.** `read` returns the expiration
  count and re-arms: the expirations due on the timer's clock since the last
  read, each counted once however late the read comes, since the count is
  taken from the clock under the timer's lock and the next due time moves past
  them (`test_one_shot_and_periodic`). Clocks: QPC (MONOTONIC), interrupt
  time (BOOTTIME), `GetSystemTimePreciseAsFileTime` (REALTIME),
  process/thread times (CPU clocks).
- **signals = APCs and an exception filter.** A signal to a thread is a
  special user APC (`QueueUserAPC2`, else `NtQueueApcThreadEx`), which
  interrupts the thread in user code or an alertable wait; a thread in a
  system call or a non-alertable wait runs the handler once that ends, where
  Linux interrupts it (`EINTR` or a restart): a stated difference
  (`test_a_signal_to_a_thread_in_a_wait_runs_once_its_wait_ends`; Learn,
  QueueUserAPC2). Firecracker's vCPU kick does not depend on it: the WHP
  backend's `set_kvm_immediate_exit` cancels a run itself. Faults are caught by
  `SetUnhandledExceptionFilter` and reported with Linux `si_code` and
  `si_addr`. Below every filter is a last one, installed before `main` in
  the VMM, its API process and the jailer (`windows_mm::last_filter`): it
  writes a line naming an exception nothing took, calls the filter it
  replaced (the Visual C++ runtime's, installed by its startup before the
  C++ initializers, which ends an unhandled C++ exception with
  `terminate()`) and, in a job that dies on unhandled exceptions (the
  jailer's; the process's immediate job is asked), ends the process with its
  code by `TerminateProcess`; out of one by `RaiseFailFastException` with the
  exception's record, which Windows Error Reporting reports, with its dump,
  where it is enabled. It passes on only a filter's
  `EXCEPTION_CONTINUE_EXECUTION`: under `SEM_NOGPFAULTERRORBOX` a thread
  pool's worker took the `EXCEPTION_EXECUTE_HANDLER` the system's filter
  gives and went on. Console control events are `SIGINT`, `SIGQUIT` and `SIGHUP`.
- **mmap = placeholder virtual memory (Windows 10 1803+).** One mapping is one
  Windows allocation, tracked in a table. So that partial `munmap` and
  `MAP_FIXED` behave as on Linux, reservations are placeholders
  (`VirtualAlloc2`), shared mappings are section views (`MapViewOfFile3`) and
  private file mappings are committed and filled from the file whole when
  mapped (a fill by the page is not race-free in private memory; see
  `windows_mm::fill`). With no usable hint, an anonymous private mapping whose
  length is a multiple of 2 MiB is reserved on a 2 MiB boundary, as Linux has
  placed such mappings since 6.7 (v6.12 mm/mmap.c :902 to :907; not v6.1 or
  v5.10): a placement choice, which commits nothing, so that a registered
  userfaultfd range of such a mapping has no 2 MiB chunk at its edge
  (`test_a_whole_2_mib_anonymous_mapping_is_placed_on_a_2_mib_boundary`).
  `madvise(DONTNEED)`
  discards private pages. File offsets not aligned to 64 KiB, shared mappings
  past EOF, `MAP_FIXED` over part of a view and `MAP_HUGETLB` fail with the
  Linux errno.
- **Released userfaultfd ranges = a fixed table of records (`windows_mm::RELEASED`).** A registered range's pages
  that leave the registration while missing (its userfaultfd released, `wick_uffd::destroy`, or an unregister of
  them) are pending: one never filled is not committed, and is committed at its first access with the protection
  `mprotect` gave it; one discarded is committed, closed and still charged, and is zeroed through the range's alias
  at its first access and opened, as Linux gives a zapped page as zeros at its next touch. Linux's release clears
  each vma's flags in place and the pages stay in its page tables (v6.1 fs/userfaultfd.c `userfaultfd_release`,
  885-899), so it needs no memory; here the release runs at the job's limit too, so it may allocate nothing:
  - **One record per registration, taken at the register** (`released_reserve`) with its bitmaps (`pending`,
    `noread`, `nowrite`, one bit a page), from a table as large as the slots (64). With none free the register is
    `ENOMEM` and nothing is done, as Linux's register past `vm.max_map_count` (mm/mmap.c `split_vma`). The release
    then only sets bits and stores fields (`test_a_userfaultfd_released_at_the_limit_allocates_nothing`).
  - **A record is freed when its registration is released and its views are all gone** (each chunk's view counted
    at the register and counted out when it is unmapped or mapped over), not when its last pending page is
    resolved: two threads faulting on the last pending page must both find the record, the second to see the page
    resolved and run its access again (`test_released_records_reused_under_touching_threads`). So a register is
    refused while 64 registrations' memory is still mapped, registered or released
    (`test_released_records_past_the_table_refuse_a_register`, `test_release_then_munmap_frees_the_record`).
  - **A discard of released pages makes them pending again** (`released_discard`, from `wick_uffd::discarding`
    for the pages no registration tracks): a chunk discarded whole gets a new reserved section in its views and
    its alias's, its commit and charge given back under `RELEASED`'s lock once its pages are pending, so a page
    a first access resolves meanwhile is charged again after it
    (`test_a_page_resolved_as_its_released_chunk_is_discarded_keeps_its_charge`); a part is closed, pending
    with the protection it had, its content dropped through the alias, and zeroed there at its next access. So a
    record keeps its bitmaps until it is freed (3 bits a page), and its alias is set at the register and kept by
    every released chunk's view until the view goes (`uffd_unalias`).
  - **Readers: every decision about a record is taken under `RELEASED`'s lock.** The access path finds the record
    holding the page, tests its bits, resolves the page and clears its bit in one critical section, so no reader
    holds a record across its reuse; taking, freeing, the release's flips, `munmap`'s and `mprotect`'s changes are
    made under the lock too. Only `RELEASED_LIVE`, the count of records in use, is read without it, a hint that
    lets an access that cannot concern a record skip the lock. It gives no false "none" for a page that matters:
    the release publishes its record before `destroy` wakes the threads waiting on the range's missing pages, which
    run their access again and find it.
  - **Lock order:** the userfaultfd's `LOCK`, the region table, `RELEASED`, then `CHARGES` or `LAZY` (the lazy
    ranges), each a leaf: nothing is taken while either is held, and neither is held with the other. The release
    does not take the region table: `mprotect` and `munmap` ask `released_overlaps` for a view a record holds. The
    WHP run loop's settled look takes `LOCK`, the table, `RELEASED` and `LAZY` in that order
    (`wick_mm::settled_access`).
  - A released chunk is not a candidate of the reclaim at the memory limit, so its discarded pages keep their charge
    until each is touched or unmapped, where Linux freed them at the discard (the `memory.max` row of
    docs/COMPATIBILITY.md).
- **The heap at the memory limit = wick's allocator (`libc::wick_alloc`).** Every Windows binary that links the
  VMM (Firecracker, `snapshot-editor`, `cpu-template-helper`) has it as its heap's allocator
  (`vmm::ext::allocator`): the system's heap, and at a refusal an answer by the size asked, as Linux answers malloc
  (its mmap refused only above RAM and swap, v6.1 mm/util.c :1002 to :1006; the memory cgroup charging at the
  touch). Above the host's commit limit: null, as the system's allocator answers
  (`test_a_heap_allocation_above_the_hosts_commit_limit_is_refused_as_the_systems`). Above what the job's limit
  holds in all: the end with 137 and a line saying so, where Linux gives it and kills at the touch past the limit
  (`test_a_heap_allocation_more_than_the_job_limit_holds_ends_with_137_and_says_so`). Any other size: what Linux's
  memory cgroup does at a charge it cannot make: the reclaim (`wick_uffd::reclaim_at_touch`), the allocation once
  more if the reclaim gave something back, then the end with 137 and a line naming the size asked and what the
  reclaim gave back (`test_a_heap_allocation_refused_at_the_limit_ends_with_137_and_a_line`,
  `test_a_heap_allocation_refused_at_the_limit_is_made_after_the_reclaim`). Both limits are read by a system call
  into a buffer on the stack (`GlobalMemoryStatusEx`, `QueryInformationJobObject`). No reclaim runs where it would take what
  the thread holds: a lock of wick's memory layer (`windows_stacklock::held_here`, which every such lock keeps), the
  exception handler (`windows_mm::in_the_handler`, two writes of the thread's TLS an exception) or the reclaim's own
  thread; there the process ends at once (`test_a_heap_allocation_refused_where_no_reclaim_may_run_ends_with_137`).
  wick's own `try_reserve` sites run under `wick_alloc::fallible` and answer `ENOMEM` as before
  (`test_a_guarded_fallible_site_answers_enomem_at_the_limit`). An allocation that succeeds costs the check of the
  system call's result only. Firecracker says which allocator its heap runs with, in a debug line when it builds a
  VM (an error line at its start if it is not wick's), and `boot-test.ps1 boot`, at `--level Debug`, checks the
  line (`test_the_heaps_allocator_is_wicks` in the VMM's own tests).
- **memfd = unnamed temporary file**, unlinked at once with
  `FILE_FLAG_DELETE_ON_CLOSE` and POSIX delete. Size seals (`SealShrink`,
  `SealGrow`) attach a section of that size to the fd, so the OS refuses to
  shrink it and mappings use a fixed size. A sealed memfd travels with its
  section through `sock_ctrl_msg`.
- **Linux-only `libc`.** Windows has no Linux system calls, so `syscall` fails
  with `EINVAL` for `arch_prctl` (like a kernel without the XSTATE permission
  interface; WHP configures the partition) and `ENOSYS` otherwise. `ioctl` is
  `FIONBIO` (above) and `ENOTTY` for every other request (Windows paths use
  `DeviceIoControl`); `fallocate` is implemented
  with sparse files and `FSCTL_SET_ZERO_DATA`, `lseek(SEEK_DATA/SEEK_HOLE)`
  with allocated ranges. Socket functions use Linux address families
  (`AF_INET6`=10), and `getsockopt(SO_DOMAIN)` and friends are built on
  Winsock.
- **`vm-memory`, `event-manager`, `micro_http`, `vhost`.** On Windows they are
  the upstream source at the same tag with mechanical rewrites only
  (`std::os::{unix, fd}` → `wick_os`; vm-memory uses its Unix mmap backend),
  generated by `tools/gen-windows-sources.sh`; `--check` verifies they are
  current.
- **`kvm-bindings`.** Windows' `c_ulong` is 32-bit, which would change the
  structure sizes. wick uses bindings fixed to the Linux x86_64 layout
  (`tools/gen-kvm-bindings-windows.sh`), which the WHP backend fills.

## Platform backends on Windows (`vmm::platform`)

- **`async_io`**: the same worker-thread queue as macOS, on the compatibility
  `libc` (`pread`, `pwrite`, `FlushFileBuffers`). It keeps io_uring's
  submission/completion model, restrictions and queue limits. A worker
  writes the completion event before a waiter in `submit_and_wait_all` can
  see the operation done, as io_uring signals its eventfd before it wakes
  its waiters, so the event is readable once the wait returns
  (`test_the_completion_event_is_readable_once_submit_and_wait_all_returns`,
  Windows Server 2022 20348 and 2025 26100).
- **`fs`**: snapshot memory files are made sparse by `keep_holes`, and holes
  of unwritten ranges are restored. NTFS allocates sparse files in 64 KiB
  units, so after restoring it checks that unwritten ranges are holes again,
  and fails otherwise (it never leaves zeros where Linux leaves a hole).
- **`net`**: a Unix stream endpoint that a host switch connects to. Ethernet
  frames are prefixed with a 32-bit big-endian length, QEMU's
  `-netdev stream` framing, which passt and gvisor-tap-vsock (`-listen-qemu`)
  use too. Those tools listen and wait for QEMU to connect, as the endpoint
  listens, so neither connects to it without an adapter (a process that
  connects to both); what has run against it is the test scripts' own switch
  (`boot-test.ps1 net`, `jailer-test.ps1 netguest`). One
  switch at a time: one that connects while another is there waits its turn,
  and what it sent reaches the guest once the other leaves. A frame the guest
  sends while no switch is connected is dropped and its write succeeds, as a
  write to a TAP that is up when nothing on the host takes the frame
  (drivers/net/tun.c, `tun_get_user`). The descriptor Firecracker holds is
  the listening socket: once it is closed, tx and rx fail with `EBADF` and
  the switch is disconnected. `platform::vnet` handles the virtio-net header.
