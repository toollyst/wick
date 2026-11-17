# macOS: what the jail's memory limit counts

The detail behind SECURITY.md, "macOS: the jail's memory limit bounds a compromised VMM's guest memory, not its
own": the two ways a process holds memory that the limit does not count, what each of macOS's counters says about
it, why the sandbox profile does not remove them, what was looked at for a bound per process, and the fix that
bounds guest memory. Every figure names the command that gives it.

In short: on macOS the jail's `memory.max` is a jetsam limit on the process's phys_footprint ledger. That ledger is
charged when a page is entered into one of the task's mappings, and a process can keep anonymous memory resident that
no mapping of its own holds, or that it took out of the ledger itself. A Firecracker that works as it should does
neither; a compromised one can, and is then bounded by the host's memory and swap, not by the jail. On Linux the
memory cgroup charges a page when it is allocated, so no mapping trick takes it out of the count.

## Prior public knowledge

The mechanism is xnu's known, documented accounting behaviour, not a new vulnerability. wick's own part is the
consequence for the jail: the limit the jailer sets with `memory.max` holds a well-behaved VMM, not a compromised one.

- **The footprint is charged per pmap insertion.** xnu's own documentation of jetsam kills
  ([doc/vm/memorystatus_kills.md](https://github.com/apple-oss-distributions/xnu/blob/main/doc/vm/memorystatus_kills.md),
  JETSAM_REASON_MEMORY_PERPROCESSLIMIT) says that "every page insertion into a process's pmap increases the
  `phys_footprint`", and that the per-process limit is a limit on that ledger. A page with no insertion in the task's
  pmap is not charged to it.
- **`MADV_FREE_REUSABLE` without `MADV_FREE_REUSE` leaves memory in use and out of the count.** Mozilla's
  [bug 1682947](https://bugzilla.mozilla.org/show_bug.cgi?id=1682947) (2020) made Firefox's allocator call
  `MADV_FREE_REUSE` before using memory it had made reusable again, as Chromium had (its patch names Chromium issue
  823915). Their measurement: without it, their RSS measures were lower (by around 30% on one test), which they took
  to mean that "some amount of memory is in use but not counted" (comment 2). Go's runtime pairs the two calls for
  the same reason: `sysUsedOS` in
  [src/runtime/mem_darwin.go](https://github.com/golang/go/blob/master/src/runtime/mem_darwin.go) calls
  `MADV_FREE_REUSE` with the comment "MADV_FREE_REUSE is necessary to keep the kernel's accounting accurate", and
  [golang/go#47656](https://github.com/golang/go/issues/47656) discusses what `MADV_FREE_REUSABLE` does to darwin's
  memory figures.
- **Purgeable memory is charged to its owner by the object, not per mapping.** xnu's own tests,
  [tests/vm_phys_footprint.c](https://github.com/apple-oss-distributions/xnu/blob/main/tests/vm_phys_footprint.c)
  (`phys_footprint_purgeable_ownership`), check that "deallocating owned memory while holding memory entry does not
  change phys_footprint", and that the footprint goes down only when the memory entry, the object's last reference,
  is released.

## The limit

The jailer spawns Firecracker with a fatal jetsam limit of `memory.max`, in whole MiB
([overlay/jailer/platform/macos/mod.rs](../overlay/jailer/platform/macos/mod.rs), `posix_spawnattr_setjetsam_ext`),
and with the API process on, Firecracker sets its own to the limit less the API process's 32 MiB
([overlay/vmm/ext/jail.rs](../overlay/vmm/ext/jail.rs), `limit_memory`). A jetsam limit is a limit on the process's
phys_footprint ledger: past it, the kernel kills the process with SIGKILL (xnu-12377.121.6
bsd/kern/kern_memorystatus.c :261, osfmk/kern/task.c `task_set_phys_footprint_limit_internal` :7602). phys_footprint
is the sum of the task's ledgers `internal`, `internal_compressed`, `iokit_mapped`, `purgeable_nonvolatile`,
`purgeable_nonvolatile_compressed` and `page_table` (osfmk/kern/task.c :1258 to :1266). The `internal` ledger is
charged per mapping: SECURITY.md's entry "macOS: a page is charged to the memory limit once for each mapping that
touched it" measures that side, a page counted twice when two mappings touched it. This page is the other side:
memory that no mapping of the task counts at all.

## The two ways

**1. Written through a mapping removed after.** A process maps its own anonymous memory a second time
(`mach_vm_remap`, shared, anywhere), writes the pages through that second mapping, and removes it
(`mach_vm_deallocate`). The pages stay resident in their VM object, still mapped by the original range, but the only
mapping that ever entered them into the pmap is gone, and with it their charge. They count once something touches
them through the original range. These are the calls a userfaultfd fill makes in wick (`libc::wick_uffd::fill_view`:
a mapping of the pages made for the fill and taken away once it is done), which is why the run-phase profile must
allow them.

**2. Made reusable and written again.** A process writes anonymous memory, calls `madvise(MADV_FREE_REUSABLE)` on
it, which takes the pages out of the footprint (the `reusable` ledger is not one of its terms), and writes the pages
again without `MADV_FREE_REUSE`. The pages hold the new data and stay mapped, and the footprint does not count them
again.

## Measurements

On an M1 Pro, macOS 27.2, with no limit, as an ordinary user, 3 rounds of each command, the same each round
(host_statistics64 aside, below). The program is
[crates/compat/libc/examples/uffd_charge_probe.rs](../crates/compat/libc/examples/uffd_charge_probe.rs), built as
[tools/macos/jailer-test.sh](../tools/macos/jailer-test.sh) builds it (from lib/firecracker,
`cargo build --manifest-path ../../crates/compat/libc/Cargo.toml --example uffd_charge_probe`). The footprint is the
change from the program's start; the other counters are the values the program prints, in MiB, from a start of 1 MiB
each.

| Command | What it does | Footprint (proc_pid_rusage `ri_phys_footprint`) | task_info TASK_VM_INFO: phys_footprint, internal, resident_size | proc_pidinfo PROC_PIDTASKINFO resident size; proc_pid_rusage `ri_resident_size` |
| --- | --- | --- | --- | --- |
| `uffd_charge_probe 256 views-only then-read` | 256 MiB of `mach_vm_allocate` memory written only through 16 MiB mappings removed after | +0 | 1, 0, 1 | 1; 1 |
| (the same, `then-read`) | then read through its own range | +256 | 257, 256, 257 | 257; 257 |
| `uffd_charge_probe 256 views-only-purgeable then-read` | the same on a purgeable (nonvolatile) object | +256 | 257, 0, 1 | 1; 1 |
| (the same, `then-read`) | then read through its own range | +256 (+0 at the read) | 257, 256, 257 | 257; 257 |
| `uffd_charge_probe 256 reusable` | 256 MiB written, made reusable, written again, 16 MiB at a time | +0 | 1, 0, 257 | 257; 257 |

- The first way: none of the task's own counters counts the 256 MiB until the task reads them through its own
  range. The purgeable object is charged as the writes go (+64 MiB each 64 MiB written), whatever wrote them (to
  `purgeable_nonvolatile`, not `internal`), and not again at the read.
- The second way: the footprint and `internal` do not count the pages; the resident sizes do, since the pages stay
  mapped and resident.
- The host counts both: host_statistics64's internal pages went up by +257 and +258 MiB for the 256 MiB in two rounds
  of each and by +0 in the third, host-wide, since every other process moves it too (printed by the same command,
  "host internal pages").
- The userfaultfd modes, for comparison: `uffd_charge_probe 64` fills 64 MiB with a footprint of +0 and reads it at
  +64; `uffd_charge_probe 64 second-view` +0, +64 at the second mapping's read, +128 at the range's;
  `uffd_charge_probe 128 purgeable`, the same fills on a purgeable object, counts 16 MiB more each 16 MiB filled, 128
  at the end of the fills, +0 at the read.

Under the limit, as root, the jailer runs the same program under `memory.max` of 96 MiB (`jailer-test uffd-charge`,
[tools/macos/jailer-test.py](../tools/macos/jailer-test.py), in CI's macos job; not run on this Mac, where root is not
used). Its cases and what each must do:

| Case | Arguments | Must | Why |
| --- | --- | --- | --- |
| `uffd-charge` | `64` | live | filled and read memory counts once, as Linux charges it |
| `uffd-charge-view` | `64 second-view` | be killed at the read | its control: a second mapping read too counts 128 MiB |
| `views-only` | `256 views-only` | live | records the first way: 256 MiB held under a 96 MiB limit |
| `views-only-purgeable` | `256 views-only-purgeable` | be killed | the first way's control: the object is charged |
| `reusable` | `256 reusable` | live | records the second way |
| `uffd-charge-purgeable` | `128 purgeable` | be killed during the fills | the design below: each page charged at its fill |

A case that records a way (must live) failing means the gap closed or the limit counts differently; the stage then
fails, so that this page and SECURITY.md are brought in step.

## Why the sandbox profile does not remove them

- The run-phase profile allows `mach_vm_remap_external` (a MIG routine), the `mach_vm_allocate` and
  `mach_vm_deallocate` traps and `madvise` ([overlay/vmm/ext/sandbox.rs](../overlay/vmm/ext/sandbox.rs), its
  `SYSCALLS`, `MACH_TRAPS` and `MIG_ROUTINES`): a userfaultfd fill needs the remap and the deallocation, and the
  balloon's discards need `madvise`.
- Seatbelt's `syscall-unix` rules filter a system call by its number (`syscall-number`); no filter on `madvise`'s
  advice was found in the profile language, so `MADV_FREE_REUSABLE` cannot be refused there.
- The API process's "`madvise` with `MADV_DONTNEED` only" (upstream's api filter) is the compatibility libc's check,
  in the process (`libc::wick_mm::allow_only_advice`, made by `vmm::ext::sandbox::apply_api`): code that a
  compromised process does not have to go through. The VMM has no such check, as upstream's VMM filter allows
  `madvise`.

## What was looked at for a bound per process

| Looked at | What it counts here | Why it does not serve |
| --- | --- | --- |
| proc_pid_rusage `ri_phys_footprint` | neither way | it is the ledger jetsam holds |
| proc_pid_rusage `ri_resident_size`, proc_pidinfo PROC_PIDTASKINFO `pti_resident_size` | the second way, not the first | readable by the jailer from outside (it is root), but it would bound the second way only, and it also counts clean file pages (mapped libraries, a memory file), which the limit does not: not done |
| task_info TASK_VM_INFO (`phys_footprint`, `internal`, `resident_size`, `compressed`, the purgeable ledgers) | as above | the same ledgers, and it needs the task's port, which the jailer does not take |
| host_statistics64 internal pages | both | host-wide, and too noisy on a busy host to tell one process's share |
| Seatbelt rules | — | filter by system call number, not by `madvise`'s advice; the fills need the remap and deallocation |
| `RLIMIT_AS` (xnu checks it in `vm_map_enter`, osfmk/vm/vm_map.c, "Address space limit enforcement (RLIMIT_AS and RLIMIT_DATA)") | address space, not memory | not established as a bound. Measured with a standalone C program, not in the tree, as an ordinary user, 3 rounds each the same: with `RLIMIT_AS` at the task's virtual size plus 128 MiB (and plus 512), `mach_vm_allocate` is refused (`KERN_NO_SPACE`) once 128 (512) MiB more is mapped, `mmap` with `ENOMEM`, and the process cannot raise the limit back (`EPERM`); but `mach_vm_remap` is not refused: four 64 MiB mappings of memory mapped before took the virtual size to 384 MiB over the limit's start, past it. So a process past the limit can still map memory it already has, as the first way does; whether a bound can be built on `RLIMIT_AS` at all is not established |

So on macOS nothing found bounds this memory per process but the host's memory and swap. macOS's memory-pressure
jetsam of the whole host still applies: under pressure, the kernel kills processes by their jetsam priority.

## Linux

Linux's memory cgroup charges an anonymous page when it is allocated (v6.12 mm/memory.c `alloc_anon_folio` :4711), a
shmem page when it is added (mm/shmem.c :1818), and a `UFFDIO_COPY` page at the fill (mm/userfaultfd.c
`mfill_atomic_pte_copy` :302), once (mm/memcontrol.c `commit_charge` :2370), whatever then maps it. Neither way has a
counterpart: removing a mapping does not uncharge a page another mapping holds, and `MADV_FREE` pages stay charged
until the kernel frees them.

## The fix: guest memory as objects the task owns

Guest RAM is committed as objects the task owns: purgeable, nonvolatile objects (`mach_vm_allocate` with
`VM_FLAGS_PURGABLE`), charged by the object to the task's `purgeable_nonvolatile` ledger, part of the footprint,
whatever maps or writes their pages, the Hypervisor.framework's stage 2 and a userfaultfd fill's mapping included
(the purgeable rows above). That closes the gap for guest memory, and also counts a page the guest and the VMM both
touched once: 64 MiB written by the guest and read by the VMM is charged 64 MiB, and 64 MiB a userfaultfd filled
and both then read is charged 64 MiB, at the fills, where plain memory is charged 128 in the same run
(`test_owned_anonymous_guest_memory_is_charged_once`, `test_owned_guest_read_of_filled_pages_is_charged_once`, next
to `test_anonymous_guest_memory_is_charged_once` and `test_a_guest_read_of_filled_pages_is_charged_once`). It does
not close it for the VMM's own memory (its heap, buffers, anything it maps for itself): a
compromised VMM can still hold anonymous memory of its own either way, so SECURITY.md keeps the entry under "Not at
parity yet" for that part.

The implementation ([crates/compat/libc/src/wick_owned.rs](../crates/compat/libc/src/wick_owned.rs), macOS only;
used from [the single guest-RAM commit](../lib/firecracker/src/vmm/src/vstate/memory.rs), `owned_guest_commit`, the
`fd == -1` anonymous boot or userfaultfd-restore memory, not a `File` restore's `fd`-backed mapping or a huge-page
guest):

- **Allocate.** The usable guest range is carved into 2 MiB chunks, each its own purgeable object
  (`mach_vm_allocate` with `VM_FLAGS_PURGABLE | VM_FLAGS_OVERWRITE` over the `PROT_NONE` reservation, then the
  protection). Per chunk, because a purgeable object gives its charge back only when the whole object is released: a
  sub-range freed within a larger object frees nothing. Proven charged and usable under a live guest
  (`test_owned_guest_memory_is_charged_and_usable`).
- **Discard** (a balloon inflate or a userfaultfd `UFFDIO_ZEROPAGE`, through the compatibility libc's
  `discard_piece`). A whole chunk is replaced with a fresh purgeable object, which gives the whole chunk's charge
  back (`test_owned_whole_chunk_discard_returns_the_charge`). A partial chunk is zeroed in place with
  `madvise(MADV_ZERO)` (not `MADV_FREE_REUSABLE`, which would be the bypass of "the second way" above, and not
  `VM_BEHAVIOR_ZERO`, a Mach call the run-phase profile does not allow): the object keeps the pages, so the charge
  stays pinned, and the count of such dead pages per chunk is kept (`test_owned_partial_discard_zeroes_and_pins_the_charge`).
- **Reclaim.** Once a chunk crosses `RECLAIM_DEAD_RATIO_PERCENT` (50%) dead — a trigger only — its object is
  replaced with a fresh purgeable one holding only the pages that are **currently** not all-zero, so the pinned
  charge falls to the live set. The drop is decided by current page **content**, never by the dead count: the guest
  can re-write a zeroed page to non-zero without the compatibility libc seeing it (it writes the object through
  stage 2, not through a `libc` call), so a dead mark is not a safe drop oracle; the scan reads each page and moves
  every page that is not currently zero, and drops only the pages that are (they re-fault to zero, which the guest
  cannot tell from their old value). The move runs under the quiesce the replace hook gives (the chunk's guest slot
  is unmapped, so a guest access stalls and cannot write the old object), with the live pages copied out to an
  `mmap`/`munmap` temporary and back, so no guest write reaches the freed object
  (`test_owned_reclaim_keeps_rewritten_dead_page_and_drops_zero_pages`,
  `test_owned_reclaim_racing_guest_write_is_not_lost` over its 24 rounds). The 50% trigger is a macOS difference by
  an OS gap, not by choice: Windows and Linux's memory cgroup reclaim at the commit/charge limit, when an allocation
  is refused; macOS has no refused commit — a purgeable charge grows until jetsam kills — so it reclaims proactively
  at this ratio (the constant is cross-referenced to the Windows dead-chunk reclaim).

Every chunk's object is freed and dropped from the registry when the range is unmapped (the compatibility libc's
`munmap`, the registry's `forget`), before the mapping is torn down so a reused address never matches a stale entry.
The owned path uses only calls the sandbox profile allows in each phase: under both the setup and the run profile,
where a denial is the kill, the carve, both discards and a reclaim are made and checked, the reclaim by its chunk's
dead count reset and by what it kept and dropped (`test_owned_memory_path_survives_each_profile`).

Remaining, under "Not at parity yet": the VMM's own memory (its heap, buffers) is not bounded, and guest memory made
by a `File` snapshot restore (`MAP_PRIVATE` of the memory file) or shared with a vhost-user backend (the
compatibility memfd, a POSIX shared memory object) cannot be a purgeable object as it is, nor is a huge-page
guest's committed as one, so that guest memory is not charged this way either: it is charged once for each mapping
that touched it (SECURITY.md, "macOS: a page is charged to the memory limit once for each mapping that touched
it"), twice for a page the guest and the VMM both touched.
