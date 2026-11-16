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
therefore only change existing upstream files: 53 feature patches touching 88
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
            Windows: polling 3.11.0's source, its waitable removal fixed (below)
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
that change memory as Linux keeps it (`libc::wick_uffd`), except where this
table says not yet. Each such call on memory a userfaultfd has registered,
against Linux v6.12:

| Call | Linux | wick on macOS | Test |
| --- | --- | --- | --- |
| `mprotect` | the vma's protection changes and its registration stays (mm/mprotect.c `mprotect_fixup` :603, `vma_modify_flags` :664 and `vm_flags_reset` :677, nothing of `vm_userfaultfd_ctx`); an access the protection refuses is a `SIGSEGV` with no event (arch/arm64/mm/fault.c `do_page_fault` :590 to :595), one it allows to a missing page faults to the userfaultfd | the same (`protecting`): present pages take the protection, missing ones stay `PROT_NONE` so that they still fault, and every registered page has the protection recorded as asked, which a missing page takes once it is filled, or unregistered, or its userfaultfd released; an access the asked protection refuses goes on to the process's own `SIGSEGV` or `SIGBUS` handler with no event (`asked_allows`; an instruction fetch needs `PROT_EXEC`, a write `PROT_WRITE`, a read any of the three, as on a processor without EPAN, :566) | `test_mprotect_of_registered_missing_pages_keeps_them_missing`, `test_a_filled_page_takes_the_protection_asked_while_it_was_missing`, `test_an_unregistered_page_takes_the_protection_asked_while_it_was_missing`, `test_a_released_page_takes_the_protection_asked_while_it_was_missing`, `test_a_registered_page_its_protection_denies_is_no_userfault`, `test_mprotect_of_a_filled_page_does_not_make_it_missing`, `test_plug_after_a_uffd_restore`, and in the VMM `test_a_slot_plugged_after_a_uffd_restore_still_faults_host_accesses` (patch 0053) |
| `madvise(MADV_DONTNEED)` | a remove event (`EVENT_REMOVE`), then the pages are zapped and missing again (mm/madvise.c `madvise_dontneed_free` :880, `userfaultfd_remove` :894) | the same (`discarding`); the userfaultfd's alias, remapped over the new pages, stays writable whatever their protection | `test_remove_event`, `test_a_slot_unplugged_and_plugged_again_is_filled_through_its_alias` |
| `madvise(MADV_FREE)` | as `MADV_DONTNEED` for the userfaultfd: `madvise_vma_behavior` sends it to `madvise_dontneed_free` (mm/madvise.c :1046 to :1049) | not yet as Linux, fix in progress: passed to macOS's `MADV_FREE`, which frees lazily, so the pages are not made missing and no event is posted; Firecracker does not use it | `test_madv_free_of_registered_pages_makes_them_missing`, `test_madv_free_of_registered_pages_posts_a_remove_event` (ignored until then) |
| `munmap`, `mmap(MAP_FIXED)` over registered memory | the registration goes with the vma in the same step (mm/vma.c `do_vmi_align_munmap` :1332; fs/userfaultfd.c `userfaultfd_unmap_prep` :811, called at mm/vma.c :1267; mm/mmap.c `__mmap_region` :1361 unmaps first, :1386); a cut of a hugetlb vma off its huge page boundaries is `EINVAL` before anything changes (mm/vma.c `__split_vma` :377 to :378); a thread waiting on such a page waits until its userfaultfd's `UFFDIO_WAKE`, which checks the range only (fs/userfaultfd.c `userfaultfd_wake` :1545 to :1575), or its release (:873), then runs its access again | the same (`unmapping`): `LOCK` is held from before the system call until the pages it reached are in no registration, so no fill or release runs in between; a range with no page left registered is freed; a fill of such a page is `ENOENT`; registered again, its alias follows the new pages; a waiter as on Linux; a cut of a huge page is `EINVAL`. Firecracker unmaps its registered guest memory at teardown, while the VM's userfaultfd is still open (the guest regions' drop, lib/firecracker/src/vmm/src/vstate/memory.rs:308, before `uffd`, vstate/vm.rs:84 and :95), and the release after it changes nothing | `test_memory_unmapped_while_registered_leaves_no_registration_behind`, `test_a_release_after_the_memory_was_unmapped_leaves_a_new_mapping_as_it_is`, `test_an_unmapping_and_its_unregistration_are_one_step`, `test_memory_replaced_while_registered_is_in_no_registration`, `test_memory_replaced_while_registered_registers_anew`, `test_a_discard_of_memory_replaced_while_registered_is_ordinary`, `test_a_page_mapped_over_and_registered_again_is_filled_in_the_new_memory`, `test_a_waiter_on_memory_mapped_over_is_woken_by_its_userfaultfd`, `test_a_waiter_on_unmapped_memory_takes_its_own_fault_once_woken`, `test_a_cut_of_a_registered_huge_page_is_einval` |
| `read`, `write`, `recv`, `send`, ... into or out of registered memory | the copy faults to the userfaultfd and waits (for a userfaultfd made with `user_mode_only(false)`) | the buffer's missing pages are faulted in first (`prefault`), and again on `EFAULT` | `test_system_calls_wait_for_missing_pages` |
| `UFFDIO_UNREGISTER` of part of a range | the vma is split and the rest stays registered (fs/userfaultfd.c `userfaultfd_unregister` :1413) | the same; a fill whose destination holds an unregistered page is `ENOENT`, as Linux's destination must lie in one registered vma (mm/userfaultfd.c `validate_dst_vma` :23 to :37) | `test_a_partial_unregister_keeps_the_rest_registered`, `test_a_fill_of_an_unregistered_page_is_enoent` |

## Hypervisors

| | Linux | macOS | Windows |
|---|---|---|---|
| Hypervisor | KVM | Hypervisor.framework (macOS 15+) | Windows Hypervisor Platform |
| Guest | x86_64, aarch64 | aarch64 | x86_64 |
| Interrupt controller | KVM vGIC / LAPIC | `hv_gic_*` GICv3 (GICv2m MSI frame instead of an ITS) | WHP LAPIC + user-space IOAPIC, 8259 PIC, 8254 PIT |
| Process hardening | seccomp-BPF, jailer | Seatbelt, upstream's jailer on macOS backends (`overlay/jailer/platform`) | a process mitigation profile, upstream's jailer on Windows backends: a jail drive, a restricted token, a Job Object |

PV steal time on macOS 27 (`crates/compat/kvm-ioctls/src/hvf/pvtime.rs`): KVM adds a vCPU thread's run delay to the
guest's stolen-time structure at the next entry after the scheduler runs the thread again. Hypervisor.framework
does not leave `hv_vcpu_run` when the host deschedules the thread, so the backend counts a vCPU's steal as the
time inside `run()` the thread was neither on a CPU nor waiting for an interrupt, and writes it at each entry; a
thread of each microVM reads its running vCPU threads' state every 2 ms (`thread_info`) and makes one kept off
its CPU for 1 ms leave the guest (`hv_vcpus_exit`), which the run loop enters again with the steal written. It
sleeps while no vCPU is in the guest and ends with the microVM. It is an ordinary thread: on a contended host it
waits for a CPU like the vCPUs, and the steal reaches the guest later by that wait (not closed). Cost and lateness:
docs/COMPATIBILITY.md, PV time.

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
  at most one callback, which only posts a packet. Level-triggered is the default and `ONE_SHOT` is supported. Sockets
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
  count and re-arms. Clocks: QPC (MONOTONIC), interrupt time (BOOTTIME),
  `GetSystemTimePreciseAsFileTime` (REALTIME), process/thread times (CPU
  clocks).
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
  code; out of one Windows Error Reporting ends it, with its dump. Console control events are `SIGINT`, `SIGQUIT` and `SIGHUP`.
- **mmap = placeholder virtual memory (Windows 10 1803+).** One mapping is one
  Windows allocation, tracked in a table. So that partial `munmap` and
  `MAP_FIXED` behave as on Linux, reservations are placeholders
  (`VirtualAlloc2`), shared mappings are section views (`MapViewOfFile3`) and
  private file mappings are committed and filled from the file whole when
  mapped (a fill by the page is not race-free in private memory; see
  `windows_mm::fill`). `madvise(DONTNEED)`
  discards private pages. File offsets not aligned to 64 KiB, shared mappings
  past EOF, `MAP_FIXED` over part of a view and `MAP_HUGETLB` fail with the
  Linux errno.
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
  submission/completion model, restrictions and queue limits.
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
