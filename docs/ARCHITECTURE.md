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
therefore only change existing upstream files: 47 feature patches touching 84
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
   └─ external crates ([patch.crates-io] in lib/firecracker/Cargo.toml)
        libc, vmm-sys-util, memfd, userfaultfd, kvm-ioctls, kvm-bindings,
        vm-memory, event-manager, vhost, micro_http → crates/compat/<crate>
            Linux : re-exports the original crate from the same git tag, unchanged
            macOS : the same API on macOS facilities (kvm-ioctls → Hypervisor.framework)
            Windows: the same API on Win32 (kvm-ioctls → Windows Hypervisor Platform)
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
   (`PUT /extensions/{name}`, the config file's `extensions` section).
6. **No pretending.** If a host lacks a facility, wick builds the same
   semantics itself: io_uring → worker-thread queues, seccomp-BPF → Seatbelt,
   SSBD → `PSTATE.SSBS`, holes APFS fills → restored with `F_PUNCHHOLE`, TAP →
   vmnet or Unix sockets with TUN's checksum/TSO/UFO done in user space, ITS →
   the GIC's GICv2m MSI frame, userfaultfd → the kernel side above. Only what
   the hardware or OS physically cannot do is an error, and the roadmap's
   status table says so.

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
  with nothing typed too, and reads console input with std's console reader
  (`test_a_pipe_reads_as_on_linux`,
  `test_a_console_without_characters_reads_as_eagain`,
  `test_serial_input_reads_an_emptied_pipe_as_eagain`). `lock()` is std's
  lock, for the terminal modes.
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
  closed is swept when the table grows.
- **epoll = IOCP (the `polling` crate).** Sockets use AFD polls; eventfds,
  consoles and other waitable handles use wait packets that complete on the
  IOCP. Level-triggered is the default and `ONE_SHOT` is supported. Sockets
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
- **signals = APCs and an exception filter.** A signal to a thread is a user
  APC (`QueueUserAPC2`, else `NtQueueApcThreadEx`); faults are caught by
  `SetUnhandledExceptionFilter` and reported with Linux `si_code` and
  `si_addr`. Console control events are `SIGINT`, `SIGQUIT` and `SIGHUP`.
- **mmap = placeholder virtual memory (Windows 10 1803+).** One mapping is one
  Windows allocation, tracked in a table. So that partial `munmap` and
  `MAP_FIXED` behave as on Linux, reservations are placeholders
  (`VirtualAlloc2`), shared mappings are section views (`MapViewOfFile3`) and
  private file mappings are filled from the file. `madvise(DONTNEED)`
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
  `ENOTTY` (Windows paths use `DeviceIoControl`); `fallocate` is implemented
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
