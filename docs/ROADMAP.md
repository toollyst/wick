# Roadmap

The goal: upstream Firecracker, unchanged except for a small patch series, with
the same API, the same security level and usable images on Linux, macOS and
Windows.

## Done

- **Foundation.** Upstream as a pinned submodule, feature patches with a
  policy check, setup/export/rebase tooling, CI definitions.
- **Extension point.** `vmm::ext` + `wick-ext`, `PUT /extensions/{name}`, the
  config file's `"extensions"` section.
- **Platform boundary.** Compatibility crates for every Linux-only dependency,
  `vmm::platform` interfaces with a backend per OS.

## macOS (Hypervisor.framework, aarch64 guests)

Boots with 1 and 2 vCPUs; serial I/O, virtio-blk (Sync and Async), reboot and
shutdown, API socket, Seatbelt sandbox, dirty page tracking. Every row marked
done is checked end to end by `tools/macos/boot-test.sh` against upstream's
aarch64 CI kernel and rootfs. Its first run found interrupts raised before
the vCPUs first run (a snapshot restore kicks the devices then) dropped by
Hypervisor.framework, which left vsock and PCI devices without interrupts
after a restore, and a guest counter set per vCPU at its creation instead of
once for the VM (RCU stalls after a Uffd restore); both are fixed.

| Area | Interface | macOS backend | State |
|---|---|---|---|
| Block async I/O (io_uring) | `platform::async_io` | worker threads + `F_FULLFSYNC` | done |
| Holes in snapshot files | `platform::fs` | record `SEEK_HOLE`, restore with `F_PUNCHHOLE` after flush (APFS fills holes on flush) | done (diff snapshot → `snapshot-editor rebase` → restore) |
| Hypervisor (KVM) | `kvm-ioctls` API | HVF, including GIC register state | done (snapshot restore) |
| Network (TAP) | `platform::net` | vmnet (`vmnet-shared`, `vmnet-host`, `vmnet-br-<if>`) or a Unix datagram endpoint; TUN header handling in `platform::vnet` (checksum, TSO, UFO) | done (guest NAT, TCP) |
| userfaultfd | `userfaultfd` API | kernel side in `libc::wick_uffd` (`PROT_NONE` + signal, HVF stage-2, filled through an alias, fault-in before system calls, `MADV_DONTNEED` → remove events), socket protocol | done (snapshot restore with `uffd_on_demand_handler`) |
| snapshot-editor, examples | `platform::fs`, `vmm_sys_util::seek_hole` | `pread` + `write`, APFS `SEEK_HOLE` | done |
| PCI / MSI-X | `kvm-ioctls` API (`GRP_ADDR` MSI frame) | HVF GIC MSI frame (GICv2m), FDT `arm,gic-v2m-frame`, MSI SPI state saved | done (virtio-pci blk and net, snapshot restore) |
| vhost-user | `vmm-sys-util` eventfd, `libc` `SO_DOMAIN` | single-fd eventfd (FIFO, Linux counter semantics), memfd shared memory | done (vhost-user-blk backend in another process) |
| eventfd, epoll, timerfd, signals | `vmm-sys-util`, `libc` | pipes, kqueue, timer threads | works |
| seccomp | `vmm::ext::sandbox` | Seatbelt | works; see "Security parity" |

## Windows (Windows Hypervisor Platform, x86_64 guests)

**Code complete; not yet run on real hardware.** The vmm library and the
firecracker binary build and link for `x86_64-pc-windows-gnu` (cross) and
`x86_64-pc-windows-msvc` (native, the binary CI publishes).

- Done: the POSIX layer (`wick-os`, `wick-std`, `libc`, `vmm-sys-util`,
  `memfd`, generated `vm-memory`/`event-manager`/`micro_http`/`vhost`,
  `kvm-bindings` with a fixed layout), the platform backends, the **WHP
  backend** of `kvm-ioctls` (partition, vCPUs, memory with
  `WHvMapGpaRange` and dirty bitmaps, the run loop with
  `WHvCancelRunVirtualProcessor` as the kick, MMIO/PIO through the WHP
  instruction emulator decoded to KVM `VcpuExit`s, ioeventfd matching, WHP
  LAPIC with a user-space IOAPIC, 8259 PIC and 8254 PIT, irqfd routing,
  CPUID and MSR filtering, register conversion), and a host sandbox that
  blocks child processes and fails loudly if it cannot.
- Tested natively: CI runs every compatibility crate's tests on a Windows
  runner. The first native run found synchronous sockets that blocked
  descriptor passing behind a pending receive and standard descriptors passed
  as raw handle values (both fixed); a standard input that is a pipe is now
  pollable, so the serial console reads it as on Linux.
- Next, on real hardware:
  1. A first guest boot with upstream's x86_64 CI kernel and rootfs
     (`tools/windows/boot-test.ps1`): LAPIC state layout (`get/set_lapic`
     over the interrupt controller state), CPUID hypervisor leaves and
     kvm-clock, the vCPU kick at run time.
  2. WHP inside an AppContainer and under the full mitigation profile.
  3. The fd-passing changes for jailed processes (below).

## Security parity (in progress)

Firecracker's isolation on Linux is hardware virtualisation, a minimal device
model, per-thread seccomp filters and the jailer (chroot, uid/gid, namespaces,
cgroups, resource limits). The plan keeps the upstream `jailer` CLI and gives
each control a native backend. Each row names the mechanism; "verified" marks
what has been measured on that host with a probe. None of it is wired into the
jailer yet, and the jailer is not available on macOS or Windows today.

| Control | macOS | Windows |
|---|---|---|
| System call filter | Seatbelt `syscall-unix` allow-lists (kernel-enforced, process-wide; verified) | win32k lockdown, ACG, strict handle checks, extension-point and image-load policies (verified with Firecracker's run-time needs) |
| chroot | Seatbelt path rules limited to the jail directory | AppContainer + jail directory ACL (user files denied, verified) |
| network namespace | Seatbelt denies IP networking | AppContainer without capabilities (internet and loopback blocked, `AF_UNIX` API socket works; verified) |
| uid/gid | setuid from a root jailer | per-VM AppContainer SID |
| cgroups memory | jetsam limit via `posix_spawnattr_setjetsam_ext` (kills at the limit without root; verified) | Job Object commit limit (kills at the limit; verified). Shared sections are not charged to the job: memfd-backed memory goes through a jailer broker |
| cgroups CPU | vCPU time quota in the VMM run loop | Job Object hard cap (verified) |
| hugepages | 2 MiB fault/copy granularity in the uffd kernel side (no host superpages on Apple silicon) | `MEM_LARGE_PAGES` / `SEC_LARGE_PAGES` (verified); the privilege is stripped inside an AppContainer, so the jailer creates the section |

Neither macOS nor Windows filters system calls per thread. Threads of one
process share an address space, so on Linux the effective boundary of
per-thread filters is already their union; the plan applies that union
process-wide and moves the API server, the thread whose separate filter is a
real boundary, into a process of its own.

On Windows a jailed process cannot open its peer to duplicate handles into it,
so fd passing from a jailed VMM (to a uffd handler or a vhost-user backend)
changes to the receiver duplicating out of the sender, or to a jailer broker.

## Images (planned)

Kernels always run on the host architecture with hardware virtualisation;
foreign user space is translated inside the guest.

| Host | Native | Foreign images |
|---|---|---|
| macOS (arm64) | arm64 | x86_64 through FEX-Emu with hardware TSO (`HV_SYS_REG_ACTLR_EL1`, macOS 15+) |
| Windows x86_64 | x86_64 | arm64 through qemu-user in the guest |
| Windows arm64 | arm64 (WHP arm64 backend, Windows 11 24H2+) | x86_64 through FEX-Emu |

A host-architecture initramfs registers binfmt handlers and switches to the
image's rootfs, so upstream rootfs images and OCI images run unchanged.

## Desktop devices (`wick-ext`, planned)

User-mode networking (no vmnet or host switch needed), virtio-fs, a
capability query API.

## Distribution (planned)

Signed and notarised macOS releases, Windows releases, Homebrew, automatic
rebase attempts on new upstream tags.

## Platform status

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| Boot, serial, API socket, config file | upstream | works | built, hardware validation pending |
| virtio-blk (Sync) | upstream | works | built, validation pending |
| virtio-blk (Async) | upstream (io_uring) | works (worker threads) | built, validation pending |
| vsock (UDS) | upstream | works (host→guest `CONNECT`, guest→host `<uds>_<port>`, MMIO and PCI) | built, validation pending |
| virtio-net | upstream (TAP) | works (vmnet, Unix datagram endpoint) | built (Unix stream endpoint), validation pending |
| PCI / MSI-X | upstream | works (`--enable-pci`, GICv2m MSI frame) | planned |
| Snapshots | upstream | works (full and diff, restore in another process, `snapshot-editor rebase`, with PCI) | planned |
| userfaultfd (`Uffd` memory backend) | upstream | works | planned |
| hugepages | upstream | planned (uffd granularity) | planned (large pages) |
| seccomp | upstream | Seatbelt | process mitigation policies |
| jailer | upstream | planned | planned |
