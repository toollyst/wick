# Roadmap

**The goal: Firecracker, everywhere.** Upstream Firecracker, unchanged except for a small patch series, with the same
API, the same security level and usable images on Linux, macOS and Windows.

Every milestone says what "done" means, and a row is marked done only when it has been checked that way: on macOS,
end to end by [`tools/macos/boot-test.sh`](../tools/macos/boot-test.sh) against upstream's aarch64 CI kernel and
rootfs; on Windows, by [`tools/windows/boot-test.ps1`](../tools/windows/boot-test.ps1) on real hardware.

| | Milestone | State |
| --- | --- | --- |
| M1 | [Foundation](#m1-foundation) | done |
| M2 | [macOS: Hypervisor.framework, aarch64 guests](#m2-macos-hypervisorframework-aarch64-guests) | done |
| M3 | [Windows: first boot on real hardware](#m3-windows-first-boot-on-real-hardware) | in progress |
| M4 | [Linux: upstream parity](#m4-linux-upstream-parity) | in progress |
| M5 | [Security parity: the jailer on every host](#m5-security-parity-the-jailer-on-every-host) | in progress |
| M6 | [Images everywhere](#m6-images-everywhere) | planned |
| M7 | [Desktop devices](#m7-desktop-devices) | planned |
| M8 | [Distribution](#m8-distribution) | planned |

## At a glance

| Feature | Linux | macOS | Windows |
| --- | --- | --- | --- |
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

## M1. Foundation

**Done when** upstream builds from a pinned submodule plus a patch series that a check enforces, and following a new
upstream release is one command.

- **Upstream as a pinned submodule**, feature patches with a policy check, setup/export/rebase tooling, CI
  definitions. *Done.*
- **Extension point.** `vmm::ext` + `wick-ext`, `PUT /extensions/{name}`, the config file's `"extensions"` section.
  *Done.*
- **Platform boundary.** Compatibility crates for every Linux-only dependency, `vmm::platform` interfaces with a
  backend per OS. *Done.*

## M2. macOS: Hypervisor.framework, aarch64 guests

**Done when** every device and feature upstream has on aarch64 passes a scenario test in a real guest on a Mac.

Boots with 1 and 2 vCPUs; serial I/O, virtio-blk (Sync and Async), reboot and shutdown, API socket, Seatbelt
sandbox, dirty page tracking. Every row marked done is checked end to end by `tools/macos/boot-test.sh` against
upstream's aarch64 CI kernel and rootfs. Its first run found interrupts raised before the vCPUs first run (a
snapshot restore kicks the devices then) dropped by Hypervisor.framework, which left vsock and PCI devices without
interrupts after a restore, and a guest counter set per vCPU at its creation instead of once for the VM (RCU stalls
after a Uffd restore); both are fixed.

| Area | Interface | macOS backend | State |
| --- | --- | --- | --- |
| Block async I/O (io_uring) | `platform::async_io` | worker threads + `F_FULLFSYNC` | done |
| Holes in snapshot files | `platform::fs` | record `SEEK_HOLE`, restore with `F_PUNCHHOLE` after flush (APFS fills holes on flush) | done (diff snapshot → `snapshot-editor rebase` → restore) |
| Hypervisor (KVM) | `kvm-ioctls` API | HVF, including GIC register state | done (snapshot restore) |
| Network (TAP) | `platform::net` | vmnet (`vmnet-shared`, `vmnet-host`, `vmnet-br-<if>`) or a Unix datagram endpoint; TUN header handling in `platform::vnet` (checksum, TSO, UFO) | done (guest NAT, TCP) |
| userfaultfd | `userfaultfd` API | kernel side in `libc::wick_uffd` (`PROT_NONE` + signal, HVF stage-2, filled through an alias, fault-in before system calls, `MADV_DONTNEED` → remove events), socket protocol (a handler's channel end stays open until the serving thread answers, since macOS can drop a descriptor only a message in flight refers to) | done (snapshot restore with `uffd_on_demand_handler`) |
| snapshot-editor, examples | `platform::fs`, `vmm_sys_util::seek_hole` | `pread` + `write`, APFS `SEEK_HOLE` | done |
| PCI / MSI-X | `kvm-ioctls` API (`GRP_ADDR` MSI frame) | HVF GIC MSI frame (GICv2m), FDT `arm,gic-v2m-frame`, MSI SPI state saved | done (virtio-pci blk and net, snapshot restore) |
| vhost-user | `vmm-sys-util` eventfd, `libc` `SO_DOMAIN` | single-fd eventfd (FIFO, Linux counter semantics), memfd shared memory | done (vhost-user-blk backend in another process) |
| eventfd, epoll, timerfd, signals | `vmm-sys-util`, `libc` | pipes, kqueue, timer threads | works |
| seccomp | `vmm::ext::sandbox` | Seatbelt | works; see [M5](#m5-security-parity-the-jailer-on-every-host) |

What is left on macOS belongs to other milestones: hugepages (M5), the jailer (M5) and x86_64 images (M6).

## M3. Windows: first boot on real hardware

**Done when** `tools/windows/boot-test.ps1` passes every stage on a real Windows PC with the Windows Hypervisor
Platform, and the Windows column of [At a glance](#at-a-glance) says "works" for each row it covers.

**Code complete; not yet run on real hardware.** The vmm library and the firecracker binary build and link for
`x86_64-pc-windows-gnu` (cross) and `x86_64-pc-windows-msvc` (native, the binary CI publishes).

- Done: the POSIX layer (`wick-os`, `wick-std`, `libc`, `vmm-sys-util`, `memfd`, generated
  `vm-memory`/`event-manager`/`micro_http`/`vhost`, `kvm-bindings` with a fixed layout), the platform backends, the
  **WHP backend** of `kvm-ioctls` (partition, vCPUs, memory with `WHvMapGpaRange` and dirty bitmaps, the run loop
  with `WHvCancelRunVirtualProcessor` as the kick, MMIO/PIO through the WHP instruction emulator decoded to KVM
  `VcpuExit`s, ioeventfd matching, WHP LAPIC with a user-space IOAPIC, 8259 PIC and 8254 PIT, irqfd routing, CPUID
  and MSR filtering, register conversion), and a host sandbox that blocks child processes and fails loudly if it
  cannot.
- Tested natively: CI runs every compatibility crate's tests on a Windows runner. The first native run found
  synchronous sockets that blocked descriptor passing behind a pending receive and standard descriptors passed as
  raw handle values (both fixed); a standard input that is a pipe is now pollable, so the serial console reads it as
  on Linux.
- Next, on real hardware:
  1. A first guest boot with upstream's x86_64 CI kernel and rootfs (`tools/windows/boot-test.ps1`: boot, SMP,
     block, vsock, virtio-net over the Unix stream endpoint; the steps are in
     [tools/windows/README.md](../tools/windows/README.md)): the LAPIC register page (`get/set_lapic`), AP start-up
     through WHP's INIT/SIPI handling, CPUID hypervisor leaves and the guest clock, the vCPU kick at run time.
     Reading the backend against upstream's boot path before that found the vCPU kick handle
     (`create_vcpu_from_rawfd`) missing, which no boot gets past, a kick lost when it lands just before a run, APs
     not held for their SIPI, a 1 KiB LAPIC exchange and a fatal HLT exit (all fixed).
  2. WHP inside an AppContainer and under the full mitigation profile.
  3. The fd-passing changes for jailed processes ([M5](#m5-security-parity-the-jailer-on-every-host)).
- After that: PCI / MSI-X, snapshots and userfaultfd on Windows (planned in [At a glance](#at-a-glance)).

## M4. Linux: upstream parity

**Done when** upstream's own test suite gives the same results with wick as without it, by test name.

On Linux, wick is upstream Firecracker: the compatibility crates re-export the original crates, and the platform
interfaces' Linux backends are upstream's own code (io_uring, TAP).

- CI builds the firecracker binary on Linux x86_64 and aarch64 on every push.
- The test levels and the rules for comparing with upstream (which tests are re-run single-threaded, which are left
  out and why) are in [CONTRIBUTING.md](../CONTRIBUTING.md#tests).

## M5. Security parity: the jailer on every host

**Done when** every control Firecracker has on Linux has a native equivalent on macOS and Windows, wired into the
upstream `jailer` CLI, and each one has been measured on that host.

Firecracker's isolation on Linux is hardware virtualisation, a minimal device model, per-thread seccomp filters and
the jailer (chroot, uid/gid, namespaces, cgroups, resource limits). The plan keeps the upstream `jailer` CLI and
gives each control a native backend. Each row names the mechanism; "verified" marks what has been measured on that
host with a probe. None of it is wired into the jailer yet, and the jailer is not available on macOS or Windows
today.

| Control | macOS | Windows |
| --- | --- | --- |
| System call filter | Seatbelt `syscall-unix` allow-lists (kernel-enforced, process-wide; verified) | win32k lockdown, ACG, strict handle checks, extension-point and image-load policies (verified with Firecracker's run-time needs) |
| chroot | Seatbelt path rules limited to the jail directory | AppContainer + jail directory ACL (user files denied, verified) |
| network namespace | Seatbelt denies IP networking | AppContainer without capabilities (internet and loopback blocked, `AF_UNIX` API socket works; verified) |
| uid/gid | setuid from a root jailer | per-VM AppContainer SID |
| cgroups memory | jetsam limit via `posix_spawnattr_setjetsam_ext` (kills at the limit without root; verified) | Job Object commit limit (kills at the limit; verified). Shared sections are not charged to the job: memfd-backed memory goes through a jailer broker |
| cgroups CPU | vCPU time quota in the VMM run loop | Job Object hard cap (verified) |
| hugepages | 2 MiB fault/copy granularity in the uffd kernel side (no host superpages on Apple silicon) | `MEM_LARGE_PAGES` / `SEC_LARGE_PAGES` (verified); the privilege is stripped inside an AppContainer, so the jailer creates the section |

Neither macOS nor Windows filters system calls per thread. Threads of one process share an address space, so on
Linux the effective boundary of per-thread filters is already their union; the plan applies that union process-wide
and moves the API server, the thread whose separate filter is a real boundary, into a process of its own.

On Windows a jailed process cannot open its peer to duplicate handles into it, so fd passing from a jailed VMM (to a
uffd handler or a vhost-user backend) changes to the receiver duplicating out of the sender, or to a jailer broker.

## M6. Images everywhere

**Done when** upstream rootfs images and OCI images run unchanged on every host, including images built for the
other architecture.

Kernels always run on the host architecture with hardware virtualisation; foreign user space is translated inside
the guest.

| Host | Native | Foreign images |
| --- | --- | --- |
| macOS (arm64) | arm64 | x86_64 through FEX-Emu with hardware TSO (`HV_SYS_REG_ACTLR_EL1`, macOS 15+) |
| Windows x86_64 | x86_64 | arm64 through qemu-user in the guest |
| Windows arm64 | arm64 (WHP arm64 backend, Windows 11 24H2+) | x86_64 through FEX-Emu |

A host-architecture initramfs registers binfmt handlers and switches to the image's rootfs, so upstream rootfs
images and OCI images run unchanged.

## M7. Desktop devices

**Done when** a guest on a laptop gets networking and host folders without root, a host switch or extra software.

Through `wick-ext` (`PUT /extensions/{name}`): user-mode networking (no vmnet or host switch needed), virtio-fs, a
capability query API.

## M8. Distribution

**Done when** each host installs wick in one step and new upstream releases reach users without manual work.

Release binaries for macOS (the release workflow already builds and packages the Apple silicon binary on a tag) and
Windows, Homebrew, automatic rebase attempts on new upstream tags.
