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
| PCI / MSI-X | upstream | works (`--enable-pci`, GICv2m MSI frame) | built (MSI routes on the WHP LAPIC), validation pending |
| Snapshots | upstream | works (full and diff, restore in another process, `snapshot-editor rebase`, with PCI) | built (vCPU events through WHP's pending-interruption registers, `snapshot-editor` on Windows), validation pending |
| userfaultfd (`Uffd` memory backend) | upstream | works | built (vectored exception handler, WHP memory access exits, section alias), validation pending |
| vhost-user | upstream | works (vhost-user-blk backend in another process) | built, validation pending |
| hugepages | upstream | planned (uffd granularity) | built (`MEM_LARGE_PAGES`, needs "Lock pages in memory"), validation pending |
| seccomp | upstream | Seatbelt | process mitigation policies |
| jailer | upstream | in place: upstream's jailer; chroot, uid/gid, memory and CPU cgroups, resource limits, daemonize | planned |

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
- First run on real hardware (AMD Ryzen 9 7900, Windows 11 Pro build 26300, WHP): every stage failed before the
  guest started, on the terminal mode of a standard input that is a pipe (the console API fails on a pipe; the
  original leaves a descriptor that is not a TTY alone). Fixed; the stages run again with that fix.
- Built since, with the boot test stages that check them (`snapshot`, `diff`, `uffd`, `pci`, `vhost-user`,
  `hugepages`, the counterparts of the macOS ones): vCPU events for snapshots (WHP's pending-interruption and
  interrupt-state registers), `snapshot-editor`, the Uffd backend (`libc::wick_uffd` on Windows: missing pages
  `PAGE_NOACCESS`, a vectored exception handler for host threads, WHP memory access exits for guests, fills
  through a second view of a pagefile section; upstream's `uffd_on_demand_handler` builds for Windows), the
  vhost-user-blk test backend, and huge pages (`MEM_LARGE_PAGES`).
- Measured on that machine: WHP honours the host protection of guest RAM (a guest access to a `PAGE_NOACCESS` page
  exits at the instruction and re-runs once the page is accessible), which the Uffd backend relies on; WHP is
  refused inside an AppContainer (`E_ACCESSDENIED`) but works for a process on a restricted, low integrity token
  that has no access to the user's files ([M5](#m5-security-parity-the-jailer-on-every-host)).
- Next: every boot test stage passing on that machine, then the jailer ([M5](#m5-security-parity-the-jailer-on-every-host)).

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
host with a probe, "in place" what the jailer does today. On macOS upstream's jailer runs, with its Linux-only
primitives behind backends in `overlay/jailer/platform` (patch 0016) and the jail handed over to Firecracker,
since no program can start inside a chroot there (dyld maps the system libraries from outside it);
`tools/macos/jailer-test.sh` checks it as root, on CI without a VM. On Windows the jailer is not available yet;
the Windows column is what has been measured for it on a WHP machine.

| Control | macOS | Windows |
| --- | --- | --- |
| System call filter | in place: Seatbelt `syscall-unix` and `syscall-mach` allow-lists (system calls and Mach traps), process-wide, measured over every boot-test stage; any other call raises SIGSYS and Firecracker exits with upstream's bad-syscall code. Next: the kernel MIG routines reached through `mach_msg2_trap` (`syscall-mig`; 7 used over the boot-test) | win32k lockdown, ACG, strict handle checks, extension-point and image-load policies (verified with Firecracker's run-time needs) |
| chroot | in place: `chroot(2)` by the jailer, and by Firecracker first thing after the exec; Seatbelt file rule limited to the jail | the jail as a drive of its own (`DefineDosDevice`) and the current directory its root, so Firecracker's `/run/...` paths, files and `AF_UNIX` sockets alike, resolve inside it (verified); access outside it is the token's (below) |
| network namespace | in place: Seatbelt denies IP networking; `--netns` is refused | planned: Windows Filtering Platform. An AppContainer would block IP networking (verified) but WHP refuses an AppContainer (`E_ACCESSDENIED`, verified), so the jailer cannot use one |
| uid/gid | in place: dropped by Firecracker right after its chroot, exec'd from a root-owned copy the jailed user never could write | a restricted token without the user's SID, at low integrity, with an initial impersonation token for process start-up that Firecracker reverts first thing (the Chromium sandbox's pattern): WHP works, the user's files are denied (verified) |
| cgroups memory | in place: `memory.max` / `memory.limit_in_bytes` → jetsam limit at the exec, the jailer's priority kept (a guest past the limit kills the VMM; measured) | Job Object commit limit (kills at the limit; verified). Shared sections are not charged to the job: memfd-backed memory goes through a jailer broker |
| cgroups CPU | in place: `cpu.max` / `cpu.cfs_quota_us` + `cpu.cfs_period_us` → a kernel CPU limit on the whole VMM, applied by Firecracker right after the exec (macOS keeps it with the task an exec replaces); the budget refills each second rather than each period; whole percents, 1% to 255% of one CPU, anything else refused; the allow-list denies the call that would lift it, and `--no-seccomp` is refused with it (four spinning threads held to 10%: measured; a jailed guest's spinning vCPUs: `jailer-test.sh cpu`) | Job Object hard cap (verified) |
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
