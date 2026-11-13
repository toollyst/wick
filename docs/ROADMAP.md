# Roadmap

**The goal: Firecracker, everywhere.** Upstream Firecracker, unchanged except for a small patch series, with the same
API, the same security level and usable images on Linux, macOS and Windows.

Every milestone says what "done" means, and a row is marked done only when it has been checked that way: on macOS,
end to end by [`tools/macos/boot-test.sh`](../tools/macos/boot-test.sh) against upstream's aarch64 CI kernel and
rootfs; on Windows, by [`tools/windows/boot-test.ps1`](../tools/windows/boot-test.ps1) on real hardware.

| | Milestone | State |
| --- | --- | --- |
| M1 | [Foundation](#m1-foundation) | done |
| M2 | [macOS: Hypervisor.framework, aarch64 guests](#m2-macos-hypervisorframework-aarch64-guests) | in progress: the GDB stub is left |
| M3 | [Windows: first boot on real hardware](#m3-windows-first-boot-on-real-hardware) | in progress |
| M4 | [Linux: upstream parity](#m4-linux-upstream-parity) | in progress |
| M5 | [Security parity: the jailer on every host](#m5-security-parity-the-jailer-on-every-host) | in progress |
| M6 | [Images everywhere](#m6-images-everywhere) | planned |
| M7 | [Desktop devices](#m7-desktop-devices) | planned |
| M8 | [Distribution](#m8-distribution) | planned |
| M9 | [GPU (headless Vulkan)](#m9-gpu-headless-vulkan) | planned: design only, no code yet |

## At a glance

| Feature | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Boot, serial, API socket, config file | upstream | works | works (WHP; 1 and 2 vCPUs, kvm-clock) |
| virtio-blk (Sync) | upstream | works | works |
| virtio-blk (Async) | upstream (io_uring) | works (worker threads) | works (worker threads) |
| vsock (UDS) | upstream | works (host→guest `CONNECT`, guest→host `<uds>_<port>`, MMIO and PCI) | works (host→guest `CONNECT`, guest→host `<uds>_<port>`, MMIO and PCI) |
| virtio-net | upstream (TAP) | works (vmnet, Unix datagram endpoint) | works (Unix stream endpoint: ARP, ICMP, UDP) |
| PCI / MSI-X | upstream | works (`--enable-pci`, GICv2m MSI frame) | works (`--enable-pci`, MSI routes on the WHP LAPIC) |
| Snapshots | upstream | works (full and diff, restore in another process, `snapshot-editor rebase`, with PCI) | works (full and diff, restore in another process, `snapshot-editor rebase`, with PCI; diff dumps 64 KiB units, NTFS's sparse granularity) |
| userfaultfd (`Uffd` memory backend) | upstream | works | works (WHP memory access exits, vectored exception handler, section alias; upstream's `uffd_on_demand_handler`) |
| vhost-user | upstream | works (vhost-user-blk backend in another process) | works (vhost-user-blk backend in another process) |
| hugepages | upstream | works as far as the host allows: 2 MiB pages on host pages, faulted and filled whole through a userfaultfd (no superpage for user space on Apple silicon: measured; `boot-test hugepages`, docs/PORTING.md row 10) | built unjailed (`MEM_LARGE_PAGES`, needs "Lock pages in memory"; Firecracker's `MAP_FIXED` guest memory over its reservation; `boot-test hugepages`); in a jail, where no privilege can be enabled, the jailer makes them for Firecracker (`jailer-test.ps1 hugepages`, docs/PORTING.md row 10) |
| seccomp | upstream | Seatbelt | process mitigation policies |
| jailer | upstream | in place: upstream's jailer; chroot, uid/gid, memory and CPU cgroups, resource limits, daemonize (`jailer-test`); the freezer, run as root on macOS 26.7.2, all 11 cases passing, 30 starts among them (`jailer-test freeze`, run 43245532519); the 1 jail start in 6 that failed on CI before from the supervisor's `pid_suspend` check is fixed | in place: upstream's jailer; the jail as a drive, a restricted token below medium integrity with a SID per jail, CPU limits through a Job Object, a memory limit that holds private memory but not sections, and the freezer through upstream's files, freezing the jail's Job Object (`tools/windows/jailer-test.ps1`; `jailer-test.ps1 sections` fails; `jailer-test.ps1 freeze` passed elevated on Windows Server 2022 build 20348 and unelevated and elevated on Windows 11 build 26300, kit 8d577b7) |

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
| userfaultfd | `userfaultfd` API | kernel side in `libc::wick_uffd` (`PROT_NONE` + signal, HVF stage-2, filled through an alias, fault-in before system calls, `MADV_DONTNEED` → remove events), socket protocol (a handler's channel end stays open until the serving thread answers, since XNU's collector flushes a socket that only a message in flight refers to, while the message waits on a socket never in flight itself, where Linux keeps it: bsd/kern/uipc_usrreq.c `unp_gc`, net/unix/garbage.c `unix_vertex_dead`; `test_inflight_socket_is_flushed`) | done (snapshot restore with `uffd_on_demand_handler`) |
| snapshot-editor, examples | `platform::fs`, `vmm_sys_util::seek_hole` | `pread` + `write`, APFS `SEEK_HOLE` | done |
| PCI / MSI-X | `kvm-ioctls` API (`GRP_ADDR` MSI frame) | HVF GIC MSI frame (GICv2m), FDT `arm,gic-v2m-frame`, MSI SPI state saved | done (virtio-pci blk and net, snapshot restore) |
| vhost-user | `vmm-sys-util` eventfd, `libc` `SO_DOMAIN` | single-fd eventfd (FIFO, Linux counter semantics), memfd shared memory | done (vhost-user-blk backend in another process) |
| eventfd, epoll, timerfd, signals | `vmm-sys-util`, `libc` | pipes, kqueue, timer threads | works |
| seccomp | `vmm::ext::sandbox` | Seatbelt | works; see [M5](#m5-security-parity-the-jailer-on-every-host) |

What is left on macOS: the GDB stub, whose stage has run with LLDB but not with gdb (docs/COMPATIBILITY.md, CPU, GDB stub: not done yet); and in other milestones the jailer (M5) and x86_64 images (M6); hugepages are in place as far as the host allows (docs/PORTING.md row 10).

## M3. Windows: first boot on real hardware

**Done when** `tools/windows/boot-test.ps1` passes every stage on a real Windows PC with the Windows Hypervisor
Platform, and the Windows column of [At a glance](#at-a-glance) says "works" for each row it covers.

**Every boot test stage that has run on real hardware passes, but `cli`** (AMD Ryzen 9 7900, Windows 11 Pro build
26300): boot, smp, block, vsock, net, snapshot, diff, uffd, pci, restores (20 restores, each paused and snapshotted
again), vhost-user, hugepages, api-process and devices (docs/PORTING.md rows 4, 10 and 15). `smp` with CPU 1
taken offline and online, `tools`, `no-seccomp`, `foreign-snapshot`, and the drive serials and rate limiters of
`block` and `net` passed there too (kit 8d577b7, Windows 11 10.0.26300.9711), and `memory-hotplug` after a fix; on kit
dd657f4 those stages, `diff` and `memory-hotplug` passed 5 of 5 runs in a row. `gdb` passed 3 of 3 on kit 7952d31, after its address translation (kit dd657f4) and the guest's own `INT3` (kit 684042f) were fixed; `cli` ran there once (kit 8d577b7) and failed in its named-pipe case, `FlushMetrics` answering 400 once the pipes' readers had gone (docs/COMPATIBILITY.md, Logger or metrics to a FIFO; its cause is fixed since, the stage not re-run), and `balloon` waits for that
machine. The vmm library and the firecracker binary build and link for
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
  refused inside an AppContainer (`E_ACCESSDENIED`) but works for a process on a restricted token below medium integrity
  that has no access to the user's files ([M5](#m5-security-parity-the-jailer-on-every-host)).
- What the hardware runs found, each fixed and covered by its stage: the guest's CPUID (KVM's supported set, no
  MWAIT or nested virtualisation; OSXSAVE, OSPKE and the XSAVE sizes from the vCPU's state at each CPUID exit; the TSC
  deadline timer, which WHP's xAPIC lacks, now emulated as KVM does), the speculation-control MSRs, kvm-clock and KVM's hypercalls
  (the guest no longer calibrates its TSC against the PIT), one instruction emulator per vCPU thread (a shared one
  corrupted a 2 vCPU guest's memory), irqfds cleared through their eventfd, an epoll nested in another (the vsock
  muxer's; it ended Firecracker with `STATUS_THREADPOOL_HANDLE_EXCEPTION`), `SEEK_HOLE` on a write-only file,
  16-byte aligned WHP register arrays (a snapshot restore faulted inside `WHvSetVirtualProcessorRegisters`), diff
  snapshots in 64 KiB units (patch 0020) and a guest RAM access under userfaultfd never treated as MMIO.
- Found since, by reading the path `huge_pages` takes: Firecracker 1.18 maps guest memory `MAP_FIXED` over a
  `PROT_NONE` reservation, which the libc layer refused for large pages, so `hugepages` could not have passed.
  Fixed (docs/PORTING.md, row 10); a jailed Firecracker, whose token can have no privilege enabled, gets its large
  pages from the jailer (`test_hugetlb_through_the_broker`), and `hugepages` passes there, unjailed and jailed.
- Next: the stages written since, on that machine.
- Not done: Nitro Enclaves (docs/COMPATIBILITY.md, `GET`, `PUT /enclave`). AWS documents Windows Server parents for
  enclaves and nested Hyper-V, which WHP needs, on instance types that are in both lists, so a Windows host can meet
  an enclave; Windows's side, AWS's `AWSNitroEnclavesWindows` package, has no documented programmatic interface to
  build the backend on. Until one exists, the start is refused as on a Linux host without the device.

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
`tools/macos/jailer-test.sh` checks it as root, on CI without a VM. On Windows upstream's jailer runs too, with
Windows backends in the same place, and starts Firecracker in the jail; `tools/windows/jailer-test.ps1` checks it on
a WHP machine.

| Control | macOS | Windows |
| --- | --- | --- |
| System call filter | in place: Seatbelt `syscall-unix`, `syscall-mach` and `syscall-mig` allow-lists, process-wide, narrowed for good where upstream installs the VMM thread's filter (103 system calls, 15 Mach traps, 7 MIG routines (on macOS 27 also `thread_selfusage` and `thread_info`, for PV time) in the run phase, each tied to a Linux rule; what only building the microVM takes before that); checked over every boot-test stage, debug and release, by `tools/macos/sandbox-discovery.sh`; any other call raises SIGSYS and Firecracker exits with upstream's bad-syscall code (`ext::sandbox` unit tests, `test_narrow_ends_the_setup_phase`); executable mappings raise SIGSYS as upstream's `mmap`/`mprotect` rules trap (`test_executable_mappings_raise_sigsys`) | in place: a process mitigation profile, each mitigation tied to the Linux rule it stands for and read back after it is set — no child processes, no win32k, strict handle checks, extension points disabled, Microsoft-signed images only (set where building the microVM can live with them), and no dynamic code and the image-load restrictions (no remote or low-label images, System32 first) added where upstream installs the VMM thread's filter, for good; a denied operation ends Firecracker with upstream's bad-syscall code where Windows reports it, else fails closed (`test_win32k_policy`, `test_dynamic_code_policy`, `test_narrow_ends_the_setup_phase`, `test_denied_operation_exits_as_seccomp`, `test_denied_operations_fail_closed` and the other `ext::sandbox` unit tests; found with `tools/windows/mitigation-audit.ps1`) |
| chroot | in place: `chroot(2)` by the jailer, and by Firecracker first thing after the exec; Seatbelt file rule limited to the jail (`jailer-test jail`) | in place: the jail as a drive of its own (`DefineDosDevice`) and the current directory its root, so Firecracker's `/run/...` paths, files and `AF_UNIX` sockets alike, resolve inside it; the directory is protected from what its parent grants and open to the jail's SID, the user, SYSTEM and the administrators; the drive goes when the jailer exits, and a killed jailer's at the next jailer's start (all measured: `jailer-test.ps1 isolation`, `drives`) |
| network namespace | in place: Seatbelt denies IP networking; `--netns <dir>` names the jail's network, a directory of endpoints where Firecracker makes its network endpoints in a directory of the jail's own, `<dir>/<id>/`, which only that jail and the directory's owner or root reach (`test_each_jail_has_a_network_directory_of_its_own`; two jails of one uid are kept apart by the sandbox profile alone: SECURITY.md), and Unix sockets are reached only there, directly in `<dir>` (the switch's) and in the jail (`test_sandbox_restricts_child`, `test_jail_network_profile_limits_sockets`, `jailer-test netns`) | in place in code; the elevated stage passed on a WHP machine before this layout (kit 7952d31, Windows 11 build 26300) and has not run with it: `--netns <dir>` names the jail's network, a directory of endpoints that grants no jail anything; each jail makes its endpoints in a directory of its own in it, `<dir>\<id>`, which only that jail and the operator reach, and a second jail of a running id is refused as busy; and Windows Filtering Platform block filters on the jail's binary deny it every IPv4 and IPv6 connect, bind, listen and accept, in a dynamic session that goes with the jailer; an elevated jailer is needed and an unelevated one refused (`jailer-test.ps1 netns`, `refuse`, `test_netns_needs_an_existing_directory`, `test_the_network_directory_grants_no_jail`, `test_each_jail_has_a_network_directory_of_its_own`, `test_a_second_jail_of_one_id_is_refused_and_the_first_keeps_its_endpoint`). A `winprobe` run had shown an AppContainer would block IP networking but WHP refuses to run inside one (`E_ACCESSDENIED`), so the jailer uses filters, not an AppContainer |
| uid/gid | in place: dropped by Firecracker right after its chroot, exec'd from a root-owned copy the jailed user never could write (`jailer-test jail`) | in place: a restricted token without the user's SID, between low and medium integrity (`S-1-16-6144`), whose restricting SIDs are those every process of the session has plus a random SID of the jail's own (the counterpart of a per-microVM uid), with an initial impersonation token for process start-up that Firecracker reverts first thing (the Chromium sandbox's pattern). WHP works; a jailed process cannot read the user's files or SAM, write outside its jail, reach another jail's files, API socket or process, or open the operator's process; the operator reaches the API socket (`jailer-test.ps1 isolation`). No process or thread outside the jail opens to it and a process snapshot shows it none; it is not on the jailer's console (the jailer relays it), so it sends no console control event and types nothing there; `--new-pid-ns` returns as upstream's jailer does (`jailer-test.ps1 pidns`). `--uid`/`--gid` are recorded only. The jail's integrity level is above low, so a plain low-integrity process of the same user, although it holds the user's SID, cannot reach a jail's files, its API socket or its process (`jailer-test.ps1 low`) |
| cgroups memory | in place: `memory.max` / `memory.limit_in_bytes` → jetsam limit at the exec, the jailer's priority kept (a guest past the limit kills the VMM; measured) (`jailer-test limits`, `jailer-test memory`) | not in place: `memory.max` / `memory.limit_in_bytes` → Job Object memory limit, which holds private memory (charged as a guest touches it: a guest that touches more than the limit ends the VMM with 137, measured, `jailer-test.ps1 limits`, `jailer-test.ps1 memory`) but not sections: pagefile-backed and memfd (temporary-file) sections are not charged to the job (`jailer-test.ps1 sections` fails). Only large-page sections go through the jailer's broker, which holds them to `hugetlb.2MB.max` |
| cgroups CPU | in place: `cpu.max` / `cpu.cfs_quota_us` + `cpu.cfs_period_us` → a kernel CPU limit on the whole VMM, applied by Firecracker right after the exec (macOS keeps it with the task an exec replaces); the budget refills each second rather than each period; whole percents, rounded down, 1% to 255% of one CPU, anything outside refused (`test_cpu_limit`); the allow-list denies the call that would lift it, and `--no-seccomp` is refused with it (four spinning threads held to 10%: measured; a jailed guest's spinning vCPUs: `jailer-test.sh cpu`) | in place: `cpu.max` / `cpu.cfs_quota_us` + `cpu.cfs_period_us` → a Job Object CPU rate hard cap, `quota / period` CPUs, from Firecracker's start (`jailer-test.ps1 cpu` passes on a WHP machine, row 9). It used to start after 2 CPU-seconds: booted under the cap, about 1 guest in 3 found its local APIC timer far too slow, disabled it ("APIC frequency too slow") and stopped taking interrupts. Cause: Linux calibrates the APIC timer only when it has no TSC-deadline timer and no APIC frequency from the platform (KVM always emulates the timer; WHP's xAPIC has none), by polling for 100 ms (`calibrate_APIC_clock`, `LAPIC_CAL_LOOPS` = HZ/10, in Linux 6.1's arch/x86/kernel/apic/apic.c), which a throttled vCPU finishes in a burst; it then ticks on the PIT in one-shot mode, which wick's PIT did not run. Now `IA32_TSC_DEADLINE` is emulated as KVM does and the PIT raises IRQ 0 in its one-shot modes (`test_deadline_interrupt`, `test_pit_one_shot_raises_irq0_once_per_count`). The 6.1 guest reads the timing leaf 0x40000010 only on VMware and CPUID 0x15 only without kvm-clock, so stating the APIC frequency was no way out. WHP's own `CpuCap` partition property is refused |
| hugepages | in place: 2 MiB fault/copy granularity in the compatibility userfaultfd, 2 MiB-aligned mappings (no host superpages on Apple silicon: measured, `test_no_host_superpages`; `test_huge_page_ranges_fault_and_fill_whole_pages`, `boot-test hugepages`) | `MEM_LARGE_PAGES` / `SEC_LARGE_PAGES` (shown by a `winprobe` run); the jailer uses no AppContainer (WHP refuses one); the jail's token, below medium integrity, can have no privilege enabled, "Lock pages in memory" included, so a jailed Firecracker maps no large pages itself (`test_tokens_keep_only_traversal`): the jailer, which holds the privilege, makes them for it (`test_hugetlb_through_the_broker`, `jailer-test.ps1 hugepages`, docs/PORTING.md row 10) |

Neither macOS nor Windows filters system calls per thread. Threads of one process share an address space, so on
Linux the effective boundary of per-thread filters is already their union; the plan applies that union process-wide
and moves the API server, the thread whose separate filter is a real boundary, into a process of its own. That is in
place on both: on Windows the API process is a second process from Firecracker's binary with the whole mitigation
profile from its start, made by Firecracker or, in a jail, by the jailer on the jail's token and in its Job Object
(`test_the_api_process_serves_under_the_api_profile`, `jailer-test.ps1 api`).

On Windows a jailed process cannot open its peer to duplicate handles into it, so fd passing from a jailed VMM (to a
uffd handler or a vhost-user backend) is pulled: the sender keeps private copies and names them, and the receiver
duplicates them out of the sender (`test_a_sender_that_cannot_open_the_receiver_is_pulled_from`, `jailer-test.ps1
handoff`); the `uffd` and `vhost-user` jailer-test stages pass on a WHP machine (row 14).

Every "in place", "verified" or "measured" in these tables names the test that checks it (`tools/check-claims.py`, on
CI). Every Windows cell now names its test, so CI runs it with `--strict-windows`.

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

**virtio-fs: designed, no code yet** ([design-fs.md](design-fs.md)). The plan:

- The device in Firecracker only copies bounded, unparsed requests between the virtqueues and one socket.
- A separate server, `wick-fsd`, one per share, parses FUSE and does the file operations. It never sees guest
  memory, confines itself on each host (Linux: namespaces, `pivot_root`, seccomp; macOS: Seatbelt limited to the
  share; Windows: an LPAC token with an ACE on the share, a Job Object and wick's mitigation profile), and refuses to
  start if any of that fails.
- The jailer starts it next to Firecracker.
- It is off by default (a cargo feature `fs`), with no DAX window and no snapshots in the first version.
- Every known risk is in the design with the fix planned for each host and the test meant to prove it. The Windows
  parts come from documentation and are to be measured on a Windows PC with WHP.

## M8. Distribution

**Done when** each host installs wick in one step and new upstream releases reach users without manual work.

Release binaries for macOS (the release workflow already builds and packages the Apple silicon binary on a tag) and
Windows, Homebrew, automatic rebase attempts on new upstream tags.

## M9. GPU (headless Vulkan)

**Done when** a guest on each host runs a Vulkan compute workload (llama.cpp's Vulkan backend) on the host's GPU,
with the VMM's sandbox unchanged and the GPU code in sandboxed processes of its own.

Designed, no code yet ([design-gpu.md](design-gpu.md)).

**The device.** A virtio-gpu device offering the Venus (Vulkan) context type only: headless, no OpenGL, no
passthrough, no snapshots.

**The processes.**

- The VMM runs a vhost-user-gpu front-end and never opens the GPU.
- A back-end, `wick-gpu`, has no GPU access.
- Render workers, one per guest context, hold the driver in the tightest sandbox each host allows.

**Even then a guest's Vulkan calls reach the host's GPU driver.** So the design's rule is one GPU per trust domain,
and it is staged:

| Stage | Adds |
| --- | --- |
| v1 | the sandboxed processes, a fixed memory pool, and a validation stage that passes calls through; the risk stated in SECURITY.md |
| v2 | resource limits in that stage: allocation sizes, dispatches, queue depth, one GPU hang per VM |
| v3 | a shader rewrite that zeroes GPU local memory (LeftoverLocals) |
| v4 | a validated compute-only Vulkan subset, or WebGPU through Dawn, chosen after a research pass |

**Open host differences on Windows**, not decided yet (the design's §2a):

- A GPU worker there cannot have win32k lockdown.
- The host bug-checks after five GPU hangs within a minute.
