# Host backends: the reference

Everything wick runs on a host other than Linux is a backend for a Linux facility upstream Firecracker uses. This
page lists each one: what upstream does on Linux, how the macOS backend holds the same semantics, the test that shows
it, and where Windows stands. Linux and macOS are the reference: a Windows backend is done when it passes the same
test, on a WHP machine.

[ARCHITECTURE.md](ARCHITECTURE.md) explains the layers and the POSIX layer on Windows. [SECURITY.md](../SECURITY.md)
and the [roadmap](ROADMAP.md) say what is in place. This page says what each backend has to do to be called done.

## Rules for a backend

1. **The semantics are Linux's.** The backend does what the Linux call did, errors included (errno, `io::ErrorKind`,
   upstream's exit codes). Where the host has no equivalent, wick builds one. Where the hardware or OS physically
   cannot do it, the request fails loudly, and the status tables say so. A flag is never accepted and then ignored.
2. **One interface, one backend per host.** Upstream's code calls the interface, through a patch with a `wick:`
   comment. On Linux the backend is upstream's own code, and on Linux wick must match upstream test by test
   (`tools/linux/compare-unit-tests.py`, `compare-integration-tests.py`).
3. **A test proves each backend, in the repository.** It is an interface test in `platform::<iface>::tests` that
   runs against every backend, a unit test next to the backend, or a boot-test or jailer-test stage. Each row below
   names its test. A probe that once showed something is not a test.
4. **A doc claim names its test.** A table cell that says "in place", "verified" or "measured" names the test in
   backticks (`tools/check-claims.py`, on CI). Windows cells are warnings until each one names its test; then CI
   runs with `--strict-windows`.
5. **Tests leave nothing behind.** Every process a test starts is registered as soon as it is started and killed on
   any exit. Each run writes `summary.txt` ending `N passed, M failed`. Each launcher calls `prepare_test_run`
   (`tools/common.sh`), which runs `tools/clean.sh` and checks free disk space first.

## The VMM's host interfaces (`overlay/vmm/platform`)

| Interface | Linux (upstream) | macOS | Test | Windows |
| --- | --- | --- | --- | --- |
| `async_io::AsyncIo` | io_uring | worker threads, `F_FULLFSYNC`; io_uring's submission and completion model, restrictions and queue limits (`macos/async_io.rs`) | `platform::async_io::tests`, `boot-test block` | the same file as macOS, on the compatibility `libc` |
| `fs` (`keep_holes`, `SparseWriter`, `StatIds`) | ext4/tmpfs holes | `SEEK_HOLE` recorded, holes punched again with `F_PUNCHHOLE` after the flush (APFS fills them) | `platform::fs::tests`, `boot-test diff` | the same file as macOS; NTFS's 64 KiB sparse units are checked after each restore |
| `net::TapDevice` | TAP | vmnet (`vmnet.rs`, root) or a Unix datagram endpoint (`net.rs`) | `platform::net::tests`, `boot-test net`, `boot-test vmnet` | a Unix stream endpoint, QEMU `-netdev stream` framing (`windows/net.rs`) |
| `vnet` (TUN's virtio-net header) | the kernel | shared, OS-independent: checksum, TSO, UFO | `platform::vnet::tests`, fuzz `vnet_segment`, `vnet_offload` | shared |

## The jailer's primitives (`overlay/jailer/platform`)

Upstream's jailer runs on every host: its command line, `Env::new` and `Env::run`. Only the Linux primitives below
go through a backend.

| Primitive | Linux (upstream) | macOS | Test | Windows |
| --- | --- | --- | --- | --- |
| `chroot::chroot` | mount namespace + `pivot_root` | `chroot(2)`; left again for the exec only, and entered again by Firecracker first thing (`vmm::ext::jail::enter`) | `jailer-test jail` | the jail as a drive of its own, the current directory its root |
| `Env::exec_command` | exec as `uid:gid` | exec of a root-owned copy outside the jail that carries `HANDOVER_MARK`, with `WICK_JAIL=<uid>:<gid>:<root>` | `test_copy_for_exec`, `test_enter_needs_root`, `jailer-test jail` | a restricted, low-integrity token with a random SID per jail; the jailer waits and exits with Firecracker's status |
| `cgroup` memory | cgroup files | jetsam limit at the exec | `test_memory_limit`, `jailer-test limits`, `jailer-test memory` | Job Object memory limit |
| `cgroup` CPU | cgroup files | `process_policy` CPU limit, applied by `jail::enter` and read back; `--no-seccomp` refused with it | `test_cpu_limit`, `test_cpu_limit_holds`, `test_cpu_limit_needs_the_jail`, `jailer-test cpu` | Job Object CPU rate hard cap, after 2 CPU-seconds of grace (to remove) |
| `cgroup`, other controllers | cgroup files | refused | `test_other_controllers_are_refused`, `jailer-test refuse` | refused |
| `join_netns` (`--netns`) | `setns` | refused; the Seatbelt profile denies IP networking | `test_unsupported_isolation_is_refused`, `test_sandbox_restricts_child`, `jailer-test refuse` | refused; Windows Filtering Platform confinement is planned |
| `new_pid_ns` (`--new-pid-ns`) | `clone(CLONE_NEWPID)` | refused | `test_unsupported_isolation_is_refused` | refused |
| `--daemonize` | `setsid`, `/dev/null` | upstream's | `jailer-test daemonize` | refused |
| `mknod_and_own_dev` | device nodes in the jail | none needed | `test_devices` | none needed |
| `close_fds_by_close_range` | `close_range` | `proc_pidinfo` + `close`; a file and a directory outside the jail, inherited by the jailer, are not open in Firecracker | `jailer-test jail` | nothing to close: only the standard handles are passed (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`); no test yet |

## The system call filter (`overlay/vmm/ext/sandbox.rs`)

| | Linux (upstream) | macOS | Test | Windows |
| --- | --- | --- | --- | --- |
| Default | per-thread seccomp-BPF | Seatbelt, process-wide, in two phases: what building the microVM takes until `narrow()` (where Linux installs the VMM thread's filter), then 87 system calls, 15 Mach traps, 7 MIG routines, each tied to a Linux rule, for good; any other one raises SIGSYS and Firecracker exits with upstream's bad-syscall code | `test_unlisted_syscalls_raise_sigsys`, `test_denied_syscall_exits_as_seccomp`, `test_narrow_ends_the_setup_phase`, `test_narrowing_is_one_way`, every `boot-test` stage, `tools/macos/sandbox-discovery.sh` | `ProcessChildProcessPolicy` only |
| No exec, fork, IP, Mach lookups, IOKit, sysctl writes | seccomp | the profile | `test_sandbox_restricts_child` | child processes only |
| Files limited to the jail | chroot | a Seatbelt file rule on the jail | `test_jail_profile_limits_files`, `test_files_in_jail_rejects_bad_paths`, `jailer-test jail` | the jail's ACLs and token |
| `--seccomp-filter FILE` | the given filters | refused | `ext::sandbox` | refused |
| The allow-lists themselves | | no duplicates; the calls Firecracker needs are in, the ones that would lift a limit or reach another task are out; Seatbelt refuses to compile an unknown name | `test_syscall_names_are_known`, `test_mach_trap_names_are_known`, `test_mig_routine_names_are_known` | |

How the macOS lists are checked: `tools/macos/sandbox-discovery.sh` builds Firecracker with
`--cfg wick_sandbox_discovery`, where a call outside the run phase's lists is allowed and reported, after `narrow()`,
instead of raising SIGSYS. It runs every boot-test stage and fails if the kernel reported any call (debug and release
both). To find calls the first time, `(allow syscall-unix (with report))` (and the same for `syscall-mach` and
`syscall-mig`) logs each distinct call; `/usr/bin/log show --predicate 'sender == "Sandbox"'` reads them (in zsh, a
bare `log` is a builtin). The Windows counterpart is the same loop: turn a mitigation on in audit mode where Windows
has one (the ETW mitigation events), run every stage, and only then turn it on for real.

## The hypervisor and the compatibility crates (`crates/compat`)

| Crate | Linux | macOS | Test | Windows |
| --- | --- | --- | --- | --- |
| `kvm-ioctls` | the original | Hypervisor.framework: vCPUs, memory, GICv3 state, the GICv2m MSI frame, dirty tracking | crate tests, every `boot-test` stage | WHP: partition, LAPIC, user-space IOAPIC, PIC, PIT |
| `libc` | the original | `fallocate`, `memfd_create`, the userfaultfd kernel side (`wick_uffd`) | crate tests, fuzz `uffd_protocol`, `boot-test uffd` | the POSIX layer on Win32 (`wick_fd`, mmap, sockets, signals), `windows_uffd` |
| `vmm-sys-util` | the original | eventfd (pipes), epoll (kqueue), timerfd, signals | crate tests, `boot-test vhost-user` | IOCP, sections, waitable timers |
| `userfaultfd`, `memfd` | the original | on `wick_uffd`; an unlinked POSIX shared memory object | crate tests, `boot-test uffd` | on `windows_uffd`; an unnamed temporary file, size seals as sections |

## Scenario tests, stage by stage

These are the macOS stages and their Windows counterparts. A stage that has no counterpart is a gap, not an
exemption.

| Stage | macOS (`tools/macos/boot-test.sh`) | Windows (`tools/windows/boot-test.ps1`) |
| --- | --- | --- |
| `boot`, `smp`, `block`, `vsock`, `net` | yes | yes |
| `vmnet` | yes (root) | no counterpart (vmnet is macOS's) |
| `snapshot`, `diff`, `uffd`, `pci`, `restores`, `vhost-user` | yes | yes |
| `devices`: logger, metrics, MMDS, balloon, entropy, a rate limiter | yes | **missing** |
| `hugepages` | planned | yes; needs "Lock pages in memory" |

| Stage | macOS (`tools/macos/jailer-test.sh`, root) | Windows (`tools/windows/jailer-test.ps1`) |
| --- | --- | --- |
| `refuse`: unsupported isolation refused | yes | yes |
| `jail`: chroot, user, descriptors, the hand-over | yes | `isolation`, `drives` |
| `daemonize` | yes | **missing**: `--daemonize` is refused |
| `limits`: cgroups and resource limits applied | yes | yes |
| `boot`: a jailed guest boots | yes | yes |
| `memory`: a guest past the memory limit kills the VMM | yes | **missing** |
| `cpu`: a jailed guest's spinning vCPUs held to the limit | yes | yes |

## Where behaviour is not the same yet

The standard is Linux's behaviour, not a lighter version of it. Each row below is something Firecracker on Linux
does that macOS or Windows does not do the same way yet. Every row is work to do, in the order given; none is
optional and none is dropped for its cost. A row can end as "impossible" only when the host's OS or hardware
physically cannot do it. Then the request is refused loudly, and the row says why.

| # | Linux does | macOS | Windows | Done when |
| --- | --- | --- | --- | --- |
| 1 | Allows each thread only the system calls upstream's filter lists for it | Two phases as on Linux: wide until the microVM is built, then narrowed for good to 87 system calls, 15 Mach traps and 7 MIG routines, each tied to the Linux rule it stands for (`test_narrowing_is_one_way`, `tools/macos/sandbox-discovery.sh`). Left: Seatbelt cannot deny 91 system calls by number; each of those is to be tied to the operation rule that limits it, or written down as impossible | `ProcessChildProcessPolicy` only. To do: the mitigation profile, each mitigation tied to the Linux rule it stands for | a unit test per removed or kept entry; every boot-test stage passes |
| 2 | Checks the arguments of 14 calls (`ioctl` requests, `socket` domain, `mmap`/`mprotect` protections, `fcntl` commands, `futex` operations, ...) | Number-only. To do: each check expressed in Seatbelt (`file-ioctl` with `ioctl-command`, `network*`, `dynamic-code-generation`, `file-map-executable`), or written down as impossible | none. To do: the same list | a unit test per check that a call with a denied argument ends Firecracker as seccomp does |
| 3 | A denied call raises SIGSYS, and Firecracker exits with upstream's bad-syscall code | the same for system calls, Mach traps and MIG routines; other denied operations (files, network) return `EPERM`. To do: `(with send-signal SIGSYS)` on each | a mitigation failure is a Windows error. To do: the same exit | a unit test per kind of denied operation |
| 4 | The API thread has its own, narrower filter | the API thread shares the process's allow-list. To do: the API server in a process of its own with the API filter's equivalent | the same | the API filter's tests run against the API process |
| 5 | vCPU threads have a filter different from the VMM thread's | Impossible: the hypervisor needs vCPUs in the VM's process, and macOS has no per-thread sandbox. The process gets the union, which is also the effective boundary on Linux, as threads share memory | Impossible, for the same reason (WHP partitions belong to a process; mitigations are per process) | written down in SECURITY.md |
| 6 | `--netns`: Firecracker joins a network namespace, and the guest reaches only the network given there | refused. To do: the jailer gives each jail a network of its own, which the VMM reaches only through a socket in the jail | refused. To do: Windows Filtering Platform, and the same per-jail network | a jailer-test stage: two jails, each reaching only its own network |
| 7 | `--new-pid-ns`: Firecracker sees and signals no other process | refused. To do: the sandbox limits process information and signals to Firecracker itself | refused. To do: the same | a jailer-test stage |
| 8 | Every cgroup controller the operator names (`cpu.weight`, `pids.max`, `io.*`, `cpuset.*`, ...) | memory and CPU limits only, others refused. To do: each controller implemented, or refused as impossible with the reason (`cpuset`: Apple silicon has no CPU affinity) | the same | a jailer-test stage per controller |
| 9 | The CPU quota refills every period (`cpu.max`'s second field) | refills every second. To do: the period honoured, or the difference written down as impossible | after 2 CPU-seconds of grace. To do: no grace | `jailer-test cpu` with a period other than 1 s |
| 10 | Hugepages | missing. To do: 2 MiB granularity | built, not run | a `boot-test hugepages` stage on both |
| 11 | x86_64 and aarch64 guests | aarch64 only: Apple silicon has no x86 virtualisation (impossible). x86_64 images through translation in the guest (M6) | x86_64 only. aarch64 images through translation in the guest (M6) | M6 |
| 12 | Passes upstream's integration tests | not run on macOS. To do: upstream's pytest suites against the macOS build, compared test by test as on Linux | not run on Windows. To do: the same | a comparison as `compare-integration-tests.py` makes |
| 13 | Upstream's code, reviewed and fuzzed for years | the Hypervisor.framework run loop has no fuzz target. To do: one | the WHP run loop has none. To do: one | a target in `fuzz/` run on CI |
| 14 | A jailed VMM passes descriptors to a uffd handler or a vhost-user backend | the same | a jailed process cannot push handles. To do: the receiver duplicates them, or a broker does | `boot-test uffd` and `vhost-user` under the jailer |
| 15 | Device stages | the same | missing: the `devices` boot-test stage, the `memory` jailer-test stage, `--daemonize`, the inherited-handle check | the stages pass |
| 16 | Only the jail's user reaches a jail | the same | a low-integrity process of the same user reaches it | a jailer-test stage |

Windows also has to name a test in each of its doc cells; after that, CI runs `tools/check-claims.py --strict-windows`.
