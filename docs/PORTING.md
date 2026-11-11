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
   backticks (`tools/check-claims.py`, on CI). Every Windows cell now names its test, so CI runs with
   `--strict-windows`.
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
| `chroot::chroot` | mount namespace + `pivot_root` | `chroot(2)`; left again for the exec only, and entered again by Firecracker first thing (`vmm::ext::jail::enter`) | `jailer-test jail` | the jail as a drive of its own, the current directory its root (`jailer-test.ps1 isolation`, `drives`) |
| `Env::exec_command` | exec as `uid:gid` | exec of a root-owned copy outside the jail that carries `HANDOVER_MARK`, with `WICK_JAIL=<uid>:<gid>:<root>` | `test_copy_for_exec`, `test_enter_needs_root`, `jailer-test jail` | a restricted token below medium integrity with a random SID per jail; the jailer waits and exits with Firecracker's status (`jailer-test.ps1 isolation`, `low`) |
| `cgroup` memory | cgroup files | jetsam limit at the exec | `test_memory_limit`, `jailer-test limits`, `jailer-test memory` | Job Object memory limit (`jailer-test.ps1 limits`) |
| `cgroup` CPU | cgroup files | `process_policy` CPU limit, applied by `jail::enter` and read back; `--no-seccomp` refused with it | `test_cpu_limit`, `test_cpu_limit_holds`, `test_cpu_limit_needs_the_jail`, `jailer-test cpu` | Job Object CPU rate hard cap, after 2 CPU-seconds of grace (to remove) (`jailer-test.ps1 cpu`) |
| `cgroup`, other controllers | cgroup files | refused | `test_other_controllers_are_refused`, `jailer-test refuse` | refused (`jailer-test.ps1 refuse`) |
| `join_netns` (`--netns`) | `setns` | refused; the Seatbelt profile denies IP networking | `test_unsupported_isolation_is_refused`, `test_sandbox_restricts_child`, `jailer-test refuse` | refused; Windows Filtering Platform confinement is planned (`test_unsupported_isolation_is_refused`, `jailer-test.ps1 refuse`) |
| `new_pid_ns` (`--new-pid-ns`) | `clone(CLONE_NEWPID)` | refused | `test_unsupported_isolation_is_refused` | the isolation is every jail's (no other process opens or shows, no shared console); the jailer hands over to a relaunched keeper and returns 0 once Firecracker runs (`test_keeper_event`, `jailer-test.ps1 pidns`) |
| `--daemonize` | `setsid`, `/dev/null` | upstream's | `jailer-test daemonize` | the jailer relaunches itself detached, without the flag, and returns 0; the detached jailer runs Firecracker with no console (`jailer-test.ps1 daemonize`) |
| `mknod_and_own_dev` | device nodes in the jail | none needed | `test_devices` | none needed (`test_devices`) |
| `close_fds_by_close_range` | `close_range` | `proc_pidinfo` + `close`; a file and a directory outside the jail, inherited by the jailer, are not open in Firecracker | `jailer-test jail` | nothing to close: only the standard handles are passed (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), so a handle the jailer inherited is not open in Firecracker (`jailer-test.ps1 handles`) |

## The system call filter (`overlay/vmm/ext/sandbox.rs`)

| | Linux (upstream) | macOS | Test | Windows |
| --- | --- | --- | --- | --- |
| Default | per-thread seccomp-BPF | Seatbelt, process-wide, in two phases: what building the microVM takes until `narrow()` (where Linux installs the VMM thread's filter), then 87 system calls, 15 Mach traps, 7 MIG routines, each tied to a Linux rule, for good; any other one raises SIGSYS and Firecracker exits with upstream's bad-syscall code | `test_unlisted_syscalls_raise_sigsys`, `test_denied_syscall_exits_as_seccomp`, `test_narrow_ends_the_setup_phase`, `test_narrowing_is_one_way`, every `boot-test` stage, `tools/macos/sandbox-discovery.sh` | a process mitigation profile, process-wide, in the same two phases (`apply()` then `narrow()`), each mitigation tied to a Linux rule; a denied operation ends Firecracker with upstream's bad-syscall code where Windows reports it (an executable mapping, an invalid handle), else fails closed (`test_narrow_ends_the_setup_phase`, `test_narrowing_is_one_way`, `test_denied_operation_exits_as_seccomp`, `test_denied_operations_fail_closed`, `tools/windows/mitigation-audit.ps1`) |
| No exec, fork, IP, Mach lookups, IOKit, sysctl writes | seccomp | the profile | `test_sandbox_restricts_child` | no child processes, no win32k, no dynamic code, no extension points, Microsoft-signed images only, none remote or low-label (`test_child_process_policy`, `test_win32k_policy`, `test_dynamic_code_policy`, `test_extension_point_policy`, `test_signature_policy`, `test_image_load_policy`) |
| Files limited to the jail | chroot | a Seatbelt file rule on the jail | `test_jail_profile_limits_files`, `test_files_in_jail_rejects_bad_paths`, `jailer-test jail` | the jail's ACLs and token (`jailer-test.ps1 isolation`, `low`) |
| `--seccomp-filter FILE` | the given filters | refused | `ext::sandbox` | refused (`ext::sandbox`) |
| The allow-lists themselves | | no duplicates; the calls Firecracker needs are in, the ones that would lift a limit or reach another task are out; Seatbelt refuses to compile an unknown name | `test_syscall_names_are_known`, `test_mach_trap_names_are_known`, `test_mig_routine_names_are_known` | each mitigation names the Linux rule it stands for, read back after it is set (`test_every_mitigation_names_its_linux_rule`, `test_strict_handle_check_policy`) |

How the macOS lists are checked: `tools/macos/sandbox-discovery.sh` builds Firecracker with
`--cfg wick_sandbox_discovery`, where a call outside the run phase's lists is allowed and reported, after `narrow()`,
instead of raising SIGSYS. It runs every boot-test stage and fails if the kernel reported any call (debug and release
both). To find calls the first time, `(allow syscall-unix (with report))` (and the same for `syscall-mach` and
`syscall-mig`) logs each distinct call; `/usr/bin/log show --predicate 'sender == "Sandbox"'` reads them (in zsh, a
bare `log` is a builtin). The Windows counterpart is `tools/windows/mitigation-audit.ps1`: it builds Firecracker with
`--cfg wick_sandbox_discovery`, which sets the audit variant of the mitigations Windows audits at run time (dynamic
code, child processes, win32k) so an operation they would deny is allowed and reported in the Security-Mitigations
event log instead, runs an API session (no WHP) or boot-test stages, and lists what the logs reported. A control that
allocates executable memory must be reported, or a clean run would prove nothing. Image File Execution Options audit
settings were tried first and were not applied to the process on Windows Server 2022.

## The hypervisor and the compatibility crates (`crates/compat`)

| Crate | Linux | macOS | Test | Windows |
| --- | --- | --- | --- | --- |
| `kvm-ioctls` | the original | Hypervisor.framework: vCPUs, memory, GICv3 state, the GICv2m MSI frame, dirty tracking | crate tests, every `boot-test` stage | WHP: partition, LAPIC, user-space IOAPIC, PIC, PIT |
| `libc` | the original | `fallocate`, `memfd_create`, the userfaultfd kernel side (`wick_uffd`) | crate tests, fuzz `uffd_protocol`, `boot-test uffd` | the POSIX layer on Win32 (`wick_fd`, mmap, sockets, signals), `windows_uffd` |
| `vmm-sys-util` | the original | eventfd (pipes), epoll (kqueue), timerfd, signals | crate tests, `boot-test vhost-user` | IOCP, sections, waitable timers; `SCM_RIGHTS` as handles duplicated into the peer, or pulled out of a sender that cannot open its receiver, as a jailed one cannot (`test_a_sender_that_cannot_open_the_receiver_is_pulled_from`) |
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
| `daemonize` | yes | `daemonize` (the launcher returns 0; a detached Firecracker runs with no console) |
| (a handle the jailer inherited is not open in the jail) | part of `jail` | `handles` |
| (only the jail's identity reaches a jail) | part of `jail` | `low` (a low-integrity process of the user is kept out) |
| (`--new-pid-ns`: no other process to see or signal) | refused (`refuse`) | `pidns` (no process, thread or console of anyone else; the jailer's return) |
| (a jailed process hands a file and a socket to a helper outside) | part of `jail` (`SCM_RIGHTS` works from a chroot) | `handoff` (pulled out by the operator and by a medium-integrity process of the user; no guest) |
| (a snapshot restored through a uffd handler, and a vhost-user block device, under the jailer) | `boot-test uffd`, `vhost-user` (no jailer) | `uffd`, `vhost-user` (written; wait for a WHP machine) |
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
| 1 | Allows each thread only the system calls upstream's filter lists for it | Two phases as on Linux: wide until the microVM is built, then narrowed for good to 87 system calls, 15 Mach traps and 7 MIG routines, each tied to the Linux rule it stands for (`test_narrowing_is_one_way`, `tools/macos/sandbox-discovery.sh`). Left: Seatbelt cannot deny 91 system calls by number; each of those is to be tied to the operation rule that limits it, or written down as impossible | Done: a process mitigation profile in the same two phases (`apply()`, then `narrow()` where Linux installs the VMM thread's filter), each mitigation tied to the Linux rule it stands for and read back (`test_every_mitigation_names_its_linux_rule`, `test_narrowing_is_one_way`, `tools/windows/mitigation-audit.ps1`). A mitigation is coarser than a seccomp rule (it bars a capability, not a numbered call); where Windows has no mitigation for a Linux rule, it is written down | a unit test per removed or kept entry (on Windows, per mitigation, read back with `GetProcessMitigationPolicy`); every boot-test stage passes; the discovery or audit run is clean |
| 2 | Checks the arguments of 14 calls (`ioctl` requests, `socket` domain, `mmap`/`mprotect` protections, `fcntl` commands, `futex` operations, ...) | Expressed in Seatbelt where it has a counterpart: after narrowing, driver ioctls only for the terminal's settings and a block device's sizes (Linux's TCGETS/TCSETS/TIOCGWINSZ and BLK* rules; KVM, TAP and Nitro Enclaves requests have none here), Unix sockets only and no bind (`socket`/`connect`/`bind` domains), no sysctl reads (`test_run_phase_ioctls_and_holes`, `test_unlisted_syscalls_raise_sigsys`). `mmap`/`mprotect` `PROT_EXEC`: a file mapped executable and a `MAP_JIT` mapping always raise SIGSYS (Seatbelt `file-map-executable`, `dynamic-code-generation`); an anonymous mapping asking for `PROT_EXEC` after narrowing raises SIGSYS in the compatibility libc (`libc::wick_mm`), as on Windows; macOS has no kernel rule for that one (an anonymous page made executable runs, also under the hardened runtime), so a raw system call that bypasses libc is not checked (`test_executable_mappings_raise_sigsys`). Left: `fcntl` commands, `futex` operations, `madvise` advice, `accept4` flags, each expressed or written down as impossible | Partly: the `mmap`/`mprotect` `PROT_EXEC` check is the dynamic code policy, and using a handle the process does not hold is the strict handle check (`test_dynamic_code_policy`, `test_strict_handle_check_policy`). Left: `ioctl`/`socket`/`fcntl`/`futex` arguments, which a mitigation cannot express, to be tied to a token or ACL limit or written down as impossible | a unit test per check that a call with a denied argument ends Firecracker as seccomp does |
| 3 | A denied call raises SIGSYS, and Firecracker exits with upstream's bad-syscall code | A denied system call, Mach trap, MIG routine, network operation, ioctl, sysctl or any other operation raises SIGSYS and Firecracker exits with upstream's bad-syscall code; a file outside what is allowed fails with an error, as a path outside the chroot does on Linux; two operations the system libraries make and handle failing are denied with an error (`DENIED_WITH_ERROR`) (`test_unlisted_syscalls_raise_sigsys`, `test_denied_syscall_exits_as_seccomp`). Impossible to make the same: Seatbelt signals the process, not the thread that made the call (the kernel gives the signal to a thread that does not block it), so the denied call first returns `EPERM` to its thread, which runs on until the signal is taken; on Linux the trapping thread never returns from the call (`test_executable_mappings_raise_sigsys`, `test_narrow_ends_the_setup_phase` wait for the signal). The compatibility libc's check signals the calling thread, as Linux does | Done where Windows reports the denial (an executable mapping, an invalid handle): SIGSYS on the calling thread, so upstream's handler exits with the bad-syscall code (`test_denied_operation_exits_as_seccomp`, `test_denied_operation_raises_sigsys`). The denials Windows reports only as an error code (child process, win32k, unsigned/remote/low image) fail closed, with no notification to turn into SIGSYS (`test_denied_operations_fail_closed`) | a unit test per kind of denied operation |
| 4 | The API thread has its own, narrower filter | Done: the API socket's HTTP server and upstream's request parsing run in a process of its own (`vmm::ext::api_process`), sandboxed as the `api` filter: its system calls (`API_SYSCALLS`, each tied to the `api` rule it stands for), no files, no shared memory, no executable mappings; the API thread handles the requests it passes on with upstream's code, so responses, logs and metrics are upstream's. Either process's end ends the other, as the API thread's end ends Firecracker. In a jail with a memory or CPU limit, the API process is made while Firecracker is still root and gets a fixed share (32 MiB, 1% of a CPU), Firecracker the rest, so together they stay within the jail's limits as one cgroup (`test_api_profile_raises_sigsys_outside_its_list`, `test_limits_are_shared_with_the_api_process`, `boot-test api-process`). Left: a `jailer-test` stage for the shared limits (root) | the same. To do: the API server in a process of its own, made with its handles (no fork) | the API filter's tests run against the API process |
| 5 | vCPU threads have a filter different from the VMM thread's | Impossible: the hypervisor needs vCPUs in the VM's process, and macOS has no per-thread sandbox. The process gets the union, which is also the effective boundary on Linux, as threads share memory | Impossible, for the same reason (WHP partitions belong to a process; mitigations are per process) | written down in SECURITY.md |
| 6 | `--netns`: Firecracker joins a network namespace, and the guest reaches only the network given there | refused. To do: the jailer gives each jail a network of its own, which the VMM reaches only through a socket in the jail | refused. To do: Windows Filtering Platform, and the same per-jail network | a jailer-test stage: two jails, each reaching only its own network |
| 7 | `--new-pid-ns`: the jailer clones Firecracker into a new PID namespace, where it is pid 1 and alone: it can see no other process (no pid outside exists for it; `kill(pid, …)` fails with `ESRCH`) and signal none, and processes outside can send it only the signals it has a handler for (and `SIGKILL`). The jailer writes Firecracker's pid, as the jailer's namespace sees it, to `<exec file name>.pid` in the jail and exits 0 at once, while Firecracker runs on with the jailer's standard descriptors (a jailer that leads its session first moves Firecracker to a new session, so its exit sends no `SIGHUP`). An error before the clone exits the jailer non-zero; an exec that fails after it is the child's | refused. To do: the sandbox limits process information and signals to Firecracker itself | Done: every jail already holds the isolation: its token opens no process or thread outside the jail (the user's, another jail's, the jailer, SYSTEM's) and a process snapshot shows it none; Firecracker has a console of its own, so it can neither send console control events to the jailer's console nor type into it (the jailer relays the console through pipes). Before, the logon SID in the token let a jailed process end any process of the user, and the shared console let it end the console's processes. `--new-pid-ns` gives upstream's jailer behaviour: the jailer returns 0 once Firecracker runs, its pid in the pid file, and returns the keeper's status if the jail could not be built (`jailer-test.ps1 pidns`, with a plain process of the user as the control). Left: whether a pid is in use still shows (`OpenProcess` fails with access denied for one that is, invalid parameter for one that is not; recorded by `jailer-test.ps1 pidns`), as `kill(pid, 0)` shows outside a PID namespace. Windows has one process table for every process outside a server silo (the process isolation of Windows containers, which needs the Containers feature); to decide whether the jailer creates one or this is written down as the difference. Left for a WHP machine: the interactive serial console through the relay | a jailer-test stage |
| 8 | Every cgroup controller the operator names (`cpu.weight`, `pids.max`, `io.*`, `cpuset.*`, ...) | memory and CPU limits only, others refused. To do: each controller implemented, or refused as impossible with the reason (`cpuset`: Apple silicon has no CPU affinity) | the same | a jailer-test stage per controller |
| 9 | The CPU quota refills every period (`cpu.max`'s second field) | refills every second. To do: the period honoured, or the difference written down as impossible | after 2 CPU-seconds of grace. To do: no grace | `jailer-test cpu` with a period other than 1 s |
| 10 | Hugepages | missing. To do: 2 MiB granularity | built, not run | a `boot-test hugepages` stage on both |
| 11 | x86_64 and aarch64 guests | aarch64 only: Apple silicon has no x86 virtualisation (impossible). x86_64 images through translation in the guest (M6) | x86_64 only. aarch64 images through translation in the guest (M6) | M6 |
| 12 | Passes upstream's integration tests | not run on macOS. To do: upstream's pytest suites against the macOS build, compared test by test as on Linux | not run on Windows. To do: the same | a comparison as `compare-integration-tests.py` makes |
| 13 | Upstream's code, reviewed and fuzzed for years | the Hypervisor.framework run loop has no fuzz target. To do: one | the WHP run loop has none. To do: one | a target in `fuzz/` run on CI |
| 14 | A jailed VMM passes descriptors to a uffd handler or a vhost-user backend | the same | In place without a guest: a jailed process cannot open its peer, so it cannot push handles into it (and `WSADuplicateSocket` fails from a jail: measured); the compatibility `SCM_RIGHTS` (`vmm-sys-util` `sock_ctrl_msg`) then sends in pull mode, keeping private copies of the handles and writing their values, flagged, and the receiver, which can open a jail's process (its DACL grants the owner), duplicates them out and closes the sender's copies, sockets as handles. The handler's or backend's socket must be inside the jail root, where a jailed Firecracker can connect (`test_a_sender_that_cannot_open_the_receiver_is_pulled_from`: a file, an eventfd, a sealed section and a socket pulled from a sender that cannot open the receiver; `jailer-test.ps1 handoff`: a jailed probe's file and socket pulled out by the operator and by a medium-integrity process of the user, the jailed process unable to open the operator). Left for a WHP machine: `jailer-test.ps1 uffd` (a snapshot restored through upstream's `uffd_on_demand_handler` in another process) and `vhost-user` (a vhost-user block device), both under the jailer, written and not yet run | `boot-test uffd` and `vhost-user` under the jailer |
| 15 | Device stages | the same | `--daemonize` (`jailer-test.ps1 daemonize`) and the inherited-handle check (`jailer-test.ps1 handles`) are done. Left: the `devices` boot-test stage and the `memory` jailer-test stage (both need a WHP guest) | the stages pass |
| 16 | Only the jail's user reaches a jail | the same | Done: the jail's integrity level is above low, so a plain low-integrity process of the same user is kept out of a jail's files, its API socket and its process (`jailer-test.ps1 low`) | a jailer-test stage |

Each Windows doc cell names its test, so CI runs `tools/check-claims.py --strict-windows`.
