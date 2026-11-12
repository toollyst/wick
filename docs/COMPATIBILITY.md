# Compatibility

How much of Firecracker v1.18.0 works on each host. On Linux, wick is upstream Firecracker. This page compares
macOS and Windows with it: one row per feature, what is different, and the test that shows it.

wick's rule is that a feature behaves as it does on Linux. If a host truly cannot do something, Firecracker refuses
it with an error; it never accepts it and then ignores it. [PORTING.md](PORTING.md) is the full reference, with
every backend and every gap. This page is the summary.

**Legend**

| Icon | Meaning |
| --- | --- |
| 🟢 | Same as Linux |
| 🟡 | Works, with the differences given |
| 🔴 | Not available. The cell says whether the host cannot do it (*impossible*) or it is *not done yet* |
| ⚪ | Not applicable on that host |
| ❔ | Not tested, or no test result to go by |

**How to read the evidence.** Each 🟢, 🟡 and 🔴 cell names what shows it:

- `boot-test <stage>` is a stage of [`tools/macos/boot-test.sh`](../tools/macos/boot-test.sh) on a Mac.
  `boot-test.ps1 <stage>` is a stage of [`tools/windows/boot-test.ps1`](../tools/windows/boot-test.ps1) on a PC
  with the Windows Hypervisor Platform (WHP).
- `jailer-test <stage>` is [`tools/macos/jailer-test.sh`](../tools/macos/jailer-test.sh), run as root.
  `jailer-test.ps1 <stage>` is [`tools/windows/jailer-test.ps1`](../tools/windows/jailer-test.ps1).
- **row N** is row N of PORTING.md's table
  [Where behaviour is not the same yet](PORTING.md#where-behaviour-is-not-the-same-yet).
- Any other `test_*` name is one of two kinds:
  - a wick unit test in this repository;
  - an upstream integration test from `tests/integration_tests`.
- An upstream test written plainly, such as `test_api_balloon`, passes on Linux, and that host's differences file
  does not list it. A kind in brackets, such as `test_drive_patch` [error-text], means the host lists it as a
  difference of that kind.
  - The two files are [`tools/macos/integration-test-differences.txt`](../tools/macos/integration-test-differences.txt)
    and [`tools/windows/integration-test-differences.txt`](../tools/windows/integration-test-differences.txt).
  - Each host's comparison script fails on any difference the file does not list (row 12). No run report is
    committed, so "not listed" means a run matched Linux; it is not a pass count you can check here. See
    [Upstream integration tests](#upstream-integration-tests).

## Summary

The rough status of each area. The sections below give each feature's status and the test behind it.

| Area | Linux | macOS | Windows |
| --- | --- | --- | --- |
| [Host and guest](#host-requirements) | 🟢 x86_64 and aarch64 | 🟡 Apple silicon, aarch64 guests only | 🟡 x86_64, x86_64 guests only |
| [API endpoints](#api-endpoints) | 🟢 | 🟡 every endpoint; a network interface is not a TAP; errors carry macOS' errno | 🟡 every endpoint; errors carry Windows' error text |
| [CPU](#cpu) | 🟢 | 🟡 PSCI, PTP, cache topology differ; templates untested | 🟡 KVM's CPUID set less what WHP lacks; templates untested |
| [Memory and huge pages](#memory-and-huge-pages) | 🟢 | 🟡 16 KiB host pages; huge pages on host pages | 🟡 large pages need a privilege or the jailer's broker |
| [Snapshots and userfaultfd](#snapshots-and-userfaultfd) | 🟢 | 🟡 full, diff, uffd, PCI; userfaultfd's kernel side is in user space | 🟡 diff in 64 KiB units |
| [Devices](#devices) | 🟢 | 🟡 block, vsock, net, balloon, pmem, rng, MMDS, PCI, vhost-user; net is an endpoint | 🟡 the same; net is an endpoint |
| [`firecracker` command line](#firecracker-command-line) | 🟢 | 🟡 no default API socket; no custom seccomp | 🟡 the same |
| [Jailer flags](#jailer-flags) | 🟢 | 🟡 every flag, on host primitives | 🟡 every flag but `fsize=` and a non-default `no-file=` |
| [cgroup controllers](#cgroup-controllers) | 🟢 | 🟡 memory, CPU; most others refused | 🟡 memory, CPU, cpuset, weight; the rest refused |
| [Security and sandbox](#security-and-sandbox) | 🟢 | 🟡 Seatbelt, process-wide | 🟡 process mitigations, process-wide |
| [Signals and exit codes](#signals-and-exit-codes) | 🟢 | 🟡 no real-time signals | 🔴 no signals from outside the process |
| [Tools](#tools) | 🟢 | 🟡 no `seccompiler-bin`; `cpu-template-helper`'s fingerprint reads sysfs | 🟡 no `seccompiler-bin`; no fuzzing, gdb or instrumented builds yet |
| [Upstream integration tests](#upstream-integration-tests) | 🟢 the baseline | 🟡 functional suites, as the user | 🟡 functional and security suites, under the jailer |

Linux is the baseline. CI runs upstream's unit and integration tests on plain upstream and on wick, on the same
runner, and fails on any test whose result differs (the `linux-unit-tests` and `linux-integration-tests` jobs,
`tools/linux/compare-integration-tests.py`). The integration tests run on x86_64 only, because GitHub's arm runners
have no KVM. Linux aarch64 is built and unit-tested on CI, but no guest is booted there.

**Not for untrusted multi-tenant work yet.** Read [SECURITY.md](../SECURITY.md) before you run untrusted
multi-tenant workloads on macOS or Windows.

## Host requirements

| | Linux (the reference) | macOS | Windows |
| --- | --- | --- | --- |
| Host CPU | x86_64, aarch64 | 🟡 Apple silicon only (row 11). M1 lacks `FEAT_SSBS`, so SSBD is unavailable there (`test_ssbd`) | 🟡 x86_64. Guests booted on one AMD Ryzen 9 7900 (rows 4, 9, 14). Intel is not tested |
| Host OS | upstream's kernel support | 🟡 macOS 15 or later is the stated minimum. The only recorded guest runs are on macOS 27.2 (row 10). macOS 15 and 26 run only the sandbox unit tests, on CI (`test_seatbelt_skips_the_number_of_these`, job `macos-seatbelt`) | 🟡 Windows 10 1803+ and 11 are the stated range. Guests booted on Windows 11 26H2, build 26300, only (rows 4, 9). Windows 10 is not tested |
| Hypervisor | KVM, `/dev/kvm` | 🟡 Hypervisor.framework. The binary needs the hypervisor entitlement, an ad-hoc signature, which `tools/macos/run.sh` adds (`boot-test boot`) | 🟡 Windows Hypervisor Platform, turned on once by an administrator (`boot-test.ps1 boot`) |
| Guest architecture | x86_64, aarch64 | 🟡 aarch64 only. x86_64 is impossible: Apple silicon has no x86 virtualisation (row 11) | 🟡 x86_64 only. aarch64 is not done yet (row 11, roadmap M6) |
| Privileges | root for the jailer | 🟡 root for the jailer (`jailer-test jail`) and for vmnet (`boot-test vmnet`) | 🟡 the jailer runs unelevated (`jailer-test.ps1 isolation`). `--netns` needs elevation (row 6). Huge pages without the jailer need "Lock pages in memory" (row 10) |

## API endpoints

Every endpoint in upstream's `firecracker.yaml`. Host-side values differ where the host has no such thing; see
[Devices](#devices) for the devices behind them.

| Endpoint | macOS | Windows |
| --- | --- | --- |
| `GET /` | 🟢 `test_describe_instance` | 🟢 `test_describe_instance` |
| `PUT /actions` `InstanceStart` | 🟢 `test_api_happy_start`, every `boot-test` stage | 🟢 `test_api_happy_start`, every `boot-test.ps1` stage |
| `PUT /actions` `SendCtrlAltDel` | ⚪ x86's i8042 only; upstream skips it on aarch64 (`test_send_ctrl_alt_del` [arch]) | 🟢 `test_send_ctrl_alt_del` |
| `PUT /actions` `FlushMetrics` | 🟢 `test_flush_metrics` | 🟢 `test_flush_metrics` |
| `/balloon` GET, PUT, PATCH | 🟢 `test_api_balloon`, `boot-test devices` | 🟢 `test_api_balloon`, `boot-test.ps1 devices` |
| `/balloon/statistics` GET, PATCH | 🟢 `test_stats`, `test_stats_update` | 🟢 `test_stats`, `test_stats_update` |
| `/balloon/hinting/start`, `status`, `stop` | 🟢 `test_hinting_reporting_snapshot` | 🟢 `test_hinting_reporting_snapshot` |
| `PUT /boot-source` | 🟢 `test_api_put_update_pre_boot` | 🟡 a missing file reports Windows' error text (`test_api_put_update_pre_boot` [error-text]) |
| `PUT /cpu-config` | ❔ `test_api_cpu_config` is skipped on Linux CI, so there is nothing to compare | ❔ the same |
| `GET`, `PUT /enclave` (Nitro Enclaves) | ❔ no Nitro Enclaves device; untested. A device's `dmb_size_mib` is refused outside an enclave, as on Linux (`test_get_full_config_kvm_rejects_dmb_size`) | ❔ the same (`test_get_full_config_kvm_rejects_dmb_size`) |
| `PUT /drives/{id}` | 🟢 `test_api_put_update_pre_boot`, `test_drive_io_engine` | 🟡 errors in Windows' text (`test_api_put_update_pre_boot` [error-text]); `test_drive_io_engine` |
| `PATCH /drives/{id}` | 🟢 `test_drive_patch`, `test_patch_drive` | 🟡 `test_patch_drive`; errors in Windows' text (`test_drive_patch` [error-text]) |
| `PUT`, `PATCH /pmem/{id}` | 🟢 `test_pmem_api`, `test_pmem_rate_limiter_api` | 🟢 `test_pmem_api`, `test_pmem_rate_limiter_api` |
| `PUT /logger` | 🟢 `test_log_config` | 🟡 `test_log_config`; a missing file's error in Windows' text (`test_api_requests_logs` [error-text]) |
| `/machine-config` GET, PUT, PATCH | 🟡 `test_negative_machine_config_api`. The out-of-memory path is untested: its test caps the address space with `prlimit`, which macOS has no form of (`test_api_machine_config` [impossible]) | 🟡 `test_negative_machine_config_api`; out of memory is `ERROR_NOT_ENOUGH_MEMORY` (8), not `ENOMEM` (12) (`test_api_machine_config` [error-text]) |
| `PUT /metrics` | 🟢 `test_metrics_default_shape`, `test_metrics_emit_id_and_properties` | 🟢 `test_metrics_default_shape`, `test_metrics_emit_id_and_properties` |
| `/mmds` PUT, PATCH, GET; `/mmds/config` | 🟢 `test_api_mmds_config`, `test_mmds_response` | 🟢 `test_api_mmds_config`, `test_mmds_response` |
| `PUT /entropy` | 🟢 `test_api_entropy` | 🟢 `test_api_entropy` |
| `PUT /serial` | 🟢 `test_serial_file_output`, `test_serial_rate_limiting` | 🟢 `test_serial_file_output`, `test_serial_rate_limiting` |
| `/hotplug/memory` PUT, PATCH, GET | 🟢 the API (`test_api_memory_hotplug`); the guest side is under [Memory](#memory-and-huge-pages) | 🟢 the API (`test_api_memory_hotplug`) |
| `PUT`, `PATCH /network-interfaces/{id}` | 🟡 `host_dev_name` names a Unix datagram endpoint or a vmnet mode, not a TAP (`test_net_api_put_update_pre_boot`, `boot-test net`) | 🟡 `host_dev_name` names a Unix stream endpoint, not a TAP (`test_net_api_put_update_pre_boot`, `boot-test.ps1 net`) |
| `PUT /snapshot/create`, `/snapshot/load` | 🟢 see [Snapshots](#snapshots-and-userfaultfd) (`boot-test snapshot`) | 🟢 see [Snapshots](#snapshots-and-userfaultfd) (`boot-test.ps1 snapshot`) |
| `GET /version` | 🟢 `test_api_version`. A wick fix release reports `<upstream>+wick.N` (`test_firecracker_version_is_upstream_plus_wick_number`) | 🟢 `test_api_version` |
| `PATCH /vm` (pause, resume) | 🟢 `test_pause_resume`, `boot-test restores` | 🟢 `test_pause_resume`, `boot-test.ps1 restores` |
| `GET /vm/config` | 🟢 `test_get_full_config` | 🟢 `test_get_full_config`; the after-restore test fails only on the VMM memory budget (`test_get_full_config_after_restoring_snapshot` [bug]) |
| `PUT /vsock` | 🟢 `test_api_vsock` | 🟢 `test_api_vsock` |
| The API server | 🟡 runs in a sandboxed process of its own, where Linux has a thread with its own filter. Responses are upstream's (row 4, `boot-test api-process`) | 🟡 the same (row 4, `boot-test.ps1 api-process`) |
| Host errors in API responses | 🟡 macOS' errno numbers and text, e.g. `ENOTSOCK` where Linux has `ECONNREFUSED` (111) (`test_unbinded_socket` [impossible]) | 🟡 Windows' error codes and messages, in the system's language (26 tests, such as `test_hotplug_net` [error-text]) |

## CPU

| Feature | macOS | Windows |
| --- | --- | --- |
| `vcpu_count` | 🟢 `boot-test smp`, `test_all_vcpus_online` | 🟡 `boot-test.ps1 smp`. With 16 vCPUs the VMM's own memory is over the tests' 5 MiB budget (`test_all_vcpus_online` [bug]) |
| `smt` | ⚪ aarch64 has no SMT, and upstream refuses it there | ❔ every test with SMT on is listed for the VMM memory budget (`test_cache_topology` [bug]) |
| Static CPU templates (x86: C3, T2, T2S, T2CL, T2A) | ⚪ x86 only | ❔ the template tests are skipped on Linux CI (`test_cpu_template`) |
| Static CPU template V1N1 (aarch64) | ❔ no test, and no Linux aarch64 result | ⚪ aarch64 only |
| Custom CPU templates | ❔ `test_api_cpu_config` is skipped on Linux CI | ❔ the same |
| `vcpu_features` (aarch64: SVE, pointer authentication) | ❔ untested. The backend takes only the power-off and PSCI 0.2 features (`hvf/vcpu.rs`) | ⚪ aarch64 only |
| Guest CPUID (x86) | ⚪ | 🟡 KVM's supported set, less what WHP lacks: MWAIT and nested virtualisation (roadmap M3). `test_brand_string`, `test_extended_cache_features`, `test_host_vs_guest_cpu_features`, `test_waitpkg_inaccessibility`; `test_cpuid` [bug: VMM memory] |
| kvm-clock and `KVMCLOCK_CTRL` (x86) | ⚪ x86 only (`test_kvmclock_ctrl` [arch]) | 🟢 `test_kvmclock_ctrl`, `boot-test.ps1 boot` |
| TSC-deadline timer (x86) | ⚪ | 🟡 emulated as KVM does; fires about 0.75 ms after the deadline, where KVM's fires within microseconds (row 9, `test_timers_are_high_resolution`) |
| PSCI 1.0, SMCCC 1.1 (aarch64) | 🟡 as KVM, but `SMCCC_ARCH_FEATURES` answers NOT_SUPPORTED for `WORKAROUND_1`, `_2` and `_3` (`test_psci_version_is_the_vms`) | ⚪ |
| KVM PTP clock | 🟡 `test_kvm_ptp`; no physical counter: Hypervisor.framework does not let the guest read it (`test_kvm_ptp_counters`) | 🟢 `test_kvm_ptp` |
| PV time, steal time (aarch64) | ❔ untested; the backend reports no PV time device, and `test_guest_has_pvtime_enabled` has no Linux result | ⚪ |
| Cache topology in the guest | 🟡 the guest has no cache entries: Firecracker reads them from sysfs, which macOS lacks (`test_cache_topology` [bug]) | ❔ listed for the VMM memory budget only (`test_cache_topology` [bug]) |
| Guest-visible aarch64 features | ❔ `test_guest_cpu_features` is skipped on Linux x86_64 | ⚪ |
| GDB stub | ❔ upstream's test needs an x86 vmlinux (`test_gdb_connects` [arch]) | 🔴 not done yet: no Windows build with the gdb feature (`test_gdb_connects` [bug]) |

## Memory and huge pages

| Feature | macOS | Windows |
| --- | --- | --- |
| `mem_size_mib` | 🟡 `boot-test boot`. Memory is managed in whole 16 KiB host pages, where Linux uses 4 KiB (`test_whole_host_pages`) | 🟡 `boot-test.ps1 boot`. Committed a 64 KiB block at a time, at first touch (row 15, `test_noreserve_memory_is_committed_at_first_access`) |
| `huge_pages: None` | 🟢 every `boot-test` stage | 🟢 every `boot-test.ps1` stage |
| `huge_pages: 2M` | 🟡 boots, snapshots and restores. Pages are Linux's hugetlb in layout and alignment, on host pages: not pinned, and no TLB gain. macOS gives user space no superpages (row 10, `boot-test hugepages`, `test_no_host_superpages`) | 🟡 real 2 MiB large pages. Unjailed, they need "Lock pages in memory"; in a jail, the jailer brokers them, limited by `hugetlb.2MB.max` (row 10, `boot-test.ps1 hugepages`, `jailer-test.ps1 hugepages`, `test_hugetlb_through_the_broker`) |
| `huge_pages: Transparent` | 🟡 accepted, and the memory stays on host pages, as on a Linux host whose transparent huge pages are `never` (row 10, `test_transparent_huge_page_advice`); the Transparent variants of `test_reboot`, `test_resume`, `test_snapshot_huge_pages_override` and `test_pmem_*` pass, but for the memory budget (see [Tests](#upstream-integration-tests)) | 🟡 accepted, and nothing changes, as with `never` on Linux (Transparent variants of `test_pmem_add`, `test_resume`, `test_reboot`) |
| Transparent huge pages actually used | 🔴 impossible: no huge pages for a process's memory (`test_transparent_huge_pages_allocation` [impossible]) | 🔴 impossible: Windows' large pages are explicit only (`test_transparent_huge_pages_allocation` [impossible]) |
| Memory hotplug (virtio-mem) in the guest | ❔ only upstream's performance test plugs memory, and it was not run | ❔ the same. Over huge pages it is refused with `ENOMEM` (row 10) |
| VMM memory besides the guest | 🟡 at or just over the tests' 5 MiB budget, because of 16 KiB pages. One entry excuses any test that fails only on it (`failure:host_tools.memory.MemoryUsageExceededError` [bug]) | 🟡 5.0 to 5.6 MiB with 16 vCPUs (7 test functions, such as `test_all_vcpus_online` [bug]) |

## Snapshots and userfaultfd

| Feature | macOS | Windows |
| --- | --- | --- |
| Full snapshot, restore in another process | 🟢 `boot-test snapshot`, `boot-test restores` (20 rounds) | 🟢 `boot-test.ps1 snapshot`, `boot-test.ps1 restores` |
| Diff snapshot, `snapshot-editor edit-memory rebase` | 🟢 `boot-test diff`, `test_diff_snapshot_overlay`, `test_cmp_full_and_first_diff_mem` | 🟡 dirty memory is written in 64 KiB units, NTFS's sparse granularity (`boot-test.ps1 diff`, `test_diff_snapshot_overlay`) |
| `mem_backend: Uffd` | 🟡 the kernel side of userfaultfd is rebuilt in user space (`boot-test uffd`, `test_valid_handler`, `test_malicious_handler`). A handler path that is not a socket fails with `ENOTSOCK` (`test_unbinded_socket` [impossible]) | 🟡 the same, on Windows (`boot-test.ps1 uffd`, `jailer-test.ps1 uffd`, `test_valid_handler`); errors in Windows' text (`test_bad_socket_path`, `test_unbinded_socket` [error-text]) |
| Snapshot with PCI devices | 🟢 `boot-test pci`, `test_bar_relocation_snapshot` | 🟢 `boot-test.ps1 pci`, `test_bar_relocation_snapshot` |
| `resume_vm`, network and vsock overrides on load | 🟢 `test_snapshot_rename_interface`, `test_snapshot_rename_vsock`, `test_resume` (its `None` variants) | 🟢 `test_resume`, `test_snapshot_rename_interface`, `test_snapshot_rename_vsock` |
| Clock source, VMGenID, vmclock across a restore | 🟢 `test_clocksource_snapshot_restore`, `test_vmgenid`, `test_snapshot_update` | 🟢 `test_clocksource_snapshot_restore`, `test_vmgenid`, `test_snapshot_update` |
| `sync_snapshot_files`, dirty pages in a full snapshot | 🟢 `test_sync_snapshot_files`, `test_dirty_pages_after_full_snapshot` | 🟢 `test_sync_snapshot_files`, `test_dirty_pages_after_full_snapshot` |
| Snapshot to a directory the jail cannot write | ❔ the test needs root, and the run was as the user (`test_negative_snapshot_permissions` [root]) | 🟡 refused, with Windows' error text (`test_negative_snapshot_permissions` [error-text]) |
| Diff snapshot after an out-of-space error | ❔ the test mounts a tmpfs, which macOS cannot (`test_diff_snapshot_works_after_error` [impossible]) | ❔ the same (`test_diff_snapshot_works_after_error` [impossible]) |
| aarch64 physical counter reset; `snapshot-editor edit-vmstate remove-regs` | ❔ `test_physical_counter_reset_aarch64`, `test_remove_regs`: no Linux aarch64 result | ⚪ aarch64 only |
| A snapshot restored on another host OS | ❔ untested | ❔ untested |

## Devices

### Block

| Feature | macOS | Windows |
| --- | --- | --- |
| virtio-blk, `io_engine: Sync` | 🟢 `boot-test block` | 🟢 `boot-test.ps1 block` |
| `io_engine: Async` | 🟢 io_uring's model on worker threads (`boot-test block`, `test_drive_io_engine`) | 🟢 the same code (`boot-test.ps1 block`, `test_drive_io_engine`) |
| `is_read_only`, root device | 🟢 `boot-test block` checks that a write fails | 🟢 `boot-test.ps1 block` |
| Flush, `cache_type` | 🟢 a flush is `F_FULLFSYNC` (`test_flush`, `test_no_flush`) | 🟢 `test_flush`, `test_no_flush` |
| Discard, block size, topology | 🟢 `test_discard`, `test_blk_size`, `test_topology_advertised` | 🟢 `test_discard`, `test_blk_size`, `test_topology_advertised` |
| Rate limiter | 🟢 `boot-test devices`, `test_rate_limiters_api_config` | 🟢 `boot-test.ps1 devices`, `test_rate_limiters_api_config` |
| Boot by `partuuid` | ❔ the test harness lacks `sfdisk` (`test_partuuid_boot` [bug]); `test_partuuid_update` | 🟢 `test_partuuid_boot` |
| A file-backed drive changed and rescanned | 🟢 `test_rescan_file` | 🟢 `test_rescan_file` |
| A drive on a host block device | ❔ the test harness lacks `losetup` (`test_rescan_dev` [bug]) | 🔴 impossible: no device nodes or loop devices (`test_rescan_dev` [impossible]) |
| The drive's serial (`VIRTIO_BLK_GET_ID`) | ❔ upstream's code, from the file's device and inode numbers; no test | 🟡 20 base-32 digits, distinct per file (`test_disk_image_id_is_per_file_and_stable`) |
| Drive hotplug | 🟢 `test_hotplug_block` | 🟡 errors in Windows' text (`test_hotplug_block` [error-text]) |
| vhost-user-blk | 🟢 `boot-test vhost-user`, `test_vhost_user_block_read_write`; on huge page memory too (`boot-test hugepages`) | 🟡 `boot-test.ps1 vhost-user`, `jailer-test.ps1 vhost-user`, `test_vhost_user_block_read_write`. Not with huge pages: `MFD_HUGETLB` memfds fail with `EINVAL` (row 10, not done yet) |

### Network

| Feature | macOS | Windows |
| --- | --- | --- |
| virtio-net | 🟡 the host side is a Unix datagram endpoint, or vmnet as root, instead of a TAP (`boot-test net`, `boot-test vmnet`) | 🟡 the host side is a Unix stream endpoint with QEMU's stream framing, instead of a TAP (`boot-test.ps1 net`) |
| MTU advertised to the guest | 🟢 `test_tap_mtu_advertised_to_guest` | 🟢 `test_tap_mtu_advertised_to_guest` |
| Checksum, TSO, UFO offloads | 🟡 done in user space, as TUN's header (fuzz `vnet_offload`); the upstream test needs a host program the harness cannot run (`test_tap_offload` [bug]) | 🟡 the same code; untested end to end (`test_tap_offload` [row-6]) |
| Guest changes its MAC | ❔ the test needs a host program in the network (`test_net_change_mac_address` [bug]) | ❔ the same (`test_net_change_mac_address` [row-6]) |
| High ingress traffic, transmit queue length | ❔ the harness lacks a TAP's queue length (`test_high_ingress_traffic` [bug]) | ❔ (`test_high_ingress_traffic` [row-6]) |
| Multi-queue TAP refused | ⚪ no TAP devices (`test_multi_queue_unsupported` [impossible]) | ⚪ no TAP devices (`test_multi_queue_unsupported` [row-6]) |
| rx/tx rate limiters | ❔ the API takes them (`test_rate_limiters_api_config`); throttling is tested only in the performance suite, which was not run | ❔ the same |
| Net hotplug | 🟡 any free endpoint name opens, so plugging a device nobody prepared succeeds, where Linux refuses it (`test_hotplug_net` [row-6]) | 🟡 refused, as on Linux, with Windows' error (`ERROR_BUSY`, 170) (`test_hotplug_net` [error-text]) |
| vmnet (macOS' own network) | 🟢 `boot-test vmnet` (root) | ⚪ |

### vsock

| Feature | macOS | Windows |
| --- | --- | --- |
| Host to guest `CONNECT`, guest to host `<uds>_<port>`, over MMIO and PCI | 🟢 `boot-test vsock`, `boot-test pci`. Most upstream tests need `socat`, which the harness lacks (`test_vsock` [bug]) | 🟢 `boot-test.ps1 vsock`, `test_vsock` |
| Transport reset on snapshot, in-flight data | ❔ the tests pin threads to CPUs, and macOS has no CPU affinity (`test_vsock_transport_reset_h2g` [impossible]) | 🟢 `test_vsock_transport_reset_h2g`, `test_snapshot_restore_with_inflight_vsock_tx` |
| A peer that closes with data in flight | 🟡 no SIGPIPE is counted where Linux counts one (`test_vsock_epipe` [bug]) | 🟢 `test_vsock_epipe` |

### Balloon, entropy, pmem, MMDS

| Feature | macOS | Windows |
| --- | --- | --- |
| Balloon inflate and deflate | 🟡 gives back only whole 16 KiB host pages (`boot-test balloon`, `test_inflate_reduces_free`, `test_rss_memory_lower`) | 🟢 `test_inflate_reduces_free`, `test_rss_memory_lower`, `boot-test.ps1 devices`. The `boot-test.ps1 balloon` stage is written but not yet run |
| `deflate_on_oom` | 🟡 the test sizes the balloon from the VMM's resident memory, which includes the system libraries, so the guest never runs out (`test_deflate_on_oom` [bug]) | 🟢 `test_deflate_on_oom` |
| Statistics, free page hinting and reporting, snapshot | 🟢 `test_stats`, `test_hinting_reporting_snapshot`, `test_balloon_snapshot` | 🟢 `test_stats`, `test_hinting_reporting_snapshot`, `test_balloon_snapshot` |
| virtio-rng | 🟢 `test_rng_present`, `boot-test devices` | 🟢 `test_rng_present`, `boot-test.ps1 devices` |
| Entropy throughput | 🟡 about 80 KB/s, where a test needs 1 MB/s (`test_rng_bw_rate_limiter` [bug]) | 🟢 `test_rng_bw_rate_limiter` |
| virtio-pmem | 🟢 `test_pmem_add` and `test_pmem_add_as_root_rw` (their `None` variants; Transparent: see [Memory](#memory-and-huge-pages)), `test_hotplug_pmem` | 🟢 `test_pmem_add`, `test_pmem_add_as_root_rw`; hotplug errors in Windows' text (`test_hotplug_pmem` [error-text]) |
| pmem DAX memory saving | ❔ the test reads `/proc` (`test_pmem_dax_memory_saving` [bug]) | 🟢 `test_pmem_dax_memory_saving` |
| MMDS V1, V2, IMDS compatibility | 🟢 `test_mmds_token`, `test_mmds_snapshot`, `boot-test devices` (V2); no `test_mmds.py` test is listed | 🟢 `test_mmds_token`, `test_mmds_snapshot`, `boot-test.ps1 devices` (V2) |

### PCI, interrupts, serial and other devices

| Feature | macOS | Windows |
| --- | --- | --- |
| MMIO transport | 🟢 every `boot-test` stage | 🟢 every `boot-test.ps1` stage |
| PCI transport (`--enable-pci`) | 🟢 `boot-test pci`, `test_pci_root_present`, `test_bar_relocation` | 🟢 `boot-test.ps1 pci`, `test_pci_root_present`, `test_bar_relocation` |
| MSI-X | 🟡 through a GICv2m MSI frame, as Apple's GIC has no ITS (`test_msi_spi_regs`, `boot-test pci`) | 🟢 MSI routes on WHP's local APIC (`boot-test.ps1 pci`) |
| Interrupt controller | 🟡 GICv3 only, Hypervisor.framework's (`boot-test boot`) | 🟡 the I/O APIC, PICs and PIT are emulated in user space; WHP has the local APIC (fuzz `whp_irqchip`, `test_speaker_port_reads_as_kvm`) |
| Maximum devices | 🟢 `test_attach_maximum_devices`, `test_hotplug_max_devices` | 🟢 `test_attach_maximum_devices`; the hotplug variant fails only on the VMM memory budget (`test_hotplug_max_devices` [bug]) |
| Serial console | 🟢 input and output (`boot-test boot`, `test_serial_console_login`). Characters pushed into the terminal are untested: the harness lacks `/proc` (`test_serial_dos` [bug]) | 🟡 standard input is a pipe (`boot-test.ps1 boot`, `test_serial_console_login`). Windows has no terminal ioctls (`test_serial_dos` [impossible]). In a jail the jailer relays the console; interactive use there is untested (row 7) |
| VMGenID, sysgenid, vmclock | 🟢 `test_vmgenid`, `test_sysgenid_via_mmap`, `test_vmclock_read_fields` | 🟢 `test_vmgenid`, `test_sysgenid_via_mmap`, `test_vmclock_read_fields` |
| RTC (PL031, aarch64) | ❔ `test_rtc` has no Linux aarch64 result | ⚪ |
| i8042, speaker port (x86) | ⚪ | 🟢 `test_send_ctrl_alt_del`, `test_speaker_port_reads_as_kvm` |

### Logger and metrics

| Feature | macOS | Windows |
| --- | --- | --- |
| Logger to a file: level, origin, module | 🟢 `test_log_config`, `test_api_requests_logs`, `boot-test devices` | 🟡 `test_log_config`, `boot-test.ps1 devices`; errors in Windows' text (`test_api_requests_logs` [error-text]) |
| Metrics to a file | 🟢 `test_metrics_default_shape`, `test_block_metrics`, `test_net_metrics`, `boot-test devices` | 🟢 `test_metrics_default_shape`, `test_block_metrics`, `boot-test.ps1 devices`; the net test fails only on the VMM memory budget (`test_net_metrics` [bug]) |
| Logger or metrics to a FIFO | ❔ no test | ❔ no test |
| Log instrumentation | 🟢 `test_instrumentation_example_output`, `test_log_instrument_firecracker_basic_functionality` | 🟡 `test_instrumentation_example_output`; no Windows instrumented build yet (`test_log_instrument_firecracker_basic_functionality` [bug]) |

## `firecracker` command line

| Flag | macOS | Windows |
| --- | --- | --- |
| `--api-sock PATH` | 🟢 every `boot-test` stage | 🟢 every `boot-test.ps1` stage |
| No `--api-sock` (default `/run/firecracker.socket`) | 🔴 impossible: the read-only system volume has no `/run` (`test_cli_no_params` [impossible]) | 🔴 impossible: that path is `\run` on the current drive, which no host has (`test_cli_no_params` [impossible]) |
| `--config-file`, `--no-api` | 🟢 `test_config_start_with_api`, `test_config_start_no_api`, `jailer-test no-api` | 🟢 `test_config_start_with_api`, `test_config_start_no_api` |
| `--metadata` | 🟢 `test_start_with_metadata`, `test_start_with_missing_metadata` | 🟡 `test_start_with_metadata`; a missing file's error in Windows' text (`test_start_with_missing_metadata` [error-text]) |
| `--mmds-size-limit`, `--http-api-max-payload-size` | 🟢 `test_config_start_with_limit`, `test_mmds_limit_scenario` | 🟢 `test_config_start_with_limit`, `test_mmds_limit_scenario` |
| `--log-path`, `--level`, `--show-level`, `--show-log-origin` | 🟢 `test_log_config` | 🟢 `test_log_config` |
| `--module` | ❔ no test | ❔ no test |
| `--metrics-path` | 🟢 `test_cli_metrics_path`, `test_cli_metrics_if_resume_no_metrics` | 🟢 `test_cli_metrics_path`, `test_cli_metrics_if_resume_no_metrics` |
| `--describe-snapshot`, `--snapshot-version` | 🟢 `test_describe_snapshot` | 🟢 `test_describe_snapshot` |
| `--enable-pci` | 🟢 `boot-test pci` | 🟢 `boot-test.ps1 pci` |
| `--id` | 🟢 the jailer passes it (every `jailer-test` stage) | 🟢 the jailer passes it (`jailer-test.ps1 isolation`, `test_empty_jailer_id`) |
| `--start-time-us`, `--start-time-cpu-us`, `--parent-cpu-time-us` | ❔ passed by the jailer as on Linux; their values are untested | ❔ the same |
| `--boot-timer` | ❔ only the performance suite uses it, and it was not run | ❔ the same |
| `--no-seccomp` | 🟡 turns the Seatbelt profile off. Refused in a jail with a CPU limit, since Firecracker could then lift that limit itself (`jailer-test refuse`) | ❔ turns the mitigation profile off in the code; untested, as upstream's test reads `/proc` (`test_no_seccomp` [impossible]) |
| `--seccomp-filter FILE` | 🔴 impossible: no seccomp-BPF. Refused with an error (`ext::sandbox`) | 🔴 impossible: refused the same way (`ext::sandbox`, `test_working_filter` [impossible]) |
| `--version` | 🟢 prints `<upstream>[+wick.N]` (`test_firecracker_version_is_upstream_plus_wick_number`) | 🟢 the same version code; CI runs `firecracker.exe --version` (job `windows`) |

## Jailer flags

On Linux the jailer uses namespaces, a chroot and cgroups. On macOS and Windows, upstream's jailer runs with each
Linux primitive behind a host backend. On macOS the jailer needs root, as on Linux; on Windows it runs unelevated.

| Flag | macOS | Windows |
| --- | --- | --- |
| `--id`, `--exec-file`, `--uid`, `--gid` | 🟡 Firecracker runs from a root-owned copy next to the jail, since dyld cannot start a program inside a chroot. It enters the jail first thing and drops to `uid:gid`; root cannot be regained (`jailer-test jail`, `test_copy_for_exec`, `test_enter_needs_root`) | 🟡 the copy runs on a restricted token below medium integrity with a random SID per jail. `--uid` and `--gid` are recorded only, and files have no numeric owners (`jailer-test.ps1 isolation`, `jailer-test.ps1 low`, `test_default_chroot_hierarchy` [impossible]) |
| `--chroot-base-dir` | 🟡 `chroot(2)` plus a Seatbelt file rule; no mount namespace or bind mounts (`jailer-test jail`) | 🟡 the jail is a drive letter of its own, with a protected ACL. No bind mounts (`jailer-test.ps1 isolation`, `jailer-test.ps1 drives`, `test_jailer_bind_mount_propagation` [impossible]) |
| `--netns` | 🟡 names a directory of endpoints that is the jail's network; no IP at all (row 6, `jailer-test netns`) | 🟡 the same directory, plus Windows Filtering Platform filters that deny the jail IP. Needs an elevated jailer (row 6, `jailer-test.ps1 netns`, `jailer-test.ps1 netguest`) |
| `--new-pid-ns` | 🟡 a fork, not a clone. No other process is in reach, and unhandled signals are dropped as for a namespace's init. Firecracker's pid is the host's, not 1 (row 7, `jailer-test pidns`, `test_no_other_process_in_reach`) | 🟡 a relaunched keeper. The pid is not 1 (`test_new_pid_namespace` [impossible]); whether a pid is in use still shows (row 7, `jailer-test.ps1 pidns`) |
| `--daemonize` | 🟢 upstream's code (`jailer-test daemonize`) | 🟡 the jailer relaunches itself detached and returns 0 (`jailer-test.ps1 daemonize`) |
| `--cgroup`, `--cgroup-version 1\|2` | 🟡 both versions' file names, on host limits: see [cgroup controllers](#cgroup-controllers) (`jailer-test limits`) | 🟡 the same (`jailer-test.ps1 limits`) |
| `--parent-cgroup` | 🟡 accepted, but there is no hierarchy to join, so it places nothing (`test_no_parent_cgroup_to_join`) | 🟡 the same (`test_no_parent_cgroup_to_join`; `test_cgroups_custom_parent` [impossible]) |
| `--resource-limit fsize=` | ❔ upstream's `setrlimit` code, unchanged; no end-to-end test (`jailer-test limits` does not set it; `test_sigxfsz_handler` [impossible] needs `prlimit`) | 🔴 impossible: Windows cannot limit file sizes. Refused (`test_resource_limits`, `jailer-test.ps1 refuse`) |
| `--resource-limit no-file=` | ❔ `jailer-test limits` sets `no-file=512` but does not read it back | 🔴 impossible: Windows cannot limit a process's handles. A non-default value is refused, and the default 2048 is not enforced (`test_resource_limits`, `test_negative_no_file_limit` [impossible]) |
| Inherited descriptors closed | 🟢 a file and a directory open in the jailer are not open in Firecracker (`jailer-test jail`) | 🟢 only the standard handles are passed (`jailer-test.ps1 handles`) |
| Device nodes in the jail | ⚪ none are needed (`test_devices`) | ⚪ none are needed (`test_devices`) |
| Passing descriptors from a jail to a uffd handler or vhost-user backend | 🟢 `SCM_RIGHTS` works from a chroot (`jailer-test jail`) | 🟡 the receiver pulls the handles out of the jail, which cannot open its peer (row 14, `jailer-test.ps1 handoff`, `jailer-test.ps1 uffd`) |
| Upstream's `test_jail.py` | ❔ not run: the security suite is still to do (row 12) | 🟡 10 of 52 Linux-passing tests unlisted (`test_empty_jailer_id`, `test_firecracker_kill_by_pid`); 42 [impossible], see [the table](#upstream-integration-tests) |

## cgroup controllers

| Controller | macOS | Windows |
| --- | --- | --- |
| `memory.max`, `memory.limit_in_bytes` | 🟡 a jetsam limit on the footprint, with SIGKILL at the limit. The API process takes a fixed 32 MiB of it (row 4, `jailer-test memory`, `test_memory_limit`, `test_limits_are_shared_with_the_api_process`) | 🟡 a Job Object limit, charged in 64 KiB blocks at first touch; exit 137 at the limit. A page that is only read is charged too (row 15, `jailer-test.ps1 memory`, `test_memory_past_the_job_limit_ends_the_process`) |
| `memory.high`, `.low`, `.min`, `.swap.max` | 🔴 impossible: jetsam has a hard limit only. Refused (row 8, `jailer-test refuse`) | 🔴 refused (`jailer-test.ps1 refuse`, `test_other_controllers_are_refused_with_the_reason`) |
| `cpu.max`, `cpu.cfs_quota_us` and `cfs_period_us` | 🟡 the kernel's CPU limit refills every second, not every period; whole percents from 1% to 255% (row 9, `jailer-test cpu`, `test_cpu_limit_refills_in_whole_seconds`) | 🟡 a Job Object CPU rate cap from Firecracker's start, which Windows enforces over its own interval, not the period (row 9, `jailer-test.ps1 cpu`) |
| `cpu.weight`, `cpu.weight.nice`, `cpu.shares` | 🔴 impossible: the scheduler has no proportional share between groups. Refused (row 8, `jailer-test refuse`) | 🟡 the Job Object weight nearest to Linux's share; a share Windows cannot come close to is refused (row 8, `jailer-test.ps1 weight`, `test_cpu_weight`) |
| `cpuset.cpus` | 🟡 only a set naming every CPU, which restricts nothing. A subset is impossible: no CPU affinity (row 8, `test_cpuset`) | 🟢 the Job Object's processor affinity (`jailer-test.ps1 cpuset`, `test_cpuset_cpus`) |
| `cpuset.mems` | 🟡 only node 0, which is every node (`test_cpuset`) | 🟡 only every node; a subset is refused (`test_cpuset_mems`) |
| `pids.max` | 🔴 impossible: no per-process thread limit. Refused (row 8, `test_other_controllers_are_refused`) | 🟡 `max` is accepted; a finite value is refused, as Windows cannot limit threads (`test_pids_max_counts_threads_and_is_refused`) |
| `io.*`, `blkio.*` | 🔴 impossible: only I/O priority tiers. Refused (row 8, `test_other_controllers_are_refused`) | 🔴 refused: Windows limits I/O per volume, reads and writes together (`test_io_is_refused`) |
| `hugetlb.*` | 🔴 impossible: no hugetlb pool. Refused (row 8, `test_other_controllers_are_refused`) | 🟡 `hugetlb.2MB.max` caps the large pages the jailer's broker gives, counted when given, not when mapped (row 10, `test_hugetlb_2mb_limits_the_large_page_broker`) |
| `cpu.idle`, `cpu.uclamp.*`, `rdma`, `misc`, `freezer`, `devices`, `net_cls`, `net_prio`, `perf_event` | 🔴 refused, each with its reason (`test_other_controllers_are_refused`, `jailer-test refuse`) | 🔴 refused, each with its reason (`test_other_controllers_are_refused_with_the_reason`, `jailer-test.ps1 refuse`) |

## Security and sandbox

[SECURITY.md](../SECURITY.md) has the threat model and every control. In short:

| Control | macOS | Windows |
| --- | --- | --- |
| Hardware virtualisation, one kernel per VM | 🟢 Hypervisor.framework (every `boot-test` stage) | 🟢 WHP (every `boot-test.ps1` stage) |
| System call filter | 🟡 a Seatbelt profile, process-wide, in upstream's two phases. After the microVM is built it narrows for good to 101 system calls, 15 Mach traps and 7 MIG routines; any other call raises SIGSYS (row 1, `test_narrowing_is_one_way`, `test_unlisted_syscalls_raise_sigsys`, `tools/macos/sandbox-discovery.sh`) | 🟡 a process mitigation profile in the same two phases. Each mitigation is tied to a seccomp rule and read back (row 1, `test_every_mitigation_names_its_linux_rule`, `test_narrowing_is_one_way`) |
| Separate filters for VMM, API and vCPU threads | 🔴 impossible: no per-thread sandbox. The process gets the union, which is the real boundary on Linux too (row 5) | 🔴 impossible, for the same reason (row 5) |
| API filter | 🟡 the API server runs in a process of its own with the `api` filter's calls (row 4, `test_api_profile_raises_sigsys_outside_its_list`, `boot-test api-process`) | 🟡 a process of its own, with the whole mitigation profile from its start (row 4, `test_the_api_process_serves_under_the_api_profile`, `jailer-test.ps1 api`) |
| Argument checks (`ioctl`, `socket`, `fcntl`, `mmap`, `futex`, ...) | 🟡 checked where Seatbelt has a rule: `ioctl`, socket family, `fcntl`, executable mappings. `futex` is impossible. An anonymous `PROT_EXEC` mapping is checked only in wick's libc (row 2, `test_executable_mappings_raise_sigsys`, `test_futex_operations_are_not_checked`) | 🟡 only executable mappings and handle use. `ioctl`, `socket`, `fcntl` and `futex` are not checked yet, so a jail without `--netns` can make IP sockets (row 2, `test_dynamic_code_policy`, `test_strict_handle_check_policy`) |
| A denied call ends Firecracker with the bad-syscall exit code | 🟡 SIGSYS goes to the process, so the denied call first returns `EPERM` to its thread (row 3, `test_denied_syscall_exits_as_seccomp`) | 🟡 only where Windows reports the denial; other denials fail closed with no signal (row 3, `test_denied_operation_exits_as_seccomp`, `test_denied_operations_fail_closed`) |
| No exec, fork or IP networking | 🟢 `test_sandbox_restricts_child` | 🟡 no child processes (`test_child_process_policy`); no IP only with `--netns` (row 6, `jailer-test.ps1 netns`) |
| Confinement without the jailer | 🟡 the Seatbelt profile only; files are not limited, as on Linux without the jailer (`test_sandbox_restricts_child`) | 🟡 the mitigation profile only: no jail directory, token or Job Object (`test_child_process_policy`) |
| Upstream's security tests | ❔ not run (row 12) | 🔴 impossible: they read seccomp state from `/proc` or build BPF (`test_default_seccomp_level`, `test_validate_filter` [impossible]) |
| No nested virtualisation for the guest; FIPS | ❔ not run (`test_no_nested_virtualization`, `test_fips_enabled`) | 🟢 `test_no_nested_virtualization`, `test_fips_enabled` |
| SSBD (`enable_ssbd_mitigation`, aarch64) | 🟡 through `FEAT_SSBS` on M2 and later; on M1 it fails as on a host without SSBD (`test_ssbd`) | ⚪ aarch64 only |
| Fuzzing of the host side | 🟡 fuzz targets `hvf_exit`, `vnet_offload`, `uffd_protocol`, run on CI for a minute each; no third-party audit (row 13) | 🟡 fuzz targets `whp_exit`, `whp_irqchip`; WHP's own run loop is not fuzzed (row 13) |

Side channels between VMs on one host: upstream's
[production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md) covers
Linux. The macOS and Windows counterparts are not written yet (SECURITY.md, "Not at parity yet").

## Signals and exit codes

| Signal or exit | macOS | Windows |
| --- | --- | --- |
| SIGHUP, SIGBUS, SIGSEGV, SIGILL, SIGXCPU, SIGSYS sent from outside: logged, exit code | 🟢 `test_generic_signal_handler` | 🔴 impossible: Windows has no signals from outside, only `TerminateProcess` (`test_generic_signal_handler` [impossible]) |
| SIGRTMIN (vCPU kick) | 🔴 impossible: no real-time signals (NSIG is 32). The kick is `hv_vcpus_exit` (`test_handled_signals` [impossible]) | 🔴 impossible (`test_handled_signals` [impossible]); the kick is `WHvCancelRunVirtualProcessor` |
| SIGXFSZ from a file-size limit | 🟡 the handler runs (`test_generic_signal_handler`); the limit's own test sets it from outside with `prlimit`, which macOS lacks (`test_sigxfsz_handler` [impossible]) | 🔴 impossible: no file-size limit (`test_sigxfsz_handler` [impossible]) |
| SIGPIPE on a write to a closed peer | 🟡 `test_sigpipe_from_log_write`; not counted for vsock (`test_vsock_epipe` [bug]) | 🟢 `test_sigpipe_from_log_write`, `test_write_to_a_closed_peer_raises_sigpipe` |
| SIGSEGV, SIGBUS from a fault inside the process | 🟢 native signals; the userfaultfd backend is built on them (`boot-test uffd`) | 🟢 raised from Windows exceptions (`test_fault_handler_retries_instruction`) |
| Bad-syscall exit code | 🟡 see [Security](#security-and-sandbox) (`test_denied_syscall_exits_as_seccomp`) | 🟡 see [Security](#security-and-sandbox) (`test_denied_operation_exits_as_seccomp`) |
| Killed at the jail's memory limit | 🟢 SIGKILL (`jailer-test memory`) | 🟡 exit 137, the cause on stderr (`jailer-test.ps1 memory`) |
| A panic ends the process | 🟢 SIGABRT with the panic message (`boot-test api-process`) | 🟡 a non-zero exit with the panic message; Windows has no SIGABRT status (`boot-test.ps1 api-process`) |
| Clean exit with `--no-api` | 🟢 `test_config_start_no_api_exit` | 🟢 `test_config_start_no_api_exit` |
| Exit codes for bad configuration (152) and bad arguments (153) | ❔ upstream's tests check log lines, not codes | ❔ the same |

## Tools

| Tool | macOS | Windows |
| --- | --- | --- |
| `snapshot-editor edit-memory rebase` | 🟢 `boot-test diff` | 🟢 `boot-test.ps1 diff` |
| `snapshot-editor` other commands | ❔ `test_remove_regs` has no Linux aarch64 result; the `info-vmstate` commands have no test | ❔ no test |
| `rebase-snap` | ❔ no test | ❔ built on CI; no test |
| `cpu-template-helper` | 🟡 the fingerprint reads sysfs, which macOS lacks (`test_consecutive_fingerprint_consistency` [bug]); the dump test is x86 (`test_cpu_config_dump_vs_actual` [arch]) | 🟢 `test_cpu_config_dump_vs_actual`, `test_consecutive_fingerprint_consistency` |
| `seccompiler-bin` | 🔴 impossible: no libseccomp, so it fails with an error (`ext::sandbox`) | 🔴 impossible, the same (`test_validate_filter` [impossible]) |
| uffd example handlers | 🟢 `test_valid_handler`, `test_malicious_handler`, `boot-test uffd` | 🟢 `test_valid_handler`, `test_malicious_handler`, `boot-test.ps1 uffd` |
| Fuzzing build, gdb build, instrumented build | 🟢 `test_fuzzing_warning`, `test_log_instrument_firecracker_basic_functionality`; gdb as under [CPU](#cpu) | 🔴 not done yet: no Windows builds (`test_fuzzing_warning`, `test_gdb_connects` [bug]) |
| Static binary, ELF debug info | 🔴 impossible: Mach-O, dynamically linked (`test_firecracker_binary_static_linking`, `test_release_debuginfo` [impossible]) | 🔴 impossible: PE image, PDB (`test_firecracker_binary_static_linking`, `test_release_no_gdb` [impossible]) |
| Binary size | 🟢 `test_firecracker_binary_size`, `test_jailer_binary_size` | 🟢 `test_firecracker_binary_size`, `test_jailer_binary_size` |
| `devtool` (upstream's Docker dev container) | ⚪ Linux and Docker only; `tools/macos/*.sh` replace it | ⚪ Linux only; `tools/windows/*.ps1` replace it |

## Upstream integration tests

wick runs upstream's pytest suites unchanged on macOS and Windows, with a harness that supplies the host side of
Linux's tools. Each host's comparison script checks every result against the Linux baseline,
[`tools/macos/integration-linux-baseline.txt`](../tools/macos/integration-linux-baseline.txt). That baseline is one
CI run on GitHub's ubuntu-latest (x86_64, KVM), so a test that exists only on aarch64 has no Linux result to compare.

**What has run.**

- **macOS:** every functional suite, as the user, through a stand-in for the jailer (row 12). The security suite,
  the performance suite and the root runs (`--jailer`) are still to do.
- **Windows:** the functional and security suites in full, under the real jailer (row 12). The script reported 629
  tests agreeing with Linux. That is the comparison's count, not a pass count: it includes Linux-skipped and
  Linux-failed tests, which are not compared, and Windows-only tests that pass or skip.
- **Neither:** the performance suite. No CI job boots a guest on macOS or Windows, because GitHub's runners expose
  no Hypervisor.framework or WHP. The runs are on a developer's Mac and a WHP PC.

**These are counts of listed differences, not measured pass rates.** No run report is committed. The table below
counts, per upstream test file, the tests that pass on Linux and are listed in each host's differences file, by
kind. A test that is not listed agreed with Linux in the last full run, unless a catch-all `failure:` entry excused
it (see the notes under the table).

Kinds:

| Kind | Meaning |
| --- | --- |
| `impossible` | The host cannot do it; the entry says why |
| `bug` | A wick bug, or a gap in the test harness, to fix |
| `error-text` | Windows: the test matches Linux's error text; Firecracker reports Windows' error, as it reports Linux's there |
| `arch` | macOS: an x86_64-only test, which upstream skips on aarch64 |
| `root` | macOS: needs the jailer as root; the runs so far were as the user |
| `row-N` | A Linux feature not there yet: PORTING.md row N. `row-6` is PORTING's `--netns` row, which is done; these entries are TAP features |

The table is generated by `python3 -I tools/compat-counts.py`, and CI checks it is current
(`tools/compat-counts.py --check docs/COMPATIBILITY.md`).

<!-- compat-counts:begin -->
| Upstream test file | Linux passed | Linux skipped | Linux failed | macOS: Linux-passing tests listed | Windows: Linux-passing tests listed |
| --- | ---: | ---: | ---: | --- | --- |
| `functional/test_api.py` | 69 | 2 | 0 | 6 (arch 4, impossible 2) | 12 (bug 2, error-text 10) |
| `functional/test_api_server.py` | 2 | 0 | 0 | 2 (root 2) | – |
| `functional/test_balloon.py` | 28 | 0 | 0 | 4 (bug 4) | – |
| `functional/test_binary.py` | 3 | 0 | 0 | 2 (impossible 2) | 3 (impossible 3) |
| `functional/test_binary_size.py` | 2 | 0 | 0 | – | – |
| `functional/test_bzimage_boot.py` | 0 | 2 | 0 | – | – |
| `functional/test_cmd_line_parameters.py` | 9 | 0 | 0 | 1 (impossible 1) | 1 (impossible 1) |
| `functional/test_cmd_line_start.py` | 36 | 0 | 0 | – | 2 (error-text 2) |
| `functional/test_cpu_all.py` | 8 | 0 | 0 | – | 8 (bug 8) |
| `functional/test_cpu_features_aarch64.py` | 0 | 4 | 0 | – | – |
| `functional/test_cpu_features_host_vs_guest.py` | 2 | 0 | 0 | – | – |
| `functional/test_cpu_features_x86_64.py` | 18 | 4 | 0 | 18 (arch 18) | 12 (bug 12) |
| `functional/test_cpu_template_helper.py` | 3 | 1 | 0 | 3 (arch 2, bug 1) | – |
| `functional/test_dirty_pages_in_full_snapshot.py` | 2 | 0 | 0 | – | – |
| `functional/test_drive_vhost_user.py` | 14 | 0 | 0 | 2 (bug 2) | – |
| `functional/test_drive_virtio.py` | 54 | 0 | 0 | 8 (bug 8) | 4 (impossible 4) |
| `functional/test_error_code.py` | 0 | 2 | 0 | – | – |
| `functional/test_feat_parity.py` | 0 | 4 | 0 | – | – |
| `functional/test_fuzzing.py` | 3 | 0 | 0 | – | 1 (bug 1) |
| `functional/test_gdb.py` | 1 | 0 | 0 | 1 (arch 1) | 1 (bug 1) |
| `functional/test_hotplug.py` | 13 | 0 | 0 | 1 (row-6 1) | 8 (bug 2, error-text 6) |
| `functional/test_huge_pages.py` | 4 | 0 | 0 | 4 (impossible 4) | 4 (impossible 4) |
| `functional/test_instrumented_firecracker.py` | 1 | 0 | 0 | – | 1 (bug 1) |
| `functional/test_kernel_cmdline.py` | 2 | 0 | 0 | – | – |
| `functional/test_kvm_ptp.py` | 2 | 0 | 0 | – | – |
| `functional/test_log_instrument.py` | 6 | 0 | 0 | – | – |
| `functional/test_logging.py` | 14 | 0 | 0 | – | 2 (error-text 2) |
| `functional/test_max_devices.py` | 4 | 0 | 0 | – | – |
| `functional/test_metrics.py` | 14 | 0 | 0 | – | 2 (bug 2) |
| `functional/test_mmds.py` | 104 | 0 | 0 | – | – |
| `functional/test_net.py` | 12 | 0 | 0 | 8 (bug 6, impossible 2) | 8 (row-6 8) |
| `functional/test_net_config_space.py` | 2 | 0 | 0 | 2 (bug 2) | 2 (row-6 2) |
| `functional/test_pause_resume.py` | 8 | 0 | 0 | 2 (arch 2) | – |
| `functional/test_pci.py` | 9 | 0 | 0 | – | – |
| `functional/test_pmem.py` | 22 | 0 | 0 | 2 (bug 2) | – |
| `functional/test_pvtime.py` | 0 | 2 | 0 | – | – |
| `functional/test_rng.py` | 14 | 0 | 0 | 6 (bug 6) | – |
| `functional/test_rtc.py` | 0 | 2 | 0 | – | – |
| `functional/test_serial_io.py` | 18 | 0 | 0 | 2 (bug 2) | 2 (impossible 2) |
| `functional/test_shut_down.py` | 4 | 0 | 0 | – | – |
| `functional/test_signals.py` | 21 | 0 | 0 | 4 (impossible 4) | 20 (impossible 20) |
| `functional/test_snapshot_basic.py` | 64 | 4 | 0 | 2 (root 2) | 2 (error-text 2) |
| `functional/test_snapshot_editor.py` | 0 | 2 | 0 | – | – |
| `functional/test_snapshot_not_losing_dirty_pages.py` | 1 | 0 | 0 | 1 (impossible 1) | 1 (impossible 1) |
| `functional/test_sysgenid.py` | 6 | 0 | 0 | – | – |
| `functional/test_topology.py` | 12 | 12 | 0 | 12 (arch 6, bug 6) | 12 (bug 12) |
| `functional/test_uffd.py` | 8 | 0 | 0 | 2 (impossible 2) | 4 (error-text 4) |
| `functional/test_vmclock.py` | 22 | 0 | 0 | – | – |
| `functional/test_vsock.py` | 22 | 0 | 0 | 18 (bug 8, impossible 10) | – |
| `security/test_custom_seccomp.py` | 8 | 0 | 0 | not run | 8 (impossible 8) |
| `security/test_fips.py` | 3 | 0 | 0 | not run | – |
| `security/test_jail.py` | 52 | 2 | 0 | not run | 42 (impossible 42) |
| `security/test_nv.py` | 2 | 0 | 0 | not run | – |
| `security/test_sec_audit.py` | 0 | 1 | 0 | not run | – |
| `security/test_seccomp.py` | 7 | 0 | 0 | not run | 7 (impossible 7) |
| `security/test_seccomp_validate.py` | 3 | 0 | 0 | not run | 3 (impossible 3) |
| `security/test_vulnerabilities.py` | 0 | 2 | 6 | not run | – |
| **Total** | **738** | **46** | **6** | **113 (arch 33, bug 47, impossible 28, root 4, row-6 1)** | **172 (bug 41, error-text 26, impossible 95, row-6 10)** |

- macOS: `failure:host_tools.memory.MemoryUsageExceededError` (bug) excuses any test whose every failing phase failed with that exception, in any file; the tests it excuses are not counted above.
- macOS: entries also name tests Linux did not pass (4 skipped); not counted.
- Windows: entries also name tests Linux did not pass (2 skipped); not counted.
- macOS: counts are for `user` mode (`tools/macos/integration-tests.sh` without `--jailer`); the file has no entry for other modes.
- macOS: `security/` has not been run (docs/PORTING.md row 12), so it has no count.
- An entry for a test function names all its parameters. Windows' comparator lets some of them pass (macOS' only for `arch`), so a Windows count is an upper bound on the tests that did not pass.
<!-- compat-counts:end -->
