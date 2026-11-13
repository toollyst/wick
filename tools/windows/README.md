# Windows test kit

- `boot-test.ps1`: scenario tests of the Windows build against upstream
  Firecracker's x86_64 CI guest, the counterpart of `tools/macos/boot-test.py`.
- `winprobe.c` (`winprobe.exe` in CI's artifact): measures the host
  mechanisms the sandbox and jailer backends use.
- `jailer-test.ps1`: the jailer on WHP hardware, the counterpart of
  `tools/macos/jailer-test.py`. Stages without a guest: `refuse` (what
  Windows cannot enforce is refused, each cgroup controller and resource
  limit with its reason, and a named `--parent-cgroup`, which the jailer
  does not do yet), `freeze` (upstream's freezer files next to the
  jail: a jail frozen and thawed through `freezer.state` and through
  `cgroup.freeze` and `cgroup.events`, invalid values restored, the jail
  unable to write its control file, the jailer's death ending a frozen jail,
  `freezer.state=FROZEN` at the start holding the operator's command, plain
  and with `--daemonize`, `--new-pid-ns` and both, each case reported; it
  prints the Windows build), `cpuset` (`cpuset.cpus` is the jailed process's
  affinity), `weight` (two jailed processes at `cpu.weight` 50 and 100
  sharing one processor), `low` (a low-integrity process of the user is kept
  out of a jail), `links` (a jail makes no hard link to a file outside it and
  no entry above its root), `nofile` (`--resource-limit no-file=`, upstream's
  2048 by default: `no-file=3` stops Firecracker with EMFILE, the limits
  given are accepted and held; the jailed probe's own opens are not refused,
  which records what is left to the jailer's supervision and fails once it
  bounds them), `sections`
  (`memory.max` against sections: fails today, as a Job Object does not
  charge them), `daemonize`, `handles` (a handle the jailer inherited is not
  open in the jail), `pidns` (no process, thread or console of anyone else;
  needs a console), `handoff` (a handle and a socket held by a jailed process
  are pulled out by the operator and by a medium-integrity process of the
  user), `netns` (two jails with a network each, and a jail and a probe
  given the first's: each endpoint in its jail's own directory of the
  network, which no other jail reaches; a second jail of a running id
  refused; TCP and UDP denied; an unelevated jailer refused the flag; needs
  an elevated PowerShell) and
  `api` (the jail runs Firecracker and its API server's process, the latter
  under the whole mitigation profile; each one's end ends the other). With a
  guest: `netguest` (frames through the endpoint in the jail's own directory of the network),
  `isolation` (`jail-probe.rs`, run through the jailer as the jailed binary,
  may not read the user's files or SAM, write outside its jail, reach another
  jail's files, API socket or process, or open the operator's; the operator
  reaches the API socket), `boot` (a 2 vCPU guest in the jail), `bindlink`
  (upstream's `test_jailer_bind_mount_propagation` through bind links: a
  guest boots from a kernel and root drive bound into the jail's root before
  the jailer starts, and the backing files' security descriptors are the same
  before, during and after; elevated, Windows 11 24H2 or later, else it fails
  saying so; run once, elevated, on Windows 11 build 26300, where it failed
  at that check: no `System32\bindlink.dll`, though Microsoft gives the
  Bindlink API as available from build 25314; the rest has not run), `limits`
  (`memory.max` below the guest's memory: the VMM ends with 137), `memory`
  (a guest past the limit ends the VMM, and runs on under a larger one),
  `cpu` (`cpu.max` from Firecracker's start: twelve boots under it, each
  vCPU's local timer in TSC-deadline mode), `hugepages` (the jail keeps no
  privilege but traversal and gets its 2 MiB pages from the jailer, bounded
  by `hugetlb.2MB.max`; needs "Lock pages in memory", as the boot test's
  stage does), `uffd` and `vhost-user` (a jailed guest's memory handed to a
  handler or a backend of the operator); and a check that every jail's drive
  letter was removed. It needs the boot test's guest files (`-Assets`,
  default `C:\wbt`) and the probe (`jail-probe.exe` from the kit, or
  `rustc` to build it):

  ```
  powershell -ExecutionPolicy Bypass -File tools\windows\jailer-test.ps1 -WorkDir C:\wjt
  ```

- `vmm-memory-record.py`: what Firecracker's own memory besides its guest's
  is made of (its image's code and written pages, thread stacks, heaps, other
  private memory, sections), counted as the integration tests' memory monitor
  counts it, for a microVM with 1, 2 and 16 vCPUs whose guest is the script's
  own `hlt` loop: no guest files, WHP only. A record (VMMMEM lines), for
  upstream's 5 MiB budget; CI's windows job runs it:

  ```
  python -I tools\windows\vmm-memory-record.py <firecracker.exe> [vcpus ...]
  ```

  With `--boot <dir>` the guest is upstream's CI kernel and root file system
  (downloaded into `<dir>` when not there; the ones `boot-test.ps1` boots),
  with a network interface: every vCPU runs. Besides the VMMMEM lines it
  prints each thread's stack (VMMSTACK lines: reserved, committed, resident,
  how deep) and, for the deepest and the median thread of each kind, the
  return addresses on its stack's resident pages (module and offset, with
  the nearest symbol when `firecracker.pdb` is beside the binary, as in the
  kit), so that the calls that reached deep are named:

  ```
  python -I tools\windows\vmm-memory-record.py --boot C:\wbt lib\firecracker\build\cargo_target\release\firecracker.exe 1 2 16
  ```

CI builds the binaries on every push and uploads them as the artifact
`wick-windows-x86_64-<commit>`: `lib/firecracker/build/cargo_target/release/firecracker.exe`,
`firecracker.pdb` (its symbols, for `vmm-memory-record.py --boot`),
`snapshot-editor.exe`, `jailer.exe`, `rebase-snap.exe` and
`examples/uffd_on_demand_handler.exe` next to it,
`lib/firecracker/build/cargo_target/debug/firecracker.exe` (built with the gdb
feature, for the `gdb` stage),
`lib/firecracker/build/vhost-user-blk/release/vhost-user-blk.exe` (the
vhost-user test backend), `winprobe.exe`, and in `tools/windows/`
`boot-test.ps1`, `jailer-test.ps1` with `jail-probe.exe` built,
`job-freeze-probe.ps1`, `memory-partition-probe.exe`, `vmm-memory-record.py` and this file, at those
paths. The kit needs no Rust.

## Running it on a Windows PC

Needs Windows 10 (1803 or later) or 11 on x86_64, virtualization turned on in
the firmware, and nothing else installed: the script is Windows PowerShell 5.1.

1. **Windows Hypervisor Platform.** Once, as administrator, then reboot:

   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
   ```

   The check is the boot test's own: it prints `Windows Hypervisor Platform:
   available` (and `host.txt` says `WHP: available`) when `WinHvPlatform.dll` loads and reports a
   hypervisor, or why not. Neither `HypervisorPresent` (true whenever a
   hypervisor runs: Hyper-V, virtualization-based security) nor the feature's
   `State` is that test: on a Windows 11 build 26300 PC
   `Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform` read
   `Disabled` while WHP worked and guests booted.

2. **The binaries.** From the latest green `ci` run on `main`: GitHub,
   Actions, `ci`, the run, Artifacts, `wick-windows-x86_64-<commit>`; unzip
   it to `C:\wick-kit` and run
   `Get-ChildItem -Recurse C:\wick-kit | Unblock-File`. Or with the GitHub
   CLI:

   ```powershell
   $r = gh run list --repo toollyst/wick --workflow ci --branch main --status success --limit 1 --json databaseId,headSha | ConvertFrom-Json
   gh run download $r.databaseId --repo toollyst/wick --name "wick-windows-x86_64-$($r.headSha)" --dir C:\wick-kit
   ```

3. **The boot test.** In a PowerShell window (no administrator needed):

   ```powershell
   cd C:\wick-kit
   powershell -ExecutionPolicy Bypass -File tools\windows\boot-test.ps1
   ```

   About ten minutes; the first run downloads 145 MB (kernel and rootfs).
   It prints PASS or FAIL per stage with the reason and ends with the path
   of `results-<time>.zip` in `%LOCALAPPDATA%\wick-boot-test`.
   `-Stage boot,net` runs some stages; `-SelfTest` checks the script itself
   in seconds, without WHP.

4. **The probes.** In the same folder (`cmd /c` keeps the output plain text):

   ```powershell
   cmd /c "winprobe.exe appcontainer > probe-appcontainer.txt 2>&1"
   cmd /c "winprobe.exe profile > probe-profile.txt 2>&1"
   cmd /c "winprobe.exe fsctl > probe-fsctl.txt 2>&1"
   ```

5. **Send back** `results-<time>.zip` and the three `probe-*.txt` files.

## What the boot test checks

Every stage that needs a guest boots its own VM; before each guest reset the guest kernel log
must be free of RCU stalls, soft lockups, hung tasks, BUGs, oopses and
warnings, and the reset must end Firecracker with exit status 0.

| Stage | Checks |
|---|---|
| `boot` | 1 vCPU: kernel reaches init, serial output and input (stdin is a pipe), `x86_64`, 1 CPU, memory size, CPUID hypervisor bit, the local timer in TSC-deadline mode (`lapic-deadline`), the guest clock advances with the host's |
| `smp` | 2 vCPUs: the AP starts (INIT/SIPI), both local timers in TSC-deadline mode, work runs on each CPU, the clock agrees between them; CPU 1 taken offline and online three times (the guest's INIT/SIPI again), then work on it, after boot and after a snapshot restore (kit 8d577b7, and 5 of 5 runs on kit dd657f4, Windows 11 10.0.26300.9711: 0 spurious LAPIC timer interrupts in each) |
| `block` | an Async read-only drive (md5 of 8 MiB), a Sync and an Async writable drive (the host file holds what the guest wrote), a write to a read-only drive fails, each drive's serial is its file's (volume serial number and file index) |
| `vsock` | host to guest `CONNECT 52` with a 4 MiB echo read back by length; guest to host through `<uds>_53` |
| `net` | virtio-net over the Windows endpoint (a Unix stream, each frame preceded by its 32-bit big-endian length): a switch in the script answers ARP, ICMP echo (1400 bytes, 200 back to back) and UDP echo, and checks the checksum of every frame the guest sends; tx and rx bandwidth limiters set with `PATCH` hold each direction to 1 MiB/s, and without them it runs at three times that or more |
| `snapshot` | a full snapshot of a 2 vCPU guest with a data drive and vsock, restored in a new Firecracker process: shell state, the clock on both vCPUs, both drives, vsock |
| `diff` | a diff snapshot with dirty page tracking (its file keeps its holes), merged into the full one by `snapshot-editor edit-memory rebase` and restored |
| `uffd` | the `snapshot` stage's snapshot restored with the Uffd memory backend, its pages served by upstream's `uffd_on_demand_handler` in another process |
| `api-process` | the API server's HTTP side runs in a process of its own with the whole mitigation profile (this shell under none), serves the API; killing it ends Firecracker, and Firecracker's end ends it |
| `pci` | the `snapshot` stage over virtio-pci with MSI-X (`--enable-pci`) |
| `restores` | one snapshot restored 20 times, each paused and snapshotted again (vCPU races at the restore and at the pause) |
| `vhost-user` | a vhost-user-blk drive served by `vhost-user-blk.exe` in another process: the guest reads its content, a guest write reaches the image |
| `hugepages` | guest memory on 2 MiB large pages (`huge_pages: "2M"`): boots and keeps 160 MiB written to it. Needs "Lock pages in memory" for the account (`secpol.msc`, Local Policies, User Rights Assignment; sign out and in), as hugetlbfs on Linux needs huge pages reserved |
| `devices` | virtio-rng, a rate-limited drive, MMDS V2 over the net endpoint, the balloon and its statistics, the logger's and the metrics' files |
| `balloon` | 150 MiB balloon cycles on a guest restored from a memory file and on a booted one: O_DIRECT reads of the drive read the file, and the commit charge goes down and up again with the balloon |
| `cli` | exit codes 153 (bad arguments), 152 (bad `--level`), 1 (bad configuration file), without a guest; `--module`; the start time metrics of `--start-time-us`, `--start-time-cpu-us`, `--parent-cpu-time-us`; the log and the metrics on named pipes (the counterpart of a FIFO), with a pipe nobody reads and pipes whose readers leave and come back; `--boot-timer` with upstream's `/usr/local/bin/init` |
| `tools` | `rebase-snap` and `snapshot-editor edit-memory rebase` on a sparse and a dense synthetic diff file (the dense one refused, the base untouched), without a guest; then a diff snapshot (written as a sparse file) rebased by both alike and restored; `snapshot-editor info-vmstate` `version`, `vcpu-states`, `vm-state`; the state file with the aarch64 magic or a newer version refused at the load |
| `no-seccomp` | without `--no-seccomp` the setup-phase mitigations are in force in Firecracker and the whole profile in its API process; with it none in either. Before a boot (no guest), then with a guest running |
| `foreign-snapshot` | a state file made on another host, given as `-ForeignState <file>` (the macOS boot test's snapshot stage makes an aarch64 one), is refused at the load and Firecracker ends. No guest |
| `memory-hotplug` | virtio-mem: the 1024 MiB unplugged region not charged at the boot, 512 MiB plugged into a 512 MiB guest, seen in `MemTotal`, 600 MiB written and read back, then unplugged (Firecracker's commit charge and private working set go down) and plugged again |
| `gdb` | not in `all`: Firecracker built with the gdb feature (`-GdbFirecracker`) and gdb (`-Gdb`, or MSYS2's `gdb-multiarch`) on upstream's debug kernel: a hardware breakpoint at `start_kernel`, the kernel's bytes read through the stub as in the vmlinux, a software breakpoint at `rest_init`, the guest boots on. gdb reaches the gdb socket by its path, or through a TCP relay of the stage's own |

`uffd` needs the `snapshot` stage's files: run it after `snapshot` (as `all` does).

The results folder holds, per stage, the VM config, the serial console, the
Firecracker log at debug level and the guest kernel log, plus `host.txt`
(Windows build, CPU, WHP state) and `summary.txt`.

If WHP is not usable, every stage fails with the reason the script found
before starting, for example "the Windows hypervisor is not running".

## Upstream's integration tests

`integration-tests.ps1` runs upstream's pytest suites (functional and
security by default) against the Windows build, unchanged (patches/0027's
`tests/conftest.py` change acts on macOS only; `test_api_version` accepts
the `+wick.N` version, patches/0015), with the host side
in `integration/` (the pytest plugin `wick_windows.py`), and compares each
test with Linux's results (`compare-integration-tests.py`,
`integration-test-differences.txt`). Unlike the boot test it needs a source
checkout with the release build, not the kit, and:

- WHP, as for the boot test;
- a Python 3 for `integration\venv.ps1`, which makes the test environment at
  upstream's pinned versions, and the guest artifacts from
  `integration\setup-artifacts.ps1` (needs WSL with squashfs-tools and
  e2fsprogs);
- Git for Windows's bash (or its path in `WICK_IT_BASH`);
- rustup's Rust, its `cargo` first on `PATH` (a cargo from elsewhere, such as
  Chocolatey's, fails with "can't find crate for core"), and Visual Studio's
  C++ build tools: `test_fuzzing.py`, `test_gdb.py` and
  `test_instrumented_firecracker.py` build Firecracker themselves, with
  cargo run in Git's bash, where `link` is coreutils' and `vcvars64` needs
  `vswhere`.

The script checks the last two before anything runs and stops with the
reason: `cargo` in PowerShell and in Git's bash is rustup's
(`%CARGO_HOME%\bin`), `vswhere.exe` exists (its directory is put on `PATH`),
and `CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER` names MSVC's `link.exe`
(set from the newest MSVC tools `vswhere` finds when not set).

Run it from an elevated PowerShell. Upstream's suite runs as root on Linux
(`tools/devtool test` runs it in a `--privileged` container), which the
jailer's chroot, cgroups and network namespaces need; here every jailed
microVM's `--netns` adds Windows Filtering Platform filters, which need an
elevated jailer. Not elevated, the script warns and those tests fail.

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\integration\venv.ps1
powershell -ExecutionPolicy Bypass -File tools\windows\integration\setup-artifacts.ps1
powershell -ExecutionPolicy Bypass -File tools\windows\integration-tests.ps1
powershell -ExecutionPolicy Bypass -File tools\windows\integration-tests.ps1 -Pytest "integration_tests/functional/test_fuzzing.py"
```

The results (pytest's report and log, upstream's `test_results`, the
comparison with Linux) go to `build\integration-tests\<time>`, or `-Out`.
