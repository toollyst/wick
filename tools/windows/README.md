# Windows test kit

- `boot-test.ps1`: scenario tests of the Windows build against upstream
  Firecracker's x86_64 CI guest, the counterpart of `tools/macos/boot-test.py`.
- `winprobe.c` (`winprobe.exe` in CI's artifact): measures the host
  mechanisms the sandbox and jailer backends use.
- `jailer-test.ps1`: the jailer on WHP hardware, the counterpart of
  `tools/macos/jailer-test.py`. Stages: `refuse` (what Windows cannot
  enforce is refused, each cgroup controller with its reason), `cpuset`
  (`cpuset.cpus` is the jailed process's affinity), `weight` (two jailed
  processes at `cpu.weight` 50 and 100 sharing one processor), `isolation` (`jail-probe.rs`, run through the jailer
  as the jailed binary, may not read the user's files or SAM, write outside
  its jail, reach another jail's files, API socket or process, or open the
  operator's; the operator reaches the API socket), `netns` (two jails with
  a network each: a jail reaches its own network's endpoint and not the
  other's, is denied TCP and UDP, and an unelevated jailer is refused the
  flag; needs an elevated PowerShell), `handoff` (a handle and a socket
  held by a jailed process are pulled out by the operator and by a
  medium-integrity process of the user), `api` (the jail runs Firecracker
  and its API server's process, the latter under the whole mitigation
  profile; each one's end ends the other), `boot` (a 2 vCPU guest
  in the jail), `limits` (`memory.max`), `cpu` (`cpu.max` from Firecracker's start: twelve boots under
  it, each vCPU's local timer in TSC-deadline mode), `hugepages` (the jail
  keeps "Lock pages in memory" and no other privilege but traversal, the
  job's memory limit holds large pages, and a jailed guest boots on 2 MiB
  pages; needs the privilege, as the boot test's stage does), and a check
  that every jail's drive letter was removed. It needs the boot test's
  guest files (`-Assets`, default `C:\wbt`) and `rustc` for the probe:

  ```
  powershell -ExecutionPolicy Bypass -File tools\windows\jailer-test.ps1 -WorkDir C:\wjt
  ```

CI builds both on every push and uploads them as the artifact
`wick-windows-x86_64-<commit>`: `lib/firecracker/build/cargo_target/release/firecracker.exe`,
`snapshot-editor.exe` and `examples/uffd_on_demand_handler.exe` next to it,
`lib/firecracker/build/vhost-user-blk/release/vhost-user-blk.exe` (the
vhost-user test backend), `winprobe.exe`, `tools/windows/boot-test.ps1` and
this file, at those paths.

## Running it on a Windows PC

Needs Windows 10 (1803 or later) or 11 on x86_64, virtualization turned on in
the firmware, and nothing else installed: the script is Windows PowerShell 5.1.

1. **Windows Hypervisor Platform.** Once, as administrator, then reboot:

   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
   ```

   `(Get-CimInstance Win32_ComputerSystem).HypervisorPresent` is `True`
   afterwards.

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

Every stage boots its own VM; before each guest reset the guest kernel log
must be free of RCU stalls, soft lockups, hung tasks, BUGs, oopses and
warnings, and the reset must end Firecracker with exit status 0.

| Stage | Checks |
|---|---|
| `boot` | 1 vCPU: kernel reaches init, serial output and input (stdin is a pipe), `x86_64`, 1 CPU, memory size, CPUID hypervisor bit, the local timer in TSC-deadline mode (`lapic-deadline`), the guest clock advances with the host's |
| `smp` | 2 vCPUs: the AP starts (INIT/SIPI), both local timers in TSC-deadline mode, work runs on each CPU, the clock agrees between them |
| `block` | an Async read-only drive (md5 of 8 MiB), a Sync and an Async writable drive (the host file holds what the guest wrote), a write to a read-only drive fails, each drive's serial is its file's (volume serial number and file index) |
| `vsock` | host to guest `CONNECT 52` with a 4 MiB echo read back by length; guest to host through `<uds>_53` |
| `net` | virtio-net over the Windows endpoint (a Unix stream, each frame preceded by its 32-bit big-endian length): a switch in the script answers ARP, ICMP echo (1400 bytes, 200 back to back) and UDP echo, and checks the checksum of every frame the guest sends; tx and rx bandwidth limiters set with `PATCH` hold each direction to 1 MiB/s, and without them it runs at three times that or more |
| `snapshot` | a full snapshot of a 2 vCPU guest with a data drive and vsock, restored in a new Firecracker process: shell state, the clock on both vCPUs, both drives, vsock |
| `diff` | a diff snapshot with dirty page tracking (its file keeps its holes), merged into the full one by `snapshot-editor edit-memory rebase` and restored |
| `uffd` | the `snapshot` stage's snapshot restored with the Uffd memory backend, its pages served by upstream's `uffd_on_demand_handler` in another process |
| `api-process` | the API server's HTTP side runs in a process of its own with the whole mitigation profile (this shell under none), serves the API; killing it ends Firecracker, and Firecracker's end ends it |
| `pci` | the `snapshot` stage over virtio-pci with MSI-X (`--enable-pci`) |
| `vhost-user` | a vhost-user-blk drive served by `vhost-user-blk.exe` in another process: the guest reads its content, a guest write reaches the image |
| `hugepages` | guest memory on 2 MiB large pages (`huge_pages: "2M"`): boots and keeps 160 MiB written to it. Needs "Lock pages in memory" for the account (`secpol.msc`, Local Policies, User Rights Assignment; sign out and in), as hugetlbfs on Linux needs huge pages reserved |

| `cli` | exit codes 153 (bad arguments), 152 (bad `--level`), 1 (bad configuration file), without a guest; `--module`; the start time metrics of `--start-time-us`, `--start-time-cpu-us`, `--parent-cpu-time-us`; the log and the metrics on named pipes (the counterpart of a FIFO), with a pipe nobody reads and one whose reader leaves; `--boot-timer` with upstream's `/usr/local/bin/init` |
| `tools` | `rebase-snap` and `snapshot-editor edit-memory rebase` on a sparse and a dense synthetic diff file (the dense one refused, the base untouched), without a guest; then a diff snapshot (written as a sparse file) rebased by both alike and restored; `snapshot-editor info-vmstate` `version`, `vcpu-states`, `vm-state`; the state file with the aarch64 magic or a newer version refused at the load |
| `no-seccomp` | without `--no-seccomp` the setup-phase mitigations are in force in Firecracker and the whole profile in its API process; with it none in either. No guest |
| `foreign-snapshot` | a state file made on another host, given as `-ForeignState <file>` (the macOS boot test's snapshot stage makes an aarch64 one), is refused at the load and Firecracker ends. No guest |
| `memory-hotplug` | virtio-mem: 512 MiB plugged into a 512 MiB guest, seen in `MemTotal`, 600 MiB written and read back, then unplugged |
| `gdb` | not in `all`: Firecracker built with the gdb feature (`-GdbFirecracker`) and gdb (`-Gdb`, or MSYS2's `gdb-multiarch`) on upstream's debug kernel: a hardware breakpoint at `start_kernel`, the kernel's bytes read through the stub as in the vmlinux, a software breakpoint at `rest_init`, the guest boots on. gdb reaches the gdb socket by its path, or through a TCP relay of the stage's own |

`uffd` needs the `snapshot` stage's files: run it after `snapshot` (as `all` does).

The results folder holds, per stage, the VM config, the serial console, the
Firecracker log at debug level and the guest kernel log, plus `host.txt`
(Windows build, CPU, WHP state) and `summary.txt`.

Not implemented on Windows yet, listed as `N/A` in the summary and not run:
the jailer (docs/ROADMAP.md).

If WHP is not usable, every stage fails with the reason the script found
before starting, for example "the Windows hypervisor is not running".
