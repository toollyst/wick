# Windows test kit

- `boot-test.ps1`: scenario tests of the Windows build against upstream
  Firecracker's x86_64 CI guest, the counterpart of `tools/macos/boot-test.py`.
- `winprobe.c` (`winprobe.exe` in CI's artifact): measures the host
  mechanisms the sandbox and jailer backends use.
- `jailer-test.ps1`: the jailer on WHP hardware, the counterpart of
  `tools/macos/jailer-test.py`. Stages: `refuse` (what Windows cannot
  enforce is refused), `isolation` (`jail-probe.rs`, run through the jailer
  as the jailed binary, may not read the user's files or SAM, write outside
  its jail, reach another jail's files, API socket or process, or open the
  operator's; the operator reaches the API socket), `boot` (a 2 vCPU guest
  in the jail), `limits` (`memory.max`), `cpu` (`cpu.max` refused), and a check
  that every jail's drive letter was removed. It needs the boot test's
  guest files (`-Assets`, default `C:\wbt`) and `rustc` for the probe:

  ```
  powershell -ExecutionPolicy Bypass -File tools\windows\jailer-test.ps1 -WorkDir C:\wjt
  ```

  The jailer refuses CPU limits for now: under the job's CPU rate hard cap a
  jailed WHP guest can stop taking interrupts (docs/ROADMAP.md, M5).
  `-CpuCap` makes the `cpu` stage measure the cap through the jailer's
  opt-in, `--cgroup wick.cpu_cap=unsafe`; it fails in about 1 run in 3.

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
| `boot` | 1 vCPU: kernel reaches init, serial output and input (stdin is a pipe), `x86_64`, 1 CPU, memory size, CPUID hypervisor bit, the guest clock advances with the host's |
| `smp` | 2 vCPUs: the AP starts (INIT/SIPI), work runs on each CPU, the clock agrees between them |
| `block` | an Async read-only drive (md5 of 8 MiB), a Sync and an Async writable drive (the host file holds what the guest wrote), a write to a read-only drive fails |
| `vsock` | host to guest `CONNECT 52` with a 4 MiB echo read back by length; guest to host through `<uds>_53` |
| `net` | virtio-net over the Windows endpoint (a Unix stream, each frame preceded by its 32-bit big-endian length): a switch in the script answers ARP, ICMP echo (1400 bytes, 200 back to back) and UDP echo, and checks the checksum of every frame the guest sends |
| `snapshot` | a full snapshot of a 2 vCPU guest with a data drive and vsock, restored in a new Firecracker process: shell state, the clock on both vCPUs, both drives, vsock |
| `diff` | a diff snapshot with dirty page tracking (its file keeps its holes), merged into the full one by `snapshot-editor edit-memory rebase` and restored |
| `uffd` | the `snapshot` stage's snapshot restored with the Uffd memory backend, its pages served by upstream's `uffd_on_demand_handler` in another process |
| `pci` | the `snapshot` stage over virtio-pci with MSI-X (`--enable-pci`) |
| `vhost-user` | a vhost-user-blk drive served by `vhost-user-blk.exe` in another process: the guest reads its content, a guest write reaches the image |
| `hugepages` | guest memory on 2 MiB large pages (`huge_pages: "2M"`): boots and keeps 160 MiB written to it. Needs "Lock pages in memory" for the account (`secpol.msc`, Local Policies, User Rights Assignment; sign out and in), as hugetlbfs on Linux needs huge pages reserved |

`uffd` needs the `snapshot` stage's files: run it after `snapshot` (as `all` does).

The results folder holds, per stage, the VM config, the serial console, the
Firecracker log at debug level and the guest kernel log, plus `host.txt`
(Windows build, CPU, WHP state) and `summary.txt`.

Not implemented on Windows yet, listed as `N/A` in the summary and not run:
the jailer (docs/ROADMAP.md).

If WHP is not usable, every stage fails with the reason the script found
before starting, for example "the Windows hypervisor is not running".
