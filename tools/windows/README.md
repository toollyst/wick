# Windows test kit

- `boot-test.ps1`: scenario tests of the Windows build against upstream
  Firecracker's x86_64 CI guest, the counterpart of `tools/macos/boot-test.py`.
- `winprobe.c` (`winprobe.exe` in CI's artifact): measures the host
  mechanisms the sandbox and jailer backends use.

CI builds both on every push and uploads them as the artifact
`wick-windows-x86_64-<commit>`: `lib/firecracker/build/cargo_target/release/firecracker.exe`,
`winprobe.exe`, `tools/windows/boot-test.ps1` and this file, at those paths.

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

   About five minutes; the first run downloads 145 MB (kernel and rootfs).
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

The results folder holds, per stage, the VM config, the serial console, the
Firecracker log at debug level and the guest kernel log, plus `host.txt`
(Windows build, CPU, WHP state) and `summary.txt`.

Not implemented on Windows yet, listed as `N/A` in the summary and not run:
snapshots (full, diff, Uffd), PCI, vhost-user, huge pages and the jailer
(docs/ROADMAP.md).

If WHP is not usable, every stage fails with the reason the script found
before starting, for example "the Windows hypervisor is not running".
