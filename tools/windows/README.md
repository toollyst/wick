# Windows test kit

- `boot-test.ps1`: scenario tests of the Windows build against upstream
  Firecracker's x86_64 CI guest, the counterpart of `tools/macos/boot-test.py`.
- `winprobe.c` (`winprobe.exe` in CI's artifact): measures the host
  mechanisms the sandbox and jailer backends use.
- `jailer-test.ps1`: the jailer on WHP hardware, the counterpart of
  `tools/macos/jailer-test.py`. Stages without a guest: `refuse` (what
  Windows cannot enforce is refused, each cgroup controller and resource
  limit with its reason), `parent` (`--parent-cgroup`: a parent made
  and limited with `jail-parent.exe` bounds two jails' memory together, a
  level under it holds a jail to the least limit along the path, a
  jail's processors under it are Linux's by cgroup version, a jailer keeps
  its jail's parent when the tool has ended, and a jailed process does not
  reach the namespace the parents' jobs are named in), `freeze` (upstream's freezer files next to the
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
  needs a console: run with other stages, the script runs it alone in a
  console of its own, `<WorkDir>-pidns`, as CI's step does), `handoff` (a handle and a socket held by a jailed process
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
  saying so; it has failed at that check, no `System32\bindlink.dll`, on
  each host it ran on, though Microsoft gives the Bindlink API as available
  from build 25314: Windows 11 build 26300 (a PC, elevated and not) and
  Windows Server 2025 build 26100 (CI run 43428124115); the rest has not
  run), `limits`
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

  The work directory must be short: a jail's API socket is reached at
  `<WorkDir>\<stage>\firecracker.exe\<id>\root\run\firecracker.socket`, and an
  AF_UNIX path holds 107 bytes. A WorkDir that leaves no room for it is
  refused before any stage, naming the path and the limit (the boot
  test's socket directory is checked the same way, against the longest
  socket name the script uses, read from the script itself: a VM's API
  socket is numbered, `<n>.api`, and every other socket name is a
  constant, which `-SelfTest`'s `socknames` case holds it to).

- `jail-parent.rs` (`jail-parent.exe` in CI's artifact): the operator's tool
  for a parent cgroup, what `mkdir` and `echo` into the parent's directory
  are on Linux. The jailer's `--parent-cgroup <name>` is the Job Object
  `wick-cgroup\<name>`, in a private namespace of the account's that a
  jailed process can neither make nor open; the tool makes it, writes the limits named
  (`memory.max`, `cpu.max`, `cpuset.cpus`, or their cgroup v1 names with
  `--cgroup-version 1`) and holds it until its standard input ends, or for
  ever with `--forever`. Each jailer holds its jail's parent too, so a
  parent lasts while the tool or a jail of it runs. `--name a/b` is a level
  under `a`, a job under `a`'s: the tool makes the levels that are missing
  and writes the limits to the last, against the levels above by Linux's
  rule for the cgroup version. Run again, it writes the level that is
  there, and with its CPU cap or processors every job below it, levels and
  jails, as Linux works the hierarchy out again at every write. Run it as
  the account the jailers run as:

  ```
  tools\windows\jail-parent.exe --name tenants --cgroup memory.max=4294967296 --cgroup cpuset.cpus=0-3 --forever
  jailer.exe --id a --exec-file firecracker.exe --uid 0 --gid 0 --parent-cgroup tenants --cgroup memory.max=1073741824 ...
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
  kit), so that the calls that reached deep are named. VMMGUEST lines give
  the guest's memory after the shell and after a guest's tmpfs work: what is
  committed and resident, and the first accesses it takes at today's 4 KiB
  commit grain against what the 64 KiB grain before or a 2 MiB grain take
  (the 64 KiB blocks, 4 KiB pages and 2 MiB ranges it is in); Linux's for the same guest
  and work are `tools/linux/guest-ram-record.py`'s:

  ```
  python -I tools\windows\vmm-memory-record.py --boot C:\wbt lib\firecracker\build\cargo_target\release\firecracker.exe 1 2 16
  ```

  The release build's `firecracker.pdb` names the standard library's
  functions and none of Firecracker's own (CI run 43377614564: its frames
  came out as the nearest of std's). `--map <file>`, before the other
  arguments, names them from the linker's map of the same build, which CI
  makes for its own record:

  ```
  cargo rustc --locked -p firecracker --release --bin firecracker -- -C link-arg=-MAP:C:\wbt\firecracker.map
  python -I tools\windows\vmm-memory-record.py --map C:\wbt\firecracker.map --boot C:\wbt lib\firecracker\build\cargo_target\release\firecracker.exe 1 2 16
  ```

  After the cases, VMMGROW lines name the allocations the growth per vCPU
  is in: each group of allocations (kind, size, and a mark: a heap's later
  segment, the allocation that holds the threads' TEBs) whose number or
  resident memory differs between the fewest and the most vCPUs.
  firecracker.exe's own pages are in neither that nor the "each vCPU adds"
  line: which of them a process has resident is how it paged the file in
  (11616 and 5632 KiB in two cases of one PC run at 9af0b63), so a line of
  their own gives each case's.

  With `--snapshot <dir>` it prints VMMSNAP lines instead: a 1 GiB guest
  with dirty page tracking touches 64 MiB, is paused for a full snapshot,
  resumed to touch 128 pages more and paused for a diff snapshot, and a new
  Firecracker loads the full snapshot with the File backend. After each
  step: the guest memory committed and resident, the process's private
  bytes (what a Job Object's memory limit counts), and for a snapshot how
  long it took and its file's size and allocated bytes. Linux's for the same
  guest and steps are `tools/linux/guest-ram-record.py --snapshot`'s
  (GUESTSNAP lines). CI's windows and linux-boot jobs run both:

  ```
  python -I tools\windows\vmm-memory-record.py --snapshot C:\wbt lib\firecracker\build\cargo_target\release\firecracker.exe
  ```

CI builds the binaries on every push and uploads them as the artifact
`wick-windows-x86_64-<commit>`: `lib/firecracker/build/cargo_target/release/firecracker.exe`,
`firecracker.pdb` (its symbols, for `vmm-memory-record.py --boot`),
`snapshot-editor.exe`, `jailer.exe`, `rebase-snap.exe` and
`examples/uffd_on_demand_handler.exe` next to it,
`lib/firecracker/build/cargo_target/debug/firecracker.exe` (built with the gdb
feature, for the `gdb` stage),
`lib/firecracker/build/vhost-user-blk/release/vhost-user-blk.exe` (the
vhost-user test backend; to build it on a PC, in `tools\vhost-user-blk`:
`$env:CARGO_TARGET_DIR = (Resolve-Path ..\..).Path + '\lib\firecracker\build\vhost-user-blk'; cargo build --release --locked`,
the target directory absolute: a relative one stays in every path cargo
gives the linker as `..\..`, which took link.exe past 260 characters on a
PC, LNK1104), `winprobe.exe`, and in `tools/windows/`
`boot-test.ps1`, `jailer-test.ps1` with `jail-probe.exe` and `jail-parent.exe` built,
`job-freeze-probe.ps1`, `memory-partition-probe.exe`, `vmm-memory-record.py` and this file, with
`tools/guest-health.txt` (the guest's health patterns `boot-test.ps1` reads) and
`tools/guest-counter-warp.py` (the guest's TSC check it sends), at those
paths. The kit needs no Rust.

## Checking the scripts before Windows

`python3 -I tools/windows/check-ps.py` (macOS or Linux, with Mono's `mcs` on `PATH`) compiles the
C# of every `Add-Type` in the repository's `.ps1` files as Windows PowerShell 5.1 compiles it: C# 5,
`System.dll` and the `-ReferencedAssemblies` given, a `-MemberDefinition` wrapped as PowerShell
wraps it. Each Add-Type alone, and all of a script's together, so a type defined twice across them
fails as `Add-Type` would ("already contains a definition"); a compile error names the `.ps1` line.
It also refuses a function defined twice in one scope (PowerShell keeps the later without a word)
and a script with a byte outside ASCII and no UTF-8 byte order mark (Windows PowerShell 5.1 reads
it in the ANSI code page). It cannot check the PowerShell itself (no PowerShell parser: syntax, a
command's or parameter's name), whether a P/Invoke's DLL and entry point exist (Mono compiles a
`DllImport` it never loads), or .NET Framework APIs Mono lacks; those still show only on Windows,
in CI's `windows` job (`boot-test.ps1 -SelfTest`) and `windows-guest`. `--selftest` tests its
checks.

## What CI runs of the two scripts

GitHub's Windows runner has WHP and boots Linux (first seen in CI run
43377614564), so the `windows-guest` job of `ci` runs the scripts there on
every push, from the kit the `windows` job uploaded, in Windows PowerShell
5.1 as on a PC:

- `boot-test.ps1`: `-Stage all,diff-nospace -Except hugepages`, the stages
  of a PC's default run and `diff-nospace`; `hugepages`, `gdb` and
  `linux-snapshot` in steps of their own. `linux-snapshot` is given the
  snapshot the `linux-boot` job of the same run made (artifact
  `linux-snapshot`). `hugepages` needs "Lock pages in memory" in a logon made after the
  right was given: the job gives it to the runner's account and runs the
  stage (and `jailer-test.ps1 hugepages`) in a scheduled task as that
  account. `gdb` installs MSYS2's `gdb-multiarch` (one package, pinned by
  file and checksum) and uses the kit's gdb build.
- `jailer-test.ps1`: every stage; `pidns` in a console of its own (it types
  into its console, and a step has none), `bindlink` in a step of its own:
  on an image without `bindlink.dll` the step passes only when the stage
  failed at that check alone and left no drive, and says so in a notice;
  with the DLL the stage's result is the step's. `sections` too, as a known
  gap: `memory.max` does not bound memory in sections (docs/COMPATIBILITY.md,
  the `memory.max` row, not done yet), so the stage fails, and its step
  passes only on that exact failure (the private-memory control held, both
  kinds of section took all 256 MiB, no drive left), saying so in a notice;
  any other result fails it, the gap closing included. The job's summary
  lists both such steps, so that a green job does not read as every stage
  passing.

A failed stage fails the job, the stages after it still run, and the logs
are the artifact `windows-guest-logs`. A stage's result on the runner is a
result on Windows Server, elevated. What only a PC shows, and is run there:

- the jailer started unelevated (the runner's token is elevated);
- Windows 11, and Windows 10;
- a serial console someone types at, on conhost and on Windows Terminal;
- `boot-test.ps1 foreign-snapshot`: it needs a state file of another
  architecture (the macOS boot test's), which no CI job makes.

Whether a stage has passed on the runner is in docs/COMPATIBILITY.md with
the run, once one has; until then its claims are the PC's.

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
   `-Stage boot,net` runs some stages and `-Except` leaves some out; the
   default, `all`, is every stage that needs no input or setting (not
   `diff-nospace`, `linux-snapshot`, `foreign-snapshot`, `gdb`, each named
   below with what it needs); `-SelfTest` checks the script itself
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
must have no line with a pattern of `tools/guest-health.txt` (its `all` and `x86_64` lines, read by
the rules the Linux and macOS boot tests read it with; a malformed line stops the run, naming
it): RCU stalls, soft lockups, hung tasks, BUGs, oopses, `WARN()` reports (`WARNING: CPU:`),
stack dumps (`Call Trace:`), and the x86 reports only a VMM's fault makes (an MSR access refused,
an NMI of no source, TSCs apart, an interrupt nothing asked for, an AP that did not start), and
the reset must end Firecracker with exit status 0. A kernel notice that only uses the word (`WARNING: See ...` of SRSO on an
AMD host) is not a warning of the guest's health. A stage's PASS line is the one summary it
returns; a stage that leaves any other value unread fails as a script error naming it
(`-SelfTest`'s `summary` case). Each step a stage prints has the time since the stage began
(`- [12.3 s] ...`), so a slow run says which step took the time.

A guest that does not reach init, in a VM with an API socket, is paused and snapshotted twice a
second apart before the stage fails, and the failure adds what the two states hold (kept as
`stuck-<n>-vm-state.txt`, snapshot-editor's `info-vmstate vm-state`): how far the VM clock and
the guest TSC moved, and for each vCPU its RIP and whether it moved, RFLAGS.IF, `mp_state`, its
local APIC timer (LVT, initial and current count, divide) and the highest vector pending (IRR) and
in service (ISR). That tells a stopped clock from a lost interrupt or an AP that never started
(every stage on CI's AMD EPYC 9V45 runner stopped so, run 43435331370). The host line
(`host.txt`, and the run's first lines) names WHP's processor vendor, features, XSAVE features
and processor and interrupt clock frequencies.

| Stage | Checks |
|---|---|
| `boot` | 1 vCPU: kernel reaches init, serial output and input (stdin is a pipe), `x86_64`, 1 CPU, memory size, CPUID hypervisor bit, the local timer in TSC-deadline mode (`lapic-deadline`), the guest clock advances with the host's (PASS on a PC at 9af0b63 and at 861d365 (AMD Ryzen 9 7900, Windows 11 Pro build 26300.9711): 36.6 s each; the guest reports "Speculative Return Stack Overflow: Mitigation: safe RET" and no `WARNING: CPU:` line) |
| `smp` | 2 vCPUs: the AP starts (INIT/SIPI), both local timers in TSC-deadline mode, work runs on each CPU, the clock agrees between them; the two vCPUs' TSCs against each other in the guest, by the kernel's warp check's algorithm (`tools/guest-counter-warp.py`; not yet run on Windows), after boot and after the restore, before CPU 1 goes offline (whose own kernel check found the restored TSCs apart up to kit c2042da); CPU 1 taken offline and online three times (the guest's INIT/SIPI again), then work on it, after boot and after a snapshot restore (kit 8d577b7, and 5 of 5 runs on kit dd657f4, Windows 11 10.0.26300.9711: 0 spurious LAPIC timer interrupts in each) |
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
| `foreign-snapshot` | not in `all`: a state file made on another host, given as `-ForeignState <file>` (the macOS boot test's snapshot stage makes an aarch64 one), is refused at the load and Firecracker ends. No guest |
| `cpu-templates` | a custom CPU template through `PUT /cpu-config` that clears MOVBE, BMI1 and ABM: the guest's `/proc/cpuinfo` loses exactly `movbe`, `bmi1` and `abm` on both vCPUs, also after a snapshot's restore and cpu1 taken offline and online (its spurious LAPIC timer interrupts counted, as in `smp`); the vCPUs' TSCs against each other after the boot and the restore, as in `smp`; a template that changes a CPUID leaf no host has is refused at the start with upstream's error; a template with a modifier of MSR 0x10a (as T2S and T2CL have) is refused at the start, naming the MSR. PASS on a PC at 9af0b63 (8.3 s) and at 861d365 (8.7 s) (AMD Ryzen 9 7900, Windows 11 Pro build 26300.9711); not yet in a CI run |
| `diff-nospace` | not in `all`: needs an elevated prompt. Upstream's `test_diff_snapshot_works_after_error` on a 512 MiB virtual disk (made, attached, formatted NTFS and mounted on a directory with `diskpart`) in place of its 512 MiB tmpfs: with 90% of the volume filled, a diff snapshot of a guest that wrote 100 MiB fails with Windows's error for a full volume (`os error 112`, where Linux says "No space left on device") and Firecracker stays; with the fill removed the next diff snapshot succeeds and restores, the 100 MiB as written. Passed in CI run 43442912128 (861d365; Windows Server 2025 on an AMD EPYC 7763, elevated): the snapshot with 49 MiB free failed with `os error 112`, the next (149 MiB) restored |
| `linux-snapshot` | not in `all`: a whole snapshot made on Linux x86_64 with KVM by the same Firecracker version, given as `-LinuxSnapshot <dir>` (the directory `tools/linux/make-vmstate.py` keeps as its fourth argument; CI's artifact `linux-snapshot`), is loaded and resumed on this test's copy of the same root drive (checked by SHA-256). A record, since upstream supports a snapshot only on the kind of host that made it: the result line says RESTORED (the shell answers, the clock runs, the drive is read, a reset exits 0) or REFUSED with Firecracker's error; a guest that resumed and does not go on fails the stage. Run in CI run 43442912128 (861d365, AMD EPYC 7763): REFUSED at the first vCPU's special registers (docs/COMPATIBILITY.md, A snapshot restored on another host OS) |
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
- for `test_high_ingress_traffic`, an `iperf3.exe` on `PATH` (the test sends
  its traffic with the host's iperf3; without one the test fails saying so);
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
