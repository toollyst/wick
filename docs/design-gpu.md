# GPU access (headless Vulkan): design

**Status: design and plan only. There is no code yet.** Nothing here describes what wick does today: today
`PUT /extensions/gpu` is refused as an unknown extension (`crates/ext/src/lib.rs`, `test_unknown_extension_is_rejected`).
The roadmap milestone is [M9](ROADMAP.md#m9-gpu-headless-vulkan). Every "is", "does" and "returns" below about the
GPU device, `wick-gpu` or the render workers describes the design, not shipped behaviour.

Research of 2026-11-13. Hosts covered: Linux (KVM), macOS on Apple silicon
(Hypervisor.framework, aarch64 guests) and Windows (WHP, x86_64 guests). Folder sharing (virtio-fs) is out of scope.

Each claim carries a tag. **[S]** means read in source code or in a shipped profile. **[D]** means the vendor or
project documents it. **[I]** means it is inferred from the cited material. **[M]** means wick has to measure it on
the host before a doc may claim it. The URLs behind the macOS and Windows notes are listed in §10 (Appendix sources).

**Windows:** wick has measured none of the GPU behaviour below on Windows. Every Windows statement tagged [D] or [I]
is from documentation or source reading only, and is to be measured on a Windows PC with WHP before any doc claims
it. The few Windows sandbox facts wick did measure name the probe, its host and its date.

**Host differences to decide.** The project's rule is the same security on all three hosts. Two Windows items
below (R4: no win32k lockdown for the GPU worker; R10: the host-wide TDR bug-check) do not meet it. They are written
as open decisions with their consequences, not as accepted differences (§2a).

## 1. Recommendation

**Give every guest the same device on all three hosts:** a **virtio-gpu PCI device with the Venus (Vulkan) context
type only**, blob resources, and one host-visible shared-memory window. No 2D scanout, no virgl GL, no gfxstream, no
DRM native context. The target use is headless compute and offscreen rendering, for example llama.cpp's Vulkan
backend, as krunkit and RamaLama already run it on macOS
([Red Hat 2025](https://developers.redhat.com/articles/2025/06/05/how-we-improved-ai-inference-macos-podman-containers) [D]).

**Process layout.** The VMM never opens the GPU, and its sandbox is unchanged, which is the property the design rests on.

- The VMM (Firecracker, jailed as today) runs only a **vhost-user-gpu front-end** in `wick-ext`
  (`PUT /extensions/gpu`). It maps the window. It never reads or writes window memory and never parses a GPU command.
- **`wick-gpu`** is the device back-end: a separate binary behind its own cargo feature, which can be built from
  rust-vmm `vhost-device-gpu` ([README](https://github.com/rust-vmm/vhost-device/tree/main/vhost-device-gpu) [S]). It
  parses the virtio-gpu queues and maps guest RAM, as every vhost-user back-end does. It has **no GPU access**.
- **Render workers** are virglrenderer's render server with **one worker process per guest context**
  (`server/render_worker.c`, `render-server-worker` option [S]). They hold the Vulkan or Metal driver. They see **no
  guest RAM**, only their context's shared-memory rings and the blob pool.
  - Each host gets the tightest sandbox it allows a process that talks to a GPU driver (§3).
  - The same layout is crosvm's sandboxed GPU (gpu device jail plus `virgl_render_server` jail;
    `src/crosvm/sys/linux/gpu.rs` `create_gpu_device`, `start_gpu_render_server` [S]). crun does the same for krun:
    it starts the render server under bubblewrap and passes its fd to libkrun
    ([crun b4612da](https://github.com/containers/crun/commit/b4612da50c7ed7d6d28d277e532316dbcbe1c1cc) [D]).

**Can it meet the Firecracker-equal bar?**

- The VMM keeps Firecracker's isolation exactly. The new processes are sandboxed at least as well as Chrome's and
  crosvm's GPU processes.
- But a GPU-enabled microVM always has **more host attack surface** than one without a GPU. A guest can reach a
  command decoder and, through it, the host GPU kernel driver: DRM on Linux, AGX/IOGPUFamily on macOS, dxgkrnl plus
  the vendor driver and **all of win32k** on Windows. All of these have a steady CVE stream (§4).
- Upstream itself says: "We can only run 1 customer workload securely per physical GPU"
  ([#849, acatangiu 2019](https://github.com/firecracker-microvm/firecracker/issues/849) [D]).
- So the honest bar is:
  - VMM isolation is unchanged and default off. The device is unreachable when off and absent when compiled out.
  - The extra surface is sandboxed, bounded, tested and written in SECURITY.md.
  - **GPU-enabled VMs are one tenant per GPU.** Cross-VM GPU side channels (LeftoverLocals on Apple M2 (M1 not stated by the advisory; M3 fixed), AMD, Qualcomm;
    GPU.zip) cannot be closed by wick.
- This is not a "dev-only" mode, but it is a different and documented trust statement. On Linux and macOS it holds
  as stated; on Windows two items fall short of it (R4, R10) and are open decisions (§2a).

**Passthrough (VFIO, DDA, WHP VPCI) is refused on every host for now.** Upstream has no VFIO in a release: tracking
issue [#5679](https://github.com/firecracker-microvm/firecracker/issues/5679) is open (its page, 2026-11-13). The work
goes on in upstream's `feature/vfio` branch: PR [#5870](https://github.com/firecracker-microvm/firecracker/pull/5870)
was closed in favour of [#6055](https://github.com/firecracker-microvm/firecracker/pull/6055), itself closed unmerged
on 2026-10-21 with follow-ups #6085 and #6114 (the PR pages, 2026-11-13) [D]. macOS has no device assignment at all.
When upstream lands VFIO, Linux would gain passthrough that macOS cannot have: a parity question to decide then (§6).

**Work this needs.** The work items below are not started. They are listed so that nothing is hidden.

1. An upstream-transport patch. The PCI transport needs a second 64-bit BAR and the `SharedMemory` capability.
   Upstream has the enum, marked `#[allow(dead_code)] // ... not used by us`
   (`transport/pci/device.rs` `PciCapabilityType` [S]).
2. The vhost-user back-end request channel (`VHOST_USER_BACKEND_SHMEM_MAP`/`UNMAP`, `GET_SHMEM_CONFIG`) in the
   front-end. The vhost 0.17 crate has the messages (`vhost_user/message.rs`), but upstream Firecracker sets no
   back-end request fd (`grep BACKEND_REQ` in `src/vmm` finds nothing) [S].
3. A small virglrenderer change: allocate guest-mappable memory from a fixed pool (§3.0).
4. A Windows port of virglrenderer's Venus renderer and render server. It is POSIX-only today
   ([virglrenderer#475](https://gitlab.freedesktop.org/virgl/virglrenderer/-/issues/475) [D]).
5. A guest kernel with `CONFIG_DRM_VIRTIO_GPU`. Every upstream CI guest config has `# CONFIG_DRM is not set`
   (`resources/guest_configs/microvm-kernel-ci-*.config` [S]).

## 1a. Staged plan: ship without the validator, disclose it, add it in stages

Without a validator, a guest's Vulkan calls and shaders reach the host GPU driver (user-mode driver in the worker,
kernel driver and firmware below it). So a single driver bug can be enough to take the host. A validation layer
between guest and driver (Chrome's Dawn/Tint does this for WebGPU) would cut that down and close the
LeftoverLocals-type leaks. It does not close timing/contention side channels. The validator is not in v1.

Why: the validator is the largest piece of work, and the VMM's isolation does not depend on it. Rejected: holding
GPU back until a validator exists (no use case is served meanwhile, and the risk can be stated precisely); shipping
without stating the risk (the project rule is to fail loudly, never silently).

**v1 must already have**, none of it deferrable:
- the worker sandbox per host;
- one worker per context;
- GL/vrend not compiled in;
- the fixed memory pool;
- snapshot and passthrough refused;
- the `gpu` cargo feature off by default.

Also from v1:
- **A validator slot.** The worker pipeline is decode → validate → driver from day one. In v1 the validate stage
  passes calls through, and it is named and tested as such. Adding a stage later is then not a redesign.
- **Disclosure, not silence:**
  - SECURITY.md gets a row: "GPU: guest Vulkan reaches the host driver unvalidated; one GPU per trust domain."
  - README's FAQ and the extension's API error text say the same.
  - Each later stage changes that row in the same commit (docs-in-step rule).

| Stage | Adds | Closes |
| --- | --- | --- |
| v1 | sandbox + validator slot (pass-through) | VMM unchanged; worker compromise contained to one sandboxed process |
| v2 | resource limits in the slot (allocation sizes, dispatch counts, queue depth, per-VM hang budget) | most DoS; Windows TDR aggregate still open |
| v3 | shader rewrite: zero workgroup/local memory at shader start and end | LeftoverLocals in both directions (except a shader killed mid-run) |
| v4 | validated compute-only Vulkan subset (option C), or WebGPU via Dawn as the guest API (option B), chosen by a research pass | malformed calls no longer reach the driver; driver exposure ≈ a browser's WebGPU |
| never | timing/contention side channels | stays "one GPU per trust domain" |

## 2. Risks and how wick solves each

Status values:

- **now**: solvable with known mechanisms.
- **measure:<host>**: solvable, but the mechanism has to be measured on that host first.
- **no:<host>**: cannot be solved there. The row says what wick does instead.

### 2.1 Reachability and compile-out

**R1. Feature present when not wanted.** Project rule, `docs/ARCHITECTURE.md` item 5.
- **All hosts:**
  - Cargo feature `gpu` (off by default) gates the `wick-ext` front-end and the `wick-gpu` binary.
  - Without it, `PUT /extensions/gpu` gets `unknown extension` (`crates/ext` `unknown()` [S]).
  - With it but not configured, no device, BAR, process or socket exists.
- **Planned test:** `test_unknown_extension_is_rejected` with `gpu`; a symbol check that no `vhost_user_gpu`/`virgl` symbol
  is in a default build; `boot-test gpu-off` shows no `1af4:1050` PCI device in the guest.
- **Status:** now.

### 2.2 Command decoders

**R2. Renderer command-decoder memory corruption.**
- History: 20 NVD CVEs for virglrenderer, most in the GL path (vrend). Examples: CVE-2019-18389 heap overflow in
  `vrend_renderer_transfer_write_iov`, "guest-to-host escape"; CVE-2022-0135 OOB write. And CVE-2025-2509, an OOB
  read in vertex-elements handling that gives "arbitrary address access within the crosvm sandboxed process"
  ([NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=virglrenderer) [D]).
- **All hosts:**
  - (a) Only the Venus capset is offered: `VIRGLRENDERER_VENUS | VIRGLRENDERER_NO_VIRGL`, as krunkit does
    (`src/context.rs` [S]). The vrend GL decoder, home of nearly every CVE, is not compiled in.
  - (b) One worker process per context, so one context's compromise is one sandboxed process.
  - (c) Hardened build: `-D_FORTIFY_SOURCE=3`, stack protector, and CFI/CFG where the toolchain has it.
  - (d) Fuzzing (§8).
  - (e) A worker that crashes is not restarted. The device fails closed (R15).
- **Planned test:** fuzz targets for the virtio-gpu control queue (in `wick-gpu`) and the Venus decoder; a sandbox stage
  that shows a compromised worker (a test hook that runs code in it) cannot reach files, network, other processes or
  guest RAM (§8).
- **Status:** now (Linux, macOS); measure:Windows (the port).

**R3. Host GPU driver undefined behaviour from invalid Vulkan usage.**
- Venus forwards guest Vulkan calls. Validation is off by default (`vkr_common.c`: `VKR_DEBUG_VALIDATE` "Force
  enabling the validation layer" [S]). Mesa's docs say the renderer "violates the spec and relies on
  implementation-defined behaviors" ([Mesa Venus](https://docs.mesa3d.org/drivers/venus.html) [D]).
- **All hosts:** treat every worker as compromisable by design. The worker sandbox (§3) is the boundary, not the
  decoder. The Vulkan validation layer is not a security control (too slow, and it is not fatal).
- **Planned test:** the same compromised-worker sandbox stage.
- **Status:** now. Residual risk stated in §7.

### 2.3 Host GPU kernel driver

**R4. Host GPU kernel driver reachable from the worker.** Linux DRM ioctls; macOS AGX/IOGPUFamily
(CVE-2025-24257 "write kernel memory", CVE-2026-28923 "break out of its sandbox"); Windows dxgkrnl (CVE-2025-29812,
CVE-2026-50353) and vendor escapes (NVIDIA CVE-2021-1051 `DxgkDdiEscape`) [D]. Sources:
[Apple, macOS Sequoia 15.4](https://support.apple.com/en-us/122373) (CVE-2025-24257),
[Apple, macOS Tahoe 26.5](https://support.apple.com/en-us/127115) (CVE-2026-28923),
[CVE-2025-29812](https://cveawg.mitre.org/api/cve/CVE-2025-29812),
[CVE-2026-50353](https://cveawg.mitre.org/api/cve/CVE-2026-50353),
[CVE-2021-1051](https://cveawg.mitre.org/api/cve/CVE-2021-1051).
- **Linux:**
  - Only a render node `/dev/dri/renderD*` is bind-mounted; no card node, so no KMS or master
    (crosvm `jail_mount_bind_drm(render_node_only)` [S]).
  - seccomp allows only DRM ioctls of the bound driver: core render ioctls plus the driver's `DRM_COMMAND_BASE`
    range, checked by number. crosvm's `gpu_common.policy` allows `arg1 & 0x6400`, which is broader [S]; wick narrows it.
- **macOS:**
  - Seatbelt allows `iokit-open` of `IOGPUDeviceUserClient` and `IOSurfaceRootUserClient` only. These are the classes
    in Apple's own `com.apple.gpusw.ParavirtualizedGraphicsGPUTask.sb` [S].
  - An **enforcing** `apply-message-filter` with the IOAccelerator/AGX selector list. WebKit's GPU process has the
    list but runs it in allow-with-report mode (`com.apple.WebKit.GPUProcess.sb.in` [S]). wick would enforce it.
- **Windows:**
  - Restricted token (USER_LIMITED, as Chrome's GPU process), Low integrity, Job, strict handle checks, no child
    processes. These work with Firecracker's own run-time needs (a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10, run for Firecracker's own process and not for a GPU worker; the probe is not in the repository); whether a GPU driver runs under them is
    unknown [M].
  - **win32k cannot be disabled.** The D3DKMT thunks are win32k system calls (`NtGdiDdDDI*` in the win32k table;
    Firefox bug [1718414](https://bugzilla.mozilla.org/show_bug.cgi?id=1718414) [D/I]). No browser ships a
    win32k-locked GPU process (Chromium `sandbox_win.cc`: `AddWin32kLockdownPolicy` only for renderers [S]).
- **Planned test:**
  - Linux: a seccomp stage where a non-listed DRM ioctl raises SIGSYS.
  - macOS: a Seatbelt stage where opening any other user client and calling a non-listed selector are denied; the
    list is found with `sandbox-discovery`-style allow-with-report runs of llama.cpp and vkcube offscreen.
  - Windows: `mitigation-audit.ps1` on the worker.
- **Status:**
  - now:Linux.
  - measure:macOS (selector list per macOS major, as the MIG list is; Seatbelt's filters differ between macOS majors).
  - Windows, win32k: **not solvable with known mechanisms, and an open host difference, not an accepted one.** A
    GPU worker without win32k lockdown leaves the whole win32k system-call surface reachable from a compromised
    worker; the macOS and Linux worker allow-lists have no counterpart of that size [I]. Options to decide between before Windows GPU
    ships (§2a): offer GPU on Windows with this difference stated, or not offer GPU on Windows until a worker
    configuration without win32k exists (for example the LPAC configuration of §3.3, unmeasured).

### 2.4 Guest-visible memory

**R5. Guest-visible memory freed while mapped (use-after-free in the host).**
- libkrun on macOS passes `vkMapMemory`'s pointer straight to `hv_vm_map` (`virtio_gpu.rs resource_map_blob` →
  `vstate.rs add_mapping` in [libkrun](https://github.com/containers/libkrun) at abe0a0f (2026-11-12) [S]). If the driver frees or moves that memory, the guest keeps a stale mapping.
- **All hosts:** only fd- or section-backed memory the **VMM holds open** is mapped into the guest, never a raw
  driver pointer.
  - Unix: the mapping is the VMM's own `mmap` of a pool fd, so the pages live while it is mapped.
  - Windows: `MapViewOfFile` of a section handle the VMM holds.
  - virglrenderer main already allocates guest-mappable Venus memory as a shm fd imported with
    `VK_EXT_external_memory_host` when the driver cannot export fds (`vkr_device_memory.c` `vkr_shm_alloc`,
    `use_host_memory_import`; "vkr: import shared memory as host memory instead of an MTLBuffer", 2026-11-10 [S]).
    wick forces this path on all hosts, Linux included, and draws it from one pool (§3.0).
- **Planned test:** `test_blob_unmapped_on_renderer_exit`: a guest touches a mapped blob while the worker is killed. Expect
  no host fault; the guest reads zeros or the device is reset.
- **Status:** now:Linux/macOS; measure:Windows (driver support of `VK_EXT_external_memory_host` per vendor).

**R6. A hostile back-end asks the VMM to map something else, or a range that is too big or overlapping.**
vhost-user spec `VHOST_USER_BACKEND_SHMEM_MAP` ([QEMU docs](https://gitlab.com/qemu-project/qemu/-/blob/master/docs/interop/vhost-user.rst) [S]).
- **All hosts:**
  - The front-end accepts maps of the pool object only. The object is checked by identity: `fstat` dev+ino on
    Unix, `CompareObjectHandles` on Windows.
  - Each range is checked: inside the window, aligned to the host page (16 KiB on macOS), and not overlapping
    (the spec already forbids overlap).
  - The VMM never accesses the range itself.
- **Planned test:** unit tests next to the handler and a `fuzz/` target for SHMEM_MAP/UNMAP sequences.
- **Status:** now.

**R7. Back-end shrinks the shared object, so the VMM or guest faults.**
- **Linux:** memfd with `F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL` checked by the front-end.
- **macOS:** POSIX shm can be truncated **once per lifetime** (XNU `bsd/kern/posix_shm.c` `pshm_truncate`: "We only
  allow one ftruncate() per lifetime" [S]), so a sized pool cannot change.
- **Windows:** a section's size is fixed at creation [I]. The front-end reads the size back (`NtQuerySection`) [M].
- **Planned test:** `test_pool_cannot_shrink` per host.
- **Status:** now:Linux/macOS; measure:Windows.

**R8. Uninitialised host memory leaks to the guest.** CVE-2022-0175: virgl "did not properly initialize memory
when allocating a host-backed memory resource" [D].
- **All hosts:**
  - The pool is fresh OS-zeroed memory (memfd/shm/pagefile section).
  - A pool block is zeroed before reuse.
  - Device-local memory the guest cannot map but can read through shaders is cleared by the worker on allocation
    (`vkCmdFillBuffer`, or an image clear) unless the driver documents zeroing.
- **Planned test:** `gpu-leak` stage: a guest allocates every memory type and checks for zeros; a second VM after the first
  freed memory reads only zeros.
- **Status:** now for the pool; measure:all for device-local clearing (cost, driver behaviour).

### 2.5 Resource limits

**R9. Host memory exhaustion through GPU allocations.**
- The DXGI budget is advisory ([QueryVideoMemoryInfo](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_4/ns-dxgi1_4-dxgi_query_video_memory_info) [D]).
- Windows sections are not charged to the Job (measured: `jailer-test.ps1 sections` before the jailer counted them); the jailer's 1 ms count of `SharedCommitUsage` ends a jail past `memory.max` (SECURITY.md, "`memory.max` bounds memory in sections at the jailer's next count"), so a GPU allocation in a section is bounded the same way, once the jail is ended after the next poll.
- `VKR_HEAP_MEMORY_PERCENT` "doesn't enforce" (`vkr_physical_device.c` [S]).
- Metal's `recommendedMaxWorkingSetSize` is advisory [D].
- **All hosts:**
  - (a) A fixed **pool** whose size the operator sets (`hostmem_mib`) bounds guest-mappable memory.
  - (b) A **per-VM byte quota in the worker's `vkAllocateMemory` dispatch** (`vkr_dispatch_vkAllocateMemory`)
    returns `VK_ERROR_OUT_OF_DEVICE_MEMORY` past `gpu_mem_mib`.
  - (c) A limit on contexts and resources per VM.
- **Plus per host:**
  - Linux: the workers in the jail's memory cgroup, and the `dmem` cgroup for VRAM where the driver supports it
    (merged January 2025, amdgpu and xe [D: LKML "dmem" cgroup]).
  - macOS: the workers inside the jail's jetsam limit, which must count IOGPU memory in `phys_footprint` [M].
  - Windows: the workers in the jail's Job (private commit). The pool section is created by the jailer and sized by
    the operator, so the escape from the Job limit is bounded and written down.
- **Planned test:** `gpu-oom`: a guest allocates until refused. Expect `VK_ERROR_OUT_OF_DEVICE_MEMORY` in the guest, the host
  footprint at or under pool + quota + a stated margin, and the VMM alive.
- **Status:**
  - now:Linux (memcg + quota).
  - measure:macOS.
  - Windows: driver-internal allocations (pipelines, command pools) are not counted by any OS limit. wick bounds
    object counts and documents the remainder.

**R10. GPU hang or denial of service, up to host instability.**
- Windows TDR is 2 s, and "the OS bug-checks the computer on the sixth GPU hang" when 5 happen within a minute
  ([TDR](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/timeout-detection-and-recovery) [D]).
- On macOS, Metal revokes a process's access after "too many timeouts or hangs" (`MTLCommandBufferError.accessRevoked` [D]).
- On Linux, DRM schedulers time out jobs and can reset the GPU [I].
- **All hosts:** the first device-lost (`VK_ERROR_DEVICE_LOST`) in any worker ends **all** of that VM's workers. The
  device goes to `DEVICE_NEEDS_RESET` and is not brought back for the VM's life, so one VM causes at most one hang.
  A `gpu.device_lost` metric records it. The workers run at low GPU priority:
  - Windows: `D3DKMTSetProcessSchedulingPriorityClass` set by the jailer on the worker (it takes a process handle [D]).
  - Linux: Vulkan global priority LOW where offered [I].
  - macOS: background QoS [M].
- **Planned test:** `gpu-hang`: a guest shader with an endless loop. Expect the device to fail in the guest, the VM and the
  host to run on, and no second hang from that VM.
- **Status:**
  - now:Linux.
  - measure:macOS (whether one process's hang resets the GPU for others is not documented).
  - Windows: **partly not solvable, and an open host difference, not an accepted one.** Five VMs each causing one
    hang within 60 s still bug-check the host (TdrLimitCount 5 within TdrLimitTime 60 s by default,
    [TDR registry keys](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/tdr-registry-keys),
    read 2026-11-13). Changing those keys is "for testing or debugging only" [D]. Options to decide between (§2a):
    the jailer counts GPU VMs per host and refuses a fifth (a limit only Windows has); state host DoS as a
    residual risk; or no GPU on Windows.

### 2.6 Cross-tenant leaks and side channels

**R11. Cross-tenant leak through GPU local memory (LeftoverLocals, CVE-2023-4969).**
- Affected: Apple (M3/A17 fixed; the M2 is still affected; M1 is not mentioned), AMD, Qualcomm, some Imagination.
  Not affected: NVIDIA, Intel, Arm ([Trail of Bits](https://blog.trailofbits.com/2024/01/16/leftoverlocals-listening-to-llm-responses-through-leaked-gpu-local-memory/) [D]).
- **All hosts:**
  - *Guest as reader:* the worker rewrites every guest SPIR-V module so that each `Workgroup` variable gets an
    `OpConstantNull` initializer, and enables `shaderZeroInitializeWorkgroupMemory` (Vulkan 1.3 core). A guest
    shader then cannot read leftovers.
  - *Guest as victim:* host apps reading the guest's leftovers cannot be prevented by wick. So "one tenant per GPU"
    applies on affected GPUs. The extension prints the GPU model and the advisory at start.
- **Planned test:** the Trail of Bits listener/writer PoC between a host process and a guest in both directions, on M1/M2,
  M3 and an AMD host. Results go in COMPATIBILITY.md.
- **Status:**
  - Reader direction: measure:all (MoltenVK and KosmicKrisp support of the feature is unknown).
  - Victim direction: **no:affected GPUs**. Documented: one tenant per GPU.

**R12. Other GPU side and covert channels.** GPU.zip: "all tested GPUs are affected", no vendor patch
([hertzbleed.com/gpu.zip](https://www.hertzbleed.com/gpu.zip/) [D]); contention timing [I].
- **All hosts:** cannot be closed by software in wick.
- **Planned test:** none (a documentation claim).
- **Status:** no:all. SECURITY.md: one tenant per GPU, and GPU VMs are not a side-channel boundary.

### 2.7 Firecracker features and plumbing

**R13. Snapshot of GPU state.** Upstream: "we will not aim to be able to snapshot GPU devices"
([discussion #4845](https://github.com/firecracker-microvm/firecracker/discussions/4845) [D]).
- **All hosts:**
  - The extension's `snapshot_blocker()` returns "gpu: GPU state cannot be snapshotted", so `PUT /snapshot/create`
    fails (`overlay/vmm/ext/mod.rs` `check_snapshot_with` [S]).
  - Loading a snapshot with the extension configured is refused.
- **Planned test:** `test_snapshot_refused_with_gpu` (the unit test exists for the hook: `test_snapshot_blocker`).
- **Status:** now.

**R14. Guest RAM exposed to the back-end.** vhost-user needs memfd guest RAM, as with vhost-user-blk.
- **All hosts:** as with every vhost-user device, `wick-gpu` sees all guest RAM of its own VM only. The render workers
  do not. The back-end has no GPU, network or files.
- **Linux, macOS, Windows:** existing vhost-user rows (`docs/PORTING.md` rows 10, 14).
- **Planned test:** existing `vhost-user` stages plus the `wick-gpu` sandbox stage.
- **Status:** now. On Windows the memfd escapes `memory.max`, as already documented.

**R15. A crashed or compromised worker or back-end hurts the VMM.**
- **All hosts:**
  - Socket EOF from the back-end puts the device in `DEVICE_NEEDS_RESET`, unmaps the window, and leaves the VM
    running (the GPU is gone).
  - No respawn (no exploit retries against a fresh ASLR layout).
  - A metric `gpu.backend_exits` counts it.
- **Planned test:** `gpu-crash` stage.
- **Status:** now.

**R16. Handle passing between jailed processes on Windows.** A jailed process "cannot `OpenProcess(PROCESS_DUP_HANDLE)`
the parent", so it cannot push handles (a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10, run for Firecracker's own process and not for a GPU worker; the probe is not in the repository; docs/PORTING.md row 14).
- **Windows:**
  - The **jailer** creates the pool section and the sockets and pushes them into the VMM and the back-end at start
    (privileged-to-jailed push works: a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10, run for Firecracker's own process and not for a GPU worker; the probe is not in the repository).
  - At run time, SHMEM_MAP names a range of the already-shared pool. No handle crosses at run time.
- **Linux, macOS:** the same pool, passed once with SCM_RIGHTS.
- **Planned test:** `jailer-test(.ps1) gpu`.
- **Status:** measure:Windows.

**R17. 16 KiB host pages on macOS.**
- Blobs must be 16 KiB aligned. `VIRTIO_GPU_F_BLOB_ALIGNMENT` has been in the Linux driver since the 2026-04-28
  commit "drm/virtio: support VIRTIO_GPU_F_BLOB_ALIGNMENT" [S]. libkrun offers 16 KiB ([libkrun](https://github.com/containers/libkrun) at abe0a0f (2026-11-12)) [S].
- **All hosts:** the device always offers `BLOB_ALIGNMENT` = host page size (4 KiB on Linux/Windows), so behaviour is
  one rule.
- **macOS:** a MAP_BLOB that is not aligned gets `VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER`, with a log line and metric.
  An older guest kernel fails loudly. A 4 KiB IPA granule (macOS 26 `hv_vm_config_set_ipa_granule`) could lift this
  [M].
- **Planned test:** `test_unaligned_map_blob_is_refused`.
- **Status:** now.

**R18. Window placement and size.**
- The hostmem window needs GPA space. krunkit caps RAM+VRAM at 62 GiB for the 36-bit IPA ([krunkit](https://github.com/containers/krunkit) `src/context.rs` at 9e39476 (2026-10-14): "Limit RAM + VRAM to 64 GB (36 bit IPA address limit)") [S]. wick already
  sets the max IPA size (`kvm-ioctls/src/hvf/vm.rs`).
- **All hosts:** the window is a 64-bit prefetchable BAR placed above RAM. A size that does not fit the IPA or the
  64-bit MMIO window is refused at configure time.
- **Planned test:** `test_hostmem_too_large_is_refused`.
- **Status:** now.

**R19. Passthrough (VFIO/DDA/VPCI): DMA, firmware persistence, one tenant per device.** DDA: "only ... where the
tenants of the VMs are trusted" ([Microsoft](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/plan-for-deploying-devices-using-discrete-device-assignment) [D]).
- **All hosts:** not offered. `"passthrough"` in the gpu body is refused: "GPU passthrough is not supported; upstream
  Firecracker has no VFIO (issue #5679)".
- **Planned test:** `test_passthrough_refused`.
- **Status:**
  - no:macOS ever (no assignment API in Hypervisor.framework [I]).
  - Linux and Windows: deferred until upstream VFIO lands (§6).

**R20. Renderer started from an untrusted path.** crun fixed exactly this: the image chose `virgl_render_server`
([crun b4612da](https://github.com/containers/crun/commit/b4612da50c7ed7d6d28d277e532316dbcbe1c1cc) [D]).
- **All hosts:**
  - `wick-gpu` and its worker are started by the jailer or the operator from fixed, root-owned or operator-owned
    paths.
  - Nothing comes from the guest or the API. virglrenderer's implicit exec is off
    (`allow_implicit_render_server_exec`=false when sandboxed, crosvm `gpu.rs` [S]).
- **Planned test:** `jailer-test gpu` checks the path's owner.
- **Status:** now.

**R21. Shader compiler and caches as a side door.**
- On macOS, Metal compiles in `MTLCompilerService` (an XPC service with its own profile and no IOKit) and issues
  file extensions. Chromium notes this "is much broader than we'd like" ([`gpu.sb`](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/policy/mac/gpu.sb), crbug 41485470 [S]).
- **Linux:** Mesa's disk cache goes to a per-jail tmpfs directory, or `MESA_SHADER_CACHE_DISABLE=1`.
- **macOS:** allow `mach-lookup` of `com.apple.MTLCompilerService` only. The shader cache is off
  (`disable-metal-shader-cache` style) or kept in the jail. `file-issue-extension` is limited to the jail and the
  Metal framework paths.
- **Windows:** the driver's shader cache goes to the jail's directory [M].
- **Planned test:** sandbox stage file-access checks.
- **Status:** now:Linux; measure:macOS/Windows.

**R22. Dynamic code and image signing in the worker.**
- No browser enables ACG in its GPU process (Chromium, Firefox [S]).
- Chrome sets Microsoft-signed-only *after* the driver loads (delayed mitigation; `gpu_init.cc` preloads DLLs because
  later loads "will fail" [S]).
- **Linux:** `PROT_EXEC` only for file mappings (crosvm allows `PROT_READ|PROT_EXEC` mmap [S]).
- **macOS:** `dynamic-code-generation` denied, as in WebKit's and Chromium's GPU profiles [S].
- **Windows:** set ACG and signed-images-only with `SetProcessMitigationPolicy` *after* `vkCreateDevice`, read them
  back, and fail closed if the driver then breaks.
- **Planned test:** `mitigation-audit.ps1` on the worker, and a guest running llama.cpp.
- **Status:** now:Linux/macOS; measure:Windows (per vendor UMD).

**R23. Rate limiting.** Upstream has no rate limiter on vhost-user devices [I].
- **All hosts:** the limits are the bounded quotas of R9 and R10 plus a cap on command-buffer size and fence count
  per context. No token bucket.
- **Planned test:** `gpu-oom`, `gpu-hang`.
- **Status:** now.

## 2a. Host differences to decide

The rule is the same security on all three hosts; a difference is allowed only where the OS or the hardware truly
cannot do something, and then it is stated. These two are such differences, but whether wick ships GPU on Windows
with them is **not decided**:

| Item | Consequence on Windows | Options |
| --- | --- | --- |
| R4: no win32k lockdown for a process that uses D3D or Vulkan | a compromised worker reaches all of win32k, which has a long record of privilege-escalation bugs | ship with it stated; or no GPU on Windows until a worker without win32k exists |
| R10: TDR bug-checks the host after 5 GPU hangs within 60 s (default keys) | five GPU VMs, each held to one hang, can still take the host down | the jailer refuses a fifth GPU VM per host; state host DoS; or no GPU on Windows |

Both are Windows-only facts of the OS (documentation: R4, R10); none of them has been measured by wick.

## 3. Per-host design

### 3.0 Common to all hosts

**API.** `PUT /extensions/gpu` before boot, or `extensions.gpu` in the config file, with:

```json
{"socket": "<vhost-user path in jail>", "hostmem_mib": 4096, "gpu_mem_mib": 8192, "max_contexts": 8}
```

- `--enable-pci` is required; without it the request is refused with "gpu needs --enable-pci".
- `update` after boot is refused (the default `Extension::update`).

**Front-end (VMM, `wick-ext`).** It reuses upstream's `VhostUserHandleImpl` handshake, as vhost-user-blk does.

- It reads the device config with `GET_CONFIG`: `num_capsets`, `blob_alignment`.
- It negotiates `PROTOCOL_F_SHMEM` and `BACKEND_REQ`.
- It gets one region (`GET_SHMEM_CONFIG`, shmid 1 = `VIRTIO_GPU_SHM_ID_HOST_VISIBLE`, as vhost-device-gpu answers with
  `VhostUserShMemConfig::new(1, &[0, SHMEM_SIZE])` in `device.rs` [S]).
- It exposes the region as BAR2 plus a `VIRTIO_PCI_CAP_SHARED_MEMORY_CFG` capability. Linux reads it in
  `virtio_pci_modern.c vp_get_shm_region` [S] and the driver reserves it in `virtgpu_kms.c` ("Host memory window" [S]).
- Blob mappings go through the same slot API upstream's virtio-pmem uses for host memory in the GPA space
  (`pmem/device.rs`: `vm.next_kvm_slot`, `set_user_memory_region` [S]). wick already backs that API on HVF and WHP,
  since pmem runs on all three hosts.

**Pool.**

- One sealed, fixed-size shared object of `hostmem_mib`, created by the jailer (or by Firecracker before it narrows
  when unjailed). It is mapped once by the VMM and once by the back-end/workers.
- The worker's `vkr_shm_alloc` takes blocks from the pool instead of `os_create_anonymous_file` per allocation (the
  virglrenderer patch). The memory is imported with `VK_EXT_external_memory_host`, and `SHMEM_MAP` names
  `(pool, fd_offset)`.
- What this gives:
  - a hard bound on guest-mappable memory on every host, including Windows sections;
  - no run-time handle passing;
  - OS-zeroed memory;
  - one memory model on all hosts, instead of dma-buf on Linux versus shm on macOS.

**Guest-visible device, identical on all hosts.**

- Features: `VIRTIO_GPU_F_RESOURCE_BLOB`, `CONTEXT_INIT`, `BLOB_ALIGNMENT`, and the shm window. No `VIRGL`. No EDID.
- Scanouts: 0.
- Capset: `VIRTIO_GPU_CAPSET_VENUS` (4) only. The ids are in `include/uapi/linux/virtio_gpu.h` [S].
- The host Vulkan version and extensions differ per host GPU, as any Vulkan device does. The Vulkan feature set the
  guest sees is the host driver's, filtered by Venus. Once it exists, a COMPATIBILITY.md row would list what was measured per host.

**Metrics** follow upstream's per-device metrics style (`vhost_user_metrics.rs`):
`activate_fails`, `shmem_maps`, `shmem_unmaps`, `mapped_bytes`, `ctx_created`, `device_lost`, `backend_exits`,
`quota_refusals`.

### 3.1 Linux

- **Worker sandbox.** This is what crosvm ships.
  - minijail or wick's own namespaces: user, mount, pid, net, ipc.
  - `pivot_root` with a read-only bind of `/sys/dev/char`, `/sys/devices`, `/dev/dri/renderD*`, the Mesa or
    vendor driver libraries and `drirc.d` (`jail/src/helpers.rs` [S]).
  - `no_new_privs`, seccomp narrowed as in R4, a uid per jail, and the jail's cgroup.
- **Per-context workers.** `render-server-worker=minijail` forks a jailed worker per context with its own seccomp
  filter (`create_minijail`, `fork_minijail` [S]).
  - `vulkan-preload` stays off: the NVIDIA proprietary driver is "not ... safe to fork" (`meson_options.txt` [S]).
- **Host requirements.** Vulkan 1.1 and `VK_KHR_external_memory_fd` (Mesa Venus doc). wick additionally requires
  `VK_EXT_external_memory_host` for the pool [M per driver: ANV, RADV, NVIDIA].
- **Not used:** DRM native contexts (`drm-renderers`: amdgpu, msm, asahi, i915, panfrost [S]). They tie the guest's
  Mesa driver to the host GPU ("requires a driver in the guest OS that is tailored to the host hardware",
  [Collabora 2025](https://collabora.com/news-and-blog/blog/2025/01/15/the-state-of-gfx-virtualization-using-virglrenderer) [D])
  and exist only on Linux hosts, which breaks parity.

### 3.2 macOS

- **Worker sandbox.**
  - Seatbelt `(deny default)` modelled on Apple's PG GPU task:
    - `iokit-open` of `IOGPUDeviceUserClient` + `IOSurfaceRootUserClient`. `AGXDeviceUserClient` is a subclass, as
      all 43 instances on the M1 Pro match `IOGPUDeviceUserClient` in `ioreg` [S].
    - `mach-lookup` of `com.apple.MTLCompilerService` and `com.apple.gpumemd.source`.
    - file reads of Metal.framework and the AGX driver bundles.
    - no WindowServer (WebKit's GPU process denies `com.apple.windowserver.active` and still runs Metal [S]).
    - no network, no process info, no `dynamic-code-generation`.
  - wick then adds the parts Apple's profile lacks: syscall-unix, syscall-mach and syscall-mig allow-lists (WebKit's
    GPU profile has a working Metal list incl. `io_connect_method`, `io_connect_map_memory_into_task`,
    `_mach_make_memory_entry` [S]) and the enforcing IOKit selector filter.
  - Files are limited to the jail. There is no chroot: dyld and Metal bundles do not start in a chroot (SECURITY.md).
- **Per-context workers.** The render server's `process` worker mode (fork) works on macOS [I]. The fork happens
  before Metal is initialised, since Metal is not fork-safe [I], so each worker initialises Metal itself.
- **Vulkan.** MoltenVK has `VK_EXT_external_memory_host` since 1.2.3 [D]. KosmicKrisp is Vulkan 1.3 conformant on
  macOS 15+ [D], with its external memory unknown [M].
- **Use** `MTLCopyAllDevices` and link CoreGraphics (`MTLCreateSystemDefaultDevice` needs CoreGraphics in
  command-line tools [D]). Whether this works in a launch daemon with no user logged in is unknown [M].
- **Not used:** ParavirtualizedGraphics. It serves macOS guests only [D], and wick's guests are Linux.
  Virtualization.framework's virtio-gpu is 2D scanout only [D/I] and is not available to a Hypervisor.framework VMM anyway.

### 3.3 Windows

- **Worker sandbox.**
  - Created by the jailer, as the API process is (PORTING row 4), in the jail's Job, with:
    - restricted token USER_LIMITED with the jail's SID (Chrome: "USER_RESTRICTED breaks both the DirectX backend and
      the OpenGL backend", `gpu_process_host.cc` [S]);
    - Low integrity;
    - Job with one active process, kill on close, UI limits (Chrome grants back SYSTEMPARAMETERS, DESKTOP,
      EXITWINDOWS, DISPLAYSETTINGS [S]; wick tries without them [M]);
    - strict handle checks, no child processes, extension points disabled, no remote or low-label images;
    - ACG and signed-images-only after device creation (R22).
  - **Not available:** win32k lockdown (R4).
  - **Candidate:** LPAC with `lpacPnpNotifications`. Chrome runs Dawn/D3D12 in that configuration for on-device models
    (`sandbox_win.cc`, `pre_sandbox_init.cc` [S]), and wick measured that LPAC needs `registryRead`+`lpacCom` for
    Winsock (a probe of Windows sandbox mechanisms on Windows Server 2022 build 20348, 2026-11-10, run for Firecracker's own process and not for a GPU worker; the probe is not in the repository). Whether a Vulkan ICD runs in it is unknown [M].
- **Per-context workers.** There is no fork. The jailer spawns one worker per context on request, or a fixed small
  pool, under the same policy.
- **Vulkan.** The vendor ICD (NVIDIA, AMD, Intel) is used directly. `VK_EXT_external_memory_host` is required [M per
  vendor]. Mesa's Dozen (Vulkan on D3D12) is a fallback to evaluate [M]. gfxstream on Windows is not used, to keep
  one guest protocol, but it is the known-working Windows host renderer (crosvm Windows GPU child,
  `src/crosvm/sys/windows/broker.rs` [S]).
- **Not used:** GPU-PV. It exists only in Hyper-V's worker stack over VMBus (`vmwp.exe`/`vrdumed.dll`,
  [GPU paravirtualization](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/gpu-paravirtualization) [D]),
  and the Linux guest driver `dxgkrnl` "depends on HYPERV" (WSL2 kernel `drivers/hv/dxgkrnl/Kconfig` [S]). It is not
  in upstream Linux and not reachable from WHP [I].

## 4. Option comparison

| Option | Guest device | Linux host | macOS host | Windows host | Fits a headless microVM | Verdict |
|---|---|---|---|---|---|---|
| virtio-gpu 2D | scanout only | yes | yes | yes | no compute | not useful |
| virgl (GL) | `VIRGL`/`VIRGL2` capset | yes | via ANGLE/MoltenGL only [I] | patched forks only | GL 4.3 at best, double work ("VirGL requires most work to be done twice", Collabora [D]) | no: most CVEs live here |
| **Venus (Vulkan)** | `VENUS` capset, Mesa `virtio` driver | yes (render server, per-context workers) | yes (MoltenVK; krunkit ships it [S]) | needs virglrenderer port | yes: llama.cpp Vulkan, offscreen | **chosen** |
| gfxstream | `GFXSTREAM_VULKAN` capset, Mesa `gfxstream` driver | yes | yes (MoltenVK) | yes (crosvm Windows, Android Emulator [D]) | yes | runner-up: "calls are forwarded to the host with minimal modification" (QEMU virtio-gpu doc [D]); the Android Emulator runs it in-process, unsandboxed [D/I] |
| DRM native context | `DRM` capset, host-specific guest driver | yes | no | no | yes | no: Linux-only, breaks image parity |
| cross-domain | Wayland passthrough | Linux | no | no | display only | no |
| ParavirtualizedGraphics | Apple PCI device | no | macOS guests only [D] | no | no Linux driver | no |
| GPU-PV (dxgkrnl) | VMBus `/dev/dxg` | no | no | Hyper-V/HCS only [D] | WSL kernel only | no |
| VFIO / DDA / WHP VPCI | real GPU | VFIO (not in upstream FC) | impossible | WHP VPCI documented [D] | single tenant, no oversubscription | refused for now |

Guest requirements for Venus:

- Linux 5.16 or later (Mesa: "the guest kernel should be at least 5.16") with `CONFIG_DRM`, `CONFIG_DRM_VIRTIO_GPU`,
  `CONFIG_DRM_VIRTIO_GPU_KMS=n` for headless (the option was added 2023-03-02, Linux 6.4 [I]) and
  `CONFIG_VIRTIO_PCI=y` (already set).
- The `BLOB_ALIGNMENT` kernel for macOS hosts (R17).
- Mesa with `-Dvulkan-drivers=…,virtio`. `virtio` is **not** in Mesa's `auto` list (`meson.build` [S]), so the wick
  guest image (M6) must ship it.

## 5. Prior art

**Upstream Firecracker.**

- 2019: "To do device pass-through implies pinning physical memory which would remove our memory oversubscription
  capabilities" and "We can only run 1 customer workload securely per physical GPU"
  ([#849](https://github.com/firecracker-microvm/firecracker/issues/849)).
- 2021: settled on "plain PCIe GPU passthrough", which needs full memory mapped, "will probably negate the advantages
  of using snapshot-restore", and might become "a separate Firecracker mode or Firecracker variant"
  ([#1179](https://github.com/firecracker-microvm/firecracker/issues/1179)).
- 2022: dropped.
- 2024: community meetings ([#4845](https://github.com/firecracker-microvm/firecracker/discussions/4845)): no GPU
  snapshot "in the initial iteration"; a PoC with 8 GPUs over VFIO.
- 2025: paused for lack of contributors.
- PCIe shipped in v1.13. 2025-11: "still researching around a ways to support GPUs while maintaining our security
  promises". 2026: #1179 closed in favour of VFIO tracking issue
  [#5679](https://github.com/firecracker-microvm/firecracker/issues/5679).
- Upstream has never discussed paravirtual GPUs.

**crosvm / ChromeOS.**

- The GPU device runs in its own minijail. Sandboxed mode forces `external_blob` because "blob mapping will be done
  out-of-process by the crosvm hypervisor process", and implicit render-server exec is not allowed.
- `virgl_render_server` runs in its own jail and cgroup (`gpu.rs` [S]).
- On Windows: a GPU child under Chromium's sandbox library, USER_RESTRICTED_NON_ADMIN, Low integrity
  (`sandbox/src/policy.rs` [S]).

**libkrun / krunkit / Podman.**

- Venus in-process in the VMM with no sandbox; entitlements are hypervisor and disable-library-validation only
  ([krunkit](https://github.com/containers/krunkit) at 9e39476 (2026-10-14); [Homebrew formula](https://github.com/slp/homebrew-krunkit)) [S].
- crun on Linux runs `virgl_render_server` under bubblewrap.

**QEMU.**

- `virtio-gpu-gl,blob=true,venus=true,hostmem=` with a memfd backend (Mesa Venus doc [D]).
- `vhost-user-gpu` back-ends; CVE-2021-3544/3545/3546 were leaks and an OOB write in `contrib/vhost-user-gpu` [D].
- `apple-gfx` for macOS guests on HVF ([`hw/display/apple-gfx.m`](https://gitlab.com/qemu-project/qemu/-/blob/master/hw/display/apple-gfx.m)) [S].

**Cloud Hypervisor.**

- VFIO only, with NVIDIA notes ([docs/vfio.md](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/vfio.md) [D]).
- Spectrum OS keeps out-of-tree patches that use crosvm's GPU device over vhost-user, and reports that upstream is
  "not very interested in GPU support"
  ([Spectrum](https://inbox.spectrum-os.org/spectrum-devel/82c7b24/s/Documentation-software-cloud-hypervisor-index.html) [D]).

**rust-vmm `vhost-device-gpu`.**

- A vhost-user GPU back-end with virglrenderer (Venus) and gfxstream modes, a `--headless` mode, and an 8 GiB
  `SHMEM` region [S]. Closest starting point for `wick-gpu`.

## 6. What is impossible on which host

**macOS:**

- No device passthrough (Hypervisor.framework has no assignment API [I]).
- No DRM native context.
- No win32k-style problem.
- LeftoverLocals is unfixable on affected Apple GPUs: the M2 is reported affected, the M1 is not stated, the M3 is fixed [D].
- No per-process GPU memory quota from the OS [D: only advisory values found].

**Windows:**

- No win32k lockdown for a process that uses D3D or Vulkan [S/D].
- No enforceable per-process GPU memory quota [D].
- The host-wide TDR bug-check after 5 hangs per minute [D].
- No GPU-PV from WHP [I].
- WHP VPCI passthrough is documented but needs a "discretely assignable" device (admin, dismount) [D]. Deferred,
  not impossible.

**Linux:** nothing for the chosen design. VFIO waits for upstream.

**All hosts:**

- GPU side channels (GPU.zip, contention) cannot be closed.
- GPU state cannot be snapshotted.

## 7. Residual risks to state in SECURITY.md (once implemented)

1. A GPU-enabled microVM exposes, through sandboxed helper processes, the Venus decoder and the host's GPU user-mode
   driver and **kernel driver** to the guest. The VMM's own isolation is unchanged. Use **one tenant per GPU**: this
   is upstream's own statement and wick's rule.
2. Windows (open host difference, §2a): the GPU worker cannot run without win32k, so the whole win32k system-call
   surface is reachable from a compromised worker.
3. Windows (open host difference, §2a): five GPU hangs within a minute from any source bug-check the host. The design
   limits each VM to one.
4. LeftoverLocals on affected GPUs (Apple M2, with M1 not stated by the advisory; AMD; Qualcomm): host processes can read a guest's GPU local memory. wick's SPIR-V
   rewrite stops only the guest reading the host's.
5. GPU side channels (GPU.zip and contention) are not a boundary.
6. Memory: the pool and the allocation quota bound guest-driven GPU memory. On Windows, driver-internal allocations
   are outside every OS limit.
7. No snapshots with a GPU.
8. The back-end sees all guest RAM of its own VM, as every vhost-user back-end does.

## 8. Test plan (none of these tests or stages exists yet; each gets its name in the docs once it exists)

**Fuzzing** (CI one minute each, as the existing targets; longer runs before a release):

- `gpu_ctrlq`: the virtio-gpu control queue decoder in `wick-gpu`.
- `venus_decode`: virglrenderer's Venus decoder (`vn_dispatch_*`) with a null driver. virglrenderer has in-tree
  fuzzers for virgl GL and DRM only (`tests/fuzzer/`: `virgl_fuzzer.c`, `virgl_drm_fuzzer.c` [S]); it was not found in
  OSS-Fuzz (`google/oss-fuzz` `projects/virglrenderer/project.yaml` returns 404 [S]).
- `shmem_map`: the front-end's SHMEM_MAP/UNMAP handling.
- `spirv_zero_init`: the workgroup-initializer rewrite.

**Per-host sandbox stages:**

- `boot-test gpu`: llama.cpp Vulkan and `vulkaninfo` in the guest.
- `jailer-test(.ps1) gpu`, where a test-only hook makes the worker and the back-end try the forbidden things:
  - open files outside the jail;
  - IP sockets;
  - other processes;
  - another IOKit class or selector (macOS);
  - a non-DRM or other-driver ioctl (Linux);
  - spawn a child, load an unsigned DLL after narrowing, or allocate executable memory (Windows);
  - read guest RAM (worker).
- Each attempt must fail and be reported.

**Denial of service:**

- `gpu-hang`: an endless shader loop.
- `gpu-oom`: allocate until refused.
- `gpu-crash`: kill the worker and the back-end mid-frame.
- `gpu-contexts`: open more than `max_contexts` contexts.

**Leaks:**

- `gpu-leak`: fresh allocations read zero, and nothing crosses between VMs.
- LeftoverLocals PoC in both directions per GPU family.
- `test_blob_unmapped_on_renderer_exit`.

**Snapshot and compile-out:**

- `test_snapshot_refused_with_gpu`.
- A default build has no device and no symbols.
- Each is named in the docs once it exists (`tools/check-claims.py` checks the names).

**Parity:** the same stages on all three hosts. Windows stages run on a Windows PC with WHP.

## 9. Open questions

1. Does virglrenderer's Venus renderer (C, POSIX: fork, memfd, poll) port to Windows on its own, or through wick's
   compat layer (the Rust compat crates have no C ABI today [I])? If the port is too large, gfxstream everywhere is
   the alternative that keeps parity.
2. `VK_EXT_external_memory_host` memory types on each driver: does llama.cpp's Vulkan backend still get the host-visible
   types it needs when only imported memory is mappable?
3. Upstream acceptance of the pool allocator in virglrenderer (`vkr_shm_alloc` callback), versus carrying a patch.
4. macOS: does IOGPU memory count in the jetsam footprint? Does Metal work in a launch daemon? Is
   `shaderZeroInitializeWorkgroupMemory` supported in MoltenVK and KosmicKrisp? Do hangs reset other processes' work?
5. Windows: do vendor ICDs run under LPAC, under ACG set after device creation, and under signed-images-only?
6. The transport patch (BAR2 + SharedMemory capability) is an upstream-code change. Upstreaming it to Firecracker is
   worth proposing, since virtio-fs DAX needs the same thing.
7. Exact SHMEM_MAP encoding for "range of the pool" on Windows, where no handle crosses at run time. The
   spec-conformant fd field must carry something.

## 10. Sources (Appendix sources)

Repo and upstream source (read):

- `lib/firecracker/resources/guest_configs/*.config`
- `src/vmm/src/devices/virtio/transport/{pci/device.rs,mmio.rs}`
- `devices/virtio/vhost_user.rs`
- `devices/virtio/pmem/device.rs`
- `overlay/vmm/ext/mod.rs`
- `crates/ext/src/lib.rs`
- SECURITY.md, docs/PORTING.md rows 2, 4, 10, 14, 15
- vhost 0.17 `vhost_user/message.rs`

Linux:

- [include/uapi/linux/virtio_gpu.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_gpu.h)
- [drivers/gpu/drm/virtio/virtgpu_kms.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/virtio/virtgpu_kms.c) and its Kconfig
- [drivers/virtio/virtio_pci_modern.c](https://github.com/torvalds/linux/blob/master/drivers/virtio/virtio_pci_modern.c)
- [drivers/virtio/virtio_mmio.c](https://github.com/torvalds/linux/blob/master/drivers/virtio/virtio_mmio.c) `vm_get_shm_region`

virglrenderer (main, 2026-11):

- [server/render_worker.c](https://gitlab.freedesktop.org/virgl/virglrenderer/-/blob/main/server/render_worker.c)
- [meson_options.txt](https://gitlab.freedesktop.org/virgl/virglrenderer/-/blob/main/meson_options.txt)
- [src/venus/vkr_device_memory.c](https://gitlab.freedesktop.org/virgl/virglrenderer/-/blob/main/src/venus/vkr_device_memory.c)
- [src/venus/vkr_physical_device.c](https://gitlab.freedesktop.org/virgl/virglrenderer/-/blob/main/src/venus/vkr_physical_device.c)
- [src/virglrenderer.h](https://gitlab.freedesktop.org/virgl/virglrenderer/-/blob/main/src/virglrenderer.h)
- [tests/fuzzer](https://gitlab.freedesktop.org/virgl/virglrenderer/-/tree/main/tests/fuzzer)

Mesa:

- [Venus doc](https://docs.mesa3d.org/drivers/venus.html)
- [meson.build / meson.options](https://gitlab.freedesktop.org/mesa/mesa/-/blob/main/meson.build)
- `src/gfxstream`

crosvm:

- [src/crosvm/sys/linux/gpu.rs](https://chromium.googlesource.com/crosvm/crosvm/+/refs/heads/main/src/crosvm/sys/linux/gpu.rs)
- [jail/src/helpers.rs](https://chromium.googlesource.com/crosvm/crosvm/+/refs/heads/main/jail/src/helpers.rs)
- [jail/seccomp/x86_64/gpu_common.policy](https://chromium.googlesource.com/crosvm/crosvm/+/refs/heads/main/jail/seccomp/x86_64/gpu_common.policy) and `gpu_render_server.policy`
- `src/crosvm/sys/windows/broker.rs`
- `sandbox/src/policy.rs`

QEMU:

- [vhost-user.rst](https://gitlab.com/qemu-project/qemu/-/blob/master/docs/interop/vhost-user.rst) (SHMEM_MAP, GET_SHMEM_CONFIG)
- [vhost-user-gpu.rst](https://gitlab.com/qemu-project/qemu/-/blob/master/docs/interop/vhost-user-gpu.rst)
- [virtio-gpu doc](https://www.qemu.org/docs/master/system/devices/virtio/virtio-gpu.html)

rust-vmm:

- [vhost-device-gpu](https://github.com/rust-vmm/vhost-device/tree/main/vhost-device-gpu) (README, `src/device.rs`)

Firecracker:

- [#849](https://github.com/firecracker-microvm/firecracker/issues/849)
- [#1179](https://github.com/firecracker-microvm/firecracker/issues/1179)
- [#4845](https://github.com/firecracker-microvm/firecracker/discussions/4845)
- [#5679](https://github.com/firecracker-microvm/firecracker/issues/5679)
- [PR #5870](https://github.com/firecracker-microvm/firecracker/pull/5870)

Other:

- [crun commit b4612da](https://github.com/containers/crun/commit/b4612da50c7ed7d6d28d277e532316dbcbe1c1cc)
- [Collabora 2025](https://collabora.com/news-and-blog/blog/2025/01/15/the-state-of-gfx-virtualization-using-virglrenderer)
- [XNU posix_shm.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/posix_shm.c) `pshm_truncate`

CVEs:

- [NVD virglrenderer list](https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=virglrenderer)
- [CVE-2025-2509](https://cveawg.mitre.org/api/cve/CVE-2025-2509)
- CVE-2022-0135, CVE-2022-0175, CVE-2021-3544/3545/3546, CVE-2024-3446 (cveawg.mitre.org)
- [CVE-2023-4969 / Trail of Bits](https://blog.trailofbits.com/2024/01/16/leftoverlocals-listening-to-llm-responses-through-leaked-gpu-local-memory/)
- [GPU.zip](https://www.hertzbleed.com/gpu.zip/)
- AMD bulletin AMD-SB-6010 (LeftoverLocals; the page timed out, so AMD's per-product fix status is not confirmed here)

macOS sources (Apple docs and security notes, Chromium and WebKit profiles, libkrun/krunkit, MoltenVK, KosmicKrisp, QEMU apple-gfx), read 2026-11-13; the local checks were made on macOS 27.2 on an M1 Pro:

- <https://blog.podman.io/2024/07/podman-and-libkrun/>
- <https://blog.trailofbits.com/2024/01/16/leftoverlocals-listening-to-llm-responses-through-leaked-gpu-local-memory/>
- <https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/policy/mac/common.sb>
- <https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/policy/mac/gpu.sb>
- <https://crbug.com/75343>
- <https://crbug.com/957217>
- <https://developer.apple.com/documentation/hypervisor/hv_vm_map(_:_:_:_:)>
- <https://developer.apple.com/documentation/metal/mtlcommandbuffererror-swift.struct/code>
- <https://developer.apple.com/documentation/metal/mtlcopyalldevices()>
- <https://developer.apple.com/documentation/metal/mtlcreatesystemdefaultdevice()>
- <https://developer.apple.com/documentation/paravirtualizedgraphics>
- <https://developer.apple.com/documentation/virtualization/vzvirtiographicsdeviceconfiguration>
- <https://developer.apple.com/forums/thread/827607>
- <https://developers.redhat.com/articles/2025/06/05/how-we-improved-ai-inference-macos-podman-containers>
- <https://git.secluded.site/zed/commit/bb514c158e1604916b32fc8c9bbe602a78727742>
- <https://github.com/KhronosGroup/MoltenVK/blob/main/Docs/MoltenVK_Runtime_UserGuide.md>
- <https://github.com/KhronosGroup/MoltenVK/blob/main/Docs/Whats_New.md>
- <https://github.com/WebKit/WebKit/blob/main/Source/WebKit/GPUProcess/mac/com.apple.WebKit.GPUProcess.sb.in>
- <https://github.com/containers/krunkit>
- <https://github.com/containers/libkrun>
- <https://github.com/fxgl/steamac/wiki>
- <https://github.com/slp/homebrew-krunkit>
- <https://gitlab.com/qemu-project/qemu/-/blob/master/docs/system/arm/vmapple.rst>
- <https://gitlab.com/qemu-project/qemu/-/blob/master/hw/display/apple-gfx.m>
- <https://kb.cert.org/vuls/id/446598>
- <https://nvd.nist.gov/vuln/detail/CVE-2022-32947>
- <https://nvd.nist.gov/vuln/detail/CVE-2023-4969>
- <https://securelist.com/operation-triangulation-the-last-hardware-mystery/109453/>
- <https://sinrega.org/2024-03-06-enabling-containers-gpu-macos/>
- <https://support.apple.com/en-us/122373>
- <https://support.apple.com/en-us/124149>
- <https://support.apple.com/en-us/125110>
- <https://support.apple.com/en-us/127115>
- <https://www.hertzbleed.com/gpu.zip/>
- <https://www.hertzbleed.com/gpu.zip/GPU-zip.pdf>
- <https://www.lunarg.com/lunarg-achieves-vulkan-1-3-conformance-with-kosmickrisp-on-apple-silicon/>
- <https://www.lunarg.com/wp-content/uploads/2025/10/XDC-2025-KosmicKrisp-Overview.pdf>
- <https://www.phoronix.com/news/KosmicKrisp-Vulkan-1.4-2026>

Windows sources (Chromium, Firefox and crosvm sandbox source, Microsoft Learn on WHP, DDA, GPU-PV, TDR and D3DKMT, CVEs), read 2026-11-13:

- <https://android.googlesource.com/platform/external/qemu/+/refs/heads/emu-master-dev/android/docs/GPU-EMULATION.TXT>
- <https://android.googlesource.com/platform/hardware/google/gfxstream/+/refs/heads/main/README.md>
- <https://bugzilla.mozilla.org/show_bug.cgi?id=1718414>
- <https://bugzilla.mozilla.org/show_bug.cgi?id=1835586>
- <https://chromium.googlesource.com/chromium/src/+/b31d103b4e1b8dcc2195d723efdfe0d0425799ac/services/on_device_model/pre_sandbox_init.cc>
- <https://chromium.googlesource.com/chromium/src/+/main/docs/security/severity-guidelines.md>
- <https://chromium.googlesource.com/chromium/src/+/refs/heads/main/>
- <https://chromium.googlesource.com/chromium/src/+/refs/heads/main/content/browser/gpu/gpu_process_host.cc>
- <https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/policy/win/sandbox_win.cc>
- <https://chromium.googlesource.com/chromium/src/+/refs/tags/116.0.5793.1/sandbox/policy/win/sandbox_win.cc>
- <https://chromium.googlesource.com/chromium/src/+/refs/tags/132.0.6834.159/sandbox/policy/features.cc>
- <https://chromium.googlesource.com/crosvm/crosvm/+/refs/heads/main/sandbox/src/policy.rs>
- <https://chromium.googlesource.com/crosvm/crosvm/+/refs/heads/main/src/crosvm/sys/windows/broker.rs>
- <https://cveawg.mitre.org/api/cve/CVE-2021-1051>
- <https://cveawg.mitre.org/api/cve/CVE-2022-28186>
- <https://cveawg.mitre.org/api/cve/CVE-2025-29812>
- <https://cveawg.mitre.org/api/cve/CVE-2025-33218>
- <https://cveawg.mitre.org/api/cve/CVE-2025-55223>
- <https://cveawg.mitre.org/api/cve/CVE-2025-60716>
- <https://cveawg.mitre.org/api/cve/CVE-2026-20836>
- <https://cveawg.mitre.org/api/cve/CVE-2026-50353>
- <https://developer.android.com/studio/run/emulator-acceleration>
- <https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.6.y/drivers/hv/dxgkrnl/Kconfig>
- <https://groups.google.com/a/chromium.org/g/blink-dev/c/yhFguWS_3pM>
- <https://issues.chromium.org/issues/40051000>
- <https://j00ru.vexillium.org/syscalls/win32k/64/>
- <https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvallocatevpciresource>
- <https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvvpcidatatypes>
- <https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform>
- <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/nf-d3dkmthk-d3dkmtcreatedevice>
- <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/nf-d3dkmthk-d3dkmtsetprocessschedulingpriorityclass>
- <https://learn.microsoft.com/en-us/windows-hardware/drivers/display/gpu-paravirtualization>
- <https://learn.microsoft.com/en-us/windows-hardware/drivers/display/tdr-changes-in-windows-8>
- <https://learn.microsoft.com/en-us/windows-hardware/drivers/display/tdr-registry-keys>
- <https://learn.microsoft.com/en-us/windows-hardware/drivers/display/timeout-detection-and-recovery>
- <https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/deploy/deploying-graphics-devices-using-dda>
- <https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/plan/plan-for-deploying-devices-using-discrete-device-assignment>
- <https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_4/ns-dxgi1_4-dxgi_query_video_memory_info>
- <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_binary_signature_policy>
- <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_system_call_disable_policy>
- <https://nvidia.custhelp.com/app/answers/detail/a_id/5747>
- <https://openvmm.dev/guide/user_guide/openvmm.html>
- <https://raw.githubusercontent.com/mozilla-firefox/firefox/main/security/sandbox/win/src/sandboxbroker/sandboxBroker.cpp>
- <https://www.amd.com/en/resources/product-security/bulletin/amd-sb-1000.html>
