# Your first microVM

This guide takes you from a fresh clone to a shell inside a Firecracker microVM, then through the REST API and
networking. It uses the kernel and root filesystem that upstream Firecracker's own CI boots, so nothing here is
specific to wick except where it says so.

The commands are written for macOS on Apple silicon, the host where wick goes beyond upstream today. On Linux
everything after the build is identical to
[upstream's getting started guide](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md);
Windows notes are at the end.

## 1. Build

You need git, Rust ([rustup](https://rustup.rs); cargo installs the toolchain upstream pins) and, on macOS,
macOS 15 or later on Apple silicon.

```sh
git clone --recurse-submodules https://github.com/toollyst/wick
cd wick
tools/setup.sh                       # upstream at patches/base + the patch series, as branch `wick`
tools/macos/run.sh --build-only --release
```

`tools/macos/run.sh` builds `firecracker`, signs it ad hoc with the Hypervisor.framework entitlement
(`com.apple.security.hypervisor`, and `com.apple.security.virtualization` for vmnet) and, unless given `--build-only`, runs it with the arguments after `--`. The
binary is at `lib/firecracker/build/cargo_target/release/firecracker`; if you rebuild with plain `cargo`, run
`run.sh` again (or `codesign` yourself) so it keeps the entitlement.

```sh
lib/firecracker/build/cargo_target/release/firecracker --version
# Firecracker v1.18.0
```

## 2. Get a guest

Any Firecracker guest for your host's architecture works: aarch64 on Apple silicon, x86_64 on Windows, either on
Linux. Upstream's CI images are a good start:

```sh
mkdir -p ~/wick-vm && cd ~/wick-vm
ARCH=aarch64                         # x86_64 on an Intel/AMD Linux or Windows host
CI=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261105-6ea6634994fa-0/$ARCH
curl -fLO "$CI/vmlinux-6.1.188"
curl -fLO "$CI/ubuntu-24.04.squashfs"
```

That is an uncompressed Linux 6.1 kernel and a read-only Ubuntu 24.04 root filesystem, about 100 MB together.

## 3. Boot from a config file

Write the machine down once:

```sh
cat > vm.json <<EOF
{
  "boot-source": {
    "kernel_image_path": "$PWD/vmlinux-6.1.188",
    "boot_args": "console=ttyS0 reboot=k panic=1 root=/dev/vda ro rootfstype=squashfs init=/bin/sh"
  },
  "drives": [{
    "drive_id": "rootfs",
    "path_on_host": "$PWD/ubuntu-24.04.squashfs",
    "is_root_device": true,
    "is_read_only": true
  }],
  "machine-config": { "vcpu_count": 2, "mem_size_mib": 512 }
}
EOF
```

and boot it, with the serial console on your terminal:

```sh
~/wick/tools/macos/run.sh --release -- --no-api --config-file vm.json
```

A second or so later, after the kernel log, you are at a root shell in the guest:

```console
[    0.669216] Run /bin/sh as init process
# uname -sm
Linux aarch64
# nproc
2
```

`init=/bin/sh` skips the distribution's init system, which keeps the first boot fast and simple. To leave, reset the
guest; Firecracker exits with status 0 (the shell needs `/proc` before `reboot` will act):

```console
# mount -t proc proc /proc; reboot -f
```

Drop `init=/bin/sh` from `boot_args` to boot Ubuntu's own init instead.

## 4. Drive it through the API

The REST API over a Unix socket is the way most tools drive Firecracker, and it is unchanged. Start Firecracker with
an API socket and nothing else (keep the path under 104 bytes, macOS's limit for Unix socket paths):

```sh
~/wick/tools/macos/run.sh --release -- --api-sock /tmp/firecracker.socket
```

Then, from a second terminal in `~/wick-vm`:

```sh
api() { curl -sS --unix-socket /tmp/firecracker.socket -H 'Content-Type: application/json' "$@"; }

api -X PUT http://localhost/boot-source -d "{
  \"kernel_image_path\": \"$PWD/vmlinux-6.1.188\",
  \"boot_args\": \"console=ttyS0 reboot=k panic=1 root=/dev/vda ro rootfstype=squashfs init=/bin/sh\" }"
api -X PUT http://localhost/drives/rootfs -d "{
  \"drive_id\": \"rootfs\", \"path_on_host\": \"$PWD/ubuntu-24.04.squashfs\",
  \"is_root_device\": true, \"is_read_only\": true }"
api -X PUT http://localhost/machine-config -d '{ "vcpu_count": 2, "mem_size_mib": 512 }'
api -X PUT http://localhost/actions -d '{ "action_type": "InstanceStart" }'

api http://localhost/
# {"id":"anonymous-instance","state":"Running","vmm_version":"1.18.0","app_name":"Firecracker"}
```

The guest's console appears in the first terminal. Everything else in
[upstream's API documentation](https://github.com/firecracker-microvm/firecracker/tree/main/docs) applies:
[snapshots](https://github.com/firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md)
(pause, create, restore in another process), [vsock](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md),
[metrics and logging](https://github.com/firecracker-microvm/firecracker/blob/main/docs/logger.md), and the
[OpenAPI specification](https://github.com/firecracker-microvm/firecracker/blob/main/src/firecracker/swagger/firecracker.yaml).

## 5. Networking

On Linux, a network interface is a TAP device, as upstream documents. A Mac has no TAP, so on macOS the
`host_dev_name` of an interface names one of these instead:

| `host_dev_name` | What the guest is connected to |
| --- | --- |
| `vmnet-shared` | NAT to the host's networks (vmnet.framework) |
| `vmnet-host` | The host and other VMs on the same host-only network |
| `vmnet-br-<if>` | Bridged to the host interface `<if>`, for example `vmnet-br-en0` |
| a path, or a name without `/` | A Unix datagram endpoint that a host-side switch exchanges plain Ethernet frames with |

Add an interface to `vm.json`:

```json
"network-interfaces": [
  { "iface_id": "eth0", "host_dev_name": "vmnet-shared", "guest_mac": "06:00:ac:10:00:02" }
]
```

Firecracker logs the network vmnet picked, with the host's address on it: `vmnet: network 192.168.64.1/24`, for
example. In the guest, give `eth0` another address on that network:

```console
# ip addr add 192.168.64.77/24 dev eth0 && ip link set eth0 up
# ping -c 3 192.168.64.1
```

Bridged mode, and every mode before macOS 26, needs root for vmnet.framework; a Unix datagram endpoint never does.

## 6. Run it jailed (macOS)

In production Firecracker runs under the
[jailer](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md), with the same command line
on macOS as on Linux. It needs root, chroots into `<chroot-base-dir>/firecracker/<id>/root` and drops to
`--uid`/`--gid`; paths in the configuration are then inside the jail:

```sh
(cd lib/firecracker && cargo build --locked --release -p jailer)
JAIL=/private/var/wick/firecracker/vm1/root
sudo mkdir -p $JAIL && sudo cp -c ~/wick-vm/vmlinux-6.1.188 ~/wick-vm/ubuntu-24.04.squashfs $JAIL/
sed "s|$HOME/wick-vm/|/|" ~/wick-vm/vm.json | sudo tee $JAIL/vm.json >/dev/null
sudo chown -R 4271:4271 $JAIL
sudo lib/firecracker/build/cargo_target/release/jailer --id vm1 \
  --exec-file lib/firecracker/build/cargo_target/release/firecracker \
  --uid 4271 --gid 4271 --chroot-base-dir /private/var/wick \
  --cgroup memory.limit_in_bytes=1073741824 \
  -- --api-sock /run/firecracker.socket --config-file /vm.json
```

The API socket is then `$JAIL/run/firecracker.socket`. On macOS `--cgroup` takes the memory limit
(`memory.limit_in_bytes`, or `memory.max` with `--cgroup-version 2`): the VMM is killed when it uses more, guest
memory included. It also takes the CPU limit (`cpu.cfs_quota_us` and `cpu.cfs_period_us`, or `cpu.max` with
`--cgroup-version 2`): the VMM's threads are held to that share of a CPU, refilled each second. The freezer's files
are upstream's, in `/private/var/wick/firecracker/vm1/` next to `root/` (`freezer.state`, or `cgroup.freeze` with
`--cgroup-version 2`): writing `FROZEN` (or `1`) as root suspends the jail, kept by a root supervisor process the
jailer leaves for each jail until it ends. The jailer refuses
what macOS cannot enforce, each with its reason: other cgroup controllers (`cpuset.cpus` and `cpuset.mems` only
when they name every CPU and memory node) and CPU limits below 1% or above
255% of one CPU. Networking inside a jail is a Unix datagram endpoint, since the sandbox denies IP networking, and the
jailed Firecracker is not root, which vmnet's bridged mode (and every mode before macOS 26) needs; vmnet-shared
and vmnet-host on macOS 26 need no root but have not yet been run in a jail. The endpoint is in the jail, or in
the jail's network, as on Windows: `--netns DIR` names a directory of
endpoints you made, where a `host_dev_name` without `/` is then made, and your host-side switch binds its own
socket there too (by the directory's real path or a name relative to it). Two jails given one directory share a
network; a jail given its own reaches no other's. [SECURITY.md](../SECURITY.md) has how each control is held.

## Windows (preview)

wick on Windows uses the Windows Hypervisor Platform and x86_64 guests. Turn the feature on first (in
`optionalfeatures.exe`, or as administrator: `Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform`).

The fastest way to try it is the boot test, which downloads upstream's x86_64 CI guest and checks, stage by stage,
what the macOS boot test checks (boot, serial I/O, SMP, block devices, vsock, virtio-net, snapshots, uffd, PCI,
vhost-user, the devices, the command line and more)
([tools/windows/README.md](../tools/windows/README.md) has the steps):

```powershell
powershell -ExecutionPolicy Bypass -File tools\windows\boot-test.ps1
```

It uses `firecracker.exe` next to the script, or the one under `lib\firecracker\build\cargo_target`. CI uploads the
Windows kit (natively built binaries, this script, the jailer test and its probe; listed in
[`tools/windows/README.md`](../tools/windows/README.md)) as a workflow artifact on every run. Network interfaces on Windows
are Unix stream endpoints that a host switch such as gvisor-tap-vsock or passt connects to.

The Windows build has booted guests on one Windows 11 PC so far ([PORTING.md](PORTING.md) lists the stages that
have run there), so the results of a run on other hardware are genuinely useful: please [open an issue](https://github.com/toollyst/wick/issues/new/choose)
with the zip the script writes.

## When something goes wrong

| Symptom | Cause |
| --- | --- |
| `Failed to create VM: Operation not permitted (os error 1)` on macOS | The binary lost its Hypervisor.framework entitlement (rebuilt with plain `cargo`); run it through `tools/macos/run.sh` |
| `error: needs macOS on Apple silicon` | wick on macOS needs Apple silicon and macOS 15 or later (`hv_gic_*`) |
| The API socket can't be created | The path is 104 bytes or longer, or the file already exists from an earlier run |
| `reboot` prints "Running in chroot, ignoring request." | With `init=/bin/sh`, mount `/proc` first |
| The guest kernel doesn't start | The kernel must be built for Firecracker and for the host's architecture; upstream's CI kernels above are |

Still stuck? Open an issue with the command, the Firecracker log and the output of `firecracker --version`.
