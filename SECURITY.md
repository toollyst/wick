# Security policy

## Reporting a vulnerability

Please report vulnerabilities in wick privately through GitHub:
[Report a vulnerability](https://github.com/toollyst/wick/security/advisories/new).
Do not open a public issue.

wick's own code is everything outside `lib/firecracker`: the compatibility
crates, the overlay modules, the patches and the tools. A vulnerability that
also affects upstream Firecracker on Linux (code in `lib/firecracker` that wick
does not change) belongs to the Firecracker project; report it to AWS as
described in [Firecracker's security policy](https://github.com/firecracker-microvm/firecracker/blob/main/SECURITY.md).
If you are not sure which, report it here and we will coordinate.

## Supported versions

Security fixes go into the latest release: `v<upstream>`, or a fix release
`v<upstream>+wick.<N>` on it.

## Security model

On Linux, wick builds upstream Firecracker with its own isolation: KVM, the
minimal device model, seccomp filters and the jailer. On macOS and Windows the
VMM process is confined with the host's sandbox (Seatbelt; process mitigation
policies), and jailer equivalents are in progress; see
[docs/ROADMAP.md](docs/ROADMAP.md), "Security parity". Until that work lands,
do not run untrusted multi-tenant workloads on macOS or Windows hosts.
