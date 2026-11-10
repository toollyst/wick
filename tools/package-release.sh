#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Package a macOS (Apple silicon) release of wick in the upstream
# Firecracker release layout.
#
#   tools/package-release.sh <tag> [out-dir]      (default out-dir: dist)
#
# Produces, for tag T:
#   <out>/wick-T-darwin-aarch64.tgz
#       release-T-darwin-aarch64/firecracker-T-darwin-aarch64
#           (release build, signed with the Hypervisor.framework entitlement)
#       release-T-darwin-aarch64/LICENSE, NOTICE
#   <out>/wick-T-darwin-aarch64.tgz.sha256.txt
#       "<hex>  wick-T-darwin-aarch64.tgz"  (checked with `shasum -a 256 -c`)
#
# The binary needs macOS 15 or later on Apple silicon (hv_gic_*). The signature
# is ad hoc; a copy downloaded by a browser gets a quarantine attribute that has
# to be removed (`xattr -d com.apple.quarantine`), one fetched with curl does not.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ROOT="$WICK_ROOT"

tag="${1:-}"
out="${2:-dist}"
[[ -n "$tag" ]] || die "usage: $0 <tag> [out-dir]"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-wick\.[0-9]+$ ]] \
    || die "tag must look like v1.18.0-wick.1 (got '$tag')"
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] \
    || die "needs macOS on Apple silicon"

# The tag's upstream version must be the one wick tracks.
base="$(upstream_base)"
[[ "${tag%%-wick.*}" == "$base" ]] \
    || die "tag $tag does not match the tracked upstream $base (patches/base)"

name="wick-$tag-darwin-aarch64"
bin_name="firecracker-$tag-darwin-aarch64"
dir="release-$tag-darwin-aarch64"
target_dir="${CARGO_TARGET_DIR:-$ROOT/lib/firecracker/build/cargo_target}"

# Build and sign (release profile).
CARGO_TARGET_DIR="$target_dir" "$ROOT/tools/macos/run.sh" --build-only --release

bin="$target_dir/release/firecracker"
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q com.apple.security.hypervisor \
    || die "$bin is not signed with the hypervisor entitlement"

mkdir -p "$out"
out="$(cd "$out" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/$dir"
cp "$bin" "$stage/$dir/$bin_name"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$stage/$dir/"
# The copy must keep the signature (it is embedded in the Mach-O).
codesign --verify --strict "$stage/$dir/$bin_name" || die "signature broken by copy"

# No AppleDouble (._*) files; owner and group normalised.
(cd "$stage" && COPYFILE_DISABLE=1 tar --uid 0 --gid 0 --uname root --gname wheel \
    -czf "$out/$name.tgz" "$dir")
(cd "$out" && shasum -a 256 "$name.tgz" >"$name.tgz.sha256.txt" \
    && shasum -a 256 -c "$name.tgz.sha256.txt" >/dev/null)

echo "$out/$name.tgz"
echo "$out/$name.tgz.sha256.txt"
