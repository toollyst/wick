#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Dependency policy (CONTRIBUTING.md, "Dependencies"): the checks CI and the
# release workflow run on lib/firecracker's Cargo.lock (with wick's patches)
# and tools/vhost-user-blk's.
#
#   tools/check-dependencies.sh
#
# 1. cargo-deny with upstream's own policy (lib/firecracker/deny.toml) on
#    lib/firecracker, as upstream runs it, so wick never accepts what upstream
#    would refuse.
# 2. cargo-deny with wick's policy (tools/deny.toml, and
#    tools/vhost-user-blk/deny.toml for the test backend), warnings as errors:
#    RustSec advisories (vulnerable, unmaintained, unsound, yanked), licenses,
#    banned and duplicate crates, and a closed list of sources.
# 3. tools/linux/check-dependency-sources.py: every crate taken from git is
#    the crates.io release upstream's Cargo.lock uses.
#
# cargo-deny must be the version upstream's development container installs
# (lib/firecracker/tools/devctr/Dockerfile); CARGO_DENY names the binary
# (default: cargo-deny on PATH). Needs the network: the advisory database,
# crates.io and the git dependencies.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ROOT="$WICK_ROOT"
DENY="${CARGO_DENY:-cargo-deny}"

[[ -f "$UPSTREAM_DIR/Cargo.toml" ]] || die "lib/firecracker is not checked out; run tools/setup.sh"

sha256() {
    if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

want="$(cargo_deny_version)"
command -v "$DENY" >/dev/null \
    || die "cargo-deny not found; install upstream's version: cargo install --locked cargo-deny --version $want"
have="$("$DENY" --version)"
[[ "$have" == "cargo-deny $want" ]] \
    || die "need cargo-deny $want (upstream's), found '$have': cargo install --locked cargo-deny --version $want"

# tools/deny.toml carries upstream's policy over and records which version of it.
recorded="$(sed -n 's/^# upstream-deny-sha256: //p' "$ROOT/tools/deny.toml")"
actual="$(sha256 "$UPSTREAM_DIR/deny.toml")"
[[ "$recorded" == "$actual" ]] \
    || die "lib/firecracker/deny.toml (sha256 $actual) is not the file tools/deny.toml was made from ($recorded); carry its changes over to tools/deny.toml and tools/vhost-user-blk/deny.toml"

failed=()
run() {
    local what="$1"
    shift
    echo "--- $what"
    if "$@"; then
        echo "--- $what: ok"
    else
        echo "--- $what: FAILED"
        failed+=("$what")
    fi
}

fc="$UPSTREAM_DIR/Cargo.toml"
vub="$ROOT/tools/vhost-user-blk/Cargo.toml"
run "upstream's policy, lib/firecracker" \
    "$DENY" --manifest-path "$fc" --locked check --config "$UPSTREAM_DIR/deny.toml"
run "wick's policy, lib/firecracker" \
    "$DENY" --manifest-path "$fc" --locked check --config "$ROOT/tools/deny.toml" -D warnings
run "wick's policy, tools/vhost-user-blk" \
    "$DENY" --manifest-path "$vub" --locked check --config "$ROOT/tools/vhost-user-blk/deny.toml" -D warnings

# The git checkouts the next check compares with crates.io.
(cd "$UPSTREAM_DIR" && cargo fetch --locked -q)
(cd "$ROOT/tools/vhost-user-blk" && cargo fetch --locked -q)
run "git dependencies are upstream's crates.io releases" \
    python3 -I "$ROOT/tools/linux/check-dependency-sources.py" \
    "${CARGO_HOME:-$HOME/.cargo}/git/checkouts" "$ROOT/tools/vhost-user-blk/Cargo.lock"

((${#failed[@]} == 0)) || die "dependency checks failed: $(IFS=,; echo "${failed[*]}")"
echo "dependency checks passed"
