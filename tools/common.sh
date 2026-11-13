# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for wick's scripts. Source, don't execute.

WICK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_DIR="$WICK_ROOT/lib/firecracker"
PATCHES_DIR="$WICK_ROOT/patches"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/firecracker-microvm/firecracker.git}"
# The local branch in lib/firecracker that holds the patch series as commits.
# `wick` unless the environment names another: a second worktree of the
# wick checkout, whose lib/firecracker shares its branches with the first's,
# exports and checks its own series from a branch of its own
# (WICK_BRANCH=<branch> tools/patches.sh export|check) without moving `wick`.
# CI and the main checkout never set it.
WICK_BRANCH="${WICK_BRANCH:-wick}"

die() {
    echo "error: $*" >&2
    exit 1
}

# For a script that builds as the user and then asks for sudo itself for
# what needs root (tools/macos/jailer-test.sh, integration-tests.sh): it
# refuses to start as root, before it builds or makes anything. Under sudo,
# cargo builds as root, and the root-owned files it leaves in the build
# directories the user's builds share can make a later build of the user's
# fail: two runs of jailer-test.sh under sudo (build/jailer-test/20261112-13*,
# root-owned) left 272 (cargo's fingerprints and incremental state for the
# jailer, build/jailer-test itself), and the user's jailer build of
# 2026-11-13 failed writing its fingerprint, "Permission denied".
# $1: the script as invoked, $2...: its arguments, for the command to run
# instead.
not_as_root() {
    ((EUID != 0)) && return 0
    local script="$1"
    shift
    die "$script refuses to run as root: it builds as you and asks for sudo itself for what needs root. As root,
cargo would build as root, and the root-owned files left in the build directories your own builds share
(lib/firecracker/build, build/) can make your next build fail with \"Permission denied\".
Run it as yourself, without sudo: $script${*:+ $*}"
}

# git in the upstream checkout. Commits made by the tools (git am, rebase) get
# an identity even on a machine without git config.
up() {
    git -C "$UPSTREAM_DIR" \
        -c user.name="${GIT_COMMITTER_NAME:-$(git config user.name || echo wick)}" \
        -c user.email="${GIT_COMMITTER_EMAIL:-$(git config user.email || echo wick@localhost)}" \
        "$@"
}

# The upstream release tag the patches apply to (patches/base).
upstream_base() {
    tr -d '[:space:]' <"$PATCHES_DIR/base"
}

# wick's fix release number on top of the upstream base (patches/version):
# 0 for the release of the base itself.
wick_number() {
    local n
    n="$(tr -d '[:space:]' <"$PATCHES_DIR/version")" || die "cannot read patches/version"
    [[ "$n" =~ ^(0|[1-9][0-9]*)$ ]] || die "patches/version must hold wick's release number (0, 1, 2, ...), not '$n'"
    echo "$n"
}

# wick's version: the upstream release (1.18.0) for number 0, then
# <upstream>+wick.<N> (1.18.0+wick.1) for wick's fix releases, which never sort
# below the upstream release. The binaries report the same string
# (crates/version reads the same two files at build time).
wick_version() {
    local base n
    base="$(upstream_base)"
    n="$(wick_number)" || exit 1
    if [[ "$n" == 0 ]]; then
        echo "${base#v}"
    else
        echo "${base#v}+wick.$n"
    fi
}

# The patch files, in order (patches/series).
series() {
    grep -v '^\s*\(#\|$\)' "$PATCHES_DIR/series"
}

# Make sure an upstream release tag exists in lib/firecracker (the submodule
# is shallow, so tags are fetched one at a time).
ensure_tag() {
    local tag="$1"
    up rev-parse -q --verify "refs/tags/$tag^{commit}" >/dev/null && return 0
    up fetch -q --no-tags --depth 1 "$UPSTREAM_URL" "refs/tags/$tag:refs/tags/$tag" \
        || die "cannot fetch tag $tag from $UPSTREAM_URL"
}

# The upstream commit wick records for lib/firecracker (the submodule pointer).
recorded_upstream() {
    git -C "$WICK_ROOT" ls-files -s lib/firecracker | awk '$1 == "160000" { print $2 }'
}

# The cargo-deny version upstream's development container installs
# (lib/firecracker/tools/devctr/Dockerfile); wick's dependency checks use the
# same (tools/check-dependencies.sh).
cargo_deny_version() {
    local v
    v="$(sed -n 's/.*cargo install --locked cargo-deny --version \([0-9][0-9.]*\).*/\1/p' \
        "$UPSTREAM_DIR/tools/devctr/Dockerfile")"
    [[ -n "$v" ]] || die "cannot find the cargo-deny version in lib/firecracker/tools/devctr/Dockerfile"
    echo "$v"
}

# The cargo-cyclonedx version that writes the release SBOM
# (tools/package-release.sh).
CARGO_CYCLONEDX_VERSION=0.5.9

# Before a test run: removes what earlier runs left behind (tools/clean.sh:
# old runs, stray test processes, temporary directories), then fails unless
# the file system holding $1 has at least $2 GiB free. A full disk otherwise
# shows up as unrelated failures (vmnet's VMNET_MEM_FAILURE once swap cannot
# grow, short writes of snapshot files).
prepare_test_run() {
    local dir="$1" need_gib="$2" avail_gib mount
    mkdir -p "$dir"
    "$WICK_ROOT/tools/clean.sh" --quiet || echo "warning: tools/clean.sh could not remove everything (see above)" >&2
    avail_gib="$(df -Pk "$dir" | awk 'NR == 2 { print int($4 / 1048576) }')"
    mount="$(df -Pk "$dir" | awk 'NR == 2 { print $6 }')"
    ((avail_gib >= need_gib)) || die "only $avail_gib GiB free on $mount; a test run needs $need_gib GiB (tools/clean.sh --all also removes the build output)"
}
