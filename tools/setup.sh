#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Prepare lib/firecracker for building: check out upstream at the release in
# patches/base and apply the patch series as commits on the local branch
# `wick`. Run it after cloning and after pulling changes to patches/.
#
#   tools/setup.sh           set up, or confirm lib/firecracker is up to date
#   tools/setup.sh --force   discard local commits on `wick` and set up again
#
# Your own changes to upstream files live as commits on `wick` in
# lib/firecracker; tools/patches.sh export turns them back into patches/.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

force=0
[[ "${1:-}" == "--force" ]] && force=1

cd "$WICK_ROOT"
if [[ ! -e "$UPSTREAM_DIR/.git" ]]; then
    git submodule update --init lib/firecracker
fi

base="$(upstream_base)"
ensure_tag "$base"
base_commit="$(up rev-parse "refs/tags/$base^{commit}")"
[[ "$(recorded_upstream)" == "$base_commit" ]] \
    || die "lib/firecracker is recorded at $(recorded_upstream), but patches/base says $base ($base_commit)"

# Already set up: `wick` is the series on top of the base, nothing else.
if up rev-parse -q --verify "refs/heads/$WICK_BRANCH" >/dev/null && ((force == 0)); then
    if [[ "$("$WICK_ROOT/tools/patches.sh" fingerprint-branch)" == "$("$WICK_ROOT/tools/patches.sh" fingerprint-files)" ]]; then
        if [[ "$(up symbolic-ref -q --short HEAD || true)" != "$WICK_BRANCH" ]]; then
            up checkout -q "$WICK_BRANCH"
        fi
        echo "lib/firecracker is up to date: upstream $base + $(series | wc -l | tr -d ' ') patches on branch $WICK_BRANCH"
        exit 0
    fi
    die "branch $WICK_BRANCH in lib/firecracker differs from patches/.
  Keep your commits there:   tools/patches.sh export
  Or discard them:           tools/setup.sh --force"
fi

up diff --quiet && up diff --cached --quiet \
    || die "lib/firecracker has uncommitted changes; commit or discard them first"

up checkout -q -B "$WICK_BRANCH" "$base_commit"
patches=()
while IFS= read -r p; do
    patches+=("$PATCHES_DIR/$p")
done < <(series)
if ! up am -q --3way "${patches[@]}"; then
    up am --abort || true
    die "the patches do not apply to upstream $base"
fi
echo "lib/firecracker: upstream $base + ${#patches[@]} patches on branch $WICK_BRANCH"
echo "Build:  cd lib/firecracker && cargo build -p firecracker"
