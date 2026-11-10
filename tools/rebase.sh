#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Move the patch series to a new upstream release tag (CONTRIBUTING.md,
# "Following upstream").
#
#   tools/rebase.sh <new-tag>            rebase branch `wick` in lib/firecracker
#   tools/rebase.sh --finish <new-tag>   after resolving conflicts and
#                                        `git rebase --continue` there
#
# On success patches/, patches/base, patches/version (wick's number, reset to
# 1) and the lib/firecracker pointer are updated in the index; build, test and
# commit them. The previous series stays in lib/firecracker as branch
# wick-<old-tag>.
#
# Cargo.lock conflicts: take upstream's file, then `cargo update -w` in
# lib/firecracker and amend the lockfile patch.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

finish() {
    local new="$1"
    [[ ! -d "$(up rev-parse --git-path rebase-merge)" && ! -d "$(up rev-parse --git-path rebase-apply)" ]] \
        || die "a rebase is still in progress in lib/firecracker; resolve it and run 'git rebase --continue' first"
    local new_commit
    new_commit="$(up rev-parse "refs/tags/$new^{commit}")"
    up merge-base --is-ancestor "$new_commit" "refs/heads/$WICK_BRANCH" \
        || die "branch $WICK_BRANCH is not based on $new"

    printf '%s\n' "$new" >"$PATCHES_DIR/base"
    # wick's release number counts from 1 again on each upstream release.
    printf '1\n' >"$PATCHES_DIR/version"
    "$WICK_ROOT/tools/patches.sh" export
    git -C "$WICK_ROOT" update-index --cacheinfo "160000,$new_commit,lib/firecracker"
    git -C "$WICK_ROOT" add patches
    "$WICK_ROOT/tools/patches.sh" check
    echo
    echo "Staged upstream $new. Build and test, then:"
    echo "  git commit -m 'lib: Firecracker $new'"
}

if [[ "${1:-}" == "--finish" ]]; then
    [[ $# -eq 2 ]] || die "usage: $0 --finish <new-tag>"
    finish "$2"
    exit 0
fi
[[ $# -eq 1 ]] || die "usage: $0 <new-tag> | --finish <new-tag>"

new="$1"
old="$(upstream_base)"
[[ "$new" != "$old" ]] || die "already on $new"
up diff --quiet && up diff --cached --quiet || die "lib/firecracker has uncommitted changes"
[[ "$("$WICK_ROOT/tools/patches.sh" fingerprint-branch)" == "$("$WICK_ROOT/tools/patches.sh" fingerprint-files)" ]] \
    || die "branch $WICK_BRANCH differs from patches/; export or discard your commits first"

ensure_tag "$old"
ensure_tag "$new"
up branch -f "$WICK_BRANCH-$old" "$WICK_BRANCH"
echo "Saved the $old series as branch $WICK_BRANCH-$old in lib/firecracker"
up checkout -q "$WICK_BRANCH"
if up rebase -q --onto "refs/tags/$new" "refs/tags/$old" "$WICK_BRANCH"; then
    finish "$new"
else
    echo
    echo "Conflicts in lib/firecracker. Resolve them there, then:"
    echo "  git -C lib/firecracker add <files> && git -C lib/firecracker rebase --continue"
    echo "  tools/rebase.sh --finish $new"
    exit 1
fi
