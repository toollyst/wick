#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# The Python environment upstream's tests run in (build/integration/venv):
# the packages the framework and the functional and security tests import, at
# the versions of upstream's development container
# (lib/firecracker/tools/devctr/poetry.lock).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../../common.sh"

PACKAGES=(pytest pytest-json-report pytest-timeout pytest-xdist pytest-rerunfailures
    pytest-repeat tenacity psutil requests requests-unixsocket2 filelock semver setproctitle
    pyyaml openapi-spec-validator aws-embedded-metrics numpy scipy pandas ipython packaging)
venv="$WICK_ROOT/build/integration/venv"
pins="$(python3 -I - "$UPSTREAM_DIR/tools/devctr/poetry.lock" "${PACKAGES[@]}" <<'PY'
import sys, tomllib
lock = {p["name"]: p["version"] for p in tomllib.load(open(sys.argv[1], "rb"))["package"]}
for name in sys.argv[2:]:
    if name not in lock:
        sys.exit(f"{name} is not in upstream's poetry.lock")
    print(f"{name}=={lock[name]}")
PY
)"
command -v uv >/dev/null || die "uv is needed (https://docs.astral.sh/uv/)"
uv venv -q --allow-existing -p 3.12 "$venv"
# shellcheck disable=SC2086
VIRTUAL_ENV="$venv" uv pip install -q $pins
echo "$venv"
