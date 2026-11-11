# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Prints `name==version` for each package named, at the version upstream's
poetry.lock (the first argument) has it (tools/windows/integration/venv.ps1)."""

import sys
import tomllib

lock = {p["name"]: p["version"] for p in tomllib.load(open(sys.argv[1], "rb"))["package"]}
for name in sys.argv[2:]:
    if name not in lock:
        sys.exit(f"{name} is not in upstream's poetry.lock")
    print(f"{name}=={lock[name]}")
