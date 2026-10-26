# SPDX-License-Identifier: Apache-2.0
"""Fail if a tracked source file lacks the SPDX licence header."""

from __future__ import annotations

import subprocess
import sys

HEADER = "SPDX-License-Identifier: Apache-2.0"
SUFFIXES = (".py", ".toml", ".yml", ".yaml", ".sh")
SKIP = {"uv.lock", "pyproject.toml"}


def main() -> int:
    files = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True, timeout=30
    ).stdout.split()
    missing = [
        f
        for f in files
        if f.endswith(SUFFIXES)
        and f.rsplit("/", 1)[-1] not in SKIP
        and HEADER not in "".join(open(f, encoding="utf-8").readlines()[:3])
    ]
    for f in missing:
        print(f"missing SPDX header: {f}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
