#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def find_repo_root(start: Path) -> Path:
  """Walk upward from *start* until a pyproject.toml file is found."""
  for directory in (start, *start.parents):
    if (directory / "pyproject.toml").is_file():
      return directory

  raise FileNotFoundError("pyproject.toml not found")


def main() -> int:
  ruff_bin = shutil.which("ruff")
  if ruff_bin is None:
    print("error: ruff binary not found in PATH", file=sys.stderr)
    return 2

  repo_root = find_repo_root(Path(__file__).resolve().parent)
  result = subprocess.run(  # noqa: S603
    [ruff_bin, "check", str(repo_root)],
    check=False,
  )
  return result.returncode


if __name__ == "__main__":
  sys.exit(main())
