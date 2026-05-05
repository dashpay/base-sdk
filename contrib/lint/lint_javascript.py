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

ESLINT_VERSION = "9.39.3"

DEFAULT_TARGETS: tuple[str, ...] = (".github/scripts",)


def find_repo_root(start: Path) -> Path:
  """Walk upward from *start* until a pyproject.toml file is found."""
  for directory in (start, *start.parents):
    if (directory / "pyproject.toml").is_file():
      return directory

  raise FileNotFoundError("pyproject.toml not found")


def main() -> int:
  npx_bin = shutil.which("npx")
  if npx_bin is None:
    print("error: npx binary not found in PATH", file=sys.stderr)
    return 2

  repo_root = find_repo_root(Path(__file__).resolve().parent)
  config_path = repo_root / "contrib" / "js" / "eslint.config.mjs"

  if not config_path.is_file():
    print(f"error: eslint config not found: {config_path}", file=sys.stderr)
    return 2

  targets = [str(repo_root / t) for t in DEFAULT_TARGETS]

  result = subprocess.run(  # noqa: S603
    [
      npx_bin,
      "--yes",
      f"eslint@{ESLINT_VERSION}",
      "--config",
      str(config_path),
      *targets,
    ],
    check=False,
    cwd=str(repo_root),
  )
  return result.returncode


if __name__ == "__main__":
  sys.exit(main())
