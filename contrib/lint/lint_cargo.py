#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Validate and enforce constraints across Rust's build system, cargo.

Includes a TOML formatter using taplo that affects all TOML files regardless of
provenance or origin, exclusions must be defined in '.taplo.toml'
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from common import (
  DEFAULT_BASE,
  RETCODE_ERR,
  RETCODE_PASS,
  RETCODE_SKIP,
  declare_verbs,
  require_bin,
  root_dir,
  touched,
)

SCRIPT = Path(__file__).stem


def _check_format(
  repo_root: Path,
  *,
  fix: bool,
  only: list[str] | None = None,
) -> int | None:
  """Format or check TOML, or None when taplo is absent."""
  try:
    taplo = require_bin("taplo")
  except FileNotFoundError as e:
    print(f"{e}, skipping the format check", file=sys.stderr)
    return None

  if only is not None and not only:
    print(f"{SCRIPT}: no TOML file was touched")
    return RETCODE_PASS

  argv = [taplo, "fmt"] + ([] if fix else ["--check", "--diff"]) + (only or [])
  result = subprocess.run(  # noqa: S603
    argv,
    capture_output=True,
    check=False,
    cwd=str(repo_root),
    text=True,
  )
  prefix = str(repo_root) + "/"
  for line in result.stdout.splitlines():
    print(line.replace(prefix, ""))

  # Taplo reports the file count on stderr at INFO, so only the lines that
  # name a fault should be emitted.
  for line in result.stderr.splitlines():
    if not line.lstrip().startswith("INFO"):
      print(line.replace(prefix, ""), file=sys.stderr)

  if result.returncode != 0:
    if not fix:
      print(
        f"hint: run 'python3 contrib/lint/{SCRIPT}.py apply-all' to rewrite",
        file=sys.stderr,
      )
    return RETCODE_ERR
  scope = (
    f"{len(only)} touched TOML file(s)" if only is not None
    else "every TOML file"
  )
  print(f"{SCRIPT}: rewrote {scope}" if fix else f"{SCRIPT}: {scope} conforms")
  return RETCODE_PASS


def main() -> int:
  args = declare_verbs(
    "Check the TOML the workspace is described in.",
    {
      "check": "report every fault, changing nothing",
      "apply": f"rewrite the TOML this branch touches, against {DEFAULT_BASE}",
      "apply-all": "rewrite every TOML file, whatever its history",
    },
  ).parse_args(sys.argv[1:])
  fix = args.verb.startswith("apply")
  repo_root = root_dir()
  only = touched(repo_root, (".toml",)) if args.verb == "apply" else None

  verdicts: list[int | None] = [
    _check_format(repo_root, fix=fix, only=only),
  ]
  ran = [v for v in verdicts if v is not None]
  if not ran:
    return RETCODE_SKIP
  return RETCODE_ERR if any(v != RETCODE_PASS for v in ran) else RETCODE_PASS


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
