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
  formatted,
  relay,
  require_bin,
  root_dir,
  touched,
)

# Base name of this script (equivalent to argv[0]).
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

  def shorten(out: str, err: str) -> None:
    relay(out, repo_root)
    # Taplo reports the file count on stderr at INFO, so only the lines
    # that name a fault should be emitted.
    relay(
      err,
      repo_root,
      stream=sys.stderr,
      drop=lambda line: line.lstrip().startswith("INFO"),
    )

  # None, not an empty list: with no paths taplo finds its own through
  # '.taplo.toml', so there is no count to report for the whole tree.
  return formatted(
    SCRIPT,
    "TOML file",
    None if only is None else [Path(name) for name in only],
    lambda paths: [
      taplo, "fmt",
      *([] if fix else ["--check", "--diff"]),
      *[str(p) for p in paths],
    ],
    fix=fix,
    scoped=only is not None,
    cwd=repo_root,
    output=shorten,
  )


def _check_yanked(repo_root: Path) -> int | None:
  """Fail on a yanked release, or None when cargo-deny is absent."""
  try:
    deny_bin = require_bin("cargo-deny")
  except FileNotFoundError as e:
    print(f"{e}, skipping the yanked check", file=sys.stderr)
    return None

  print("checking yanked: every crate the graph resolves")
  result = subprocess.run(  # noqa: S603
    [deny_bin, "check", "advisories"],
    capture_output=True,
    check=False,
    cwd=str(repo_root),
    text=True,
  )
  relay(result.stdout, repo_root)
  relay(result.stderr, repo_root, stream=sys.stderr)
  return RETCODE_PASS if result.returncode == 0 else RETCODE_ERR


def main() -> int:
  args = declare_verbs(
    "Validate the crate graph against yanked releases.",
    {
      "check": "report every fault, changing nothing",
      "apply": f"also rewrite TOML this branch changed vs {DEFAULT_BASE}",
      "apply-all": "also rewrite every TOML file in the tree",
    },
  ).parse_args(sys.argv[1:])
  fix = args.verb.startswith("apply")
  repo_root = root_dir()
  only = touched(repo_root, (".toml",)) if args.verb == "apply" else None

  verdicts: list[int | None] = [
    _check_format(repo_root, fix=fix, only=only),
    _check_yanked(repo_root),
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
