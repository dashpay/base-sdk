#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Runs CodeQL queries against the workspace."""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _find_workspace_root(start: Path) -> Path:
  """Walk upward from *start* until a workspace Cargo.toml is found."""
  for directory in (start, *start.parents):
    cargo = directory / "Cargo.toml"
    if (
      cargo.is_file()
      and "[workspace]" in cargo.read_text()
      and (directory / "pkgs").is_dir()
    ):
      return directory
  raise FileNotFoundError("workspace Cargo.toml not found")


def _discover_queries(query_dir: Path) -> list[Path]:
  """Return all .ql files in *query_dir*, sorted by name."""
  return sorted(query_dir.glob("*.ql"))


def _discover_ql_sources(query_dir: Path) -> list[Path]:
  """Return all .ql and .qll files in *query_dir* recursively."""
  return sorted(
    [*query_dir.rglob("*.ql"), *query_dir.rglob("*.qll")],
  )


def _print_csv_diagnostics(results_path: Path) -> int:
  """Print CSV results to stderr. Returns the finding count."""
  count = 0
  with results_path.open(newline="") as f:
    for row in csv.DictReader(f):
      uri = row.get("path", "?")
      line = row.get("startline", "0")
      msg = row.get("message", "")
      print(f"{uri}:{line}: {msg}", file=sys.stderr)
      count += 1
  return count


def main() -> int:
  codeql_bin = shutil.which("codeql")
  if codeql_bin is None:
    print("codeql not found in PATH, skipping", file=sys.stderr)
    return 77

  repo_root = _find_workspace_root(Path(__file__).resolve().parent)
  query_dir = repo_root / "contrib" / "codeql"
  queries = _discover_queries(query_dir)

  if not queries:
    print(
      "error: no .ql queries found in contrib/codeql/",
      file=sys.stderr,
    )
    return 1

  # Check QL formatting before doing any heavy lifting.
  ql_sources = _discover_ql_sources(query_dir)
  if ql_sources:
    result = subprocess.run(  # noqa: S603
      [
        codeql_bin,
        "query",
        "format",
        "--check-only",
        "--",
        *[str(p) for p in ql_sources],
      ],
      check=False,
    )
    if result.returncode != 0:
      print(
        "error: QL formatting check failed; run "
        "'codeql query format -i' to fix",
        file=sys.stderr,
      )
      return 1

  # Install CodeQL pack dependencies.
  result = subprocess.run(  # noqa: S603
    [codeql_bin, "pack", "install", "--no-strict-mode", str(query_dir)],
    check=False,
  )
  if result.returncode != 0:
    print(
      "error: codeql pack install failed", file=sys.stderr,
    )
    return 1

  # Create database in a temporary directory.
  with tempfile.TemporaryDirectory() as tmp_dir:
    db_path = Path(tmp_dir) / "db"

    db_env = {**os.environ, "CARGO_INCREMENTAL": "0"}
    result = subprocess.run(  # noqa: S603
      [
        codeql_bin,
        "database",
        "create",
        str(db_path),
        "--language=rust",
        f"--source-root={repo_root / 'pkgs'}",
        "--overwrite",
        f"-j{max(1, (os.cpu_count() or 2) - 1)}",
        "--command=cargo check --features full,_internal",
      ],
      env=db_env,
      check=False,
    )
    if result.returncode != 0:
      print(
        "error: codeql database create failed",
        file=sys.stderr,
      )
      return 1

    # Run each query and collect diagnostics.
    results_dir = query_dir / ".cache" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    results_path = results_dir / "results.csv"

    result = subprocess.run(  # noqa: S603
      [
        codeql_bin,
        "database",
        "analyze",
        str(db_path),
        *[str(q) for q in queries],
        "--format=csv",
        f"--output={results_path}",
        f"--threads={max(1, (os.cpu_count() or 2) - 1)}",
        "--ram=12288",
      ],
      check=False,
    )
    if result.returncode != 0:
      print("error: codeql analyze failed")
      return 1

    total_findings = _print_csv_diagnostics(results_path)

    return 1 if total_findings > 0 else 0


if __name__ == "__main__":
  sys.exit(main())
