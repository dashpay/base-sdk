#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Shared constants and helpers for lint scripts."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
  from collections.abc import Callable, Mapping
  from typing import TextIO

# ANSI escape codes for terminal output.
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_RESET = "\033[0m"

# Cargo workspace roots, relative to the repository root.
CARGO_WORKSPACES: tuple[str, ...] = (".", "docs/samples")

# Rust source roots the analysers scan, relative to the repository root.
SOURCE_DIRS: tuple[str, ...] = ("pkgs", "docs/samples")

# Assumed base branch for codebase.
DEFAULT_BASE = "develop"

# Return codes.
RETCODE_ERR = 1
RETCODE_PASS = 0
RETCODE_SKIP = 77

# Matches an address that names something other than a path on disk.
_OFF_DISK_RE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.\-]*:|//|#)")


class _VerbParser(argparse.ArgumentParser):
  """Parser spelling a usage fault in the harness' return codes."""

  def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
    if message:
      self._print_message(message, sys.stderr)
    sys.exit(RETCODE_ERR if status else RETCODE_PASS)


def declare_verbs(
  description: str,
  verbs: Mapping[str, str],
) -> argparse.ArgumentParser:
  """Return a parser taking one of *verbs*.

  *verbs* maps each verb to what it does, and insertion order picks the
  default, so the first entry must avoid mutating effects.
  """
  if not verbs:
    raise ValueError("no verbs declared")
  default = next(iter(verbs))
  parser = _VerbParser(
    description=description,
    formatter_class=argparse.RawTextHelpFormatter,
  )
  parser.add_argument(
    "verb",
    choices=tuple(verbs),
    default=default,
    nargs="?",
    help="\n".join(
      f"{name}: {what}" + (" (default)" if name == default else "")
      for name, what in verbs.items()
    ),
  )
  return parser


def off_disk(target: str) -> bool:
  """Whether *target* addresses something other than a file on disk."""
  return _OFF_DISK_RE.match(target) is not None


@cache
def _entries(where: Path) -> frozenset[str]:
  """Return the names *where* holds, as the filesystem spells them."""
  return frozenset(entry.name for entry in where.iterdir())


def spelt_as_stored(root: Path, target: Path) -> bool:
  """Whether *target* is spelt as the filesystem under *root* holds it.

  A case-insensitive filesystem resolves a misspelt path, so a wrong-case
  link passes `exists()` on macOS and Windows and then serves a 404 from a
  case-sensitive host. Each component is matched against its directory.
  """
  # Normalising first drops the `..` a caller may have left in the path,
  # which names no directory entry and so would fail the walk outright.
  target = target.resolve()
  if not target.is_relative_to(root):
    return True
  probe = root
  for part in target.relative_to(root).parts:
    if part not in _entries(probe):
      return False
    probe = probe / part
  return True


def is_plain_file(root: Path, name: str) -> bool:
  """Whether *name* is a regular file inside *root*, reached without links."""
  path = root / name
  if not path.is_file():
    return False
  try:
    relative = path.relative_to(root)
  except ValueError:
    return False
  probe = root
  for part in relative.parts:
    probe = probe / part
    if probe.is_symlink():
      return False
  return path.resolve().is_relative_to(root.resolve())


def git_run(cwd: Path | str, *args: str) -> subprocess.CompletedProcess[str]:
  """Run a git command in *cwd* and return the result."""
  return subprocess.run(  # noqa: S603
    [require_bin("git"), *args],
    capture_output=True,
    check=False,
    cwd=str(cwd),
    encoding="utf-8",
    errors="replace",
  )


def git_out(cwd: Path | str, *args: str) -> str:
  """Run a git command in *cwd*, raise on failure, return its output."""
  result = git_run(cwd, *args)
  if result.returncode != 0:
    fault = result.stderr.strip() or result.stdout.strip()
    raise RuntimeError(f"git {args[0]}: {fault or result.returncode}")
  return result.stdout.strip()


def relay(
  text: str,
  repo_root: Path,
  *,
  stream: TextIO | None = None,
  drop: Callable[[str], bool] | None = None,
) -> None:
  """Print *text* with paths shortened against *repo_root*."""
  prefix = str(repo_root) + "/"
  for line in text.splitlines():
    if drop is not None and drop(line):
      continue
    print(line.replace(prefix, ""), file=stream or sys.stdout)


def touched(repo_root: Path, suffixes: tuple[str, ...]) -> list[str]:
  """Return the files matching *suffixes* that this branch has changed."""
  base = git_out(repo_root, "merge-base", DEFAULT_BASE, "HEAD")
  return [
    name
    for name in git_out(repo_root, "diff", "--name-only", base).splitlines()
    if name.endswith(suffixes) and is_plain_file(repo_root, name)
  ]


def format_table(
  headers: tuple[str, ...],
  rows: list[tuple[str, ...]],
  status_colors: dict[str, str] | None = None,
) -> str:
  """Render a markdown table with optional color on the last column."""
  colors = status_colors or {}
  widths = [
    max(len(h), *(len(r[i]) for r in rows), 0) for i, h in enumerate(headers)
  ]

  def fmt(cells: tuple[str, ...], *, color: bool = False) -> str:
    parts: list[str] = []
    for i, cell in enumerate(cells):
      pre = post = ""
      if color and i == len(cells) - 1 and colors:
        pre = colors.get(cell, ANSI_DIM)
        post = ANSI_RESET
      pad = widths[i] - len(cell)
      parts.append(f" {pre}{cell}{post}{' ' * pad} ")
    return f"|{'|'.join(parts)}|"

  sep = "|" + "|".join("-" * (w + 2) for w in widths) + "|"
  return "\n".join(
    [
      fmt(headers),
      sep,
      *(fmt(r, color=True) for r in rows),
    ]
  )


def find_up_dir(
  start: Path,
  predicate: Callable[[Path], bool],
  label: str = "matching directory",
  stop: Path | None = None,
) -> Path:
  """Walk upward from *start*, returning the first matching directory.

  The walk ends after *stop* when given, so a directory above the tree
  the caller belongs to cannot answer for one inside it.
  """
  for directory in (start, *start.parents):
    if predicate(directory):
      return directory
    if directory == stop:
      break
  raise FileNotFoundError(f"{label} not found above {start}")


def find_up_file(
  start: Path,
  name: str,
  stop: Path | None = None,
) -> Path | None:
  """Walk upward from *start*, returning the first *name* found."""
  try:
    holder = find_up_dir(
      start,
      lambda d: (d / name).is_file(),
      name,
      stop=stop,
    )
  except FileNotFoundError:
    return None
  return holder / name


def is_workspace_root(d: Path) -> bool:
  """Return True if *d* looks like a Cargo workspace root."""
  cargo = d / "Cargo.toml"
  return (
    cargo.is_file()
    and "[workspace]" in cargo.read_text(encoding="utf-8")
    and (d / "pkgs").is_dir()
  )


def require_bin(name: str, path: str | None = None) -> str:
  """Return the path to *name* or raise FileNotFoundError."""
  result = shutil.which(name, path=path)
  if result is None and os.name == "nt":
    result = shutil.which(f"{name}.exe", path=path)
  if result is None:
    where = "in expected path" if path else "in PATH"
    raise FileNotFoundError(f"error: {name} binary not found {where}")
  return result


@cache
def root_dir() -> Path:
  """Return the workspace root (directory containing Cargo.toml)."""
  return find_up_dir(
    Path(__file__).resolve().parent,
    is_workspace_root,
    "workspace Cargo.toml",
  )


def usable_threads() -> int:
  """Return a conservative thread count (total CPUs minus one)."""
  return max(1, (os.cpu_count() or 2) - 1)


def usable_mem() -> int:
  """Return half the physical RAM in MiB.

  Raises RuntimeError when physical RAM cannot be determined.
  """
  total = _physical_ram_bytes()
  return total // (2 * 1024 * 1024)


def _physical_ram_bytes() -> int:
  """Return total physical RAM in bytes."""
  if sys.platform.startswith("linux"):
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
      if line.startswith("MemTotal:"):
        return int(line.split()[1]) * 1024
    raise RuntimeError("MemTotal not found in /proc/meminfo")
  if sys.platform == "darwin":
    try:
      out = subprocess.check_output(
        ["sysctl", "-n", "hw.memsize"],  # noqa: S607
      )
      return int(out.strip())
    except (
      FileNotFoundError, subprocess.CalledProcessError, ValueError,
    ) as exc:
      raise RuntimeError(
        "could not determine physical RAM on macOS",
      ) from exc
  if sys.platform == "win32":
    try:
      out = subprocess.check_output(
        ["powershell", "-NoProfile", "-Command",  # noqa: S607
         "(Get-CimInstance Win32_ComputerSystem)"
         ".TotalPhysicalMemory"],
      ).decode()
      value = out.strip()
      if value.isdigit():
        return int(value)
    except (FileNotFoundError, subprocess.CalledProcessError):
      pass
    try:
      out = subprocess.check_output(
        ["wmic", "computersystem", "get",  # noqa: S607
         "TotalPhysicalMemory", "/value"],
      ).decode()
      for line in out.splitlines():
        if line.startswith("TotalPhysicalMemory="):
          return int(line.split("=", 1)[1].strip())
    except (FileNotFoundError, subprocess.CalledProcessError, ValueError):
      pass
    raise RuntimeError("could not determine physical RAM on Windows")
  raise RuntimeError(f"unsupported platform: {sys.platform}")
