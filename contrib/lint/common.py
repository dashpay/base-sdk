#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Shared constants and helpers for lint scripts."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from collections.abc import Callable

RETCODE_ERR = 1
RETCODE_PASS = 0
RETCODE_SKIP = 77


def find_up(
  start: Path,
  predicate: Callable[[Path], bool],
  label: str = "matching directory",
) -> Path:
  """Walk upward from *start*, returning the first matching directory."""
  for directory in (start, *start.parents):
    if predicate(directory):
      return directory
  raise FileNotFoundError(f"{label} not found above {start}")


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


def root_dir() -> Path:
  """Return the workspace root (directory containing Cargo.toml)."""
  return find_up(
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
