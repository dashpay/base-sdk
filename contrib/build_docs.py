#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Build the documentation site."""

from __future__ import annotations

import http.server
import socket
import subprocess
import sys
from functools import partial
from pathlib import Path

from common import RETCODE_ERR, RETCODE_PASS, require_bin, root_dir

SITE_DIR = Path("public")
PREVIEW_PORT = 8000


def _build_site(root: Path, zensical: str) -> None:
  """Run zensical to build the documentation site."""
  subprocess.run(  # noqa: S603
    [zensical, "build", "-f", str(root / "zensical.toml")],
    check=True,
  )


def _build(root: Path) -> None:
  """Run the full build pipeline."""
  zensical = require_bin("zensical")
  _build_site(root, zensical)


def _find_free_port(host: str, start: int) -> int:
  """Return the first port from *start* upward that is not in use."""
  for port in range(start, 65536):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
      try:
        sock.bind((host, port))
        return port
      except OSError:
        continue
  raise RuntimeError("no free port found")


def _preview(root: Path) -> None:
  """Build then serve the site on localhost for testing."""
  _build(root)
  site = root / SITE_DIR

  handler = partial(
    http.server.SimpleHTTPRequestHandler,
    directory=str(site),
  )
  host = "localhost"
  port = _find_free_port(host, PREVIEW_PORT)

  http.server.HTTPServer.allow_reuse_address = True
  srv = http.server.HTTPServer((host, port), handler)
  print(f"serving {site} at http://{host}:{port}")
  try:
    srv.serve_forever()
  except KeyboardInterrupt:
    print("\ninterrupted, shutting down")
  finally:
    srv.server_close()


VERBS = {"build": _build, "preview": _preview}


def main() -> int:
  """Entry point."""
  verb = sys.argv[1] if len(sys.argv) > 1 else "build"
  action = VERBS.get(verb)
  if action is None:
    print(
      f"unknown verb: {verb} (expected: {', '.join(VERBS)})",
      file=sys.stderr,
    )
    return RETCODE_ERR

  root = root_dir()
  action(root)
  return RETCODE_PASS


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
