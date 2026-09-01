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
import os
import re
import shutil
import socket
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

import rjsmin
from common import (
  RETCODE_ERR,
  RETCODE_PASS,
  declare_verbs,
  require_bin,
  root_dir,
)

if TYPE_CHECKING:
  from collections.abc import Callable

# Parent directory sourced by walking back from current file.
DOCS_DIR = Path(__file__).resolve().parent

# Path to Zensical's configuration file.
CONFIG_FILE = DOCS_DIR / "zensical.toml"

# Starting port the preview server binds to.
PREVIEW_PORT = 8000


@dataclass(frozen=True)
class Config:
  """Settings the build is driven by, as read from *CONFIG_FILE*."""

  # Contents to drop from the site once Zensical has copied it in.
  ignore_file: Path

  # Source directory of sample crates.
  samples_dir: Path

  # Target directory for build output.
  site_dir: Path

  @classmethod
  def load(cls, path: Path) -> Config:
    """Return the settings held by the file at *path*."""
    with path.open("rb") as f:
      settings = tomllib.load(f)
    project = settings["project"]
    build = settings["build_docs"]
    return cls(
      ignore_file=DOCS_DIR / build["ignore_file"],
      samples_dir=DOCS_DIR / build["samples_dir"],
      site_dir=DOCS_DIR / project["site_dir"],
    )


def _build_wasm_samples(root: Path, wasm_pack: str, cfg: Config) -> None:
  """Compile every WASM sample crate under the samples directory."""
  samples = sorted(cfg.samples_dir.glob("*/Cargo.toml"))
  if not samples:
    print("no WASM samples found", file=sys.stderr)
    return

  toolchain_file = root / "rust-toolchain.toml"
  with toolchain_file.open("rb") as f:
    channel = tomllib.load(f)["toolchain"]["channel"]
  env = {
    **os.environ,
    "CARGO_TARGET_DIR": str(root / "target" / "samples"),
    "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS":
      "-C target-feature=+simd128",
    "RUSTUP_TOOLCHAIN": channel,
  }

  for cargo_toml in samples:
    crate_dir = cargo_toml.parent
    name = crate_dir.name
    print(f"building WASM sample: {name}")
    subprocess.run(  # noqa: S603
      [
        wasm_pack,
        "build",
        str(crate_dir),
        "--target",
        "web",
        "--out-dir",
        "pkg",
        "--no-pack",
        "--no-default-features",
      ],
      check=True,
      env=env,
    )


def _build_site(root: Path, zensical: str) -> None:
  """Run zensical to build the documentation site."""
  env = {**os.environ, "PYTHONPATH": str(DOCS_DIR)}
  subprocess.run(  # noqa: S603
    [zensical, "build", "--strict", "-f", str(CONFIG_FILE)],
    check=True,
    cwd=str(root),
    env=env,
  )


def _parse_ignorelist(ignore_file: Path) -> list[str]:
  """Translate *ignore_file* into globs rooted at the built site."""
  globs = []
  lines = ignore_file.read_text(encoding="utf-8").splitlines()
  for number, line in enumerate(lines, start=1):
    entry = line.strip()
    if not entry or entry.startswith("#"):
      continue
    if entry.startswith("!"):
      where = f"{ignore_file.name}:{number}"
      raise ValueError(f"{where}: negation is not supported")
    if entry.startswith("/"):
      globs.append(entry.removeprefix("/"))
    elif "/" in entry.rstrip("/"):
      globs.append(entry)
    else:
      globs.append(f"**/{entry}")
  return globs


def _trim_site(site: Path, ignore_file: Path) -> None:
  """Trim files that are supposed to be excluded from site bundle."""
  for pattern in _parse_ignorelist(ignore_file):
    for stale in sorted(site.glob(pattern)):
      print(f"pruning {stale}")
      if stale.is_dir():
        shutil.rmtree(stale)
      else:
        stale.unlink()


def _generate_pygments_css(site: Path) -> None:
  """Append Pygments syntax-highlight CSS to the built style.css."""
  from pygments.formatters import HtmlFormatter

  # Lines Pygments prepends for line-numbered blocks (unused by this site).
  skip_re = re.compile(r"^(pre |td\.linenos |span\.linenos )")

  parts = []
  for style_name, prefix in (
    ("github-light-default", ".md-typeset .highlight"),
    ("github-dark-default",
     '[data-md-color-scheme="slate"] .md-typeset .highlight'),
  ):
    fmt = HtmlFormatter(style=style_name)
    for line in fmt.get_style_defs(prefix).splitlines():
      if not skip_re.match(line):
        parts.append(line)
    parts.append("")

  css_file = site / "style.css"
  with css_file.open("a", encoding="utf-8") as f:
    f.write("\n")
    f.write("\n".join(parts))

  print(f"appended Pygments CSS to {css_file}")


def _minify_js(site: Path) -> None:
  """Minify JS files in the built sample directories."""
  samples_dir = site / "samples"
  if not samples_dir.is_dir():
    return
  for js in sorted(samples_dir.rglob("*.js")):
    if js.parent.name == "pkg":
      continue
    print(f"minifying {js}")
    original = js.read_text(encoding="utf-8")
    minified = rjsmin.jsmin(original)
    js.write_text(minified, encoding="utf-8")


def _build(root: Path, cfg: Config) -> None:
  """Run the full build pipeline."""
  wasm_pack = require_bin("wasm-pack")
  zensical = require_bin("zensical")

  _build_wasm_samples(root, wasm_pack, cfg)
  _build_site(root, zensical)
  _trim_site(cfg.site_dir, cfg.ignore_file)
  _generate_pygments_css(cfg.site_dir)
  _minify_js(cfg.site_dir)


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


def _preview(root: Path, cfg: Config) -> None:
  """Build then serve the site on localhost for testing."""
  _build(root, cfg)
  site = cfg.site_dir

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


VERBS: dict[str, tuple[Callable[[Path, Config], None], str]] = {
  "build": (_build, "render the site into the directory it is configured for"),
  "preview": (_preview, "render the site, then serve it over localhost"),
}


def main() -> int:
  """Entry point."""
  args = declare_verbs(
    "Build the documentation site.",
    {verb: what for verb, (_, what) in VERBS.items()},
  ).parse_args(sys.argv[1:])
  VERBS[args.verb][0](root_dir(), Config.load(CONFIG_FILE))
  return RETCODE_PASS


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
