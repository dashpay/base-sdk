#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Pre-processing used before generating Zensical documentation."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from common import root_dir
from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor

if TYPE_CHECKING:
  from markdown import Markdown

# Admonition each alert kind is rendered as.
_ALERT_KIND = {
  "NOTE": "note",
  "TIP": "tip",
  "IMPORTANT": "info",
  "WARNING": "warning",
  "CAUTION": "danger",
}

# Matches the marker opening a GitHub-flavoured alert.
_ALERT_RE = re.compile(
  r"^>[ ]?\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\][ ]*(.*)$"
)

# Matches a line carrying the body of a block quote.
_QUOTE_LINE_RE = re.compile(r"^>[ ]?(.*)$")


class GfmAlertsPreprocessor(Preprocessor):
  """Rewrite `> [!NOTE]` blocks into admonition syntax."""

  def run(self, lines: list[str]) -> list[str]:
    source = list(lines)
    output: list[str] = []
    index = 0

    while index < len(source):
      line = source[index]
      match = _ALERT_RE.match(line)
      if match is None:
        output.append(line)
        index += 1
        continue

      level = _ALERT_KIND[match.group(1)]
      output.append(f"!!! {level}")

      first_line = match.group(2).strip()
      body: list[str] = []
      if first_line:
        body.append(first_line)

      index += 1
      while index < len(source):
        quoted = _QUOTE_LINE_RE.match(source[index])
        if quoted is None:
          break
        body.append(quoted.group(1))
        index += 1

      if not body:
        output.append("    ")
        continue

      for body_line in body:
        if body_line:
          output.append(f"    {body_line}")
        else:
          output.append("    ")

    return output


# Matches a splice from another file, or one named section from it.
_INCLUDE_RE = re.compile(r'^\s*--8<--\s+"([^"]+)"\s*$')



class IncludePreprocessor(Preprocessor):
  """Splice in a file from elsewhere in the repository."""

  def run(self, lines: list[str]) -> list[str]:
    output: list[str] = []
    for line in lines:
      match = _INCLUDE_RE.match(line)
      if match is None:
        output.append(line)
      else:
        output.extend(self._include(match.group(1)))
    return output

  def _include(self, spec: str) -> list[str]:
    name, _, section = spec.partition(":")
    source = root_dir() / name
    if not source.is_file():
      raise ValueError(f"{spec}: no such file in the repository")

    lines = source.read_text(encoding="utf-8").splitlines()
    if section:
      lines = _section(lines, section, spec)
    return lines


def _section(lines: list[str], name: str, spec: str) -> list[str]:
  """Return the lines between the markers naming *name*."""
  opener = f"[start:{name}]"
  closer = f"[end:{name}]"
  begin = next((i for i, text in enumerate(lines) if opener in text), None)
  finish = next((i for i, text in enumerate(lines) if closer in text), None)
  if begin is None or finish is None or finish < begin:
    raise ValueError(f"{spec}: no such section")
  return lines[begin + 1 : finish]


class PreprocessorHost(Extension):
  """Markdown extension entrypoint."""

  def extendMarkdown(self, md: Markdown) -> None:
    include = IncludePreprocessor(md)
    md.preprocessors.register(include, "include", 32)
    md.preprocessors.register(GfmAlertsPreprocessor(md), "gfm_alerts", 31)


def makeExtension(**kwargs: object) -> PreprocessorHost:
  """Construct the extension."""
  return PreprocessorHost(**kwargs)
