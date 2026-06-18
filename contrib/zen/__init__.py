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

from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor

if TYPE_CHECKING:
  from markdown import Markdown

_ALERT_RE = re.compile(
  r"^>[ ]?\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\][ ]*(.*)$"
)
_QUOTE_LINE_RE = re.compile(r"^>[ ]?(.*)$")

_ALERT_KIND = {
  "NOTE": "note",
  "TIP": "tip",
  "IMPORTANT": "info",
  "WARNING": "warning",
  "CAUTION": "danger",
}


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


class GfmAlertsExtension(Extension):
  """Markdown extension entrypoint for alert rewriting."""

  def extendMarkdown(self, md: Markdown) -> None:
    md.preprocessors.register(GfmAlertsPreprocessor(md), "zen", 110)


def makeExtension(**kwargs: object) -> GfmAlertsExtension:
  """Construct the extension."""
  return GfmAlertsExtension(**kwargs)
