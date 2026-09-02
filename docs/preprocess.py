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
from pathlib import Path
from typing import TYPE_CHECKING

from common import off_disk, root_dir, spelt_as_stored
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
    fences = _Fences()

    while index < len(source):
      line = source[index]
      # An alert shown inside a fence is an example, not a callout.
      match = None if fences.covers(line) else _ALERT_RE.match(line)
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


# Matches a code block, and whatever trails the marker on that line.
_FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")

# Matches a splice from another file, or one named section from it.
_INCLUDE_RE = re.compile(r'^\s*--8<--\s+"([^"]+)"\s*$')

# Matches the target of an inline link, and any title trailing it.
_LINK_RE = re.compile(
  r"\]\(\s*(<[^<>]*>|[^\s()]+)"
  r"((?:\s+(?:\"[^\"]*\"|'[^']*'|\([^()]*\)))?\s*)\)"
)

# Directory holding this extension, which is the documentation root.
_DOCS_ROOT = Path(__file__).resolve().parent

# Stems Zensical serves as a directory's own index, matched as spelt here.
_INDEX_STEMS = frozenset({"README", "index"})

# How many includes may nest before the splice is called a cycle.
_DEPTH_LIMIT = 8


class _Fences:
  """Running fence state over a sequence of lines."""

  def __init__(self, opener: str | None = None) -> None:
    self.opener = opener

  def covers(self, line: str) -> bool:
    """Whether *line* is fenced, counting the fence markers themselves."""
    marker = _FENCE_RE.match(line)
    if marker is None:
      return self.opener is not None
    found, trailing = marker.group(1), marker.group(2)
    if self.opener is None:
      self.opener = found
    # A closing fence carries no info string, so a marker that does is
    # content the block holds rather than the end of it.
    elif (
      found[0] == self.opener[0]
      and len(found) >= len(self.opener)
      and not trailing.strip()
    ):
      self.opener = None
    return True


def forge_url(repo_url: str, branch: str, source: Path) -> str:
  """Return the URL *source* is served from, by its kind."""
  kind = "tree" if source.is_dir() else "blob"
  where = source.relative_to(root_dir())
  return f"{repo_url}/{kind}/{branch}/{where}"


class IncludePreprocessor(Preprocessor):
  """Splice in a file and parse disk-local links.

  A link is relative to the file holding it, so a link carried in from elsewhere
  in the repository cannot be served from the site and is pointed at the
  upstream host instead.
  """

  def __init__(self, md: Markdown, repo_url: str, branch: str) -> None:
    super().__init__(md)
    self.repo_url = repo_url.rstrip("/")
    self.branch = branch

  def run(self, lines: list[str]) -> list[str]:
    return self._expand(lines, _DEPTH_LIMIT, _Fences())

  def _expand(
    self, lines: list[str], budget: int, fences: _Fences,
  ) -> list[str]:
    """Splice every include in *lines*, recursing *budget* levels deep.

    *fences* is shared across levels because the renderer sees one stream,
    a fence opened by an included file still holds when the parent resumes.
    """
    output: list[str] = []

    for line in lines:
      # A directive inside a fence is the syntax being shown, not used.
      match = None if fences.covers(line) else _INCLUDE_RE.match(line)
      if match is None:
        output.append(line)
        continue
      if budget <= 0:
        raise ValueError(f"{match.group(1)}: includes nested past the limit")
      spliced = self._include(match.group(1), fences)
      output.extend(self._expand(spliced, budget - 1, fences))

    return output

  def _include(self, spec: str, fences: _Fences) -> list[str]:
    name, _, section = spec.partition(":")
    source = (root_dir() / name).resolve()
    # An absolute *name* would displace the root it is joined to, so the
    # containment check has to follow the join rather than precede it.
    if not source.is_relative_to(root_dir()):
      raise ValueError(f"{spec}: outside the repository")
    if not source.is_file():
      raise ValueError(f"{spec}: no such file in the repository")

    lines = source.read_text(encoding="utf-8").splitlines()
    if section:
      lines = _section(lines, section, spec)
    # `_rebase` walks these same lines, so it takes a copy of the fence
    # state at the splice point rather than advancing the caller's.
    return self._rebase(lines, source.parent, _Fences(fences.opener))

  def _rebase(
    self, lines: list[str], home: Path, fences: _Fences,
  ) -> list[str]:
    output: list[str] = []

    for line in lines:
      if fences.covers(line):
        output.append(line)
      else:
        output.append(_LINK_RE.sub(lambda m: self._point(m, home), line))

    return output

  def _point(self, match: re.Match[str], home: Path) -> str:
    target, title = match.group(1), match.group(2)
    caged = target.startswith("<") and target.endswith(">")
    if caged:
      target = target[1:-1]
    if off_disk(target):
      return match.group(0)

    path, mark, rest = target.partition("#")
    # A site-root address resolves against the built site, which only
    # postprocessing can see, so it is left for that pass to anchor.
    if path.startswith("/"):
      return match.group(0)
    source = (home / path).resolve()
    if not source.exists():
      raise ValueError(f"{target}: no such file, relative to {home}")
    if not source.is_relative_to(root_dir()):
      raise ValueError(f"{target}: outside the repository")
    if not spelt_as_stored(root_dir(), source):
      raise ValueError(f"{target}: not spelt as the repository holds it")

    where = f"{self._address(source)}{mark}{rest}"
    return f"]({f'<{where}>' if caged else where}{title})"

  def _address(self, source: Path) -> str:
    """Return where *source* is served from, preferring the site."""
    if source.suffix != ".md" or not source.is_relative_to(_DOCS_ROOT):
      return forge_url(self.repo_url, self.branch, source)

    # A page is addressed from the site root, as the file the link was
    # carried in from says nothing about the page it lands on.
    where = [*source.relative_to(_DOCS_ROOT).parent.parts]
    if source.stem not in _INDEX_STEMS:
      where.append(source.stem)
    return "/" + "".join(f"{part}/" for part in where)


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

  def __init__(self, **kwargs: object) -> None:
    self.config = {
      "repo_url": ["", "Repository the root-relative links point at"],
      "branch": ["", "Branch those links resolve against"],
    }
    super().__init__(**kwargs)

  def extendMarkdown(self, md: Markdown) -> None:
    include = IncludePreprocessor(
      md,
      str(self.getConfig("repo_url")),
      str(self.getConfig("branch")),
    )
    md.preprocessors.register(include, "include", 32)
    md.preprocessors.register(GfmAlertsPreprocessor(md), "gfm_alerts", 31)


def makeExtension(**kwargs: object) -> PreprocessorHost:
  """Construct the extension."""
  return PreprocessorHost(**kwargs)
