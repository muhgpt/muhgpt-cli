"""Render a model's Markdown reply into organized, colorized terminal output.

Pure stdlib. Handles the GitHub-flavored Markdown subset that LLMs actually
emit: headings, bold/italic/inline-code, bullet & numbered lists, fenced code
blocks, blockquotes, horizontal rules, and — the headline — pipe tables drawn
with box characters and per-column alignment. Colors come from :mod:`ui`, so
``--no-color`` / non-TTY output still gets the structure (boxes, bullets) just
without the ANSI styling.
"""
from __future__ import annotations

import math
import re

from . import ui

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
_FENCE_RE = re.compile(r"^\s*```(.*)$")
_FENCE_END_RE = re.compile(r"^\s*```\s*$")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_HR_RE = re.compile(r"^\s*([-*_])\1\1+\s*$")
_QUOTE_RE = re.compile(r"^\s*>\s?(.*)$")
_LIST_RE = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")


# --- display-width helpers (ANSI-aware, rough wide-char support) -----------
def _visible(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _width(text: str) -> int:
    """Approximate terminal column width, ignoring ANSI and counting CJK/emoji as 2."""
    total = 0
    for ch in _visible(text):
        o = ord(ch)
        if o == 0 or 0x0300 <= o <= 0x036F or o in (0x200B, 0xFEFF):
            continue  # combining / zero-width
        if (
            0x1100 <= o <= 0x115F
            or 0x2E80 <= o <= 0xA4CF
            or 0xAC00 <= o <= 0xD7A3
            or 0xF900 <= o <= 0xFAFF
            or 0xFE30 <= o <= 0xFE4F
            or 0xFF00 <= o <= 0xFF60
            or 0xFFE0 <= o <= 0xFFE6
            or 0x1F300 <= o <= 0x1FAFF
            or 0x2600 <= o <= 0x27BF
        ):
            total += 2
        else:
            total += 1
    return total


def wrapped_rows(text: str, width: int) -> int:
    """How many terminal rows ``text`` occupies when printed at the given width.

    Used to rewind the cursor for in-place re-rendering of streamed output.
    Accounts for soft-wrapping of long lines and ignores ANSI codes.
    """
    if width <= 0:
        width = 80
    rows = 0
    for line in _visible(text).split("\n"):
        cells = _width(line)
        rows += 1 if cells == 0 else math.ceil(cells / width)
    return rows


def _pad(text: str, width: int, align: str = "left") -> str:
    gap = width - _width(text)
    if gap <= 0:
        return text
    if align == "right":
        return " " * gap + text
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


# --- inline span styling ---------------------------------------------------
def _inline(text: str) -> str:
    """Style inline Markdown: code, bold, italic, links."""
    stash: list[str] = []

    def _hold(match: re.Match) -> str:
        stash.append(match.group(1))
        return f"\x00{len(stash) - 1}\x00"

    text = re.sub(r"`([^`]+)`", _hold, text)  # protect code spans first
    text = re.sub(r"\*\*([^*]+)\*\*", lambda m: ui.style(m.group(1), ui.BOLD), text)
    text = re.sub(r"__([^_]+)__", lambda m: ui.style(m.group(1), ui.BOLD), text)
    text = re.sub(
        r"(?<!\*)\*(?!\*)([^*]+)\*(?!\*)", lambda m: ui.style(m.group(1), ui.ITALIC), text
    )
    text = re.sub(
        r"(?<![A-Za-z0-9_])_([^_]+)_(?![A-Za-z0-9_])",
        lambda m: ui.style(m.group(1), ui.ITALIC),
        text,
    )
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: ui.info(m.group(1)) + ui.dim(f" ({m.group(2)})"),
        text,
    )
    return re.sub(
        r"\x00(\d+)\x00", lambda m: ui.style(stash[int(m.group(1))], ui.fg(216)), text
    )


# --- block renderers -------------------------------------------------------
def _heading(level: int, text: str) -> str:
    prefix = {1: "▌ ", 2: "▌ ", 3: "› "}.get(level, "· ")
    color = {1: ui.fg(213), 2: ui.MAGENTA, 3: ui.CYAN}.get(level, ui.fg(250))
    return ui.style(prefix + text, ui.BOLD, color)


def _code_block(lines: list[str], lang: str) -> str:
    bar = ui.style("│", ui.fg(238))
    out = []
    if lang:
        out.append(ui.dim(f"  {lang}"))
    out.extend(f"  {bar} " + ui.style(line, ui.fg(250)) for line in lines)
    return "\n".join(out)


def _split_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [cell.strip().replace("\\|", "|") for cell in re.split(r"(?<!\\)\|", line)]


def _is_table_separator(line: str) -> bool:
    if "-" not in line:
        return False
    cells = _split_row(line)
    return bool(cells) and all(re.fullmatch(r":?-+:?", c.strip()) for c in cells)


def _alignments(sep_cells: list[str]) -> list[str]:
    aligns = []
    for cell in sep_cells:
        cell = cell.strip()
        left, right = cell.startswith(":"), cell.endswith(":")
        aligns.append("center" if left and right else "right" if right else "left")
    return aligns


def _table(block: list[str]) -> str:
    header = _split_row(block[0])
    aligns = _alignments(_split_row(block[1]))
    rows = [_split_row(r) for r in block[2:]]
    cols = max([len(header)] + [len(r) for r in rows])

    def _norm(row: list[str]) -> list[str]:
        return row + [""] * (cols - len(row))

    header = _norm(header)
    rows = [_norm(r) for r in rows]
    aligns = (aligns + ["left"] * cols)[:cols]

    h_cells = [ui.style(_inline(c), ui.BOLD) for c in header]
    r_cells = [[_inline(c) for c in row] for row in rows]
    widths = [
        max([_width(h_cells[c])] + [_width(row[c]) for row in r_cells]) for c in range(cols)
    ]

    def _rule(left: str, mid: str, right: str) -> str:
        return ui.style(
            left + mid.join("─" * (widths[c] + 2) for c in range(cols)) + right, ui.fg(240)
        )

    vbar = ui.style("│", ui.fg(240))

    def _row(cells: list[str]) -> str:
        parts = [" " + _pad(cells[c], widths[c], aligns[c]) + " " for c in range(cols)]
        return vbar + vbar.join(parts) + vbar

    out = [_rule("┌", "┬", "┐"), _row(h_cells), _rule("├", "┼", "┤")]
    out.extend(_row(r) for r in r_cells)
    out.append(_rule("└", "┴", "┘"))
    return "\n".join(out)


def render_markdown(md: str) -> str:
    """Render a Markdown string into formatted, colorized terminal text."""
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i, n = 0, len(lines)

    while i < n:
        line = lines[i]

        fence = _FENCE_RE.match(line)
        if fence:
            i += 1
            code: list[str] = []
            while i < n and not _FENCE_END_RE.match(lines[i]):
                code.append(lines[i])
                i += 1
            i += 1  # consume closing fence
            out.append(_code_block(code, fence.group(1).strip()))
            continue

        if "|" in line and i + 1 < n and _is_table_separator(lines[i + 1]):
            block = [line, lines[i + 1]]
            i += 2
            while i < n and "|" in lines[i] and lines[i].strip():
                block.append(lines[i])
                i += 1
            out.append(_table(block))
            continue

        heading = _HEADING_RE.match(line)
        if heading:
            out.append(_heading(len(heading.group(1)), heading.group(2).strip()))
            i += 1
            continue

        if _HR_RE.match(line):
            out.append(ui.style("─" * 48, ui.fg(238)))
            i += 1
            continue

        quote = _QUOTE_RE.match(line)
        if quote:
            out.append(ui.style("│ ", ui.fg(244)) + ui.dim(_inline(quote.group(1))))
            i += 1
            continue

        item = _LIST_RE.match(line)
        if item:
            depth = len(item.group(1)) // 2
            marker = item.group(2)
            bullet = ui.accent("•") if marker[-1] in "-*+" else ui.info(marker)
            out.append("  " * depth + f"  {bullet} " + _inline(item.group(3)))
            i += 1
            continue

        out.append(_inline(line) if line.strip() else "")
        i += 1

    return "\n".join(out)
