"""Make right-to-left (Arabic) replies readable on terminals without BiDi.

Most terminal emulators lay text out in *logical* order, left-to-right, and do
**not** implement the Unicode Bidirectional Algorithm (UAX #9) or Arabic
contextual shaping. The result is that an Arabic word like ``العربية`` is shown
with its letters mirrored and disconnected (``ﺔﻴﺑﺮﻌﻟﺍ``) — unreadable.

This module is a small, pure-stdlib reimplementation of the two pieces a proper
terminal would do, applied at the **display layer only** (never to the audit log
or the saved Markdown report, which stay in logical order):

1. **Arabic shaping** — replace each Arabic letter with its contextual
   presentation form (isolated / initial / medial / final) from the
   Arabic Presentation Forms-B block, including the lam-alef ligatures.
2. **BiDi reordering (level 0/1)** — a pragmatic subset of UAX #9: resolve
   neutral runs to their surrounding strong direction, pick a per-line base
   direction from the first strong character, then emit runs in visual order
   (reversing RTL runs) so a dumb terminal, printing left-to-right, shows the
   text the way a BiDi-aware terminal would.

It is not a full UAX #9 implementation — nested embeddings and explicit
direction marks beyond one level are approximated — but it handles the chat-style
mix of Arabic, Latin, digits, punctuation and emoji that the model actually
emits. Use :func:`to_display`; it is a no-op for lines without RTL content.
"""
from __future__ import annotations

import re
import unicodedata

_RESET = "\033[0m"
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

# --- Arabic shaping tables -------------------------------------------------
# base codepoint -> (joining type, start of its run in Presentation Forms-B).
# 'D' dual-joining letters occupy 4 consecutive forms (isolated, final,
# initial, medial); 'R' right-joining letters occupy 2 (isolated, final).
_FORMS_START = {
    0x0622: ("R", 0xFE81), 0x0623: ("R", 0xFE83), 0x0624: ("R", 0xFE85),
    0x0625: ("R", 0xFE87), 0x0626: ("D", 0xFE89), 0x0627: ("R", 0xFE8D),
    0x0628: ("D", 0xFE8F), 0x0629: ("R", 0xFE93), 0x062A: ("D", 0xFE95),
    0x062B: ("D", 0xFE99), 0x062C: ("D", 0xFE9D), 0x062D: ("D", 0xFEA1),
    0x062E: ("D", 0xFEA5), 0x062F: ("R", 0xFEA9), 0x0630: ("R", 0xFEAB),
    0x0631: ("R", 0xFEAD), 0x0632: ("R", 0xFEAF), 0x0633: ("D", 0xFEB1),
    0x0634: ("D", 0xFEB5), 0x0635: ("D", 0xFEB9), 0x0636: ("D", 0xFEBD),
    0x0637: ("D", 0xFEC1), 0x0638: ("D", 0xFEC5), 0x0639: ("D", 0xFEC9),
    0x063A: ("D", 0xFECD), 0x0641: ("D", 0xFED1), 0x0642: ("D", 0xFED5),
    0x0643: ("D", 0xFED9), 0x0644: ("D", 0xFEDD), 0x0645: ("D", 0xFEE1),
    0x0646: ("D", 0xFEE5), 0x0647: ("D", 0xFEE9), 0x0648: ("R", 0xFEED),
    0x0649: ("R", 0xFEEF), 0x064A: ("D", 0xFEF1),
}
# Hamza: a single isolated form, joins to nothing.
_ISOLATED_ONLY = {0x0621: 0xFE80}
# Tatweel (kashida): a join-causing connector whose glyph never changes.
_TATWEEL = 0x0640
# lam (0644) + alef variant -> (isolated ligature, final ligature).
_LAMALEF = {
    0x0622: (0xFEF5, 0xFEF6), 0x0623: (0xFEF7, 0xFEF8),
    0x0625: (0xFEF9, 0xFEFA), 0x0627: (0xFEFB, 0xFEFC),
}


def contains_rtl(text: str) -> bool:
    """Whether ``text`` has any strong right-to-left (Arabic/Hebrew/…) character."""
    return any(unicodedata.bidirectional(ch) in ("R", "AL") for ch in text)


def _jtype(ch: str) -> str | None:
    """Arabic joining type of ``ch``: 'D', 'R', 'C' (tatweel), 'U' (hamza), or None."""
    cp = ord(ch)
    if cp == _TATWEEL:
        return "C"
    if cp in _FORMS_START:
        return _FORMS_START[cp][0]
    if cp in _ISOLATED_ONLY:
        return "U"
    return None


def _joins_prev(bases: list[str], i: int) -> bool:
    """Does the letter at ``i`` connect to the previous one (take final/medial)?"""
    return i > 0 and _jtype(bases[i - 1]) in ("D", "C")


def _joins_next(bases: list[str], i: int) -> bool:
    """Does the letter at ``i`` connect to the next one (take initial/medial)?"""
    return i + 1 < len(bases) and _jtype(bases[i + 1]) in ("D", "R", "C")


def _select_form(cp: int, jt: str, prev: bool, nxt: bool) -> str:
    start = _FORMS_START[cp][1]
    if jt == "R":
        return chr(start + 1) if prev else chr(start)  # final / isolated
    if prev and nxt:
        return chr(start + 3)  # medial
    if prev:
        return chr(start + 1)  # final
    if nxt:
        return chr(start + 2)  # initial
    return chr(start)  # isolated


def shape(text: str) -> str:
    """Replace Arabic letters with their contextual presentation forms.

    Combining marks (harakat) are treated as transparent — they neither break
    joining nor change a letter's form — and are passed through untouched.
    """
    bases: list[str] = []
    marks: list[str] = []  # combining marks trailing each base char
    for ch in text:
        if unicodedata.combining(ch) and bases:
            marks[-1] += ch
        else:
            bases.append(ch)
            marks.append("")
    out: list[str] = []
    i, n = 0, len(bases)
    while i < n:
        cp = ord(bases[i])
        if cp == 0x0644 and i + 1 < n and ord(bases[i + 1]) in _LAMALEF:
            iso, fin = _LAMALEF[ord(bases[i + 1])]
            out.append(chr(fin if _joins_prev(bases, i) else iso))
            out.append(marks[i] + marks[i + 1])
            i += 2
            continue
        jt = _jtype(bases[i])
        if jt is None or jt == "C":
            out.append(bases[i])
        elif jt == "U":
            out.append(chr(_ISOLATED_ONLY[cp]))
        else:
            out.append(_select_form(cp, jt, _joins_prev(bases, i), _joins_next(bases, i)))
        out.append(marks[i])
        i += 1
    return "".join(out)


# --- BiDi reordering (UAX #9, level 0/1 subset) ----------------------------
def _strong(ch: str) -> str:
    """Coarse BiDi class: 'L', 'R', or 'N' (neutral). Digits resolve to 'L'."""
    b = unicodedata.bidirectional(ch)
    if b == "L":
        return "L"
    if b in ("R", "AL"):
        return "R"
    if b in ("EN", "AN"):
        return "L"  # numbers display left-to-right even inside Arabic
    return "N"


class _Cell:
    """One visual unit: a base char plus trailing combining marks, with the ANSI
    codes that preceded it and the strong direction of its base character."""

    __slots__ = ("ansi", "ch", "marks", "cls")

    def __init__(self, ansi: str, ch: str) -> None:
        self.ansi = ansi
        self.ch = ch
        self.marks = ""
        self.cls = _strong(ch)


def _build_cells(line: str) -> tuple[list[_Cell], str]:
    """Split a line into cells, separating ANSI escapes and combining marks."""
    cells: list[_Cell] = []
    pending = ""
    i, n = 0, len(line)
    while i < n:
        m = _ANSI_RE.match(line, i)
        if m:
            pending += m.group(0)
            i = m.end()
            continue
        ch = line[i]
        if unicodedata.combining(ch) and cells:
            cells[-1].marks += ch
            if pending:
                cells[-1].ansi += pending
                pending = ""
        else:
            cell = _Cell(pending, ch)
            pending = ""
            cells.append(cell)
        i += 1
    return cells, pending


def _resolve_neutrals(classes: list[str], base: str) -> list[str]:
    """UAX #9 N1/N2: a neutral run takes its neighbours' direction if they agree,
    otherwise the base direction (line edges count as the base)."""
    res = classes[:]
    n = len(res)
    i = 0
    while i < n:
        if res[i] != "N":
            i += 1
            continue
        j = i
        while j < n and res[j] == "N":
            j += 1
        left = res[i - 1] if i > 0 else base
        right = res[j] if j < n else base
        fill = left if left == right else base
        for k in range(i, j):
            res[k] = fill
        i = j
    return res


def _reorder(cells: list[_Cell]) -> list[_Cell]:
    """Return cells in visual (left-to-right) order for a non-BiDi terminal."""
    classes = [c.cls for c in cells]
    base = next((c for c in classes if c in ("L", "R")), "L")
    res = _resolve_neutrals(classes, base)

    runs: list[tuple[str, list[int]]] = []
    i, n = 0, len(res)
    while i < n:
        j = i
        while j < n and res[j] == res[i]:
            j += 1
        runs.append((res[i], list(range(i, j))))
        i = j

    ordered = reversed(runs) if base == "R" else runs
    visual: list[_Cell] = []
    for direction, idxs in ordered:
        seq = reversed(idxs) if direction == "R" else idxs
        visual.extend(cells[k] for k in seq)
    return visual


def _render_line(line: str) -> str:
    cells, trailing = _build_cells(line)
    # Shaping needs neighbour context, so it runs across cells (lam-alef also
    # merges two cells into one ligature) rather than per isolated character.
    cells = _shape_cells(cells)
    if not cells:
        return trailing
    has_ansi = bool(trailing) or any(c.ansi for c in cells)
    out = "".join(c.ansi + c.ch + c.marks for c in _reorder(cells)) + trailing
    if has_ansi and not out.endswith(_RESET):
        out += _RESET
    return out


def _shape_cells(cells: list[_Cell]) -> list[_Cell]:
    """Apply contextual shaping over the cells' base characters in place,
    collapsing lam-alef pairs into a single ligature cell."""
    bases = [c.ch for c in cells]
    keep: list[_Cell] = []
    i, n = 0, len(bases)
    while i < n:
        cp = ord(bases[i]) if len(bases[i]) == 1 else 0
        if cp == 0x0644 and i + 1 < n and len(bases[i + 1]) == 1 and ord(bases[i + 1]) in _LAMALEF:
            iso, fin = _LAMALEF[ord(bases[i + 1])]
            cells[i].ch = chr(fin if _joins_prev(bases, i) else iso)
            cells[i].marks += cells[i + 1].marks
            keep.append(cells[i])
            i += 2
            continue
        jt = _jtype(bases[i]) if cp else None
        if jt and jt not in ("C", "U"):
            cells[i].ch = _select_form(cp, jt, _joins_prev(bases, i), _joins_next(bases, i))
        elif jt == "U":
            cells[i].ch = chr(_ISOLATED_ONLY[cp])
        keep.append(cells[i])
        i += 1
    return keep


def to_display(text: str, mode: str = "auto") -> str:
    """Reshape ``text`` for display on a terminal that lacks BiDi support.

    Args:
        text: Rendered terminal text (may contain ANSI styling and newlines).
        mode: ``"off"`` returns ``text`` unchanged; ``"on"`` reshapes every line;
            ``"auto"`` (default) reshapes only lines that contain RTL characters.

    Returns:
        The visually-reordered, Arabic-shaped text. Display-only — never feed the
        result back into logic, logs, or saved reports.
    """
    if mode == "off" or not text:
        return text
    lines = text.split("\n")
    return "\n".join(
        _render_line(line) if (mode == "on" or contains_rtl(line)) else line for line in lines
    )
