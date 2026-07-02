"""Tests for Arabic shaping + BiDi reordering (display-only RTL support)."""
from __future__ import annotations

import re

from muhgpt import bidi

# A few presentation-form codepoints used in assertions.
SEEN_INI = chr(0xFEB3)   # س initial
MEEM_ISO = chr(0xFEE1)   # م isolated
BEH_INI = chr(0xFE8F + 2)  # ب initial (FE91)
LAMALEF_ISO = chr(0xFEFB)  # لا isolated ligature
LAMALEF_FIN = chr(0xFEFC)  # لا final ligature

_ANSI = re.compile(r"\033\[[0-9;]*m")


def _visible(s: str) -> str:
    return _ANSI.sub("", s)


# --- contains_rtl ----------------------------------------------------------
def test_contains_rtl_detects_arabic():
    assert bidi.contains_rtl("مرحبا")
    assert bidi.contains_rtl("hello مرحبا")


def test_contains_rtl_false_for_latin_and_symbols():
    assert not bidi.contains_rtl("hello world 123 !?")
    assert not bidi.contains_rtl("😈🔥 nmap -sV")


# --- shaping ---------------------------------------------------------------
def test_shape_picks_contextual_forms():
    # سلام -> س(initial) + لا ligature(final) + م(isolated)
    assert bidi.shape("سلام") == SEEN_INI + LAMALEF_FIN + MEEM_ISO


def test_shape_lam_alef_isolated_ligature():
    assert bidi.shape("لا") == LAMALEF_ISO


def test_shape_lam_alef_final_after_joining_letter():
    # بلا -> ب(initial) + لا ligature(final)
    assert bidi.shape("بلا") == BEH_INI + LAMALEF_FIN


def test_shape_leaves_non_arabic_untouched():
    assert bidi.shape("abc 123 .") == "abc 123 ."


def test_shape_is_length_preserving_except_ligatures():
    # No lam-alef here, so shaping is one glyph per input letter.
    assert len(bidi.shape("كيف")) == 3


# --- reordering / to_display ----------------------------------------------
def test_all_rtl_line_is_reversed_shaped():
    line = "نعم، أنا أتحدث العربية. كيف يمكنني مساعدتك؟😈🔥"
    assert bidi.to_display(line) == "".join(reversed(bidi.shape(line)))


def test_trailing_emoji_moves_to_visual_start():
    out = bidi.to_display("مرحبا😈")
    assert out[0] == "😈"  # emoji is leftmost in RTL visual order


def test_mixed_base_ltr_keeps_latin_first():
    out = bidi.to_display("IP مفتوح")
    assert out.startswith("IP ")
    assert bidi.contains_rtl(out)  # the Arabic word is still present


def test_digits_keep_their_order_inside_rtl():
    out = bidi.to_display("صفحة 12")
    assert "12" in out  # not reversed to "21"


def test_off_mode_is_identity():
    line = "مرحبا بالعالم"
    assert bidi.to_display(line, "off") == line


def test_non_rtl_text_is_returned_unchanged():
    assert bidi.to_display("hello world") == "hello world"
    assert bidi.to_display("hello world", "on") == "hello world"


def test_multiline_only_touches_rtl_lines():
    text = "title\nمرحبا\nfooter 123"
    out = bidi.to_display(text)
    lines = out.split("\n")
    assert lines[0] == "title"
    assert lines[2] == "footer 123"
    assert lines[1] == "".join(reversed(bidi.shape("مرحبا")))


# --- ANSI preservation -----------------------------------------------------
def test_ansi_codes_are_preserved_around_arabic():
    styled = "\033[1mعنوان\033[0m"
    out = bidi.to_display(styled)
    assert "\033[1m" in out
    assert out.endswith("\033[0m")
    assert len(_visible(out)) == 5  # five Arabic glyphs, reordered


def test_empty_string():
    assert bidi.to_display("") == ""
