"""Tests for the terminal Markdown renderer."""
from __future__ import annotations

import pytest

from muhgpt import ui
from muhgpt.render import _width, render_markdown, wrapped_rows


@pytest.fixture(autouse=True)
def colors_off():
    """Render without ANSI so assertions can match structure and widths directly."""
    ui.set_enabled(False)
    yield
    ui.set_enabled(None)


def test_table_is_boxed_and_columns_align():
    md = "| Name | Age |\n|------|----:|\n| Bob | 5 |\n| Alexandra | 12 |"
    out = render_markdown(md)
    lines = out.splitlines()
    assert lines[0].startswith("┌") and lines[0].endswith("┐")
    assert lines[-1].startswith("└") and lines[-1].endswith("┘")
    assert "Name" in out and "Alexandra" in out
    # With colors off, character length == display width: every row/border line
    # must be the same width, which proves the columns line up.
    assert len({len(line) for line in lines}) == 1


def test_table_right_alignment_pads_on_the_left():
    md = "| K | V |\n|---|--:|\n| a | 7 |"
    rows = render_markdown(md).splitlines()
    data_row = next(r for r in rows if "7" in r)
    # right-aligned cell -> the digit hugs the trailing border, space before it
    assert data_row.rstrip("│").endswith(" 7 ")


def test_headings_and_bullets():
    out = render_markdown("# Title\n\n- one\n- two")
    assert "Title" in out
    assert out.count("•") == 2


def test_numbered_list_keeps_markers():
    out = render_markdown("1. first\n2. second")
    assert "1." in out and "2." in out


def test_code_block_is_left_untouched_inside():
    out = render_markdown("```bash\nnmap -sV **target**\n```")
    # inline markdown must NOT be interpreted inside a fenced block
    assert "**target**" in out


def test_inline_styling_emits_ansi_when_colors_on():
    ui.set_enabled(True)
    out = render_markdown("plain **bold** and `code`")
    assert "\033[1m" in out  # bold
    assert "\033[" in out
    ui.set_enabled(None)


def test_plain_text_passes_through():
    assert render_markdown("just a sentence.") == "just a sentence."


def test_width_counts_wide_chars_as_two():
    assert _width("ab") == 2
    assert _width("漢字") == 4


def test_wrapped_rows_accounts_for_soft_wrap_and_newlines():
    assert wrapped_rows("abc", 80) == 1
    assert wrapped_rows("", 80) == 1
    assert wrapped_rows("a" * 81, 80) == 2
    assert wrapped_rows("a" * 160, 80) == 2
    assert wrapped_rows("line1\nline2", 80) == 2
    assert wrapped_rows("x\n" + "y" * 81, 80) == 3  # 1 + 2 wrapped
