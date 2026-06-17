"""Tests for the terminal styling helpers."""
from __future__ import annotations

import pytest

from muhgpt import ui


@pytest.fixture(autouse=True)
def restore_auto():
    """Each test sets the color mode explicitly; restore auto-detect after."""
    yield
    ui.set_enabled(None)


def test_no_ansi_when_disabled():
    ui.set_enabled(False)
    assert ui.error("boom") == "boom"
    assert ui.success("ok") == "ok"
    assert "\033[" not in ui.banner("1.0.0")


def test_ansi_emitted_when_enabled():
    ui.set_enabled(True)
    styled = ui.error("boom")
    assert styled.startswith("\033[")
    assert styled.endswith(ui.RESET)
    assert "boom" in styled


def test_banner_contains_art_and_version():
    ui.set_enabled(False)
    out = ui.banner("9.9.9")
    assert "v9.9.9" in out
    assert "pentest & osint assistant" in out
    # the block-letter art survives regardless of color
    assert any("|" in line for line in out.splitlines())


def test_no_color_env_disables(monkeypatch):
    ui.set_enabled(None)
    monkeypatch.setenv("NO_COLOR", "1")
    assert ui.enabled() is False
    assert ui.info("x") == "x"
