"""Tests for main.py internals: stream view, autonomous gate, cost line."""
from __future__ import annotations

import io
import sys

import main
from muhgpt.config import Settings


class FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


# --- _StreamView -----------------------------------------------------------
def test_streamview_delta_then_intermediate_boundary(monkeypatch):
    main.ui.set_enabled(False)
    cap = FakeTTY()
    monkeypatch.setattr(sys, "stdout", cap)
    view = main._StreamView()
    view.delta("hello ")
    view.delta("world")
    view.boundary(final=False)  # intermediate -> just close the line
    main.ui.set_enabled(None)
    assert cap.getvalue() == "\nhello world\n"  # leading newline, pieces, closing newline


def test_streamview_boundary_is_noop_when_nothing_streamed(monkeypatch):
    cap = FakeTTY()
    monkeypatch.setattr(sys, "stdout", cap)
    main._StreamView().boundary(final=True)
    assert cap.getvalue() == ""


def test_streamview_rerenders_final_reply_on_tty(monkeypatch):
    main.ui.set_enabled(True)
    cap = FakeTTY()
    monkeypatch.setattr(sys, "stdout", cap)
    view = main._StreamView()
    for piece in ["## Result\n\n", "| A | B |\n", "|---|---|\n", "| 1 | 2 |\n"]:
        view.delta(piece)
    view.boundary(final=True)
    main.ui.set_enabled(None)
    out = cap.getvalue()
    assert "\033[" in out  # cursor/clear/color control codes were emitted
    assert "┌" in out      # the table was re-rendered with box borders


def test_streamview_keeps_raw_stream_off_tty(monkeypatch):
    main.ui.set_enabled(False)
    cap = io.StringIO()  # not a TTY
    monkeypatch.setattr(sys, "stdout", cap)
    view = main._StreamView()
    view.delta("## R\n\n| A | B |\n|---|---|\n| 1 | 2 |\n")
    view.boundary(final=True)
    main.ui.set_enabled(None)
    out = cap.getvalue()
    assert "\033[" not in out      # no cursor games off-TTY
    assert "|---|" in out          # the raw markdown is left as printed


# --- _authorize_autonomous -------------------------------------------------
def _settings():
    return Settings(api_key="k")


def test_authorize_not_requested_returns_false(session):
    assert main._authorize_autonomous(False, "x", _settings(), session) is False


def test_authorize_interactive_yes(monkeypatch, session):
    monkeypatch.setattr(main, "console_confirm", lambda _p: True)
    main.ui.set_enabled(False)
    try:
        assert main._authorize_autonomous(True, "example.com", _settings(), session) is True
    finally:
        main.ui.set_enabled(None)
    assert any(e["kind"] == "autonomous_authorized" for e in session._events)


def test_authorize_interactive_no_falls_back_to_hitl(monkeypatch, session):
    monkeypatch.setattr(main, "console_confirm", lambda _p: False)
    main.ui.set_enabled(False)
    try:
        assert main._authorize_autonomous(True, "example.com", _settings(), session) is False
    finally:
        main.ui.set_enabled(None)


def test_authorize_noninteractive_does_not_prompt(monkeypatch, session):
    calls = []
    monkeypatch.setattr(main, "console_confirm", lambda _p: calls.append(1) or True)
    main.ui.set_enabled(False)
    try:
        ok = main._authorize_autonomous(
            True, "example.com", _settings(), session, interactive=False
        )
    finally:
        main.ui.set_enabled(None)
    assert ok is True
    assert calls == []  # the flag is the consent; never prompted


# --- cost line -------------------------------------------------------------
def test_cost_helper():
    s = Settings(api_key="k", price_prompt_per_1m=3.0, price_completion_per_1m=15.0)
    assert abs(main._cost(1_000_000, 1_000_000, s) - 18.0) < 1e-9
    assert main._cost(1000, 1000, Settings(api_key="k")) == 0.0  # unpriced -> 0


def test_print_usage_appends_cost_when_priced(capsys, session):
    main.ui.set_enabled(False)
    usage = {"prompt_tokens": 1_000_000, "completion_tokens": 0, "total_tokens": 1_000_000}
    session.add_usage(usage)
    main._print_usage(usage, session, Settings(api_key="k", price_prompt_per_1m=2.0))
    main.ui.set_enabled(None)
    out = capsys.readouterr().out
    assert "tokens" in out and "$2.0000" in out


def test_print_usage_no_cost_when_unpriced(capsys, session):
    main.ui.set_enabled(False)
    usage = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    session.add_usage(usage)
    main._print_usage(usage, session, Settings(api_key="k"))
    main.ui.set_enabled(None)
    out = capsys.readouterr().out
    assert "tokens" in out and "$" not in out


# --- budget wiring ---------------------------------------------------------
def test_auto_max_idle_is_wired_into_the_budget(monkeypatch, tmp_path):
    # Regression: MUHGPT_AUTO_MAX_IDLE was loaded + validated but never passed to
    # Budget, so the no-progress guard always used the default 3. Drive main() in
    # one-shot autonomous mode and capture the Budget handed to the Agent.
    monkeypatch.setenv("MUHGPT_API_KEY", "k")
    monkeypatch.setenv("MUHGPT_AUTO_MAX_IDLE", "7")
    monkeypatch.setenv("MUHGPT_REPORTS_DIR", str(tmp_path))
    captured = {}

    class StubAgent:
        def __init__(self, *_a, **kw):
            captured["budget"] = kw.get("budget")
            self.last_turn_usage = None

        def run_turn(self, _msg):
            return "ok"

    monkeypatch.setattr(main, "Agent", StubAgent)
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--auto", "--objective", "do a thing", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    assert captured["budget"] is not None
    assert captured["budget"].max_idle_rounds == 7
