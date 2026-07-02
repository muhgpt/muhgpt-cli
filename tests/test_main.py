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


def test_streamview_reorders_rtl_even_with_colors_off(monkeypatch):
    # --no-color (ui disabled) must still re-render to reorder Arabic, which the
    # terminal would otherwise show with letters mirrored and disconnected.
    main.ui.set_enabled(False)
    cap = FakeTTY()
    monkeypatch.setattr(sys, "stdout", cap)
    view = main._StreamView(bidi_mode="auto")
    view.delta("مرحبا")
    view.boundary(final=True)
    main.ui.set_enabled(None)
    out = cap.getvalue()
    assert "\033[J" in out                               # the streamed block was cleared
    assert main.bidi.to_display("مرحبا", "auto") in out  # and replaced with the reshaped form


def test_streamview_leaves_rtl_raw_when_bidi_off(monkeypatch):
    main.ui.set_enabled(False)
    cap = FakeTTY()
    monkeypatch.setattr(sys, "stdout", cap)
    view = main._StreamView(bidi_mode="off")
    view.delta("مرحبا")
    view.boundary(final=True)  # colors off + bidi off -> no re-render
    main.ui.set_enabled(None)
    assert cap.getvalue() == "\nمرحبا\n"


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


# --- _build_mcp (no-network paths) -----------------------------------------
def test_research_model_flag_wires_research_client(monkeypatch, tmp_path):
    # --research-model must build a research client and hand it to the registry.
    monkeypatch.setenv("MUHGPT_API_KEY", "k")
    monkeypatch.setenv("MUHGPT_REPORTS_DIR", str(tmp_path))
    captured = {}

    class StubReg:
        def __init__(self, *_a, **kw):
            captured["research_client"] = kw.get("research_client")

    class StubAgent:
        def __init__(self, *_a, **_kw):
            self.last_turn_usage = None

        def run_turn(self, _msg):
            return "ok"

    monkeypatch.setattr(main, "ToolRegistry", StubReg)
    monkeypatch.setattr(main, "Agent", StubAgent)
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--research-model", "relace-search", "--objective", "x", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    assert captured["research_client"] is not None


def test_no_research_disables_even_when_enabled_in_env(monkeypatch, tmp_path):
    monkeypatch.setenv("MUHGPT_API_KEY", "k")
    monkeypatch.setenv("MUHGPT_RESEARCH_ENABLED", "1")
    monkeypatch.setenv("MUHGPT_REPORTS_DIR", str(tmp_path))
    captured = {}

    class StubReg:
        def __init__(self, *_a, **kw):
            captured["research_client"] = kw.get("research_client")

    class StubAgent:
        def __init__(self, *_a, **_kw):
            self.last_turn_usage = None

        def run_turn(self, _msg):
            return "ok"

    monkeypatch.setattr(main, "ToolRegistry", StubReg)
    monkeypatch.setattr(main, "Agent", StubAgent)
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--no-research", "--objective", "x", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    assert captured["research_client"] is None


# --- first-run API-key setup ------------------------------------------------
class _StubBalanceClient:
    def __init__(self, *_a, **_kw):
        pass

    def get_usage(self, *_a, **_k):
        return {}

    def list_models(self, *_a, **_k):
        return [{"id": "muh-chat", "owned_by": "muhgpt"}]


def test_first_run_setup_prompts_saves_and_runs(monkeypatch, tmp_path, capsys):
    # No key anywhere + interactive stdin -> prompt, save to user config, then run.
    monkeypatch.delenv("MUHGPT_API_KEY", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("MUHGPT_REPORTS_DIR", str(tmp_path / "reports"))

    class _TTY:
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", _TTY())
    monkeypatch.setattr("builtins.input", lambda _p="": "mghp_pastedkey")
    monkeypatch.setattr(main, "MuhGPTClient", _StubBalanceClient)
    monkeypatch.setattr(main, "Agent", _stub_agent())
    main.ui.set_enabled(False)
    try:
        # --env-file at a nonexistent path so the repo's real .env is never read.
        rc = main.main(["--env-file", str(tmp_path / "noenv"), "--objective", "x", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    from muhgpt.config import user_config_path

    assert "mghp_pastedkey" in user_config_path().read_text()  # persisted
    assert "Saved to" in capsys.readouterr().out


def test_first_run_rejects_non_muhgpt_paste_then_reprompts(monkeypatch, tmp_path, capsys):
    # A paste that isn't an 'mghp_' key is rejected up front and re-prompted;
    # only the valid key is ever persisted.
    monkeypatch.delenv("MUHGPT_API_KEY", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("MUHGPT_REPORTS_DIR", str(tmp_path / "reports"))

    class _TTY:
        def isatty(self):
            return True

    pastes = iter(["not-a-key", "sk-openai-wrongvendor", "mghp_goodkey"])
    monkeypatch.setattr(sys, "stdin", _TTY())
    monkeypatch.setattr("builtins.input", lambda _p="": next(pastes))
    monkeypatch.setattr(main, "MuhGPTClient", _StubBalanceClient)
    monkeypatch.setattr(main, "Agent", _stub_agent())
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--env-file", str(tmp_path / "noenv"), "--objective", "x", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    from muhgpt.config import user_config_path

    saved = user_config_path().read_text()
    assert "mghp_goodkey" in saved and "not-a-key" not in saved  # only the valid one
    out = capsys.readouterr().out
    assert out.count("start with 'mghp_'") >= 2  # both bad pastes flagged


def test_first_run_rejects_invalid_key_via_api_then_reprompts(monkeypatch, tmp_path, capsys):
    # A well-formed 'mghp_' key the API rejects with 401 is not saved; re-prompt
    # until a key validates.
    monkeypatch.delenv("MUHGPT_API_KEY", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("MUHGPT_REPORTS_DIR", str(tmp_path / "reports"))

    from muhgpt.api_client import APIStatusError

    class _AuthCheckingClient:
        def __init__(self, settings, *_a, **_kw):
            self._key = settings.api_key

        def get_usage(self, *_a, **_k):
            return {}

        def list_models(self, *_a, **_k):
            if self._key != "mghp_goodkey":
                raise APIStatusError(401, "invalid key", error_type="invalid_api_key")
            return [{"id": "muh-chat", "owned_by": "muhgpt"}]

    class _TTY:
        def isatty(self):
            return True

    pastes = iter(["mghp_revoked", "mghp_goodkey"])
    monkeypatch.setattr(sys, "stdin", _TTY())
    monkeypatch.setattr("builtins.input", lambda _p="": next(pastes))
    monkeypatch.setattr(main, "MuhGPTClient", _AuthCheckingClient)
    monkeypatch.setattr(main, "Agent", _stub_agent())
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--env-file", str(tmp_path / "noenv"), "--objective", "x", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    from muhgpt.config import user_config_path

    saved = user_config_path().read_text()
    assert "mghp_goodkey" in saved and "mghp_revoked" not in saved
    assert "rejected that key" in capsys.readouterr().out


def test_first_run_accepts_valid_key_when_api_unreachable(monkeypatch, tmp_path, capsys):
    # A network error while validating must NOT block setup — the key is saved and
    # the real auth check happens on first use.
    monkeypatch.delenv("MUHGPT_API_KEY", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("MUHGPT_REPORTS_DIR", str(tmp_path / "reports"))

    from muhgpt.api_client import MuhGPTError

    class _OfflineClient:
        def __init__(self, *_a, **_kw):
            pass

        def get_usage(self, *_a, **_k):
            return {}

        def list_models(self, *_a, **_k):
            raise MuhGPTError("network down")

    class _TTY:
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", _TTY())
    monkeypatch.setattr("builtins.input", lambda _p="": "mghp_offlinekey")
    monkeypatch.setattr(main, "MuhGPTClient", _OfflineClient)
    monkeypatch.setattr(main, "Agent", _stub_agent())
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--env-file", str(tmp_path / "noenv"), "--objective", "x", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    from muhgpt.config import user_config_path

    assert "mghp_offlinekey" in user_config_path().read_text()


def test_missing_key_non_interactive_still_errors(monkeypatch, tmp_path, capsys):
    # Piped / cron (no TTY): keep the hard config error — never hang on input.
    monkeypatch.delenv("MUHGPT_API_KEY", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))

    class _NoTTY:
        def isatty(self):
            return False

    monkeypatch.setattr(sys, "stdin", _NoTTY())
    main.ui.set_enabled(False)
    try:
        # --env-file nonexistent so the repo's real .env can't satisfy the key.
        rc = main.main(["--env-file", str(tmp_path / "noenv"), "--objective", "x", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 2
    assert "MUHGPT_API_KEY is not set" in capsys.readouterr().err


# --- models / balance / typed-error hints ----------------------------------
def test_error_hint_maps_typed_api_errors():
    from muhgpt.api_client import APIStatusError

    assert "out of credits" in main._error_hint(
        APIStatusError(402, "x", error_type="insufficient_quota"))
    assert "/models" in main._error_hint(APIStatusError(404, "x", error_type="model_not_found"))
    assert "/models" in main._error_hint(APIStatusError(403, "x"))       # by status code
    assert "API key" in main._error_hint(APIStatusError(401, "x"))
    assert main._error_hint(APIStatusError(500, "x")) == ""              # unknown -> no hint


def test_render_models_marks_current():
    out = main._render_models(
        [{"id": "muh-chat", "owned_by": "muhgpt"}, {"id": "gpt-4o", "owned_by": "muhgpt"}],
        "muh-chat",
    )
    assert "muh-chat" in out and "gpt-4o" in out and "current" in out


def test_render_usage_shows_balance_and_totals():
    out = main._render_usage({
        "balance": 12500, "totals": {"credits": 5000, "tokens": 1000, "requests": 4},
        "start": "2026-06-01", "end": "2026-06-30",
        "by_model": [{"model": "muh-chat", "credits": 4500, "requests": 40}],
    })
    assert "12,500" in out and "5,000" in out and "requests" in out and "muh-chat" in out


def _stub_agent():
    class StubAgent:
        def __init__(self, *_a, **_kw):
            self.last_turn_usage = None

        def run_turn(self, _msg):
            return "ok"

    return StubAgent


def test_startup_balance_line_shown(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("MUHGPT_API_KEY", "k")
    monkeypatch.setenv("MUHGPT_REPORTS_DIR", str(tmp_path))

    class StubClient:
        def __init__(self, *_a, **_kw):
            pass

        def get_usage(self, start=None, end=None):
            return {"balance": 4242}

    monkeypatch.setattr(main, "MuhGPTClient", StubClient)
    monkeypatch.setattr(main, "Agent", _stub_agent())
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--objective", "x", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    assert "4,242 remaining" in capsys.readouterr().out


def test_no_balance_flag_suppresses_startup_line(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("MUHGPT_API_KEY", "k")
    monkeypatch.setenv("MUHGPT_REPORTS_DIR", str(tmp_path))

    class StubClient:
        def __init__(self, *_a, **_kw):
            pass

        def get_usage(self, *_a, **_k):
            raise AssertionError("get_usage must not be called with --no-balance")

    monkeypatch.setattr(main, "MuhGPTClient", StubClient)
    monkeypatch.setattr(main, "Agent", _stub_agent())
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--no-balance", "--objective", "x", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    assert "remaining" not in capsys.readouterr().out


def test_startup_balance_is_best_effort_on_error(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("MUHGPT_API_KEY", "k")
    monkeypatch.setenv("MUHGPT_REPORTS_DIR", str(tmp_path))

    class StubClient:
        def __init__(self, *_a, **_kw):
            pass

        def get_usage(self, *_a, **_k):
            raise RuntimeError("network down")

    monkeypatch.setattr(main, "MuhGPTClient", StubClient)
    monkeypatch.setattr(main, "Agent", _stub_agent())
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--objective", "x", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0  # a balance error never aborts the session
    out = capsys.readouterr().out
    assert "remaining" not in out and "Done." in out


# --- guard inspector + extra-recon wiring ----------------------------------
def test_classify_inspector_blocks_without_api_key(monkeypatch, capsys):
    # --classify must work with NO MUHGPT_API_KEY (like --version): early return.
    monkeypatch.delenv("MUHGPT_API_KEY", raising=False)
    monkeypatch.delenv("MUHGPT_EXTRA_SAFE_RECON", raising=False)
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--no-color", "--classify", "rm -rf /"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    out = capsys.readouterr().out
    assert "BLOCK" in out and "rm -rf /" in out


def test_classify_inspector_allows_mixed_case_tool(monkeypatch, capsys):
    monkeypatch.delenv("MUHGPT_API_KEY", raising=False)
    monkeypatch.delenv("MUHGPT_EXTRA_SAFE_RECON", raising=False)
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--no-color", "--classify", "theHarvester -d example.com"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    assert "ALLOW" in capsys.readouterr().out


def test_classify_inspector_reports_extra_recon(monkeypatch, capsys):
    monkeypatch.delenv("MUHGPT_API_KEY", raising=False)
    monkeypatch.delenv("MUHGPT_EXTRA_SAFE_RECON", raising=False)
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--no-color", "--extra-recon", "gobuster,bash",
                        "--classify", "gobuster dir -u http://x"])
    finally:
        main.ui.set_enabled(None)
    out = capsys.readouterr().out
    assert rc == 0
    assert "ALLOW" in out
    assert "gobuster" in out  # accepted
    assert "bash" in out      # rejected (never-allowlist)


def test_extra_recon_flag_wires_a_working_classifier(monkeypatch, tmp_path):
    # The classifier built from --extra-recon is what ToolRegistry receives, and it
    # honors the added tool while keeping the denylist intact.
    monkeypatch.setenv("MUHGPT_API_KEY", "k")
    monkeypatch.setenv("MUHGPT_REPORTS_DIR", str(tmp_path))
    monkeypatch.delenv("MUHGPT_EXTRA_SAFE_RECON", raising=False)
    captured = {}

    class StubReg:
        def __init__(self, *_a, **kw):
            captured["classifier"] = kw.get("classifier")

    class StubAgent:
        def __init__(self, *_a, **_kw):
            self.last_turn_usage = None

        def run_turn(self, _msg):
            return "ok"

    monkeypatch.setattr(main, "ToolRegistry", StubReg)
    monkeypatch.setattr(main, "Agent", StubAgent)
    main.ui.set_enabled(False)
    try:
        rc = main.main(["--extra-recon", "gobuster", "--objective", "x", "--no-color"])
    finally:
        main.ui.set_enabled(None)
    assert rc == 0
    from muhgpt.guard import Verdict

    clf = captured["classifier"]
    assert clf is not None
    assert clf("gobuster dir -u http://x")[0] is Verdict.ALLOW  # extra-recon honored
    assert clf("rm -rf /")[0] is Verdict.BLOCK                  # denylist intact
    assert clf("bash -c id")[0] is Verdict.CONFIRM              # bash was rejected


def test_build_mcp_disabled_returns_none():
    main.ui.set_enabled(False)
    settings = Settings(api_key="x")
    assert main._build_mcp(settings, enabled=False, config_path=None, use_defaults=True) is None


def test_build_mcp_no_servers_returns_none():
    main.ui.set_enabled(False)
    settings = Settings(api_key="x")
    # enabled, but defaults disabled and no user config -> nothing to connect to
    assert main._build_mcp(settings, enabled=True, config_path=None, use_defaults=False) is None
