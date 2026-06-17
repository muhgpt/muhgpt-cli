"""Tests for the tool dispatcher and human-in-the-loop guard."""
from __future__ import annotations

import pytest

from muhgpt.guard import Budget, BudgetExceeded, Verdict
from muhgpt.packages import PackageManager
from muhgpt.tools import ToolRegistry, _missing_command

ALLOW = lambda _prompt: True   # noqa: E731 - terse confirmer for tests
DENY = lambda _prompt: False   # noqa: E731

# A harmless fake manager whose "install" is just an echo, safe to run in tests.
FAKE_PM = PackageManager(name="fake", install_template="echo installing {pkg}")


class SeqConfirm:
    """Confirmer that returns a scripted sequence of answers and records prompts."""

    def __init__(self, *answers):
        self._answers = list(answers)
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        return self._answers.pop(0) if self._answers else False


def test_unknown_tool_is_reported(session):
    result = ToolRegistry(session, confirm=ALLOW).dispatch("nope", "{}")
    assert not result.executed
    assert "Unknown tool" in result.content


def test_bad_json_arguments_are_reported(session):
    result = ToolRegistry(session, confirm=ALLOW).dispatch("read_file", "{not json")
    assert not result.executed
    assert "Could not parse arguments" in result.content


def test_non_object_arguments_rejected(session):
    result = ToolRegistry(session, confirm=ALLOW).dispatch("read_file", "[1, 2]")
    assert not result.executed
    assert "must be an object" in result.content


def test_command_declined_is_not_run(session):
    result = ToolRegistry(session, confirm=DENY).dispatch(
        "execute_terminal_command", '{"command": "echo hi"}'
    )
    assert not result.executed
    assert "[declined]" in result.content
    # the refusal is still audited
    assert any(
        e["kind"] == "command" and e["approved"] is False for e in session._events
    )


def test_command_approved_runs_and_captures_output(session):
    result = ToolRegistry(session, confirm=ALLOW).dispatch(
        "execute_terminal_command", '{"command": "echo hello"}'
    )
    assert result.executed
    assert "hello" in result.content
    assert "exit code: 0" in result.content


def test_empty_command_rejected(session):
    result = ToolRegistry(session, confirm=ALLOW).dispatch(
        "execute_terminal_command", '{"command": "   "}'
    )
    assert not result.executed
    assert "No command provided" in result.content


def test_read_file_is_byte_bounded(session, tmp_path):
    target = tmp_path / "big.txt"
    target.write_text("A" * 1000)
    result = ToolRegistry(session, confirm=ALLOW).dispatch(
        "read_file", f'{{"path": "{target}", "max_bytes": 10}}'
    )
    assert result.executed
    assert result.content == "A" * 10


def test_read_file_missing_path(session, tmp_path):
    result = ToolRegistry(session, confirm=ALLOW).dispatch(
        "read_file", f'{{"path": "{tmp_path / "nope.txt"}"}}'
    )
    assert not result.executed
    assert "Not a file" in result.content


def test_read_file_declined(session, tmp_path):
    target = tmp_path / "secret.txt"
    target.write_text("x")
    result = ToolRegistry(session, confirm=DENY).dispatch(
        "read_file", f'{{"path": "{target}"}}'
    )
    assert not result.executed
    assert "[declined]" in result.content


def test_save_report_records_a_finding(session):
    result = ToolRegistry(session, confirm=ALLOW).dispatch(
        "save_report", '{"title": "SQLi", "content": "details"}'
    )
    assert result.executed
    assert len(session.findings) == 1
    assert session.findings[0].title == "SQLi"


def test_install_package_runs_manager_command(session):
    reg = ToolRegistry(session, confirm=ALLOW, package_manager=FAKE_PM)
    result = reg.dispatch("install_package", '{"package": "nmap"}')
    assert result.executed
    assert "installing nmap" in result.content  # fake PM echoes this
    assert "exit code: 0" in result.content


def test_install_package_declined_is_not_run(session):
    reg = ToolRegistry(session, confirm=DENY, package_manager=FAKE_PM)
    result = reg.dispatch("install_package", '{"package": "nmap"}')
    assert not result.executed
    assert "[declined]" in result.content


def test_install_package_without_manager_explains(session):
    reg = ToolRegistry(session, confirm=ALLOW, package_manager=None)
    result = reg.dispatch("install_package", '{"package": "nmap"}')
    assert not result.executed
    assert "No supported package manager" in result.content


def test_install_package_requires_name(session):
    reg = ToolRegistry(session, confirm=ALLOW, package_manager=FAKE_PM)
    result = reg.dispatch("install_package", '{"package": "  "}')
    assert not result.executed
    assert "No package specified" in result.content


def test_missing_command_parsing():
    assert _missing_command("zsh:1: command not found: nmap", "nmap x") == "nmap"
    assert _missing_command("/bin/sh: nmap: command not found", "nmap x") == "nmap"
    assert _missing_command("sh: 1: nmap: not found", "nmap x") == "nmap"
    # no parseable stderr -> fall back to first real token (skipping sudo/VAR=)
    assert _missing_command("", "sudo FOO=1 masscan 10.0.0.0/8") == "masscan"


def test_missing_tool_offers_install_then_retries(session):
    # First confirm = run the command, second = approve the install. The fake PM
    # installs a real stub onto a PATH dir so the retry actually succeeds.
    import os
    bindir = session.reports_dir.parent / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    pm = PackageManager(
        name="fake",
        install_template=(
            "printf '#!/bin/sh\\necho scan-ok\\n' > " + str(bindir) + "/{pkg}"
            " && chmod +x " + str(bindir) + "/{pkg}"
        ),
    )
    confirm = SeqConfirm(True, True)
    reg = ToolRegistry(session, confirm=confirm, package_manager=pm)
    env_path = os.environ["PATH"]
    os.environ["PATH"] = f"{bindir}:{env_path}"
    try:
        result = reg.dispatch("execute_terminal_command", '{"command": "muhgpttool42"}')
    finally:
        os.environ["PATH"] = env_path
    assert result.executed
    assert "installed 'muhgpttool42'" in result.content
    assert "scan-ok" in result.content  # the re-run succeeded after install
    assert any("Install 'muhgpttool42'" in p for p in confirm.prompts)


def test_missing_tool_install_declined(session):
    confirm = SeqConfirm(True, False)  # run the command, decline the install
    reg = ToolRegistry(session, confirm=confirm, package_manager=FAKE_PM)
    result = reg.dispatch("execute_terminal_command", '{"command": "muhgpttool-nope-xyz"}')
    assert not result.executed
    assert "declined to install" in result.content


def test_missing_tool_no_recovery_without_manager(session):
    reg = ToolRegistry(session, confirm=ALLOW, package_manager=None)
    result = reg.dispatch("execute_terminal_command", '{"command": "muhgpttool-nope-xyz"}')
    assert result.executed
    assert "exit code: 127" in result.content  # plain failure, no install offered


def test_install_package_tool_is_advertised(session):
    names = [s["function"]["name"] for s in ToolRegistry(session).schemas]
    assert "install_package" in names


# --- autonomous mode -------------------------------------------------------
# Inject deterministic verdicts so these test the WIRING, independent of the
# (separately tested) denylist content and of which binaries are installed.
ALLOW_ALL = lambda _c: (Verdict.ALLOW, "test")     # noqa: E731
BLOCK_ALL = lambda _c: (Verdict.BLOCK, "test")     # noqa: E731
CONFIRM_ALL = lambda _c: (Verdict.CONFIRM, "test")  # noqa: E731


def _never(_prompt):
    raise AssertionError("confirmer must NOT be called for an auto-approved command")


def test_auto_mode_runs_allowed_command_without_confirming(session):
    reg = ToolRegistry(session, confirm=_never, auto=True, classifier=ALLOW_ALL)
    result = reg.dispatch("execute_terminal_command", '{"command": "echo recon"}')
    assert result.executed
    assert "recon" in result.content
    assert "exit code: 0" in result.content


def test_auto_mode_blocks_destructive_without_confirming(session):
    reg = ToolRegistry(session, confirm=_never, auto=True, classifier=BLOCK_ALL)
    result = reg.dispatch("execute_terminal_command", '{"command": "echo anything"}')
    assert not result.executed
    assert "blocked by policy" in result.content
    assert any(e["kind"] == "guard_block" for e in session._events)


def test_auto_mode_confirms_unlisted_command(session):
    asked = {"n": 0}

    def confirm(_prompt):
        asked["n"] += 1
        return False

    reg = ToolRegistry(session, confirm=confirm, auto=True, classifier=CONFIRM_ALL)
    result = reg.dispatch("execute_terminal_command", '{"command": "some-unknown-tool --x"}')
    assert asked["n"] == 1
    assert not result.executed


def test_hitl_mode_still_prompts_for_everything(session):
    # Default (auto=False): the guard is bypassed; even 'rm -rf /' just prompts.
    asked = {"n": 0}

    def confirm(_prompt):
        asked["n"] += 1
        return False

    reg = ToolRegistry(session, confirm=confirm)  # auto defaults False
    result = reg.dispatch("execute_terminal_command", '{"command": "rm -rf /tmp/x"}')
    assert asked["n"] == 1  # prompted, not auto-blocked
    assert not result.executed
    assert "[declined]" in result.content


def test_auto_mode_out_of_scope_target_is_confirmed_not_auto_run(session):
    # session.scope is "example.com"; a command targeting a different host must
    # not auto-run even though the (injected) verdict is ALLOW — it confirms.
    session.scope = "example.com"
    asked = {"n": 0}

    def confirm(_prompt):
        asked["n"] += 1
        return False

    reg = ToolRegistry(session, confirm=confirm, auto=True, classifier=ALLOW_ALL)
    result = reg.dispatch("execute_terminal_command", '{"command": "nmap -sV 10.0.0.5"}')
    assert asked["n"] == 1  # downgraded ALLOW -> CONFIRM, operator was prompted
    assert not result.executed
    assert any(e["kind"] == "scope_confirm" for e in session._events)


def test_auto_mode_in_scope_target_still_auto_runs(session):
    session.scope = "example.com"
    reg = ToolRegistry(session, confirm=_never, auto=True, classifier=ALLOW_ALL)
    result = reg.dispatch("execute_terminal_command", '{"command": "echo example.com"}')
    assert result.executed  # in-scope -> stays auto-approved (confirmer never called)


def test_auto_mode_charges_command_budget(session):
    budget = Budget(max_commands=1, wall_clock_s=9999)
    budget.start()
    reg = ToolRegistry(session, confirm=_never, auto=True, classifier=ALLOW_ALL, budget=budget)
    assert reg.dispatch("execute_terminal_command", '{"command": "echo a"}').executed
    with pytest.raises(BudgetExceeded):
        reg.dispatch("execute_terminal_command", '{"command": "echo b"}')  # 2nd over cap

