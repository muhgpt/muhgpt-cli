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


# --- research sub-agent tool -----------------------------------------------
def test_research_tool_advertised_only_when_configured(session):
    off = [s["function"]["name"] for s in ToolRegistry(session).schemas]
    assert "research" not in off  # off unless a research client is wired
    on = [s["function"]["name"] for s in ToolRegistry(session, research_client=object()).schemas]
    assert "research" in on


def test_research_dispatch_delegates_to_run_research(session, monkeypatch):
    import muhgpt.research as research_mod

    captured = {}

    def fake_run_research(query, *, client, tools, session, budget, scan_mode="standard"):
        captured["query"] = query
        captured["tools_type"] = type(tools).__name__
        captured["sub_has_research"] = "research" in [
            s["function"]["name"] for s in tools.schemas
        ]
        captured["bounds"] = (budget.max_rounds, budget.max_commands)
        return "## Brief\n- finding [src]"

    monkeypatch.setattr(research_mod, "run_research", fake_run_research)
    reg = ToolRegistry(
        session, research_client=object(), research_max_rounds=7, research_max_commands=9
    )
    result = reg.dispatch("research", '{"query": "who owns example.com"}')
    assert result.executed and "Brief" in result.content
    assert captured["query"] == "who owns example.com"
    # A dedicated sub-registry with NO research tool of its own (cannot recurse).
    assert captured["tools_type"] == "ToolRegistry"
    assert captured["sub_has_research"] is False
    assert captured["bounds"] == (7, 9)  # research_* knobs flow into the sub-budget
    assert any(e["kind"] == "research" for e in session._events)


def test_research_subregistry_drops_yolo(session, monkeypatch):
    # In a --auto --yolo parent, the research sub-registry must NOT inherit yolo:
    # it ingests untrusted web, so its CONFIRM-tier primitives stay gated.
    import muhgpt.research as research_mod

    captured = {}

    def fake_run_research(query, *, client, tools, session, budget, scan_mode="standard"):
        captured["sub_yolo"] = tools._yolo
        captured["sub_auto"] = tools._auto
        return "brief"

    monkeypatch.setattr(research_mod, "run_research", fake_run_research)
    reg = ToolRegistry(
        session, research_client=object(), auto=True, yolo=True,
        budget=Budget(wall_clock_s=9999),
    )
    reg.dispatch("research", '{"query": "x"}')
    assert captured["sub_yolo"] is False   # yolo dropped for the sub-agent
    assert captured["sub_auto"] is True     # but auto (hands-off recon) is inherited


def test_research_tool_cannot_be_dispatched_without_a_client(session):
    # The sub-registry is built with research_client=None, so 'research' is unknown
    # there — structurally preventing recursion.
    result = ToolRegistry(session).dispatch("research", '{"query": "x"}')
    assert not result.executed and "unknown tool" in result.content.lower()


def test_research_dispatch_rejects_empty_query(session, monkeypatch):
    import muhgpt.research as research_mod

    monkeypatch.setattr(
        research_mod, "run_research",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run on empty query")),
    )
    reg = ToolRegistry(session, research_client=object())
    result = reg.dispatch("research", '{"query": "   "}')
    assert not result.executed and "no research question" in result.content.lower()


def test_research_dispatch_surfaces_subagent_failure(session, monkeypatch):
    import muhgpt.research as research_mod

    def boom(*a, **k):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(research_mod, "run_research", boom)
    reg = ToolRegistry(session, research_client=object())
    result = reg.dispatch("research", '{"query": "x"}')
    assert result.executed  # an error is still a real (failed) action, not a no-op
    assert "research sub-agent failed" in result.content.lower()


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


# --- MCP tool dispatch through the approval boundary ------------------------
from muhgpt.mcp import McpTool  # noqa: E402


class FakeMcp:
    """A ToolRegistry-compatible MCP manager stand-in (no subprocess)."""

    def __init__(self, raw_name="do", server="srv", auto_tools=(), fail=False):
        self._tool = McpTool(
            server=server, raw_name=raw_name, name=f"mcp__{server}__{raw_name}",
            description="d", input_schema={"type": "object", "properties": {}},
        )
        self._auto = frozenset(auto_tools)
        self._fail = fail
        self.invoked: list = []

    @property
    def schemas(self):
        return [self._tool.openai_schema]

    @property
    def auto_tools(self):
        return self._auto

    def has_tool(self, name):
        return name == self._tool.name

    def tool(self, name):
        return self._tool if name == self._tool.name else None

    def is_auto_allowed(self, name):
        return name in self._auto

    def invoke(self, name, args):
        self.invoked.append((name, args))
        if self._fail:
            raise RuntimeError("boom")
        return f"ran {name}"


def test_mcp_schemas_are_merged(session):
    reg = ToolRegistry(session, confirm=ALLOW, mcp=FakeMcp())
    names = {s["function"]["name"] for s in reg.schemas}
    assert "mcp__srv__do" in names
    assert "execute_terminal_command" in names  # built-ins still present


def test_mcp_call_hitl_approve(session):
    mcp = FakeMcp()
    reg = ToolRegistry(session, confirm=ALLOW, mcp=mcp)
    result = reg.dispatch("mcp__srv__do", '{"x": 1}')
    assert result.executed and result.content == "ran mcp__srv__do"
    assert mcp.invoked == [("mcp__srv__do", {"x": 1})]


def test_mcp_call_hitl_decline(session):
    mcp = FakeMcp()
    reg = ToolRegistry(session, confirm=DENY, mcp=mcp)
    result = reg.dispatch("mcp__srv__do", "{}")
    assert not result.executed and "declined" in result.content
    assert mcp.invoked == []


def test_mcp_auto_allowlisted_runs_without_confirm(session):
    mcp = FakeMcp(auto_tools=("mcp__srv__do",))
    reg = ToolRegistry(session, confirm=_never, auto=True, mcp=mcp)
    result = reg.dispatch("mcp__srv__do", "{}")
    assert result.executed and mcp.invoked  # confirmer never called


def test_mcp_auto_not_allowlisted_confirms(session):
    mcp = FakeMcp()  # not in auto_tools
    reg = ToolRegistry(session, confirm=DENY, auto=True, mcp=mcp)
    result = reg.dispatch("mcp__srv__do", "{}")
    assert not result.executed and mcp.invoked == []  # fell to a (declined) CONFIRM


def test_mcp_auto_blocks_weaponized(session):
    budget = Budget(wall_clock_s=9999)
    budget.start()
    mcp = FakeMcp(raw_name="run_exploit", auto_tools=("mcp__srv__run_exploit",))
    reg = ToolRegistry(session, confirm=_never, auto=True, budget=budget, mcp=mcp)
    result = reg.dispatch("mcp__srv__run_exploit", "{}")
    assert not result.executed and "blocked by policy" in result.content
    assert mcp.invoked == [] and budget.blocks == 1


def test_mcp_auto_out_of_scope_is_confirmed(session):
    session.scope = "example.com"
    mcp = FakeMcp(auto_tools=("mcp__srv__do",))
    reg = ToolRegistry(session, confirm=DENY, auto=True, mcp=mcp)
    # allowlisted, but the argument names an out-of-scope host -> downgraded to CONFIRM
    result = reg.dispatch("mcp__srv__do", '{"host": "10.0.0.5"}')
    assert not result.executed and mcp.invoked == []


def test_mcp_invoke_failure_is_surfaced(session):
    mcp = FakeMcp(auto_tools=("mcp__srv__do",), fail=True)
    reg = ToolRegistry(session, confirm=_never, auto=True, mcp=mcp)
    result = reg.dispatch("mcp__srv__do", "{}")
    assert "[error]" in result.content and "boom" in result.content


def test_load_skill_returns_playbook_and_does_not_count_as_progress(session):
    reg = ToolRegistry(session, confirm=DENY)  # no confirm needed; it's internal data
    result = reg.dispatch("load_skill", '{"name": "xss"}')
    assert result.content.lstrip().startswith("#") and not result.executed
    unknown = reg.dispatch("load_skill", '{"name": "nope"}')
    assert "Unknown skill" in unknown.content and not unknown.executed


def test_note_and_recall(session):
    reg = ToolRegistry(session, confirm=DENY)
    note = reg.dispatch("note", '{"content": "IDOR at /api/u/{id}", "category": "lead"}')
    assert not note.executed
    assert session.notes and session.notes[0]["category"] == "lead"
    recalled = reg.dispatch("recall_notes", "{}")
    assert "IDOR at /api/u/{id}" in recalled.content and not recalled.executed


def test_report_vulnerability_requires_poc(session):
    reg = ToolRegistry(session, confirm=DENY)
    r = reg.dispatch("report_vulnerability", '{"title": "T", "description": "d", "poc": ""}')
    assert not r.executed and "PoC" in r.content
    assert session.vulnerabilities == []


def test_report_vulnerability_computes_cvss_and_dedupes(session):
    import json as _json
    reg = ToolRegistry(session, confirm=DENY)
    payload = {
        "title": "Reflected XSS in q", "description": "q reflected unencoded",
        "poc": "GET /?q=<svg onload=alert(document.domain)> -> dialog fires",
        "cvss": {"AV": "N", "AC": "L", "PR": "N", "UI": "R",
                 "S": "C", "C": "L", "I": "L", "A": "N"},
    }
    ok = reg.dispatch("report_vulnerability", _json.dumps(payload))
    assert ok.executed and "CVSS 6.1" in ok.content
    v = session.vulnerabilities[0]
    assert v["severity"] == "Medium" and v["cvss_score"] == 6.1
    # duplicate title is ignored
    dup = reg.dispatch("report_vulnerability", _json.dumps(payload))
    assert "duplicate" in dup.content.lower() and len(session.vulnerabilities) == 1


def test_report_vulnerability_bad_cvss_still_files(session):
    import json as _json
    reg = ToolRegistry(session, confirm=DENY)
    r = reg.dispatch("report_vulnerability", _json.dumps({
        "title": "Issue", "description": "d", "poc": "proof", "severity": "High",
        "cvss": {"AV": "X"},  # invalid -> dropped, but the finding is still recorded
    }))
    assert r.executed and session.vulnerabilities[0]["severity"] == "High"


def test_mcp_charges_command_budget(session):
    budget = Budget(max_commands=1, wall_clock_s=9999)
    budget.start()
    mcp = FakeMcp(auto_tools=("mcp__srv__do",))
    reg = ToolRegistry(session, confirm=_never, auto=True, budget=budget, mcp=mcp)
    assert reg.dispatch("mcp__srv__do", "{}").executed
    with pytest.raises(BudgetExceeded):
        reg.dispatch("mcp__srv__do", "{}")


# --- yolo mode: auto-approve the CONFIRM tier (but never BLOCK / secret reads) ---
def test_yolo_auto_runs_confirm_tier_command(session):
    # A CONFIRM verdict (e.g. curl) would normally prompt even in --auto; yolo runs it.
    reg = ToolRegistry(session, confirm=_never, auto=True, yolo=True, classifier=CONFIRM_ALL)
    result = reg.dispatch("execute_terminal_command", '{"command": "echo hi"}')
    assert result.executed  # confirmer never called


def test_yolo_still_blocks_destructive(session):
    reg = ToolRegistry(session, confirm=_never, auto=True, yolo=True, classifier=BLOCK_ALL)
    result = reg.dispatch("execute_terminal_command", '{"command": "rm -rf /"}')
    assert not result.executed and "blocked by policy" in result.content


def test_yolo_requires_auto(session):
    # yolo without auto is inert — HITL still confirms everything.
    reg = ToolRegistry(session, confirm=DENY, auto=False, yolo=True, classifier=CONFIRM_ALL)
    result = reg.dispatch("execute_terminal_command", '{"command": "echo hi"}')
    assert not result.executed  # prompted (and declined)


def test_yolo_auto_reads_nonsecret_file_but_not_secret(session, tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("KEY", encoding="utf-8")
    normal = tmp_path / "notes.txt"
    normal.write_text("data", encoding="utf-8")
    reg = ToolRegistry(session, confirm=DENY, auto=True, yolo=True)
    # non-secret file outside the read-root auto-reads under yolo
    assert reg.dispatch("read_file", f'{{"path": "{normal}"}}').content == "data"
    # secret path stays gated even in yolo (DENY confirmer -> declined)
    declined = reg.dispatch("read_file", f'{{"path": "{secret}"}}')
    assert not declined.executed and "declined" in declined.content


def test_yolo_auto_approves_mcp_confirm_but_blocks_weaponized(session):
    mcp = FakeMcp(raw_name="search")  # benign -> CONFIRM, not in auto_tools
    reg = ToolRegistry(session, confirm=_never, auto=True, yolo=True, mcp=mcp)
    assert reg.dispatch("mcp__srv__search", "{}").executed  # CONFIRM auto-runs under yolo
    weap = FakeMcp(raw_name="run_exploit")
    reg2 = ToolRegistry(session, confirm=_never, auto=True, yolo=True, mcp=weap)
    blocked = reg2.dispatch("mcp__srv__run_exploit", "{}")
    assert not blocked.executed and "blocked by policy" in blocked.content

