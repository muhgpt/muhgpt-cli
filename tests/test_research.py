"""Tests for the OSINT research sub-agent (relace-search-style delegate)."""
from __future__ import annotations

from typing import Any

from muhgpt.guard import Budget
from muhgpt.research import RESEARCH_SYSTEM_PROMPT, run_research
from muhgpt.tools import ToolResult


def _budget():
    return Budget(max_rounds=12, max_commands=20, wall_clock_s=9999)


class ScriptedClient:
    """Returns a pre-scripted sequence of assistant messages; records what it saw."""

    def __init__(self, messages: list[dict[str, Any]]) -> None:
        self._messages = list(messages)
        self.calls = 0
        self.seen: list[list[dict[str, Any]]] = []

    def chat_completion(self, messages, tools=None, tool_choice="auto"):
        self.calls += 1
        self.seen.append([dict(m) for m in messages])
        return self._messages.pop(0)


class RecordingTools:
    """A tool-view stand-in: records dispatches, returns canned output, no schemas."""

    schemas: list[dict[str, Any]] = []

    def __init__(self) -> None:
        self.dispatched: list[tuple[str, str]] = []

    def dispatch(self, name: str, arguments: str) -> ToolResult:
        self.dispatched.append((name, arguments))
        return ToolResult(f"ran {name}")


def _tool_call(name="execute_terminal_command", args="{}"):
    return {
        "role": "assistant",
        "tool_calls": [{"id": "1", "function": {"name": name, "arguments": args}}],
    }


def test_run_research_returns_brief_when_model_signals_done(session):
    client = ScriptedClient([{"role": "assistant", "content": "## Brief\n- x [src]\nDONE"}])
    brief = run_research("who owns example.com?", client=client, tools=RecordingTools(),
                         session=session, budget=_budget())
    assert "Brief" in brief and brief.strip().endswith("DONE")
    assert client.calls == 1


def test_run_research_uses_tools_then_briefs(session):
    client = ScriptedClient([
        _tool_call("execute_terminal_command", '{"command": "whois example.com"}'),
        {"role": "assistant", "content": "summary of findings DONE"},
    ])
    tools = RecordingTools()
    brief = run_research("background on example.com", client=client, tools=tools,
                         session=session, budget=_budget())
    assert tools.dispatched == [("execute_terminal_command", '{"command": "whois example.com"}')]
    assert brief.strip().endswith("DONE")


def test_run_research_is_bounded_by_its_budget(session):
    # A model that never stops must be halted by the sub-run's round budget, not
    # loop forever — the budget caps are genuinely enforced on the sub-agent.
    class AlwaysToolClient:
        def chat_completion(self, messages, tools=None, tool_choice="auto"):
            return {"role": "assistant", "tool_calls": [
                {"id": "x", "function": {"name": "execute_terminal_command", "arguments": "{}"}}]}

    brief = run_research("loop", client=AlwaysToolClient(), tools=RecordingTools(),
                         session=session, budget=Budget(max_rounds=3, max_idle_rounds=99,
                                                        wall_clock_s=9999))
    assert "[autopilot]" in brief and "budget" in brief.lower()


def test_research_subagent_uses_research_persona_and_scope(session):
    # The sub-agent must run under the RESEARCH persona (not the pentest one) and
    # still carry the confirmed scope so it stays in-bounds.
    client = ScriptedClient([{"role": "assistant", "content": "brief DONE"}])
    run_research("q", client=client, tools=RecordingTools(), session=session, budget=_budget())
    system = client.seen[0][0]
    assert system["role"] == "system"
    assert "RESEARCH sub-agent" in system["content"]
    assert "example.com" in system["content"]  # session.scope injected


def test_research_persona_text_demands_sources_and_done():
    assert "SOURCED" in RESEARCH_SYSTEM_PROMPT
    assert "UNTRUSTED DATA" in RESEARCH_SYSTEM_PROMPT
    assert "single word DONE" in RESEARCH_SYSTEM_PROMPT  # autonomous completion sentinel


def test_research_end_to_end_through_registry(session):
    # Full integration, no mocks/network/subprocess: ToolRegistry._research builds
    # a real dedicated sub-registry, run_research runs a real Agent on it, and the
    # brief comes back. The scripted model returns a brief immediately (no tools).
    from muhgpt.tools import ToolRegistry

    client = ScriptedClient([{"role": "assistant", "content": "## Brief\n- found [src]\nDONE"}])
    reg = ToolRegistry(session, research_client=client)
    result = reg.dispatch("research", '{"query": "background on example.com"}')
    assert result.executed
    assert "Brief" in result.content and result.content.strip().endswith("DONE")
    assert any(e["kind"] == "research" for e in session._events)
