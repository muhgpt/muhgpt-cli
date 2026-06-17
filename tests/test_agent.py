"""Tests for the agentic loop: tool round-trips, narration, history trimming."""
from __future__ import annotations

from typing import Any

from conftest import FakeTools

from muhgpt.agent import Agent


class ScriptedClient:
    """Returns a pre-scripted sequence of assistant messages."""

    def __init__(self, messages: list[dict[str, Any]]) -> None:
        self._messages = list(messages)
        self.calls = 0

    def chat_completion(self, messages, tools=None, tool_choice="auto"):
        self.calls += 1
        return self._messages.pop(0)


class LoopingToolClient:
    """Always asks for a tool call — used to exercise the round limit."""

    def chat_completion(self, messages, tools=None, tool_choice="auto"):
        return {
            "role": "assistant",
            "tool_calls": [
                {"id": "x", "function": {"name": "execute_terminal_command", "arguments": "{}"}}
            ],
        }


def _tool_call(name="execute_terminal_command", content=None):
    msg: dict[str, Any] = {
        "role": "assistant",
        "tool_calls": [{"id": "1", "function": {"name": name, "arguments": "{}"}}],
    }
    if content is not None:
        msg["content"] = content
    return msg


def test_plain_reply_returned_without_tool_calls(session):
    client = ScriptedClient([{"role": "assistant", "content": "all done"}])
    agent = Agent(client, FakeTools(), session)
    assert agent.run_turn("status?") == "all done"
    assert client.calls == 1


def test_tool_call_then_final_reply(session):
    client = ScriptedClient([_tool_call(), {"role": "assistant", "content": "found it"}])
    tools = FakeTools()
    agent = Agent(client, tools, session)
    assert agent.run_turn("scan") == "found it"
    assert tools.dispatched == [("execute_terminal_command", "{}")]


def test_intermediate_reasoning_is_narrated(session):
    narrated: list[str] = []
    client = ScriptedClient([
        _tool_call(content="Let me enumerate ports first."),
        {"role": "assistant", "content": "ok"},
    ])
    agent = Agent(client, FakeTools(), session, on_assistant_text=narrated.append)
    agent.run_turn("go")
    assert narrated == ["Let me enumerate ports first."]


def test_final_reply_is_not_narrated(session):
    narrated: list[str] = []
    client = ScriptedClient([{"role": "assistant", "content": "done"}])
    agent = Agent(client, FakeTools(), session, on_assistant_text=narrated.append)
    agent.run_turn("go")
    assert narrated == []


def test_round_limit_stops_runaway_tool_loop(session):
    tools = FakeTools()
    agent = Agent(LoopingToolClient(), tools, session, max_tool_rounds=3)
    reply = agent.run_turn("loop forever")
    assert "tool-round limit" in reply
    assert len(tools.dispatched) == 3


def test_trim_history_keeps_system_and_cuts_to_user_boundary(session):
    agent = Agent(ScriptedClient([]), FakeTools(), session, max_history_messages=2)
    agent._messages = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "u1"},
        {"role": "assistant", "content": "a1"},
        {"role": "tool", "content": "t1"},
        {"role": "user", "content": "u2"},
        {"role": "assistant", "content": "a2"},
    ]
    agent._trim_history()
    assert [m["role"] for m in agent._messages] == ["system", "user", "assistant"]
    assert agent._messages[1]["content"] == "u2"


def test_trim_history_never_splits_a_tool_group(session):
    # A naive count-based cut would land mid tool-call group; trimming must
    # advance to the next user message so tool_calls keep their tool replies.
    agent = Agent(ScriptedClient([]), FakeTools(), session, max_history_messages=4)
    agent._messages = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "u1"},
        {"role": "assistant", "tool_calls": [{"id": "1"}]},
        {"role": "tool", "content": "t1"},
        {"role": "assistant", "content": "a1"},
        {"role": "user", "content": "u2"},
        {"role": "assistant", "content": "a2"},
    ]
    agent._trim_history()
    roles = [m["role"] for m in agent._messages]
    assert roles[0] == "system"
    assert roles[1] == "user"
    assert "tool" not in roles  # the dangling tool group was dropped whole
    assert agent._messages[1]["content"] == "u2"


class StreamingClient:
    """Scripted streaming client: yields content deltas and returns (message, usage)."""

    def __init__(self, scripted):
        self._scripted = list(scripted)  # list of (message, usage)
        self.calls = 0

    def stream_chat_completion(self, messages, tools=None, tool_choice="auto", on_delta=None):
        self.calls += 1
        message, usage = self._scripted.pop(0)
        if on_delta and message.get("content"):
            for ch in message["content"]:  # emit char-by-char like a real stream
                on_delta(ch)
        return message, usage


def test_streaming_emits_deltas_and_returns_final(session):
    deltas: list[str] = []
    boundaries: list[bool] = []
    client = StreamingClient([
        (
            {"role": "assistant", "content": "hi there"},
            {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        ),
    ])
    agent = Agent(
        client, FakeTools(), session,
        stream=True,
        on_delta=deltas.append,
        on_message_boundary=boundaries.append,
    )
    reply = agent.run_turn("hello")
    assert reply == "hi there"
    assert "".join(deltas) == "hi there"
    assert boundaries == [True]  # final message -> boundary(final=True)
    assert agent.last_turn_usage == {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}
    assert session.usage["total_tokens"] == 7


def test_streaming_tool_round_then_final(session):
    boundaries: list[bool] = []
    tools = FakeTools()
    client = StreamingClient([
        ({
            "role": "assistant", "content": "checking",
            "tool_calls": [
                {"id": "1", "function": {"name": "execute_terminal_command", "arguments": "{}"}}
            ],
        }, None),
        ({"role": "assistant", "content": "done"}, None),
    ])
    agent = Agent(client, tools, session, stream=True, on_delta=lambda _t: None,
                  on_message_boundary=boundaries.append)
    assert agent.run_turn("go") == "done"
    assert tools.dispatched == [("execute_terminal_command", "{}")]
    assert boundaries == [False, True]  # intermediate (has tool calls), then final


def test_autonomous_keeps_going_until_done(session):
    from muhgpt.guard import Budget

    # 1st reply: plain text (no DONE) -> should be nudged to continue, not returned.
    # 2nd reply: ends with DONE -> turn completes.
    client = ScriptedClient([
        {"role": "assistant", "content": "Recon underway, no findings yet."},
        {"role": "assistant", "content": "Mapped the target and saved the report. DONE"},
    ])
    agent = Agent(client, FakeTools(), session, autonomous=True, budget=Budget(wall_clock_s=9999))
    reply = agent.run_turn("map example.com")
    assert reply.strip().endswith("DONE")
    assert client.calls == 2  # it did not stop after the first non-DONE reply


def test_autonomous_stops_at_round_budget(session):
    from muhgpt.guard import Budget

    # Model keeps productively calling tools -> bounded by the round budget
    # (idle guard disabled so it isn't what stops the run).
    agent = Agent(
        LoopingToolClient(), FakeTools(), session,
        autonomous=True, budget=Budget(max_rounds=3, max_idle_rounds=99, wall_clock_s=9999),
    )
    reply = agent.run_turn("go")
    assert "[autopilot]" in reply
    assert "budget" in reply.lower()


def test_autonomous_halts_when_model_wont_act(session):
    from muhgpt.guard import Budget

    # Model never calls a tool and never says DONE -> the no-progress guard halts
    # it well before the (much larger) round budget.
    agent = Agent(
        ScriptedClient([{"role": "assistant", "content": "thinking out loud"}] * 50),
        FakeTools(), session,
        autonomous=True, budget=Budget(max_idle_rounds=3, max_rounds=99, wall_clock_s=9999),
    )
    reply = agent.run_turn("go")
    assert "[autopilot]" in reply
    assert "no tool action" in reply.lower()


def test_autonomous_halts_when_all_tool_calls_fail(session):
    from muhgpt.guard import Budget
    from muhgpt.tools import ToolResult

    class FailingTools(FakeTools):
        def dispatch(self, name, arguments):
            return ToolResult("[declined] nope", executed=False)

    agent = Agent(
        LoopingToolClient(), FailingTools(), session,
        autonomous=True, budget=Budget(max_idle_rounds=2, max_rounds=99, wall_clock_s=9999),
    )
    reply = agent.run_turn("go")
    assert "[autopilot]" in reply
    assert "no command actually executed" in reply.lower()


class RecordingClient:
    """Records each chat_completion call (messages + tools) and returns a fixed reply."""

    def __init__(self, reply, usage=None):
        self.reply = reply
        self.usage = usage
        self.calls = []

    def chat_completion(self, messages, tools=None, tool_choice="auto"):
        self.calls.append({"messages": [dict(m) for m in messages], "tools": tools})
        return {"role": "assistant", "content": self.reply}


def test_ask_once_uses_clean_persona_and_is_isolated(session):
    client = RecordingClient("def reverse(node): ...")
    agent = Agent(client, FakeTools(), session)
    before = [dict(m) for m in agent._messages]

    reply = agent.ask_once("You are an engineer.", "reverse a linked list")

    assert reply == "def reverse(node): ..."
    # the call used the role as the system prompt, the text as user, and NO tools
    sent = client.calls[0]
    assert sent["messages"][0] == {"role": "system", "content": "You are an engineer."}
    assert sent["messages"][1] == {"role": "user", "content": "reverse a linked list"}
    assert sent["tools"] is None
    # the persistent pentest conversation is untouched (no history pollution)
    assert [dict(m) for m in agent._messages] == before


def test_ask_once_tracks_usage(session):
    client = RecordingClient("ok")

    def chat_completion(messages, tools=None, tool_choice="auto"):
        client.calls.append({"messages": messages, "tools": tools})
        return {"role": "assistant", "content": "ok"}

    client.chat_completion = chat_completion  # no usage in buffered mode -> None
    agent = Agent(client, FakeTools(), session)
    agent.ask_once("role", "hi")
    assert agent.last_turn_usage is None  # buffered path reports no usage


def test_trim_history_disabled_when_limit_zero(session):
    agent = Agent(ScriptedClient([]), FakeTools(), session, max_history_messages=0)
    agent._messages = [{"role": "system", "content": "s"}] + [
        {"role": "user", "content": str(i)} for i in range(50)
    ]
    agent._trim_history()
    assert len(agent._messages) == 51
