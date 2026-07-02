"""Tests for SSE stream accumulation and the streaming request method."""
from __future__ import annotations

import json

import pytest
from conftest import FakeResponse, FakeSession

from muhgpt.api_client import APIStatusError, MuhGPTClient, accumulate_stream
from muhgpt.config import Settings


def _data(obj) -> str:
    return "data: " + json.dumps(obj)


def test_accumulates_content_and_forwards_deltas():
    deltas: list[str] = []
    lines = [
        _data({"choices": [{"delta": {"role": "assistant", "content": "Hel"}}]}),
        _data({"choices": [{"delta": {"content": "lo"}}]}),
        "data: [DONE]",
    ]
    message, usage = accumulate_stream(lines, on_delta=deltas.append)
    assert message == {"role": "assistant", "content": "Hello"}
    assert deltas == ["Hel", "lo"]
    assert usage is None


def test_stops_at_done_and_ignores_trailing():
    lines = [
        _data({"choices": [{"delta": {"content": "x"}}]}),
        "data: [DONE]",
        _data({"choices": [{"delta": {"content": "SHOULD NOT APPEAR"}}]}),
    ]
    message, _ = accumulate_stream(lines)
    assert message["content"] == "x"


def test_reassembles_fragmented_tool_call():
    lines = [
        _data({"choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "call_1", "type": "function",
             "function": {"name": "execute_terminal_command", "arguments": ""}}
        ]}}]}),
        _data({"choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": '{"command":'}}
        ]}}]}),
        _data({"choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": ' "id"}'}}
        ]}}]}),
        "data: [DONE]",
    ]
    message, _ = accumulate_stream(lines)
    assert "content" not in message
    (call,) = message["tool_calls"]
    assert call["id"] == "call_1"
    assert call["function"]["name"] == "execute_terminal_command"
    assert call["function"]["arguments"] == '{"command": "id"}'


def test_multiple_tool_calls_keep_index_order():
    lines = [
        _data({"choices": [{"delta": {"tool_calls": [
            {"index": 1, "id": "b", "function": {"name": "read_file", "arguments": "{}"}}
        ]}}]}),
        _data({"choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "a", "function": {"name": "save_report", "arguments": "{}"}}
        ]}}]}),
        "data: [DONE]",
    ]
    message, _ = accumulate_stream(lines)
    ids = [c["id"] for c in message["tool_calls"]]
    assert ids == ["a", "b"]  # sorted by index, not arrival


def test_usage_captured_from_final_chunk():
    lines = [
        _data({"choices": [{"delta": {"content": "hi"}}]}),
        _data({"choices": [], "usage": {"prompt_tokens": 10, "completion_tokens": 3,
                                        "total_tokens": 13}}),
        "data: [DONE]",
    ]
    _, usage = accumulate_stream(lines)
    assert usage == {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13}


def test_blank_lines_and_garbage_are_skipped():
    lines = [
        "", ": comment", "data: not json",
        _data({"choices": [{"delta": {"content": "ok"}}]}), "data: [DONE]",
    ]
    message, _ = accumulate_stream(lines)
    assert message["content"] == "ok"


def test_byte_lines_are_decoded():
    lines = [b'data: {"choices": [{"delta": {"content": "byte"}}]}', b"data: [DONE]"]
    message, _ = accumulate_stream(lines)
    assert message["content"] == "byte"


# --- stream_chat_completion (transport) -----------------------------------
def _client(responses, **overrides):
    http = FakeSession(responses)
    return MuhGPTClient(Settings(api_key="k", **overrides), session=http), http


def test_stream_request_sets_stream_flag_and_parses():
    ok = FakeResponse(200, lines=[
        'data: {"choices": [{"delta": {"content": "hi"}}]}', "data: [DONE]"
    ])
    client, http = _client([ok])
    message, _ = client.stream_chat_completion([{"role": "user", "content": "x"}])
    assert message["content"] == "hi"
    assert http.calls[0]["json"]["stream"] is True
    assert http.calls[0]["stream"] is True
    assert ok.closed  # body always closed


def test_stream_retries_on_500_then_streams(no_sleep):
    bad = FakeResponse(500, text="boom")
    ok = FakeResponse(200, lines=['data: {"choices":[{"delta":{"content":"ok"}}]}', "data: [DONE]"])
    client, http = _client([bad, ok])
    message, _ = client.stream_chat_completion([{"role": "user", "content": "x"}])
    assert message["content"] == "ok"
    assert len(http.calls) == 2
    assert bad.closed


def test_stream_4xx_raises_status_error():
    client, _ = _client([FakeResponse(400, {"error": {"message": "bad"}})])
    with pytest.raises(APIStatusError):
        client.stream_chat_completion([{"role": "user", "content": "x"}])
