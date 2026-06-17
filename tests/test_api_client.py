"""Tests for the resilient chat-completions HTTP client."""
from __future__ import annotations

import pytest
import requests
from conftest import FakeResponse, FakeSession

from muhgpt.api_client import (
    APIConnectionError,
    APIResponseError,
    APIStatusError,
    MuhGPTClient,
)
from muhgpt.config import Settings

_OK = {"choices": [{"message": {"role": "assistant", "content": "hi"}}]}


def _client(responses, **overrides):
    settings = Settings(api_key="k", **overrides)
    http = FakeSession(responses)
    return MuhGPTClient(settings, session=http), http


def test_success_returns_first_message():
    client, http = _client([FakeResponse(200, _OK)])
    message = client.chat_completion([{"role": "user", "content": "x"}])
    assert message == {"role": "assistant", "content": "hi"}
    assert http.calls[0]["url"].endswith("/chat/completions")


def test_retries_on_500_then_succeeds(no_sleep):
    client, http = _client([FakeResponse(500, text="boom"), FakeResponse(200, _OK)])
    message = client.chat_completion([{"role": "user", "content": "x"}])
    assert message["content"] == "hi"
    assert len(http.calls) == 2
    assert no_sleep  # backed off once before the retry


def test_retries_on_network_error_then_succeeds(no_sleep):
    client, http = _client([requests.ConnectionError("down"), FakeResponse(200, _OK)])
    assert client.chat_completion([{"role": "user", "content": "x"}])["content"] == "hi"
    assert len(http.calls) == 2


def test_4xx_raises_status_error_without_retry():
    client, http = _client([FakeResponse(400, {"error": {"message": "bad"}})])
    with pytest.raises(APIStatusError) as exc:
        client.chat_completion([{"role": "user", "content": "x"}])
    assert exc.value.status_code == 400
    assert len(http.calls) == 1


def test_exhausting_retries_raises_connection_error(no_sleep):
    client, _ = _client([FakeResponse(500)] * 3, max_retries=2)
    with pytest.raises(APIConnectionError):
        client.chat_completion([{"role": "user", "content": "x"}])


def test_retry_after_header_is_honoured(no_sleep):
    responses = [FakeResponse(429, headers={"Retry-After": "7"}), FakeResponse(200, _OK)]
    client, _ = _client(responses)
    client.chat_completion([{"role": "user", "content": "x"}])
    assert no_sleep == [7.0]


def test_bad_json_raises_response_error():
    client, _ = _client([FakeResponse(200, json_data=None, text="<html>")])
    with pytest.raises(APIResponseError):
        client.chat_completion([{"role": "user", "content": "x"}])


def test_unexpected_shape_raises_response_error():
    client, _ = _client([FakeResponse(200, {"nope": True})])
    with pytest.raises(APIResponseError):
        client.chat_completion([{"role": "user", "content": "x"}])


def test_temperature_omitted_when_none():
    client, http = _client([FakeResponse(200, _OK)], temperature=None)
    client.chat_completion([{"role": "user", "content": "x"}])
    assert "temperature" not in http.calls[0]["json"]


def test_temperature_sent_when_set():
    client, http = _client([FakeResponse(200, _OK)], temperature=0.3)
    client.chat_completion([{"role": "user", "content": "x"}])
    assert http.calls[0]["json"]["temperature"] == 0.3


def test_tools_only_sent_when_provided():
    client, http = _client([FakeResponse(200, _OK), FakeResponse(200, _OK)])
    client.chat_completion([{"role": "user", "content": "x"}])
    assert "tools" not in http.calls[0]["json"]
    client.chat_completion([{"role": "user", "content": "x"}], tools=[{"type": "function"}])
    assert http.calls[1]["json"]["tools"] == [{"type": "function"}]
