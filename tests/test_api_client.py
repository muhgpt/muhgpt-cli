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


# --- models + usage (GET endpoints) ----------------------------------------
def test_list_models_returns_data_array():
    client, http = _client([FakeResponse(200, {"object": "list", "data": [
        {"id": "muh-chat", "owned_by": "muhgpt"}, {"id": "gpt-4o", "owned_by": "muhgpt"}]})])
    models = client.list_models()
    assert [m["id"] for m in models] == ["muh-chat", "gpt-4o"]
    assert http.calls[0]["method"] == "GET"
    assert http.calls[0]["url"].endswith("/models")


def test_get_usage_sends_date_range_and_parses_balance():
    client, http = _client([FakeResponse(200, {
        "object": "usage", "balance": 12500, "totals": {"credits": 5000}})])
    usage = client.get_usage(start="2026-06-01", end="2026-06-30")
    assert usage["balance"] == 12500
    assert http.calls[0]["url"].endswith("/usage")
    assert http.calls[0]["params"] == {"start": "2026-06-01", "end": "2026-06-30"}


def test_get_usage_omits_empty_params():
    client, http = _client([FakeResponse(200, {"balance": 1})])
    client.get_usage()
    assert http.calls[0]["params"] is None


def test_get_endpoints_retry_on_500(no_sleep):
    client, http = _client([FakeResponse(500, text="boom"),
                            FakeResponse(200, {"object": "list", "data": []})])
    assert client.list_models() == []
    assert len(http.calls) == 2


def test_typed_error_carries_error_type():
    for code, etype in [(402, "insufficient_quota"), (403, "model_not_allowed"),
                        (404, "model_not_found")]:
        client, _ = _client([FakeResponse(code, {"error": {"message": "m", "type": etype}})])
        with pytest.raises(APIStatusError) as exc:
            client.list_models()
        assert exc.value.status_code == code
        assert exc.value.error_type == etype


def test_chat_completion_errors_are_typed_too():
    client, _ = _client([FakeResponse(402, {"error": {
        "message": "no credits", "type": "insufficient_quota"}})])
    with pytest.raises(APIStatusError) as exc:
        client.chat_completion([{"role": "user", "content": "x"}])
    assert exc.value.error_type == "insufficient_quota"


def test_models_bad_shape_raises_response_error():
    client, _ = _client([FakeResponse(200, {"nope": True})])
    with pytest.raises(APIResponseError):
        client.list_models()
