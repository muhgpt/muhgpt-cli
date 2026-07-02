"""HTTP client for the MuhGPT OpenAI-compatible chat completions API."""
from __future__ import annotations

import json
import random
import time
from collections.abc import Iterable
from typing import Any, Callable

import requests

from .config import Settings


class MuhGPTError(RuntimeError):
    """Base class for all MuhGPT client errors."""


class APIConnectionError(MuhGPTError):
    """Raised when the API cannot be reached after exhausting all retries."""


class APIStatusError(MuhGPTError):
    """Raised for non-retryable HTTP error responses (typically 4xx).

    ``error_type`` carries the API's machine-readable error category when present
    (e.g. ``insufficient_quota``, ``model_not_allowed``, ``model_not_found``), so
    callers can surface an actionable hint. ``None`` when the body has no typed error.
    """

    def __init__(self, status_code: int, message: str, error_type: str | None = None) -> None:
        super().__init__(f"API returned {status_code}: {message}")
        self.status_code = status_code
        self.error_type = error_type


class APIResponseError(MuhGPTError):
    """Raised when the API response body cannot be parsed as expected."""


class MuhGPTClient:
    """Thin, resilient client around the chat completions endpoint.

    Transient failures (timeouts, connection errors, HTTP 429 and 5xx) are
    retried with exponential backoff and jitter. A ``Retry-After`` header, when
    present, takes precedence over the computed backoff.
    """

    def __init__(self, settings: Settings, session: requests.Session | None = None) -> None:
        self._settings = settings
        self._http = session or requests.Session()
        self._http.headers.update(
            {
                "Authorization": f"Bearer {settings.api_key}",
                "Content-Type": "application/json",
            }
        )

    def chat_completion(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str = "auto",
    ) -> dict[str, Any]:
        """Request one chat completion and return the first choice's message.

        Args:
            messages: The full conversation history in OpenAI message format.
            tools: Optional tool schemas to advertise to the model.
            tool_choice: How the model may select tools (``auto`` by default).

        Returns:
            The ``message`` object from the first choice, which may contain
            ``content`` and/or ``tool_calls``.

        Raises:
            APIConnectionError: On unrecoverable network failure.
            APIStatusError: On non-retryable HTTP errors.
            APIResponseError: When the body is not valid, expected JSON.
        """
        payload = self._build_payload(messages, tools, tool_choice)

        last_error: Exception | None = None
        for attempt in range(self._settings.max_retries + 1):
            try:
                response = self._http.post(
                    self._settings.chat_completions_url,
                    json=payload,
                    timeout=(self._settings.connect_timeout, self._settings.request_timeout),
                )
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = exc
                self._sleep_for_retry(attempt)
                continue

            if response.status_code == 429 or response.status_code >= 500:
                last_error = APIStatusError(response.status_code, _safe_text(response))
                self._sleep_for_retry(attempt, response)
                continue

            if response.status_code >= 400:
                _raise_status(response)

            return self._parse_message(response)

        raise APIConnectionError(
            f"Request failed after {self._settings.max_retries + 1} attempts: {last_error}"
        )

    def list_models(self) -> list[dict[str, Any]]:
        """Return the available models (``GET /v1/models`` → the ``data`` array).

        Each entry is a dict like ``{"id", "object", "created", "owned_by"}``. Uses
        the same auth + retry policy as chat.
        """
        data = self._request_json("GET", self._settings.models_url)
        models = data.get("data") if isinstance(data, dict) else None
        if not isinstance(models, list):
            raise APIResponseError(f"Unexpected models response shape: {data!r}")
        return models

    def get_usage(self, start: str | None = None, end: str | None = None) -> dict[str, Any]:
        """Return the account's usage + credit balance (``GET /v1/usage``).

        ``start`` / ``end`` are optional ISO dates (``YYYY-MM-DD``). The result
        includes ``balance`` and a ``totals`` breakdown. muh-specific: on a plain
        OpenAI-compatible endpoint this may 404 — callers should treat it as best-effort.
        """
        params = {k: v for k, v in (("start", start), ("end", end)) if v}
        data = self._request_json("GET", self._settings.usage_url, params=params or None)
        if not isinstance(data, dict):
            raise APIResponseError(f"Unexpected usage response shape: {data!r}")
        return data

    def _request_json(
        self, method: str, url: str, params: dict[str, str] | None = None
    ) -> Any:
        """Send a non-streaming request and return parsed JSON, with the shared
        retry/backoff policy (429/5xx/network) and typed-error raising."""
        last_error: Exception | None = None
        for attempt in range(self._settings.max_retries + 1):
            try:
                response = self._http.request(
                    method,
                    url,
                    params=params,
                    timeout=(self._settings.connect_timeout, self._settings.request_timeout),
                )
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = exc
                self._sleep_for_retry(attempt)
                continue

            if response.status_code == 429 or response.status_code >= 500:
                last_error = APIStatusError(response.status_code, _safe_text(response))
                self._sleep_for_retry(attempt, response)
                continue
            if response.status_code >= 400:
                _raise_status(response)

            try:
                return response.json()
            except json.JSONDecodeError as exc:
                raise APIResponseError(
                    "Could not decode JSON from the API response. "
                    "Verify MUHGPT_BASE_URL points to an OpenAI-compatible endpoint."
                ) from exc

        raise APIConnectionError(
            f"Request failed after {self._settings.max_retries + 1} attempts: {last_error}"
        )

    def stream_chat_completion(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str = "auto",
        on_delta: Callable[[str], None] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Stream one chat completion, reassembling the message as chunks arrive.

        ``on_delta`` is invoked with each fragment of assistant ``content`` as it
        is received, enabling live token-by-token display. Tool calls (which the
        API streams in fragments) are reassembled into a complete ``tool_calls``
        list. The same retry policy as :meth:`chat_completion` applies to the
        initial connection; once the body is streaming it is consumed in full.

        Returns:
            A ``(message, usage)`` tuple. ``usage`` is the token-accounting dict
            from the terminating chunk, or ``None`` if the server omitted it.
        """
        payload = self._build_payload(messages, tools, tool_choice)
        payload["stream"] = True

        last_error: Exception | None = None
        for attempt in range(self._settings.max_retries + 1):
            try:
                response = self._http.post(
                    self._settings.chat_completions_url,
                    json=payload,
                    timeout=(self._settings.connect_timeout, self._settings.request_timeout),
                    stream=True,
                )
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = exc
                self._sleep_for_retry(attempt)
                continue

            if response.status_code == 429 or response.status_code >= 500:
                last_error = APIStatusError(response.status_code, _safe_text(response))
                response.close()
                self._sleep_for_retry(attempt, response)
                continue

            if response.status_code >= 400:
                message, error_type = _error_info(response)
                response.close()
                raise APIStatusError(response.status_code, message, error_type=error_type)

            try:
                return accumulate_stream(
                    response.iter_lines(decode_unicode=True), on_delta=on_delta
                )
            finally:
                response.close()

        raise APIConnectionError(
            f"Request failed after {self._settings.max_retries + 1} attempts: {last_error}"
        )

    def _build_payload(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        tool_choice: str,
    ) -> dict[str, Any]:
        """Assemble the request body shared by the buffered and streaming paths."""
        payload: dict[str, Any] = {
            "model": self._settings.model,
            "messages": messages,
        }
        if self._settings.temperature is not None:
            payload["temperature"] = self._settings.temperature
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice
        return payload

    def _parse_message(self, response: requests.Response) -> dict[str, Any]:
        """Extract the assistant message from a successful HTTP response."""
        try:
            data = response.json()
        except json.JSONDecodeError as exc:
            raise APIResponseError(
                "Could not decode JSON from the API response. "
                "Verify MUHGPT_BASE_URL points to an OpenAI-compatible endpoint."
            ) from exc

        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise APIResponseError(f"Unexpected response shape: {data!r}") from exc

    def _sleep_for_retry(self, attempt: int, response: requests.Response | None = None) -> None:
        """Sleep before the next retry, honouring ``Retry-After`` when given."""
        if attempt >= self._settings.max_retries:
            return
        retry_after = _retry_after_seconds(response)
        if retry_after is not None:
            time.sleep(retry_after)
            return
        backoff = self._settings.backoff_base ** attempt
        time.sleep(backoff + random.uniform(0.0, 0.5))


def accumulate_stream(
    lines: Iterable[str | bytes],
    on_delta: Callable[[str], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Reassemble an OpenAI-style SSE stream into a ``(message, usage)`` pair.

    Each ``data:`` line carries a ``chat.completion.chunk``; the stream ends at
    ``data: [DONE]``. Assistant ``content`` fragments are concatenated (and
    forwarded to ``on_delta`` live), tool calls are merged by their ``index``
    (ids/names arrive once, ``arguments`` arrive in fragments), and a ``usage``
    object is captured from whichever chunk carries it.
    """
    content_parts: list[str] = []
    tool_calls: dict[int, dict[str, Any]] = {}
    usage: dict[str, Any] | None = None
    role = "assistant"

    for raw in lines:
        if raw is None:
            continue
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        line = line.strip()
        if not line or not line.startswith("data:"):
            continue
        data = line[len("data:"):].strip()
        if data == "[DONE]":
            break
        try:
            chunk = json.loads(data)
        except json.JSONDecodeError:
            continue

        if isinstance(chunk.get("usage"), dict):
            usage = chunk["usage"]

        choices = chunk.get("choices") or []
        if not choices:
            continue
        delta = choices[0].get("delta") or {}
        if delta.get("role"):
            role = delta["role"]

        piece = delta.get("content")
        if piece:
            content_parts.append(piece)
            if on_delta is not None:
                on_delta(piece)

        for call in delta.get("tool_calls") or []:
            index = call.get("index", 0)
            slot = tool_calls.setdefault(
                index, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}}
            )
            if call.get("id"):
                slot["id"] = call["id"]
            if call.get("type"):
                slot["type"] = call["type"]
            function = call.get("function") or {}
            if function.get("name"):
                slot["function"]["name"] += function["name"]
            if function.get("arguments"):
                slot["function"]["arguments"] += function["arguments"]

    message: dict[str, Any] = {"role": role}
    content = "".join(content_parts)
    if content:
        message["content"] = content
    if tool_calls:
        message["tool_calls"] = [tool_calls[i] for i in sorted(tool_calls)]
    return message, usage


def _safe_text(response: requests.Response) -> str:
    """Best-effort extraction of a human-readable error message from a response."""
    return _error_info(response)[0]


def _error_info(response: requests.Response) -> tuple[str, str | None]:
    """Extract ``(message, error_type)`` from an error response body.

    Handles the OpenAI-style ``{"error": {"message", "type", "code"}}`` shape used
    by the muh API; falls back to raw text / the whole body when it isn't present.
    """
    try:
        body = response.json()
    except json.JSONDecodeError:
        return response.text[:500], None
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            return str(error.get("message", body)), (error.get("type") or None)
        return str(error if error is not None else body), None
    return str(body), None


def _raise_status(response: requests.Response) -> None:
    """Raise a typed :class:`APIStatusError` from a 4xx response."""
    message, error_type = _error_info(response)
    raise APIStatusError(response.status_code, message, error_type=error_type)


def _retry_after_seconds(response: requests.Response | None) -> float | None:
    """Parse the numeric ``Retry-After`` header, if any."""
    if response is None:
        return None
    value = response.headers.get("Retry-After")
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None
