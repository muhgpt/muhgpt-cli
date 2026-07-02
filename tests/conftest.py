"""Shared test fakes for the MuhGPT suite — no network, no real model calls."""
from __future__ import annotations

import json
from typing import Any

import pytest

from muhgpt.session import Session
from muhgpt.tools import ToolResult


class FakeResponse:
    """Stand-in for ``requests.Response`` carrying a canned status + body."""

    def __init__(
        self,
        status_code: int,
        json_data: Any | None = None,
        text: str = "",
        headers: dict[str, str] | None = None,
        lines: list[str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._json = json_data
        self.text = text
        self.headers = headers or {}
        self._lines = lines or []
        self.closed = False

    def json(self) -> Any:
        if self._json is None:
            raise json.JSONDecodeError("no json", "", 0)
        return self._json

    def iter_lines(self, decode_unicode: bool = False) -> Any:
        return iter(self._lines)

    def close(self) -> None:
        self.closed = True


class FakeSession:
    """Stand-in for ``requests.Session`` that replays a queue of responses."""

    def __init__(self, responses: list[Any]) -> None:
        self.headers: dict[str, str] = {}
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def post(
        self, url: str, json: Any = None, timeout: Any = None, stream: Any = None
    ) -> FakeResponse:
        self.calls.append({"url": url, "json": json, "timeout": timeout, "stream": stream})
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def request(
        self, method: str, url: str, params: Any = None, timeout: Any = None, **kwargs: Any
    ) -> FakeResponse:
        self.calls.append({"method": method, "url": url, "params": params, "timeout": timeout})
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeTools:
    """Minimal ToolRegistry stand-in that records dispatches."""

    schemas: list[dict[str, Any]] = []

    def __init__(self) -> None:
        self.dispatched: list[tuple[str, str]] = []

    def dispatch(self, name: str, arguments: str) -> ToolResult:
        self.dispatched.append((name, arguments))
        return ToolResult(content=f"ran {name}")


@pytest.fixture
def session(tmp_path) -> Session:
    """A fresh engagement session writing into an isolated temp reports dir."""
    return Session(operator="tester", scope="example.com", reports_dir=tmp_path / "reports")


@pytest.fixture
def no_sleep(monkeypatch) -> list[float]:
    """Patch out real sleeping in the API client; return the recorded durations."""
    slept: list[float] = []
    monkeypatch.setattr("muhgpt.api_client.time.sleep", lambda s: slept.append(s))
    return slept
