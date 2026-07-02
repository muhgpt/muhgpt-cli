"""A minimal Model Context Protocol (MCP) client — pure stdlib + ``requests``.

MuhGPT can connect to external MCP servers and let the model call their tools as
if they were native tools. This module is the transport + JSON-RPC layer; the
*approval* of every MCP tool call happens in :mod:`muhgpt.tools` (HITL confirm,
or guard classification in autonomous mode) — exactly like a shell command. An
MCP server's tool descriptions and outputs are treated as UNTRUSTED input.

Scope (deliberately small — enough to list and call tools):

* JSON-RPC 2.0 over two transports:
  - **stdio**: launch the server as a subprocess and exchange newline-delimited
    JSON (``subprocess`` + ``json`` + ``threading`` — no third-party dep);
  - **HTTP**: Streamable HTTP using the existing ``requests`` dependency,
    handling both ``application/json`` and ``text/event-stream`` responses.
* The lifecycle ``initialize`` -> ``notifications/initialized`` -> ``tools/list``
  / ``tools/call``. Resources, prompts, sampling, roots and friends are skipped.

No new runtime dependency is introduced, so the macOS/Linux/Termux guarantee holds.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Callable

import requests

from . import __version__

# The protocol revision we advertise. Servers may answer with an older one
# (2025-06-18 / 2024-11-05 are common); we connect best-effort regardless.
PROTOCOL_VERSION = "2025-11-25"

# Tool names are namespaced so MCP tools never collide with the four built-ins.
NAMESPACE = "mcp"
_SEP = "__"
_NAME_RE = re.compile(r"[^A-Za-z0-9_-]")
_MAX_NAME = 64  # OpenAI function-name length cap


class McpError(RuntimeError):
    """Any MCP transport / protocol / configuration failure."""


# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class McpServerConfig:
    """One MCP server entry parsed from the ``mcpServers`` config shape."""

    name: str
    transport: str = "stdio"  # "stdio" | "http"
    command: str | None = None
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


def default_config_path() -> Path:
    """Path to the curated free-MCP config shipped inside the package."""
    return Path(__file__).resolve().parent / "mcp_defaults.json"


def merge_mcp_configs(*config_lists: list[McpServerConfig]) -> list[McpServerConfig]:
    """Merge ordered config lists into one, later entries overriding earlier by name.

    Used to layer the operator's own servers on top of the bundled defaults: a
    user entry with the same server name replaces the bundled one; new names are
    appended. Order is stable (bundled first, then user additions).
    """
    merged: dict[str, McpServerConfig] = {}
    for configs in config_lists:
        for cfg in configs:
            merged[cfg.name] = cfg
    return list(merged.values())


def load_mcp_config(path: str | os.PathLike[str]) -> list[McpServerConfig]:
    """Parse a Claude-Desktop/Cursor-style ``{"mcpServers": {...}}`` JSON file.

    Each entry is either a stdio server (``command`` + ``args`` + ``env``) or an
    HTTP server (``url`` + optional ``headers``); ``type``/``transport`` may set
    it explicitly, otherwise the presence of ``url`` selects HTTP. Entries marked
    ``"disabled": true`` (or ``"enabled": false``) are skipped.

    Raises:
        McpError: If the file is missing, unreadable, or malformed.
    """
    p = Path(path)
    if not p.is_file():
        raise McpError(f"MCP config file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise McpError(f"Could not read MCP config {p}: {exc}") from exc

    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        raise McpError("MCP config must contain an 'mcpServers' object.")

    configs: list[McpServerConfig] = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        if spec.get("disabled") is True or spec.get("enabled") is False:
            continue
        url = spec.get("url")
        raw_transport = (spec.get("type") or spec.get("transport") or "").lower()
        transport = (
            "http"
            if raw_transport in {"http", "streamable-http", "sse"} or (not raw_transport and url)
            else "stdio"
        )
        configs.append(
            McpServerConfig(
                name=str(name),
                transport=transport,
                command=spec.get("command"),
                args=tuple(str(a) for a in (spec.get("args") or ())),
                env={str(k): str(v) for k, v in (spec.get("env") or {}).items()},
                url=str(url) if url else None,
                headers={str(k): str(v) for k, v in (spec.get("headers") or {}).items()},
            )
        )
    return configs


# --------------------------------------------------------------------------- #
# Transports                                                                  #
# --------------------------------------------------------------------------- #
class Transport:
    """Sends one JSON-RPC payload and returns the matching response (or None)."""

    def request(self, payload: dict[str, Any], timeout: float) -> dict[str, Any] | None:
        raise NotImplementedError

    def note_protocol_version(self, version: str) -> None:
        """Record the negotiated protocol version (only HTTP needs this)."""

    def close(self) -> None:
        raise NotImplementedError


_EOF = object()  # sentinel pushed onto the stdio queue when the server exits


class StdioTransport(Transport):
    """Launches an MCP server subprocess and talks newline-delimited JSON-RPC.

    A reader thread parses each stdout line into a message and queues it; stderr
    is drained into a small ring buffer (so a chatty server can't deadlock on a
    full pipe, and the tail is available for error messages). Requests are
    serialized by a lock — fine for MuhGPT's single-threaded agent loop.
    """

    def __init__(
        self,
        command: str,
        args: tuple[str, ...] | list[str] = (),
        env: dict[str, str] | None = None,
    ) -> None:
        merged_env = {**os.environ, **(env or {})}
        try:
            self._proc = subprocess.Popen(  # noqa: S603 - operator-configured server
                [command, *args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=merged_env,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except OSError as exc:
            raise McpError(f"could not launch MCP server '{command}': {exc}") from exc

        self._queue: Queue[Any] = Queue()
        self._stderr_tail: deque[str] = deque(maxlen=50)
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._pump_stdout, daemon=True)
        self._errpump = threading.Thread(target=self._pump_stderr, daemon=True)
        self._reader.start()
        self._errpump.start()

    def _pump_stdout(self) -> None:
        stream = self._proc.stdout
        if stream is not None:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                try:
                    self._queue.put(json.loads(line))
                except json.JSONDecodeError:
                    continue  # not an MCP message; ignore per spec
        self._queue.put(_EOF)

    def _pump_stderr(self) -> None:
        stream = self._proc.stderr
        if stream is not None:
            for line in stream:
                self._stderr_tail.append(line.rstrip())

    def _stderr_hint(self) -> str:
        tail = "\n".join(self._stderr_tail)
        return f"\n--- server stderr ---\n{tail}" if tail.strip() else ""

    def request(self, payload: dict[str, Any], timeout: float) -> dict[str, Any] | None:
        is_notification = "id" not in payload
        with self._lock:
            self._write(payload)
            if is_notification:
                return None
            want = payload["id"]
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise McpError(
                        f"timed out after {timeout:g}s waiting for '{payload['method']}'"
                        + self._stderr_hint()
                    )
                try:
                    msg = self._queue.get(timeout=remaining)
                except Empty:
                    continue
                if msg is _EOF:
                    raise McpError("MCP server closed the connection" + self._stderr_hint())
                # Skip unsolicited notifications (no id) and any stale response.
                if isinstance(msg, dict) and msg.get("id") == want:
                    return msg

    def _write(self, payload: dict[str, Any]) -> None:
        # NOTE: this write is blocking and not independently timed out. The read
        # side IS deadline-bounded (see request()), and the reader/stderr threads
        # drain the server's stdout/stderr so it can't backpressure us. The only
        # unbounded case is a server that stops consuming its stdin while its OS
        # pipe buffer (typically 64 KiB) is full; MCP requests are tiny, so a
        # single write effectively never blocks in practice. If that ever needs
        # hardening, move the write into a watchdog'd worker thread.
        if self._proc.poll() is not None or self._proc.stdin is None:
            raise McpError("MCP server process is not running" + self._stderr_hint())
        try:
            self._proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise McpError(f"failed to write to MCP server: {exc}" + self._stderr_hint()) from exc

    def close(self) -> None:
        """Graceful shutdown: close stdin, wait, then terminate, then kill."""
        proc = self._proc
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


class HttpTransport(Transport):
    """Streamable HTTP MCP transport over ``requests``.

    Each call POSTs one JSON-RPC message. The server replies with either a single
    ``application/json`` body or an SSE (``text/event-stream``) stream carrying
    the response; both are handled. The ``MCP-Session-Id`` returned at initialize
    is echoed on every later request, as is ``MCP-Protocol-Version``.
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        http_session: requests.Session | None = None,
    ) -> None:
        self._url = url
        self._http = http_session or requests.Session()
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if headers:
            self._headers.update(headers)
        self._session_id: str | None = None
        self._protocol_version: str | None = None

    def note_protocol_version(self, version: str) -> None:
        if version:
            self._protocol_version = version

    def request(self, payload: dict[str, Any], timeout: float) -> dict[str, Any] | None:
        is_notification = "id" not in payload
        headers = dict(self._headers)
        if self._session_id:
            headers["MCP-Session-Id"] = self._session_id
        if self._protocol_version:
            headers["MCP-Protocol-Version"] = self._protocol_version
        try:
            resp = self._http.post(
                self._url, json=payload, headers=headers, timeout=timeout, stream=True
            )
        except (requests.Timeout, requests.ConnectionError) as exc:
            raise McpError(f"HTTP MCP request failed: {exc}") from exc

        sid = resp.headers.get("MCP-Session-Id") or resp.headers.get("Mcp-Session-Id")
        if sid:
            self._session_id = sid
        try:
            if is_notification:
                return None
            if resp.status_code >= 400:
                raise McpError(f"HTTP {resp.status_code}: {_safe_body(resp)}")
            if "text/event-stream" in (resp.headers.get("Content-Type") or ""):
                return _read_sse_response(resp, payload["id"])
            try:
                return resp.json()
            except json.JSONDecodeError as exc:
                raise McpError("MCP server returned a non-JSON body") from exc
        finally:
            resp.close()

    def close(self) -> None:
        try:
            self._http.close()
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass


def _read_sse_response(resp: requests.Response, want_id: Any) -> dict[str, Any]:
    """Pull the JSON-RPC response whose id matches ``want_id`` from an SSE stream.

    Matching is strict on ``id``: a Streamable-HTTP stream may also carry
    server-to-client requests, notifications, or unrelated responses, so we must
    not return the first object that merely has a ``result``/``error`` — only the
    one answering *our* request. Messages without an id (notifications) are skipped.
    """
    for raw in resp.iter_lines(decode_unicode=True):
        if not raw:
            continue
        line = raw.strip()
        if not line.startswith("data:"):
            continue
        data = line[len("data:"):].strip()
        if not data or data == "[DONE]":
            continue
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict) and msg.get("id") == want_id:
            return msg
    raise McpError("no JSON-RPC response found in SSE stream")


def _safe_body(resp: requests.Response) -> str:
    try:
        return resp.text[:500]
    except Exception:  # noqa: BLE001
        return "(unreadable body)"


# --------------------------------------------------------------------------- #
# JSON-RPC client                                                             #
# --------------------------------------------------------------------------- #
class McpClient:
    """The JSON-RPC layer over a :class:`Transport`: handshake, list, call."""

    def __init__(self, name: str, transport: Transport, timeout: float = 30.0) -> None:
        self._name = name
        self._transport = transport
        self._timeout = timeout
        self._id = 0
        self.server_info: dict[str, Any] = {}
        self.protocol_version: str = ""

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next_id(), "method": method}
        if params is not None:
            payload["params"] = params
        resp = self._transport.request(payload, self._timeout)
        if resp is None:
            raise McpError(f"no response to '{method}'")
        if isinstance(resp.get("error"), dict):
            err = resp["error"]
            raise McpError(f"{method} -> [{err.get('code')}] {err.get('message')}")
        result = resp.get("result")
        return result if isinstance(result, dict) else {}

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._transport.request(payload, self._timeout)

    def initialize(self) -> dict[str, Any]:
        """Run the mandatory handshake; returns the server's initialize result."""
        result = self._call(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "muhgpt", "version": __version__},
            },
        )
        self.server_info = result.get("serverInfo") or {}
        self.protocol_version = result.get("protocolVersion") or PROTOCOL_VERSION
        self._transport.note_protocol_version(self.protocol_version)
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        """List every tool the server exposes, following pagination cursors."""
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(100):  # hard cap so a buggy server can't loop forever
            params = {} if cursor is None else {"cursor": cursor}
            result = self._call("tools/list", params)
            tools.extend(t for t in (result.get("tools") or []) if isinstance(t, dict))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        """Invoke a tool by its server-native name; returns the raw result dict."""
        return self._call("tools/call", {"name": name, "arguments": arguments or {}})

    def close(self) -> None:
        self._transport.close()


# --------------------------------------------------------------------------- #
# Tools + manager                                                             #
# --------------------------------------------------------------------------- #
def namespaced_name(server: str, tool: str) -> str:
    """Build a collision-free, OpenAI-safe tool name: ``mcp__<server>__<tool>``."""
    base = f"{NAMESPACE}{_SEP}{_NAME_RE.sub('_', server)}{_SEP}{_NAME_RE.sub('_', tool)}"
    if len(base) <= _MAX_NAME:
        return base
    # Too long for the function-name cap — truncate and disambiguate with a STABLE
    # digest. builtin hash() is per-process randomized (PYTHONHASHSEED), which would
    # change the model-facing name every run and break the MUHGPT_MCP_AUTO_TOOLS
    # allowlist; sha1 is deterministic and stdlib.
    digest = hashlib.sha1(base.encode("utf-8")).hexdigest()[:4]
    return base[: _MAX_NAME - 5] + "_" + digest


@dataclass
class McpTool:
    """A discovered MCP tool, presented to the model as a callable function."""

    server: str
    raw_name: str
    name: str  # namespaced, model-facing
    description: str
    input_schema: dict[str, Any]

    @property
    def openai_schema(self) -> dict[str, Any]:
        """Render this tool in the OpenAI function-tool shape the agent feeds the model."""
        schema = self.input_schema if isinstance(self.input_schema, dict) else {}
        params: dict[str, Any] = dict(schema) if schema.get("type") == "object" else {}
        params.setdefault("type", "object")
        params.setdefault("properties", {})
        desc = self.description.strip() or f"MCP tool '{self.raw_name}'"
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": f"[MCP:{self.server}] {desc}",
                "parameters": params,
            },
        }


def _content_to_text(content: Any) -> str:
    """Flatten an MCP ``content`` block array into plain text for the model."""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "text":
            parts.append(str(block.get("text", "")))
        elif btype in {"image", "audio"}:
            parts.append(f"[{btype}: {block.get('mimeType', 'binary')}]")
        elif btype == "resource_link":
            parts.append(f"[resource_link: {block.get('uri', '')}]")
        elif btype == "resource":
            res = block.get("resource") or {}
            parts.append(str(res.get("text") or f"[resource: {res.get('uri', '')}]"))
    return "\n".join(p for p in parts if p)


def _default_transport_factory(
    cfg: McpServerConfig, http_session: requests.Session | None
) -> Transport:
    """Build the transport a server config calls for (the manager's default)."""
    if cfg.transport == "http":
        if not cfg.url:
            raise McpError(f"server '{cfg.name}': http transport requires a 'url'")
        return HttpTransport(cfg.url, cfg.headers, http_session)
    if not cfg.command:
        raise McpError(f"server '{cfg.name}': stdio transport requires a 'command'")
    return StdioTransport(cfg.command, cfg.args, cfg.env)


class McpManager:
    """Connects to many MCP servers and aggregates their tools for the agent.

    Construction has no side effects; :meth:`connect` does the spawning and the
    network I/O so callers can wrap it in their own error handling. A failure on
    one server is recorded in :attr:`errors` and skipped — it never aborts the
    others or the CLI.
    """

    def __init__(
        self,
        configs: list[McpServerConfig],
        timeout: float = 30.0,
        auto_tools: tuple[str, ...] | set[str] = (),
        http_session: requests.Session | None = None,
        transport_factory: Callable[[McpServerConfig, Any], Transport] | None = None,
    ) -> None:
        self._configs = list(configs)
        self._timeout = timeout
        self._auto_tools = set(auto_tools)
        self._http_session = http_session
        self._factory = transport_factory or _default_transport_factory
        self._clients: list[McpClient] = []
        self._tools: dict[str, McpTool] = {}
        self._client_of: dict[str, McpClient] = {}
        self.errors: list[tuple[str, str]] = []
        self.connected = False

    def connect(self) -> McpManager:
        """Initialize every configured server and collect its tools."""
        for cfg in self._configs:
            transport: Transport | None = None
            try:
                transport = self._factory(cfg, self._http_session)
                client = McpClient(cfg.name, transport, self._timeout)
                client.initialize()
                tools = client.list_tools()
            except Exception as exc:  # noqa: BLE001 - one bad server must not kill the rest
                self.errors.append((cfg.name, str(exc)))
                if transport is not None:
                    try:
                        transport.close()
                    except Exception:  # noqa: BLE001
                        pass
                continue
            self._clients.append(client)
            for raw in tools:
                name = namespaced_name(cfg.name, str(raw.get("name", "")))
                self._tools[name] = McpTool(
                    server=cfg.name,
                    raw_name=str(raw.get("name", "")),
                    name=name,
                    description=str(raw.get("description") or ""),
                    input_schema=raw.get("inputSchema") if isinstance(raw.get("inputSchema"), dict)
                    else {"type": "object", "properties": {}},
                )
                self._client_of[name] = client
        self.connected = True
        return self

    @property
    def tools(self) -> list[McpTool]:
        return list(self._tools.values())

    @property
    def schemas(self) -> list[dict[str, Any]]:
        """OpenAI tool schemas for every discovered MCP tool."""
        return [t.openai_schema for t in self._tools.values()]

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def tool(self, name: str) -> McpTool | None:
        return self._tools.get(name)

    def is_auto_allowed(self, name: str) -> bool:
        """Whether the operator pre-approved this tool to auto-run in --auto mode."""
        return name in self._auto_tools

    @property
    def auto_tools(self) -> frozenset[str]:
        """The operator's set of namespaced tool names allowed to auto-run."""
        return frozenset(self._auto_tools)

    def invoke(self, name: str, arguments: dict[str, Any] | None) -> str:
        """Call a namespaced MCP tool and return its text content for the model."""
        tool = self._tools.get(name)
        client = self._client_of.get(name)
        if tool is None or client is None:
            raise McpError(f"unknown MCP tool: {name!r}")
        result = client.call_tool(tool.raw_name, arguments)
        text = _content_to_text(result.get("content"))
        if result.get("isError"):
            return "[tool error] " + (text or "(no detail provided)")
        return text or "(no output)"

    def describe(self) -> str:
        """A human-readable summary of connected servers, tools, and any errors."""
        lines: list[str] = []
        servers: dict[str, list[str]] = {}
        for tool in self._tools.values():
            servers.setdefault(tool.server, []).append(tool.raw_name)
        if not servers and not self.errors:
            return "No MCP servers connected."
        for server, names in servers.items():
            lines.append(f"{server}: {len(names)} tool(s) — {', '.join(sorted(names))}")
        for server, err in self.errors:
            lines.append(f"{server}: [failed] {err}")
        return "\n".join(lines)

    def close(self) -> None:
        for client in self._clients:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        self._clients.clear()
