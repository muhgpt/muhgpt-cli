"""Tests for the MCP client: config parsing, stdio + HTTP transports, manager."""
from __future__ import annotations

import hashlib
import json
import json as json_module  # alias: the fake's post() shadows `json` with its payload param

import pytest

from muhgpt.mcp import (
    HttpTransport,
    McpClient,
    McpError,
    McpManager,
    McpServerConfig,
    McpTool,
    _content_to_text,
    _read_sse_response,
    default_config_path,
    load_mcp_config,
    merge_mcp_configs,
    namespaced_name,
)

# A tiny but real MCP server over stdio. Behaviour is switched by FAKE_MODE so
# one script exercises the happy path, tool errors, and a dead server.
FAKE_SERVER = r'''
import sys, json, os
mode = os.environ.get("FAKE_MODE", "ok")
if mode == "crash":
    sys.exit(1)

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "fake", "version": "1.0"}}})
    elif method == "notifications/initialized":
        # Emit an unsolicited notification to exercise notification-tolerance.
        send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
            {"name": "echo", "description": "Echo text",
             "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                             "required": ["text"]}},
            {"name": "boom", "description": "Always errors",
             "inputSchema": {"type": "object", "properties": {}}},
            {"name": "no_schema", "description": "No schema"}]}})
    elif method == "tools/call":
        name = msg["params"]["name"]
        args = msg["params"].get("arguments", {})
        if name == "echo":
            text = "echo: " + str(args.get("text", ""))
            send({"jsonrpc": "2.0", "id": mid,
                  "result": {"content": [{"type": "text", "text": text}]}})
        elif name == "boom":
            send({"jsonrpc": "2.0", "id": mid,
                  "result": {"content": [{"type": "text", "text": "it failed"}], "isError": True}})
        else:
            send({"jsonrpc": "2.0", "id": mid, "result": {"content": []}})
    else:
        send({"jsonrpc": "2.0", "id": mid,
              "error": {"code": -32601, "message": "unknown method"}})
'''


@pytest.fixture
def server_script(tmp_path):
    path = tmp_path / "fake_server.py"
    path.write_text(FAKE_SERVER, encoding="utf-8")
    return str(path)


def _stdio_cfg(server_script, mode="ok", name="fake"):
    return McpServerConfig(
        name=name, transport="stdio", command="python3",
        args=(server_script,), env={"FAKE_MODE": mode},
    )


# --------------------------------------------------------------------------- #
# stdio transport + manager (end to end against a real subprocess)            #
# --------------------------------------------------------------------------- #
def test_connect_lists_and_calls_tools(server_script):
    manager = McpManager([_stdio_cfg(server_script)], timeout=10).connect()
    try:
        assert manager.errors == []
        names = {t.name for t in manager.tools}
        assert names == {"mcp__fake__echo", "mcp__fake__boom", "mcp__fake__no_schema"}
        assert manager.has_tool("mcp__fake__echo")
        assert manager.invoke("mcp__fake__echo", {"text": "hi"}) == "echo: hi"
    finally:
        manager.close()


def test_tool_error_is_flagged_not_raised(server_script):
    manager = McpManager([_stdio_cfg(server_script)], timeout=10).connect()
    try:
        out = manager.invoke("mcp__fake__boom", {})
        assert out.startswith("[tool error]")
        assert "it failed" in out
    finally:
        manager.close()


def test_schema_without_inputschema_gets_default_object(server_script):
    manager = McpManager([_stdio_cfg(server_script)], timeout=10).connect()
    try:
        tool = manager.tool("mcp__fake__no_schema")
        params = tool.openai_schema["function"]["parameters"]
        assert params["type"] == "object" and params["properties"] == {}
    finally:
        manager.close()


def test_connect_tolerates_a_dead_server(server_script):
    manager = McpManager([_stdio_cfg(server_script, mode="crash")], timeout=5).connect()
    try:
        assert manager.tools == []
        assert len(manager.errors) == 1 and manager.errors[0][0] == "fake"
    finally:
        manager.close()


def test_one_bad_server_does_not_kill_the_good_one(server_script):
    cfgs = [_stdio_cfg(server_script, name="good"),
            _stdio_cfg(server_script, mode="crash", name="bad")]
    manager = McpManager(cfgs, timeout=5).connect()
    try:
        assert any(t.server == "good" for t in manager.tools)
        assert [e[0] for e in manager.errors] == ["bad"]
    finally:
        manager.close()


def test_invoke_unknown_tool_raises(server_script):
    manager = McpManager([_stdio_cfg(server_script)], timeout=10).connect()
    try:
        with pytest.raises(McpError):
            manager.invoke("mcp__fake__nope", {})
    finally:
        manager.close()


def test_launch_failure_is_reported_not_raised():
    cfg = McpServerConfig(name="nope", transport="stdio", command="definitely-not-a-binary-xyz")
    manager = McpManager([cfg], timeout=3).connect()
    assert manager.tools == [] and len(manager.errors) == 1


def test_auto_tools_membership(server_script):
    manager = McpManager(
        [_stdio_cfg(server_script)], timeout=10, auto_tools=("mcp__fake__echo",)
    ).connect()
    try:
        assert manager.is_auto_allowed("mcp__fake__echo")
        assert not manager.is_auto_allowed("mcp__fake__boom")
        assert manager.auto_tools == frozenset({"mcp__fake__echo"})
    finally:
        manager.close()


# --------------------------------------------------------------------------- #
# config parsing                                                              #
# --------------------------------------------------------------------------- #
def test_load_mcp_config_parses_stdio_http_and_skips_disabled(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "local": {"command": "python3", "args": ["s.py"], "env": {"K": "V"}},
        "remote": {"url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer x"}},
        "off": {"command": "x", "disabled": True},
    }}), encoding="utf-8")
    configs = {c.name: c for c in load_mcp_config(cfg)}
    assert set(configs) == {"local", "remote"}
    assert configs["local"].transport == "stdio" and configs["local"].args == ("s.py",)
    assert configs["local"].env == {"K": "V"}
    assert configs["remote"].transport == "http"
    assert configs["remote"].headers == {"Authorization": "Bearer x"}


def test_load_mcp_config_explicit_type_overrides(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "s": {"type": "http", "url": "https://x/mcp"}}}), encoding="utf-8")
    assert load_mcp_config(cfg)[0].transport == "http"


def test_bundled_defaults_parse_and_are_pinned():
    # The shipped curated free servers must load and every npx package be pinned
    # to an exact @version (anti supply-chain drift).
    path = default_config_path()
    assert path.is_file()
    configs = {c.name: c for c in load_mcp_config(path)}
    assert {"ddg", "fetch", "wikipedia", "think"} <= set(configs)
    for cfg in configs.values():
        assert cfg.transport == "stdio" and cfg.command == "npx"
        pkg = cfg.args[-1]
        assert "@" in pkg.lstrip("@"), f"{cfg.name} package not pinned: {pkg}"


def test_merge_mcp_configs_override_and_append():
    base = [McpServerConfig(name="ddg", transport="stdio", command="npx"),
            McpServerConfig(name="fetch", transport="stdio", command="npx")]
    user = [McpServerConfig(name="ddg", transport="stdio", command="custom"),
            McpServerConfig(name="mine", transport="stdio", command="npx")]
    merged = {c.name: c for c in merge_mcp_configs(base, user)}
    assert set(merged) == {"ddg", "fetch", "mine"}
    assert merged["ddg"].command == "custom"  # user wins
    # order is stable: base order then new user entries
    assert [c.name for c in merge_mcp_configs(base, user)] == ["ddg", "fetch", "mine"]


def test_load_mcp_config_errors(tmp_path):
    with pytest.raises(McpError):
        load_mcp_config(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("not json{", encoding="utf-8")
    with pytest.raises(McpError):
        load_mcp_config(bad)
    noservers = tmp_path / "ns.json"
    noservers.write_text(json.dumps({"other": {}}), encoding="utf-8")
    with pytest.raises(McpError):
        load_mcp_config(noservers)


# --------------------------------------------------------------------------- #
# pure helpers                                                                #
# --------------------------------------------------------------------------- #
def test_namespaced_name_sanitizes_and_caps():
    assert namespaced_name("shodan", "host.info") == "mcp__shodan__host_info"
    assert namespaced_name("sho dan", "lookup") == "mcp__sho_dan__lookup"
    long = namespaced_name("s" * 40, "t" * 40)
    assert len(long) <= 64 and long.startswith("mcp__")


def test_namespaced_name_is_deterministic_for_long_names():
    # The truncation digest must be stable (sha1, not the randomized builtin hash)
    # so the MUHGPT_MCP_AUTO_TOOLS allowlist keeps working across runs.
    a = namespaced_name("server" * 10, "tool" * 10)
    b = namespaced_name("server" * 10, "tool" * 10)
    assert a == b
    expected_base = f"mcp__{'server' * 10}__{'tool' * 10}"
    digest = hashlib.sha1(expected_base.encode("utf-8")).hexdigest()[:4]
    assert a.endswith("_" + digest)


def test_read_sse_response_matches_strictly_on_id():
    # A stream may carry a notification (no id) and an unrelated response before
    # ours; only the object whose id matches want_id may be returned.
    resp = _FakeHttpResp(lines=[
        'data: {"jsonrpc":"2.0","method":"notifications/progress"}',
        'data: {"jsonrpc":"2.0","id":99,"result":{"other":true}}',
        'data: {"jsonrpc":"2.0","id":7,"result":{"mine":true}}',
    ])
    assert _read_sse_response(resp, 7) == {"jsonrpc": "2.0", "id": 7, "result": {"mine": True}}


def test_read_sse_response_raises_when_id_absent():
    resp = _FakeHttpResp(lines=['data: {"jsonrpc":"2.0","id":1,"result":{}}'])
    with pytest.raises(McpError):
        _read_sse_response(resp, 2)


def test_content_to_text_handles_block_types():
    blocks = [
        {"type": "text", "text": "line1"},
        {"type": "image", "mimeType": "image/png", "data": "..."},
        {"type": "resource", "resource": {"uri": "file:///x", "text": "embedded"}},
        {"type": "resource_link", "uri": "file:///y"},
    ]
    out = _content_to_text(blocks)
    assert "line1" in out and "image/png" in out and "embedded" in out and "file:///y" in out
    assert _content_to_text("plain") == "plain"
    assert _content_to_text(None) == ""


def test_mcptool_openai_schema_shape():
    tool = McpTool(
        server="srv", raw_name="do_x", name="mcp__srv__do_x", description="does x",
        input_schema={"type": "object", "properties": {"a": {"type": "string"}}},
    )
    schema = tool.openai_schema
    assert schema["type"] == "function"
    assert schema["function"]["name"] == "mcp__srv__do_x"
    assert "[MCP:srv]" in schema["function"]["description"]
    assert schema["function"]["parameters"]["properties"] == {"a": {"type": "string"}}


# --------------------------------------------------------------------------- #
# HTTP transport (fake requests session)                                       #
# --------------------------------------------------------------------------- #
class _FakeHttpResp:
    def __init__(self, status=200, json_data=None, headers=None, lines=None):
        self.status_code = status
        self._json = json_data
        self.headers = headers or {}
        self._lines = lines or []
        self.text = json.dumps(json_data) if json_data is not None else ""

    def json(self):
        if self._json is None:
            raise json.JSONDecodeError("no json", "", 0)
        return self._json

    def iter_lines(self, decode_unicode=False):
        return iter(self._lines)

    def close(self):
        pass


class _FakeHttpSession:
    """Routes a posted JSON-RPC message to a canned response by method."""

    def __init__(self, sse=False):
        self.sse = sse
        self.calls = []

    def post(self, url, json=None, headers=None, timeout=None, stream=None):
        self.calls.append({"json": json, "headers": headers})
        method, mid = json.get("method"), json.get("id")
        if "id" not in json:  # notification
            return _FakeHttpResp(status=202)
        if method == "initialize":
            body = {"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "http-fake", "version": "1"}}}
            return _FakeHttpResp(json_data=body, headers={"MCP-Session-Id": "sess-123"})
        if method == "tools/list":
            body = {"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                {"name": "lookup", "description": "Look up",
                 "inputSchema": {"type": "object", "properties": {}}}]}}
        elif method == "tools/call":
            body = {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": "http-result"}]}}
        else:
            body = {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "no"}}
        if self.sse:
            lines = [f"data: {json_module.dumps(body)}", ""]
            return _FakeHttpResp(headers={"Content-Type": "text/event-stream"}, lines=lines)
        return _FakeHttpResp(json_data=body)

    def close(self):
        pass


@pytest.mark.parametrize("sse", [False, True])
def test_http_transport_end_to_end(sse):
    http = _FakeHttpSession(sse=sse)
    transport = HttpTransport("https://x/mcp", http_session=http)
    client = McpClient("http-fake", transport, timeout=5)
    client.initialize()
    tools = client.list_tools()
    assert [t["name"] for t in tools] == ["lookup"]
    result = client.call_tool("lookup", {})
    assert _content_to_text(result.get("content")) == "http-result"
    # The session id from initialize must be echoed on later requests.
    later = [c for c in http.calls if c["json"].get("method") == "tools/list"][0]
    assert later["headers"].get("MCP-Session-Id") == "sess-123"


def test_http_transport_surfaces_http_error():
    class Boom(_FakeHttpSession):
        def post(self, url, json=None, headers=None, timeout=None, stream=None):
            if "id" not in json:
                return _FakeHttpResp(status=202)
            if json.get("method") == "initialize":
                return _FakeHttpResp(json_data={"jsonrpc": "2.0", "id": json["id"],
                                                "result": {"protocolVersion": "2025-06-18",
                                                           "capabilities": {}}})
            return _FakeHttpResp(status=500, json_data=None)

    client = McpClient("x", HttpTransport("https://x/mcp", http_session=Boom()), timeout=5)
    client.initialize()
    with pytest.raises(McpError):
        client.list_tools()
