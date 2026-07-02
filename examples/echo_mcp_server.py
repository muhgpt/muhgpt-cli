#!/usr/bin/env python3
"""A tiny, dependency-free MCP server over stdio — for testing MuhGPT's MCP client.

It speaks the same JSON-RPC the real servers do (initialize -> tools/list ->
tools/call) and exposes two harmless tools: `echo` and `reverse`. Point MuhGPT at
it with examples/mcp.example.json to verify the whole MCP path end to end without
installing anything.

    python3 main.py --mcp --mcp-config examples/mcp.example.json
    # then in the session:
    /mcp
    > use the echo tool to say hello
"""
from __future__ import annotations

import json
import sys

TOOLS = [
    {
        "name": "echo",
        "description": "Echo back the given text (harmless test tool).",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Text to echo."}},
            "required": ["text"],
        },
    },
    {
        "name": "reverse",
        "description": "Return the given text reversed (harmless test tool).",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Text to reverse."}},
            "required": ["text"],
        },
    },
]


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _handle(msg: dict) -> None:
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        _send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "echo", "version": "1.0"}}})
    elif method == "notifications/initialized":
        pass  # notification: no response
    elif method == "tools/list":
        _send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        name = msg.get("params", {}).get("name")
        args = msg.get("params", {}).get("arguments", {}) or {}
        text = str(args.get("text", ""))
        if name == "echo":
            out = text
        elif name == "reverse":
            out = text[::-1]
        else:
            _send({"jsonrpc": "2.0", "id": mid,
                   "error": {"code": -32602, "message": f"unknown tool: {name}"}})
            return
        _send({"jsonrpc": "2.0", "id": mid,
               "result": {"content": [{"type": "text", "text": out}], "isError": False}})
    elif mid is not None:
        _send({"jsonrpc": "2.0", "id": mid,
               "error": {"code": -32601, "message": f"unknown method: {method}"}})


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            _handle(json.loads(line))
        except json.JSONDecodeError:
            continue  # not a valid MCP message; ignore per spec


if __name__ == "__main__":
    main()
