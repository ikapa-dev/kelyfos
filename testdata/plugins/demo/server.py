#!/usr/bin/env python3
"""A minimal MCP server, for proving the plugin path end to end (E4-7).

Standard library only, because it runs inside the guest and the guest ships
python3 and nothing else. Newline-delimited JSON-RPC on stdin and stdout, which
is the MCP stdio transport unchanged.

It does three things, chosen so a test can tell each apart: one tool that
answers, one that fails as a tool result, and one that ends the process — which
is what a crashed plugin looks like from the outside.
"""
import json
import os
import sys

TOOLS = [
    {
        "name": "echo",
        "title": "Echo",
        "description": "Return the text it was given, prefixed, so a caller can "
                       "tell this answer apart from any other.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "What to echo."}},
            "required": ["text"],
        },
    },
    {
        "name": "where",
        "title": "Where am I",
        "description": "Report the plugin's working directory and whether it can write there.",
        "inputSchema": {"type": "object"},
    },
    {
        "name": "fail",
        "title": "Fail on purpose",
        "description": "Return an error result, to show that a plugin's failure is a result "
                       "the agent can read rather than a broken session.",
        "inputSchema": {"type": "object"},
    },
    {
        "name": "die",
        "title": "Stop the plugin",
        "description": "Exit the plugin process, to show what a crashed plugin does to "
                       "everything around it, which is nothing.",
        "inputSchema": {"type": "object"},
    },
]


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def result(rid, value):
    send({"jsonrpc": "2.0", "id": rid, "result": value})


def call(name, args):
    if name == "echo":
        return {"content": [{"type": "text", "text": "demo says: " + args.get("text", "")}]}
    if name == "where":
        writable = os.access(os.getcwd(), os.W_OK)
        return {
            "content": [{"type": "text",
                         "text": "cwd %s, writable %s" % (os.getcwd(), writable)}],
            "structuredContent": {"cwd": os.getcwd(), "writable": writable},
        }
    if name == "fail":
        return {"content": [{"type": "text", "text": "this tool always fails"}], "isError": True}
    if name == "die":
        sys.exit(9)
    return {"content": [{"type": "text", "text": "unknown tool " + name}], "isError": True}


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    method, rid = msg.get("method"), msg.get("id")
    if rid is None:
        continue  # a notification; JSON-RPC forbids answering one
    if method == "initialize":
        result(rid, {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            # Announced and deliberately ignored: the host decides what a plugin
            # is called, and the thing being named does not get a vote (F-D24).
            "serverInfo": {"name": "not-the-name-that-counts", "version": "1.0.0"},
        })
    elif method == "tools/list":
        result(rid, {"tools": TOOLS})
    elif method == "tools/call":
        params = msg.get("params", {})
        result(rid, call(params.get("name", ""), params.get("arguments") or {}))
    elif method == "ping":
        result(rid, {})
    else:
        send({"jsonrpc": "2.0", "id": rid,
              "error": {"code": -32601, "message": "unknown method " + str(method)}})
