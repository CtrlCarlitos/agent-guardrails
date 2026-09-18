#!/usr/bin/env python3
"""Harmless stdio MCP fixture; records any tool execution to argv[1]."""
import json
from pathlib import Path
import sys

for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    method = message.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "guardrail-fixture", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "read", "description": "Read harmless fixture text", "inputSchema": {"type": "object", "properties": {}}}]}
    elif method == "tools/call":
        Path(sys.argv[1]).write_text("tool executed\n")
        result = {"content": [{"type": "text", "text": "fixture"}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
