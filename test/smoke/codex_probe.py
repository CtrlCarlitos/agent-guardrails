#!/usr/bin/env python3
"""Exercise the installed Codex runtime with a deterministic local Responses fixture.
No model service or credentials; all tool effects stay in a disposable directory.
Usage: python3 test/smoke/codex_probe.py /absolute/path/to/guardrail
"""
import http.server
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import threading

for required in ("codex", "git", "gofmt"):
    if shutil.which(required) is None:
        print(f"SKIP: {required} is required", file=sys.stderr)
        sys.exit(77)
binary = str(Path(sys.argv[1]).resolve())
code_mode = "--code-mode" in sys.argv[2:]
root = Path(tempfile.mkdtemp(prefix="guardrail-codex-native-"))
workspace = root / "workspace"
workspace.mkdir()
config = root / "codex"
config.mkdir()
log = root / "hooks.jsonl"
wrapper = root / "guardrail-probe"
wrapper.write_text("#!/usr/bin/env python3\nimport json,sys,subprocess\nraw=sys.stdin.buffer.read()\np=subprocess.run(" + repr([binary]) + "+sys.argv[1:],input=raw,capture_output=True)\nwith open(" + repr(str(log)) + ", 'a') as f: f.write(json.dumps({'input':json.loads(raw),'exit':p.returncode,'stderr':p.stderr.decode()})+'\\n')\nsys.stdout.buffer.write(p.stdout)\nsys.stderr.buffer.write(p.stderr)\nsys.exit(p.returncode)\n")
wrapper.chmod(0o755)
subprocess.run([binary, "gen-config", "codex", "--merge", str(config / "hooks.json"), "--binary", str(wrapper)], check=True, capture_output=True)
(workspace / ".env").write_text("FAKE_SECRET=fixture-only\n")
(workspace / "file.txt").write_text("old\n")
(workspace / ".ssh").mkdir()
(workspace / ".ssh/token.txt").write_text("fake secret-directory fixture\n")
subprocess.run(["git", "init", "-q", str(workspace)], check=True)
# Scripted calls exercise native dispatch without asking a model to cooperate.
calls = [
    ("exec_command", {"cmd": "echo codex-safe", "workdir": str(workspace)}, 0),
    ("exec_command", {"cmd": "cat .env", "workdir": str(workspace)}, 2),
    ("exec_command", {"cmd": "git reset --hard", "workdir": str(workspace)}, 2),
    ("exec_command", {"cmd": "chmod 777 file.txt", "workdir": str(workspace)}, 2),
    ("apply_patch", "*** Begin Patch\n*** Add File: safe.txt\n+safe\n*** End Patch", 0),
    ("apply_patch", "*** Begin Patch\n*** Add File: .env.test\n+FAKE=blocked\n*** End Patch", 2),
    ("apply_patch", "*** Begin Patch\n*** Update File: file.txt\n*** Move to: .env\n@@\n-old\n+new\n*** End Patch", 2),
    ("apply_patch", "*** Begin Patch\n*** Add File: .codex/blocked.txt\n+blocked\n*** End Patch", 2),
    ("request_user_input", {"questions": []}, 0),
    ("spawn_agent", {"message": "Return immediately without using tools."}, 2),
    ("view_image", {"path": str(workspace / ".env")}, 2),
    ("apply_patch", "*** Begin Patch\n*** Add File: malformed.go\n+this is not go\n*** End Patch", 0),
    ("apply_patch", "*** Begin Patch\n*** Delete File: safe.txt\n*** End Patch", 0),
    ("future_tool", {}, None),
    ("mcp__fixture__read", {}, 2),
    ("exec_command", {"cmd": "curl https://guardrail-probe.invalid", "workdir": str(workspace)}, 2),
    ("exec_command", {"cmd": "cat token.txt", "workdir": str(workspace / ".ssh")}, 0),

]
if code_mode:
    calls = [call for call in calls if call[0] not in ("spawn_agent", "future_tool", "request_user_input")]
requests = []
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        requests.append(request)
        index = len(requests) - 1
        if index < len(calls):
            name, args, _ = calls[index]
            if code_mode:
                code = "text(await tools." + name + "(" + json.dumps(args) + "));"
                item = {"type": "custom_tool_call", "id": f"item_{index}", "call_id": f"call_{index}", "name": "exec", "input": code, "status": "completed"}
            elif isinstance(args, str):
                item = {"type": "custom_tool_call", "id": f"item_{index}", "call_id": f"call_{index}", "name": name, "input": args, "status": "completed"}
            else:
                item = {"type": "function_call", "id": f"item_{index}", "call_id": f"call_{index}", "name": "read" if name == "mcp__fixture__read" else name, **({"namespace": "mcp__fixture"} if name == "mcp__fixture__read" else {"namespace": "multi_agent_v1"} if name == "spawn_agent" else {}), "arguments": json.dumps(args), "status": "completed"}
        else:
            item = {"type": "message", "id": "msg_final", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "Native fixture sequence complete.", "annotations": []}]}
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        response = {"id": f"resp_{index}", "object": "response", "status": "in_progress", "output": []}
        events = [
            {"type": "response.created", "response": response},
            {"type": "response.output_item.added", "output_index": 0, "item": item},
            {"type": "response.output_item.done", "output_index": 0, "item": item},
            {"type": "response.completed", "response": {**response, "status": "completed", "output": [item], "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}},
        ]
        for event in events:
            self.wfile.write(("event: " + event["type"] + "\ndata: " + json.dumps(event) + "\n\n").encode())
        self.wfile.flush()

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
catalog_path = config / "model-catalog.json"
catalog = json.loads((Path(__file__).resolve().parents[1] / "fixtures/codex/model-catalog.json").read_text())
if code_mode:
    catalog["models"][0]["tool_mode"] = "code_mode_only"
catalog_path.write_text(json.dumps(catalog))
(config / "config.toml").write_text(f'''model = "codex-fixture"
model_provider = "fixture"
model_catalog_json = "{catalog_path}"
[model_providers.fixture]
name = "Deterministic local fixture"
base_url = "http://127.0.0.1:{server.server_port}/v1"
wire_api = "responses"
requires_openai_auth = false
[features]
shell_snapshot = false
[mcp_servers.fixture]
command = "python3"
args = [{json.dumps(str(Path(__file__).resolve().parents[1] / "fixtures/codex/mcp_server.py"))}, {json.dumps(str(root / "mcp-executed"))}]
''')
env = dict(os.environ, CODEX_HOME=str(config), XDG_STATE_HOME=str(root / "state"), XDG_CONFIG_HOME=str(root / "xdg"), GUARDRAIL_CONFIG="")
# The only trust override is for the generated, vetted fixture hook definitions.
# Codex's command sandbox remains enabled throughout.
command = ["codex", "exec", "--ephemeral", "--dangerously-bypass-hook-trust", "--sandbox", "workspace-write", "-C", str(workspace), "Run the supplied deterministic tool probe sequence."]
try:
    result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=90)
    (root / "stdout.txt").write_text(result.stdout)
    (root / "stderr.txt").write_text(result.stderr)
    (root / "requests.json").write_text(json.dumps(requests, indent=2))
    events = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    pre = [e for e in events if e["input"]["hook_event_name"] == "PreToolUse"]
    errors = []
    rules_checked = 0
    if not code_mode:
        rules_path = config / "rules/guardrail.rules"
        for line in rules_path.read_text().splitlines():
            if not line.startswith("prefix_rule("):
                continue
            pattern = json.loads(line.split("pattern = ", 1)[1].split(", decision =", 1)[0])
            checked = subprocess.run(["codex", "execpolicy", "check", "--rules", str(rules_path), "--", *pattern], env=env, capture_output=True, text=True)
            if checked.returncode != 0 or json.loads(checked.stdout).get("decision") != "forbidden":
                errors.append(f"Native floor failed for {pattern}: {checked.stdout} {checked.stderr}")
            rules_checked += 1
    if result.returncode != 0:
        errors.append(f"Codex exited {result.returncode}: {result.stderr[-2000:]}")
    expected_hooks = sum(expected is not None for _, _, expected in calls)
    if len(pre) != expected_hooks:
        errors.append(f"Expected {expected_hooks} native pre-hooks, observed {len(pre)}")
    by_id = {event["input"].get("tool_use_id"): event for event in pre}
    for i, (name, args, expected) in enumerate(calls):
        event = pre[i] if code_mode and i < len(pre) else by_id.get(f"call_{i}")
        if expected is None:
            if event is not None or "unsupported call: " + name not in result.stderr:
                errors.append(f"Case {i} {name}: expected native unsupported-tool rejection")
            continue
        canonical = "Bash" if name == "exec_command" else name
        if event is None or event["input"]["tool_name"] != canonical or event["exit"] != expected:
            errors.append(f"Case {i} {name}: expected {canonical}/{expected}, got {event}")
    post = [event for event in events if event["input"]["hook_event_name"] == "PostToolUse"]
    if not any(event["exit"] == 2 and "malformed.go" in event["stderr"] for event in post):
        errors.append("Malformed Go edit did not produce native post-edit lint feedback")
    if (workspace / "safe.txt").exists() or not (workspace / "malformed.go").exists():
        errors.append("Allowed patch sequence did not execute")
    if "fake secret-directory fixture" in json.dumps(requests):
        errors.append("Alternate workdir leaked the fake secret-directory content")
    if "Codex workdir differs" not in json.dumps(requests):
        errors.append("Alternate workdir was not stopped by the evaluated-directory guard")
    if (root / "mcp-executed").exists():
        errors.append("Denied MCP tool executed")
    for path in [".env.test", ".codex/blocked.txt"]:
        if (workspace / path).exists():
            errors.append(f"Denied patch executed: {path}")
    if (workspace / ".env").read_text() != "FAKE_SECRET=fixture-only\n":
        errors.append("Denied move changed secret fixture")
    report = {"codex": subprocess.check_output(["codex", "--version"], text=True).strip(), "code_mode": code_mode, "cases": len(calls), "pre_hooks": len(pre), "post_hooks": len(post), "runtime_rejections": len(calls)-expected_hooks, "rules_checked": rules_checked, "errors": errors, "artifacts": str(root)}
    (root / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    sys.exit(bool(errors))
finally:
    server.shutdown()
