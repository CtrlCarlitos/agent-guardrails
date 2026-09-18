#!/usr/bin/env python3
"""Exercise the installed Codex runtime with a deterministic local Responses fixture.
No model service or credentials; all tool effects stay in a disposable directory.
Usage: python3 test/smoke/codex_probe.py /absolute/path/to/guardrail
"""
import argparse
import http.server
import json
import os
import re
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
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", help="Guardrail executable")
parser.add_argument("--code-mode", action="store_true", help="Exercise nested tools")
parser.add_argument("--mediation", action="store_true", help="Check stdin hook coverage and hosted web-search availability")
parser.add_argument("--restricted", action="store_true", help="With --mediation, disable shell tools and web search")
options = parser.parse_args()
binary = str(Path(options.binary).resolve())
code_mode = options.code_mode
mediation = options.mediation
restricted = options.restricted
if restricted and not mediation:
    parser.error("--restricted requires --mediation")
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
if mediation:
    calls = [
        ("exec_command", {"cmd": "cat > stdin.txt", "tty": True, "yield_time_ms": 1000}, None if restricted else 0),
        ("write_stdin", {"session_id": 0, "chars": "codex-stdin-fixture\n", "yield_time_ms": 1000}, None),
        ("write_stdin", {"session_id": 0, "chars": "", "yield_time_ms": 1000}, None),
        ("write_stdin", {"session_id": 0, "chars": "\u0004", "yield_time_ms": 1000}, None),
        ("apply_patch", "*** Begin Patch\n*** Add File: edit-only.txt\n+fixture edit\n*** End Patch", 0),
    ]
def output_text(item):
    output = item.get("output", "")
    if isinstance(output, list):
        return "\n".join(part.get("text", "") for part in output)
    return str(output)

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
            if name == "write_stdin":
                outputs = "\n".join(output_text(i) for i in request.get("input", [])
                                    if i.get("type", "").endswith("_output"))
                matches = re.findall(r'(?:session ID |"session_id":\s*)(\d+)', outputs)
                args = {**args, "session_id": int(matches[-1]) if matches else 0}
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
web_search = "{'disabled' if restricted else 'cached'}"
model_provider = "fixture"
model_catalog_json = "{catalog_path}"
[model_providers.fixture]
name = "Deterministic local fixture"
base_url = "http://127.0.0.1:{server.server_port}/v1"
wire_api = "responses"
requires_openai_auth = false
[features]
shell_snapshot = false
shell_tool = {'false' if restricted else 'true'}
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
    if not code_mode and not mediation:
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
    if mediation:
        # Hosted execution happens at the provider. Inspect the outgoing request;
        # do not fabricate a hosted result and call it an enforcement test.
        advertised = requests[0].get("tools", []) if requests else []
        (root / "tools.json").write_text(json.dumps(advertised, indent=2))
        def tool_names(specs):
            names = set()
            for spec in specs:
                names.add(spec.get("name", spec.get("type")))
                names.update(tool_names(spec.get("tools", [])))
            return names
        names = tool_names(advertised)
        web_enabled = any(str(name).startswith("web_search") for name in names)
        if web_enabled == restricted:
            errors.append(f"Expected web_search enabled={not restricted}, tools={sorted(names)}")
        outputs = {}
        for request in requests:
            for item in request.get("input", []):
                if item.get("type", "").endswith("_output"):
                    outputs[item.get("call_id")] = output_text(item)
        if len(requests) != len(calls) + 1:
            errors.append(f"Expected {len(calls) + 1} provider requests, got {len(requests)}")
        expected_names = ["apply_patch"] if restricted else ["Bash", "apply_patch"]
        if [event["input"]["tool_name"] for event in pre] != expected_names or any(event["exit"] != 0 for event in pre):
            errors.append(f"Expected allowed hooks {expected_names}, got {pre}")
        if restricted:
            # Direct tool specs can be inspected; code-mode exposure is checked
            # by forcing nested calls and requiring an executor rejection.
            if {"exec_command", "write_stdin"} & names:
                errors.append("Disabled shell tools remain advertised")
            for i in range(4):
                output = outputs.get(f"call_{i}", "")
                rejection = f"tools.{calls[i][0]} is not a function" if code_mode else f"unsupported call: {calls[i][0]}"
                if rejection not in output:
                    errors.append(f"Disabled tool case {i} was not rejected: {output}")
            if (workspace / "stdin.txt").exists():
                errors.append("Disabled shell tool executed")
        else:
            for i in range(4):
                output = outputs.get(f"call_{i}", "")
                if ('"chunk_id"' if code_mode else "Chunk ID:") not in output:
                    errors.append(f"Stdin case {i} did not execute: {output}")
            finished = '"exit_code":0' if code_mode else "Process exited with code 0"
            if finished not in outputs.get("call_3", ""):
                errors.append("Interactive process did not exit cleanly after EOF")
            path = workspace / "stdin.txt"
            if not path.exists() or path.read_text() != "codex-stdin-fixture\n":
                errors.append("Stdin bytes did not reach the approved command")
        path = workspace / "edit-only.txt"
        if not path.exists() or path.read_text() != "fixture edit\n":
            errors.append("Allowed patch failed in mediation fixture")
        report = {
            "codex": subprocess.check_output(["codex", "--version"], text=True).strip(),
            "code_mode": code_mode, "restricted": restricted, "cases": len(calls),
            "pre_hooks": len(pre), "stdin_pre_hooks": sum(e["input"]["tool_name"] == "write_stdin" for e in pre),
            "web_search_advertised": web_enabled, "hosted_execution_tested": False,
            "errors": errors, "artifacts": str(root),
        }
        (root / "report.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
        sys.exit(bool(errors))
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
