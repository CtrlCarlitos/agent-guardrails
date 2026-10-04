"""Disposable Windows write observer; exit 0 means observation completed, not acceptance.

Uses a local Responses fixture and the unelevated workspace-write sandbox.
It neither inspects sandbox credentials nor changes production configuration.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import subprocess
import threading

from codex_probe_support import resolve_command, run_probe_command, toml_string, write_guardrail_wrapper, create_probe_directory


def run_case(base, binary, hooks, process_cwd=False, legacy_desktop=False):
    root = create_probe_directory(base, prefix="with-hooks-" if hooks else "without-hooks-", windows=True)
    workspace, config = root / "workspace", root / "codex"
    workspace.mkdir()
    config.mkdir()
    subprocess.run([resolve_command("git", windows=True), "init", "-q", str(workspace)], check=True)
    env = dict(os.environ, CODEX_HOME=str(config), APPDATA=str(root / "operator"),
               LOCALAPPDATA=str(root / "state"), XDG_CONFIG_HOME=str(root / "operator"),
               XDG_STATE_HOME=str(root / "state"), GUARDRAIL_CONFIG="")
    log = root / "hooks.jsonl"
    if hooks:
        wrapper = write_guardrail_wrapper(root, binary, log, windows=True)
        subprocess.run([str(binary), "gen-config", "codex", "--merge", str(config / "hooks.json"),
                        "--binary", str(wrapper)], capture_output=True, check=True)
    else:
        (config / "hooks.json").write_text('{"hooks":{}}', encoding="utf-8")
    catalog = Path(__file__).resolve().parents[1] / "fixtures/codex/model-catalog.json"
    requests = []
    calls = [
        {"type": "custom_tool_call", "name": "apply_patch", "input": "*** Begin Patch\n*** Add File: plain.txt\n+plain-write\n*** End Patch"},
        {"type": "custom_tool_call", "name": "apply_patch", "input": "*** Begin Patch\n*** Add File: nested/plain.txt\n+nested-write\n*** End Patch"},
        {"type": "function_call", "name": "exec_command", "arguments": json.dumps({"cmd": "Get-Location", "workdir": str(workspace), "login": False})},
    ]

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            index = len(requests)
            requests.append(request)
            item = {"id": f"item_{index}", "status": "completed"}
            if index < len(calls):
                item.update(calls[index], call_id=f"call_{index}")
            else:
                item.update(type="message", role="assistant", content=[{"type": "output_text", "text": "Write comparison complete.", "annotations": []}])
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
    (config / "config.toml").write_text(f'''model = "codex-fixture"
model_provider = "fixture"
model_catalog_json = {toml_string(catalog)}
[model_providers.fixture]
name = "Local diagnostic"
base_url = "http://127.0.0.1:{server.server_port}/v1"
wire_api = "responses"
requires_openai_auth = false
[windows]
sandbox = "unelevated"
{('sandbox_private_desktop = false' if legacy_desktop else '')}
[features]
shell_snapshot = false
''', encoding="utf-8")
    codex = resolve_command("codex", windows=True)
    try:
        command = [codex, "exec", "--dangerously-bypass-hook-trust", "--sandbox", "workspace-write", "-C", str(workspace), "Run the supplied disposable write comparison."]
        if process_cwd:
            def launch(*args, **kwargs):
                return subprocess.run(*args, **kwargs, cwd=workspace)
            result = run_probe_command(command, env=env, timeout=180, run=launch)
        else:
            result = run_probe_command(command, env=env, timeout=180)
    finally:
        server.shutdown()
        server.server_close()
    (root / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    (root / "stdout.txt").write_text(result.stdout, encoding="utf-8")
    (root / "requests.json").write_text(json.dumps(requests, indent=2), encoding="utf-8")
    outputs = {}
    for request in requests:
        for item in request.get("input", []):
            if item.get("type", "").endswith("_output"):
                outputs[item.get("call_id")] = item.get("output")
    report = {"codex": subprocess.check_output([codex, "--version"], text=True).strip(),
              "sandbox": "workspace-write", "windows_sandbox": "unelevated",
              "hooks_enabled": hooks, "explicit_process_cwd": process_cwd,
              "legacy_desktop": legacy_desktop, "codex_exit": result.returncode,
              "files": {name: (workspace / name).read_text() if (workspace / name).exists() else None for name in ("plain.txt", "nested/plain.txt")},
              "outputs": outputs, "artifacts": str(root),
              "hook_log_exists": log.exists()}
    (root / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--process-cwd", action="store_true")
    parser.add_argument("--without-hooks-only", action="store_true")
    parser.add_argument("--legacy-desktop", action="store_true")
    args = parser.parse_args()
    base = Path(__file__).resolve().parent / ".test-tmp" / "windows-write-comparison"
    base.mkdir(parents=True, exist_ok=True)
    for hooks in ((False,) if args.without_hooks_only else (False, True)):
        run_case(base, args.binary.resolve(), hooks, args.process_cwd, args.legacy_desktop)
