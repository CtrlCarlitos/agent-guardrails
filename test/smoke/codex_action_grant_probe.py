#!/usr/bin/env python3
"""Native Codex patch approval fixture; no model service or production grants.

The POSIX fixture simulates an operator terminal using a disposable PTY.
Windows reports the missing fixture ceremony separately rather than faking it.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

from codex_probe_support import (
    probe_timeout, render_codex_config, resolve_command, run_probe_command,
    write_guardrail_wrapper,
)


def pre_hook_decisions(events, *, structured):
    """Decode the selected native transport, rejecting unexpected output."""
    decisions = []
    for event in events:
        if not structured:
            decisions.append({0: "allow", 2: "deny"}.get(event["exit"], "invalid"))
            continue
        if event["exit"] != 0:
            decisions.append("invalid")
            continue
        raw = event.get("stdout", "").strip()
        if not raw:
            decisions.append("allow")
            continue
        try:
            output = json.loads(raw).get("hookSpecificOutput", {})
            valid = output.get("hookEventName") == "PreToolUse" and output.get("permissionDecision") == "deny"
        except (ValueError, AttributeError):
            valid = False
        decisions.append("deny" if valid else "invalid")
    return decisions


def post_hook_feedback(event, *, structured):
    if not structured:
        return event["exit"] == 2 and "malformed.go" in event["stderr"]
    if event["exit"] != 0:
        return False
    try:
        output = json.loads(event.get("stdout", ""))
        return output.get("decision") == "block" and "malformed.go" in output.get("reason", "")
    except (ValueError, AttributeError, TypeError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--operator-terminal", action="store_true",
                        help="Use this interactive operator terminal for the isolated approval ceremony")
    parser.add_argument("--artifacts-dir", type=Path,
                        default=Path(__file__).resolve().parent / ".test-tmp")
    options = parser.parse_args()
    if options.operator_terminal and not sys.stdin.isatty():
        parser.error("--operator-terminal requires an interactive operator terminal")
    binary = str(options.binary.resolve())
    windows = os.name == "nt"
    codex = resolve_command("codex", windows=windows)
    git = resolve_command("git", windows=windows)
    if not codex or not git:
        print("SKIP: codex and git are required", file=sys.stderr)
        return 77
    options.artifacts_dir.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="codex-action-grant-", dir=options.artifacts_dir)).resolve()
    workspace, config = root / "workspace", root / "codex"
    # DrvFS without metadata cannot enforce POSIX 0700/0600. Keep the private
    # operator fixture on the native filesystem; never relax privatefs checks.
    operator = root / "operator" if windows else Path(tempfile.mkdtemp(prefix="guardrail-action-operator-"))
    for directory in (workspace, config):
        directory.mkdir()
    if windows:
        operator.mkdir()
    subprocess.run([git, "init", "-q", str(workspace)], check=True)
    log = root / "hooks.jsonl"
    wrapper = write_guardrail_wrapper(root, Path(binary), log, windows=windows)
    subprocess.run([binary, "gen-config", "codex", "--merge", str(config / "hooks.json"),
                    "--binary", str(wrapper)], capture_output=True, check=True)
    catalog_path = config / "model-catalog.json"
    catalog_path.write_text((Path(__file__).resolve().parents[1] /
                            "fixtures/codex/model-catalog.json").read_text(), encoding="utf-8")
    approved = "*** Begin Patch\n*** Add File: .github/workflows/fixture.yml\n+name: approved-fixture\n*** End Patch"
    changed = approved.replace("approved-fixture", "changed-fixture")
    malformed = "*** Begin Patch\n*** Add File: malformed.go\n+this is not go\n*** End Patch"
    denied = "*** Begin Patch\n*** Add File: .codex/blocked.txt\n+blocked\n*** End Patch"
    patches = [approved, changed, approved, approved, malformed, denied]
    requests, snapshots, errors = [], [], []
    ceremony = {"tested": False, "exit": None}
    target = workspace / ".github/workflows/fixture.yml"
    env = dict(os.environ, CODEX_HOME=str(config), APPDATA=str(operator),
               XDG_CONFIG_HOME=str(operator), XDG_STATE_HOME=str(root / "state"),
               LOCALAPPDATA=str(root / "state"),
               GUARDRAIL_CONFIG="")

    def snapshot(index):
        snapshots.append({"after_call": index, "workflow_exists": target.exists(),
                          "workflow_text": target.read_text() if target.exists() else None,
                          "workflow_mtime_ns": target.stat().st_mtime_ns if target.exists() else None})

    def authorize_fixture():
        if windows and not options.operator_terminal:
            errors.append("Windows operator-terminal fixture ceremony is unavailable; approval retry is inconclusive")
            return
        records = list((operator / "guardrail/actions").glob("*.json"))
        pending = [json.loads(path.read_text()) for path in records]
        pending = [record for record in pending if record["Action"]["Text"] == approved and record["Status"] == "pending"]
        if len(pending) != 1:
            errors.append("Initial blocked patch did not create one exact pending request")
            return
        if options.operator_terminal:
            print("Approve or decline the following disposable fixture action in this terminal:", flush=True)
            try:
                completed = subprocess.run([binary, "approvals", "grant", "--record", pending[0]["ID"]],
                                           env=env, cwd=workspace, timeout=60)
                ceremony.update(tested=True, exit=completed.returncode)
                if completed.returncode:
                    errors.append(f"Operator fixture approval exited {completed.returncode}")
            except subprocess.TimeoutExpired:
                errors.append("Operator fixture approval timed out")
            return
        import pty
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen([binary, "approvals", "grant", "--record", pending[0]["ID"]],
                                       stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env=env, cwd=workspace)
            os.write(master, b"yes\n")
            try:
                stdout, stderr = process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                errors.append("Fixture terminal approval timed out")
            ceremony.update(tested=True, exit=process.returncode)
            (root / "ceremony.txt").write_bytes(stdout + stderr)
            if process.returncode:
                errors.append("Fixture terminal approval failed: " + stderr.decode(errors="replace"))
        finally:
            os.close(master)
            os.close(slave)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            index = len(requests)
            requests.append(request)
            if index:
                snapshot(index - 1)
            if index == 1:
                authorize_fixture()
            if index < len(patches):
                item = {"type": "custom_tool_call", "id": f"item_{index}",
                        "call_id": f"call_{index}", "name": "apply_patch",
                        "input": patches[index], "status": "completed"}
            else:
                item = {"type": "message", "id": "msg_final", "role": "assistant",
                        "status": "completed", "content": [{"type": "output_text",
                        "text": "Exact-action fixture complete.", "annotations": []}]}
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            response = {"id": f"resp_{index}", "object": "response",
                        "status": "in_progress", "output": []}
            events = [
                {"type": "response.created", "response": response},
                {"type": "response.output_item.added", "output_index": 0, "item": item},
                {"type": "response.output_item.done", "output_index": 0, "item": item},
                {"type": "response.completed", "response": {**response,
                 "status": "completed", "output": [item],
                 "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}},
            ]
            for event in events:
                self.wfile.write(("event: " + event["type"] + "\ndata: " + json.dumps(event) + "\n\n").encode())
            self.wfile.flush()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    settings = render_codex_config(catalog_path=catalog_path, server_port=server.server_port,
                                  restricted=False, python_executable=Path(sys.executable),
                                  mcp_script=Path(__file__).resolve().parents[1] / "fixtures/codex/mcp_server.py",
                                  mcp_marker=root / "unused-mcp")
    if windows:
        settings = settings.replace("[features]", '[windows]\nsandbox = "unelevated"\n[features]')
    (config / "config.toml").write_text(settings, encoding="utf-8")
    try:
        result = run_probe_command([codex, "exec", "--dangerously-bypass-hook-trust",
                                    "--sandbox", "workspace-write", "-C", str(workspace),
                                    "Run the supplied deterministic patch fixture."],
                                   env=env, timeout=probe_timeout(windows=windows))
    finally:
        server.shutdown()
        server.server_close()
    (root / "stdout.txt").write_text(result.stdout, encoding="utf-8")
    (root / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    (root / "requests.json").write_text(json.dumps(requests, indent=2), encoding="utf-8")
    if result.returncode:
        errors.append(f"Codex exited {result.returncode}")
    if len(requests) != len(patches) + 1:
        errors.append(f"Expected {len(patches) + 1} provider requests, got {len(requests)}")
    hooks = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    pre = [event for event in hooks if event["input"]["hook_event_name"] == "PreToolUse"]
    structured = windows and env.get("GUARDRAIL_CODEX_STRUCTURED_WINDOWS") == "1"
    decisions = pre_hook_decisions(pre, structured=structured)
    if decisions != ["deny", "deny", "allow", "deny", "allow", "deny"]:
        errors.append("Native patch pre-hook verdict sequence did not match exact one-use approval")
    outputs = {}
    for request in requests:
        for item in request.get("input", []):
            if item.get("type", "").endswith("_output"):
                outputs[item.get("call_id")] = str(item.get("output", ""))
    for index in (0, 1, 3, 5):
        if "blocked by PreToolUse hook" not in outputs.get(f"call_{index}", ""):
            errors.append(f"Native executor did not acknowledge pre-execution blocking for case {index}")
    if len(snapshots) >= 4:
        if snapshots[0]["workflow_exists"] or snapshots[1]["workflow_exists"]:
            errors.append("A blocked patch edited the file before recorded approval")
        if snapshots[2]["workflow_text"] != "name: approved-fixture\n" or snapshots[3]["workflow_text"] != "name: approved-fixture\n":
            errors.append("Approved identical retry did not produce exactly the intended file")
        if snapshots[2]["workflow_mtime_ns"] != snapshots[3]["workflow_mtime_ns"]:
            errors.append("Spent approval retry rewrote the existing workflow")
    else:
        errors.append("Native patch snapshots are incomplete")
    post = [event for event in hooks if event["input"]["hook_event_name"] == "PostToolUse"]
    if not (workspace / "malformed.go").exists() or not any(post_hook_feedback(event, structured=structured) for event in post):
        errors.append("Post-edit lint feedback did not leave the already-written file visible")
    if (workspace / ".codex/blocked.txt").exists():
        errors.append("Denied self-configuration patch executed")
    report = {"codex": subprocess.check_output([codex, "--version"], text=True).strip(),
              "platform": sys.platform, "codex_exit": result.returncode,
              "ceremony": ceremony, "snapshots": snapshots,
              "pre_hooks": len(pre), "pre_decisions": decisions,
              "post_hooks": len(post), "errors": errors,
              "artifacts": str(root), "operator_fixture": str(operator)}
    (root / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
