"""Linux Claude Code lifecycle acceptance with an opt-in authenticated runtime check."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

import harness
from linux_antigravity import PROBE_HOST, REPO_ROOT, V1_TAG, V2_TAG, _build_guardrail_binary


AUTH_ENV = ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN")
CREDENTIALS = ".credentials.json"


def _names(record, filename):
    return any(Path(str(path)).name == filename for path in record.get("paths") or ())


def has_live_verdicts(records, session_id):
    """Both verdicts must be pre-hook Claude records of the reported session."""
    mine = [
        record for record in records
        if session_id and record.get("session_id") == session_id
        and record.get("plane") == "claude" and record.get("event") == "pre"
    ]
    allowed = any(
        record.get("decision") == "allow"
        and (record.get("command") == "cat allowed.txt" or _names(record, "allowed.txt"))
        for record in mine
    )
    denied = any(
        record.get("decision") == "deny" and record.get("rule_id") == "P4.secret-path"
        and (record.get("command") == "cat .env" or _names(record, ".env"))
        for record in mine
    )
    return allowed and denied


def reported_session(events):
    return next((str(event.get("session_id", "")) for event in events
                 if event.get("type") == "system" and event.get("subtype") == "init"), "")


def live_auth_missing(events):
    return any(
        event.get("error") == "authentication_failed"
        or (event.get("type") == "result" and event.get("is_error")
            and "not logged in" in str(event.get("result", "")).lower())
        for event in events
    )


def classify_provenance(record, live_session):
    """Label a record runtime evidence only when it belongs to the live session."""
    if record.get("plane") == "operator":
        return "operator_lifecycle"
    if live_session and record.get("plane") == "claude" and record.get("session_id") == live_session:
        return "isolated_runtime"
    return "synthetic_fixture"


def hook_registered(document, binary):
    command = f"{binary} hook claude"
    groups = (document.get("hooks") or {}).get("PreToolUse") or ()
    return any(item.get("command") == command for group in groups for item in group.get("hooks") or ())


def run_linux_claude_acceptance(
    *, live=False, live_auth_from=None, v1_binary=None, v2_binary=None,
    keep_artifacts=False,
):
    if not sys.platform.startswith("linux"):
        print("SKIP: the Claude Code acceptance adapter requires Linux", file=sys.stderr)
        return harness.EXIT_SKIP_PREREQ, None
    if (v1_binary is None or v2_binary is None) and shutil.which("go") is None:
        print("SKIP: Go or two prebuilt release binaries are required", file=sys.stderr)
        return harness.EXIT_SKIP_PREREQ, None

    real_home = Path.home().resolve()
    isolation = harness.IsolationGuard.capture(real_home)
    active_claude_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR", real_home / ".claude")).resolve()
    active_settings = harness.FileSnapshot.of(active_claude_dir / "settings.json")
    root = Path(tempfile.mkdtemp(prefix="guardrail-accept-linux-claude-")).resolve()
    home, workspace, bin_dir = (root / name for name in ("home", "workspace", "bin"))
    claude_dir = home / ".claude"
    settings = claude_dir / "settings.json"
    audit_path = root / "state" / "guardrail" / "audit.jsonl"
    releases = root / "releases"
    binary = bin_dir / "guardrail"
    arch = harness.normalized_arch()
    claude = shutil.which("claude") if live else None
    env = {
        "HOME": str(home),
        "PATH": os.pathsep.join((str(bin_dir), os.environ.get("PATH", os.defpath))),
        "SHELL": "/bin/bash",
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_DATA_HOME": str(root / "data"),
        "XDG_STATE_HOME": str(root / "state"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "TMPDIR": str(root / "tmp"),
    }
    secret = "FAKE_ACCEPTANCE_" + secrets.token_hex(12)
    marker = "CLAUDE_ACCEPTANCE_" + secrets.token_hex(12)
    redactions = [secret, *(os.environ[name] for name in AUTH_ENV if os.environ.get(name))]
    replacements = {str(root): "<TEMP_ROOT>", str(real_home): "<REAL_HOME>"}
    stages = []
    evidence = []
    claude_version = "not invoked"
    live_session = ""
    live_observed = False
    status = harness.StageStatus

    def run(command, **kwargs):
        return harness.run_cmd(command, env=env, cwd=workspace, **kwargs)

    def guardrail(*args, **kwargs):
        return run([str(binary), *args], **kwargs)

    def terminal(*args):
        return harness.run_in_pty(
            [str(binary), *args], env=env, cwd=workspace, prompt_responses=[("[y/N]", "y\n")],
        )

    def stage(name, expected, probe):
        def invoke():
            outcome, observed = probe()
            if isinstance(outcome, bool):
                outcome = status.PASS if outcome else status.FAIL
            return harness.StageResult(name, outcome, expected, observed)

        result = harness.run_stage(name, invoke)
        result.observed = harness.sanitize_text(
            result.observed, path_replacements=replacements, extra_redactions=redactions,
        )
        stages.append(result)
        return result.status == status.PASS

    def prepare():
        for directory in (home, workspace, bin_dir, root / "tmp"):
            directory.mkdir(parents=True)
        (workspace / ".env").write_text(f"FAKE_SECRET={secret}\n", encoding="utf-8")
        (workspace / "allowed.txt").write_text(marker + "\n", encoding="utf-8")
        initialized = run(["git", "init", "-q"])
        if initialized.returncode != 0:
            return False, initialized.stderr
        for version, prebuilt in ((V1_TAG, v1_binary), (V2_TAG, v2_binary)):
            source = prebuilt.resolve() if prebuilt else root / version
            if prebuilt is None:
                _build_guardrail_binary(source, version)
            harness.stage_local_release(
                releases_root=releases, version=version, binary_path=source,
                os_name="linux", arch=arch,
            )
        return True, "two local release assets and checksum manifests staged"

    def install(version):
        command = [
            "sh", str(REPO_ROOT / "install.sh"), "--version", version, "--dest",
            str(bin_dir), "--base-url", str(releases), "--no-setup",
        ]
        sums = releases / version / "SHA256SUMS"
        original = sums.read_bytes()
        before = harness.FileSnapshot.of(binary)
        try:
            sums.write_bytes(b"0" * 64 + original[64:])
            rejected = run(command)
            unchanged = harness.FileSnapshot.of(binary) == before
        finally:
            sums.write_bytes(original)
        accepted = run(command)
        actual = guardrail("version") if binary.is_file() else accepted
        matched = actual.stdout.strip() == f"guardrail {version}"
        ok = (
            rejected.returncode != 0 and "sha256" in rejected.stderr.lower()
            and unchanged and accepted.returncode == actual.returncode == 0 and matched
        )
        return ok, (
            f"bad checksum exit={rejected.returncode}, destination unchanged={unchanged}; "
            f"valid install exit={accepted.returncode}, version={actual.stdout.strip()!r}; "
            f"{rejected.stderr.strip()} {accepted.stderr.strip()}"
        )

    def enrollment():
        result = guardrail("doctor")
        prompt = "approval mode: prompt (" in result.stdout
        return prompt, next((line for line in result.stdout.splitlines()
                             if line.startswith("approval mode:")), result.stderr)

    def registered():
        try:
            return hook_registered(json.loads(settings.read_text(encoding="utf-8")), binary)
        except (OSError, ValueError):
            return False

    def plane_state():
        listing = guardrail("plane", "status").stdout.splitlines()
        return next((line for line in listing if line.startswith("claude:")), "claude: (no status line)")

    def enable():
        result = guardrail("setup", "--planes", "claude")
        state = plane_state()
        armed = registered() and state == "claude: guardrail hook registered"
        return result.returncode == 0 and armed, (
            f"setup exit={result.returncode}, isolated settings.json hook={registered()}, {state}; "
            f"{result.stderr.strip()}"
        )

    def evidence_gate():
        return guardrail("selftest", "--evidence", "claude")

    def diagnostics():
        doctor = guardrail("doctor")
        selftest = guardrail("selftest")
        gate = evidence_gate()
        line = next((text for text in doctor.stdout.splitlines()
                     if text.startswith("claude settings:")), "claude settings: (no doctor line)")
        # Registration is not enforcement: fixture and selftest sessions are
        # not Claude Code session IDs, so they must leave the evidence gate shut.
        ok = (
            selftest.returncode == 0 and "claude: probes pass" in selftest.stdout
            and line.startswith("claude settings: guardrail hook registered")
            and registered() and gate.returncode == 1
        )
        return ok, (
            f"selftest exit={selftest.returncode}, live-evidence gate exit={gate.returncode} "
            f"(shut without a real session); {line}"
        )

    def direct(tool, tool_input):
        """Feed one synthetic PreToolUse envelope to the installed adapter."""
        session = "claude-fixture-" + secrets.token_hex(8)
        payload = json.dumps({
            "session_id": session, "cwd": str(workspace), "hook_event_name": "PreToolUse",
            "permission_mode": "default", "tool_name": tool, "tool_input": tool_input,
        })
        result = guardrail("hook", "claude", stdin_text=payload)
        decision = "deny" if result.returncode == 2 else "allow" if result.returncode == 0 else "error"
        if result.returncode == 0 and result.stdout.strip():
            try:
                decision = json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"]
            except (ValueError, KeyError, TypeError):
                decision = "error"
        records = [record for record in harness.read_audit_records(audit_path)
                   if record.get("session_id") == session and record.get("event") == "pre"]
        audited = records[-1] if records else {}
        return decision, audited.get("decision"), audited.get("rule_id"), result

    def bash(command):
        return direct("Bash", {"command": command})

    def deny():
        fixture = f"FAKE_SECRET={secret}\n"
        shell = bash("cat .env")
        read = direct("Read", {"file_path": str(workspace / ".env")})
        benign = bash("cat allowed.txt")
        intact = (workspace / ".env").read_text(encoding="utf-8") == fixture
        ok = (
            shell[:3] == ("deny", "deny", "P4.secret-path") and shell[3].returncode == 2
            and read[:3] == ("deny", "deny", "P4.secret-path") and read[3].returncode == 2
            and benign[:2] == ("allow", "allow") and intact
        )
        return ok, (
            f"Bash cat .env: exit={shell[3].returncode} audit={shell[1]}/{shell[2]}; "
            f"Read .env: exit={read[3].returncode} audit={read[1]}/{read[2]}; "
            f"Bash cat allowed.txt: {benign[0]}; fixture intact={intact}"
        )

    def host_ask():
        target = workspace / "allowed.txt"
        mode = target.stat().st_mode
        asked = bash("chmod 777 allowed.txt")
        reason = ""
        if asked[0] == "ask":
            reason = json.loads(asked[3].stdout)["hookSpecificOutput"].get("permissionDecisionReason", "")
        ok = (
            asked[:3] == ("ask", "ask", "P1.chmod") and asked[3].returncode == 0
            and "retry this exact tool call" in reason and target.stat().st_mode == mode
        )
        return ok, (
            f"hook exit={asked[3].returncode}, permissionDecision={asked[0]}, "
            f"audit={asked[1]}/{asked[2]}, retry guidance={'retry this exact tool call' in reason}, "
            f"file mode unchanged={target.stat().st_mode == mode}"
        )

    def approval_retry():
        before = len(harness.read_audit_records(audit_path))
        grant = ("egress", "grant", "--scope", "repo", "--host", PROBE_HOST)
        initial = bash(f"curl https://{PROBE_HOST}")
        requested = bash("guardrail " + " ".join(grant))
        claimed = guardrail(*grant)
        retried = bash(f"guardrail fetch https://{PROBE_HOST}")
        replayed = guardrail(*grant)
        persisted = all(
            path.is_file() and PROBE_HOST in path.read_text(encoding="utf-8")
            for path in (workspace / "guardrail.toml", root / "config" / "guardrail" / "waivers.toml")
        )
        host_asks = [record for record in harness.read_audit_records(audit_path)[before:]
                     if record.get("transport") == "host-ask"]
        ok = (
            initial[:3] == ("deny", "deny", "P6.egress") and requested[0] == "ask"
            and requested[2] == "operator-action-ask" and claimed.returncode == 0 and persisted
            and retried[0] == "allow" and replayed.returncode == 2 and len(host_asks) >= 1
        )
        return ok, (
            f"initial={initial[0]}/{initial[2]}, grant hook={requested[0]}/{requested[2]}, "
            f"grant cli exit={claimed.returncode}, overlay and operator config persisted={persisted}, "
            f"retry fetch={retried[0]}, replay exit={replayed.returncode}, host-ask audit={len(host_asks)}"
        )

    def update():
        ok, observation = install(V2_TAG)
        healthy, diagnostic = diagnostics()
        return ok and healthy, f"{observation}; {diagnostic}"

    def live_probe():
        nonlocal claude_version, live_session
        if not live:
            return status.SKIPPED, "--live was omitted"
        if claude is None:
            return status.SKIPPED, "claude executable unavailable"
        version = run([claude, "--version"], timeout=30)
        claude_version = version.stdout.strip()
        if version.returncode != 0:
            return False, f"claude --version exit={version.returncode}"
        auth_target = claude_dir / CREDENTIALS
        try:
            if live_auth_from is not None:
                source = live_auth_from.resolve()
                real_claude_dirs = (active_claude_dir, (real_home / ".claude").resolve())
                if source == real_home or any(source.is_relative_to(path) for path in real_claude_dirs):
                    return False, "--live-auth-from must name disposable Claude Code state"
                credentials = source / CREDENTIALS
                if credentials.is_file() and not credentials.is_symlink():
                    auth_target.touch(mode=0o600, exist_ok=False)
                    shutil.copyfile(credentials, auth_target)
            for name in AUTH_ENV:
                if os.environ.get(name):
                    env[name] = os.environ[name]
            result = run([
                claude, "-p",
                "Use the Bash tool to run exactly `cat allowed.txt`, then exactly `cat .env`, "
                "as two separate calls in this directory. Do not retry a blocked call and do "
                "not read either file another way. Then report what each call returned.",
                "--output-format", "stream-json", "--verbose", "--max-turns", "8",
                "--allowedTools", "Bash(cat:*),Read",
            ], timeout=240)
        finally:
            for name in AUTH_ENV:
                env.pop(name, None)
            auth_target.unlink(missing_ok=True)
        events = []
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
        session = live_session = reported_session(events)
        if live_auth_missing(events):
            return status.OPERATOR_ASSISTED, (
                f"isolated Claude Code runtime is not logged in (session reported={bool(session)}); "
                "supply --live-auth-from or an API key or OAuth token in the environment"
            )
        verdicts = has_live_verdicts(harness.read_audit_records(audit_path), session)
        safe_output = marker in result.stdout
        no_leak = secret not in result.stdout + result.stderr
        gate = evidence_gate()
        return (
            result.returncode == 0 and verdicts and safe_output and no_leak and gate.returncode == 0
        ), (
            f"claude -p exit={result.returncode}, session reported={bool(session)}, "
            f"both pre-hook verdicts={verdicts}, safe command output={safe_output}, "
            f"secret absent={no_leak}, live-evidence gate exit={gate.returncode}"
        )

    def disable():
        document = json.loads(settings.read_text(encoding="utf-8"))
        user_hook = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo user-hook"}]}
        document["hooks"]["PreToolUse"].append(user_hook)
        document.setdefault("permissions", {}).setdefault("allow", []).append("Bash(ls:*)")
        document["model"] = "user-model-fixture"
        settings.write_text(json.dumps(document), encoding="utf-8")
        result = terminal("plane", "disable", "claude")
        remaining = json.loads(settings.read_text(encoding="utf-8"))
        hooks_preserved = remaining.get("hooks") == {"PreToolUse": [user_hook]}
        settings_preserved = (
            remaining.get("permissions") == {"allow": ["Bash(ls:*)"]}
            and remaining.get("model") == "user-model-fixture"
        )
        state = plane_state()
        ok = (
            result.returncode == 0 and not registered() and hooks_preserved and settings_preserved
            and state == "claude: present, hook NOT registered"
        )
        return ok, (
            f"disable exit={result.returncode}, guardrail hooks removed={not registered()}, "
            f"user hook preserved={hooks_preserved}, user settings preserved={settings_preserved}; {state}"
        )

    def recover():
        corrupt = b"{invalid Claude Code acceptance fixture\n"
        settings.write_bytes(corrupt)
        refused = guardrail("recover", "claude-settings")
        result = terminal("recover", "claude-settings")
        backups = sorted(claude_dir.glob("settings.json.guardrail-recover-*"))
        backup = len(backups) == 1 and backups[0].read_bytes() == corrupt
        return refused.returncode == 2 and result.returncode == 0 and backup and registered(), (
            f"recover without a terminal exit={refused.returncode}, terminal recover exit={result.returncode}, "
            f"byte-identical backup={backup}, hooks restored={registered()}"
        )

    def cleanup():
        clean, diffs = isolation.verify_unchanged()
        active_clean = harness.FileSnapshot.of(active_claude_dir / "settings.json") == active_settings
        removed = not root.exists()
        return clean and active_clean and (removed or keep_artifacts), (
            f"real home unchanged={clean and active_clean}, temp cleaned={removed}; " + ", ".join(diffs)
        )

    try:
        if stage("local_release", "stage two local releases", prepare):
            if stage("install", "install verified v1 and reject a bad checksum", lambda: install(V1_TAG)):
                stage("enrollment", "ADR-0033 prompt posture on fresh install", enrollment)
                stages.append(harness.StageResult(
                    "enrollment_webauthn", status.OPERATOR_ASSISTED,
                    "real authenticator for WebAuthn enrollment", "WebAuthn enrollment was not simulated",
                ))
                if stage("enablement", "register the Claude Code hooks in the isolated settings.json", enable):
                    stage("host_hook_trust",
                          "selftest passes, doctor reports registration, fixtures leave the live-evidence gate shut",
                          diagnostics)
                    stage("harmless_deny", "block fake secret reads through Bash and Read with P4.secret-path", deny)
                    stage("host_ask", "return a native permission ask with exact-retry guidance", host_ask)
                    stage("approval_retry",
                          "P6 deny, operator-action ask, host-ask grant persists, sanctioned fetch allows, replay refused",
                          approval_retry)
                    stages.append(harness.StageResult(
                        "interactive_host_approval", status.OPERATOR_ASSISTED,
                        "an operator answering the Claude Code permission prompt",
                        "the permission prompt was not simulated; headless `claude -p` has no one to answer it",
                    ))
                    stage("update", "install verified v2 and recheck registration, selftest and the evidence gate", update)
                    live_observed = stage(
                        "live_runtime_mediation",
                        "observe allowed and denied native calls in one real session and open the live-evidence gate",
                        live_probe,
                    )
                    if stage("disablement", "remove Guardrail integration and preserve user configuration", disable):
                        stage("recovery", "back up corrupt settings.json and restore registration", recover)
        for record in harness.read_audit_records(audit_path):
            evidence.append(harness.sanitize_audit_record(
                record, path_replacements=replacements, extra_redactions=redactions,
                provenance=classify_provenance(record, live_session),
            ))
    finally:
        if not keep_artifacts:
            shutil.rmtree(root, ignore_errors=True)
        stage("cleanup_isolation", "verify real-home isolation and temporary directory cleanup", cleanup)

    report = harness.build_report(
        plane="claude", os_name="linux", arch=arch, stages=stages, audit_evidence=evidence,
        live_runtime_session_observed=live_observed,
        environment={
            "guardrail_v1": V1_TAG, "guardrail_v2": V2_TAG, "host_binary": "claude",
            "host_version": claude_version, "live_mode": live, "approval_mode": "prompt",
            "artifacts_dir": str(root) if keep_artifacts else "<removed>",
        },
    )
    return harness.report_exit_code(report["summary"]), report
