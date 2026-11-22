"""Windows + Claude Code host adapter for the platform acceptance harness (#92).

Runs the Guardrail lifecycle for the Claude Code plane in a disposable Windows
profile. The verdict, credential and provenance rules are the Linux adapter's;
this file holds what differs on Windows:

- install.ps1 installs and updates, and its change to the User Path is undone.
- `setup` writes the hook command quoted and with forward slashes.
- There is no PTY driver, so disablement and recovery cannot answer a terminal
  prompt. They go through the prompt-mode ticket instead (ADR-0033): the hook
  answers the operator command with a native ask and records a ticket, and the
  command claims it. The harness claims the ticket itself. No operator answers
  the ask, so a human answering Claude Code's permission prompt stays
  `operator_assisted`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import sys
import tempfile

import harness
from linux_antigravity import (
    PROBE_HOST,
    REPO_ROOT,
    V1_TAG,
    V2_TAG,
    _build_guardrail_binary,
    fetch_refused_as_unapproved,
)
from linux_claude import (
    AUTH_ENV,
    CREDENTIALS,
    classify_provenance,
    gate_shut,
    has_live_verdicts,
    live_auth_status,
    live_credentials,
    reported_session,
)
import windows_antigravity
import windows_opencode


def claude_hook_registered(document, binary) -> bool:
    """Report whether a PreToolUse hook runs `<binary> hook claude`.

    `setup` writes the binary quoted and with forward slashes on Windows, so
    the binary is matched across quoting, slashes and case.
    """
    groups = (document.get("hooks") or {}).get("PreToolUse") or ()
    commands = (str(item.get("command", "")) for group in groups for item in group.get("hooks") or ())
    return any(
        command.rstrip().endswith(" hook claude")
        and windows_antigravity.hook_command_matches_binary(command, binary)
        for command in commands
    )


def run_windows_claude_acceptance(
    *, live=False, live_auth_from=None, v1_binary=None, v2_binary=None,
    keep_artifacts=False,
):
    """Execute the Windows Claude Code lifecycle acceptance suite."""
    prerequisites = (
        (sys.platform == "win32", "the Windows Claude Code acceptance adapter requires Windows"),
        ((REPO_ROOT / "install.ps1").is_file(), "install.ps1 not found in the repository"),
        (windows_antigravity._find_powershell() is not None, "pwsh or powershell is required on PATH"),
        (
            not windows_antigravity.elevated_shell(),
            "run from a non-elevated shell: elevated, install.ps1 adds a Microsoft Defender "
            "exclusion for the disposable binary",
        ),
        (
            (v1_binary is not None and v2_binary is not None) or shutil.which("go") is not None,
            "Go or two prebuilt release binaries are required",
        ),
    )
    for satisfied, message in prerequisites:
        if not satisfied:
            print(f"SKIP: {message}", file=sys.stderr)
            return harness.EXIT_SKIP_PREREQ, None

    powershell = windows_antigravity._find_powershell()
    claude = shutil.which("claude") if live else None
    arch = harness.normalized_arch()
    real_home = Path.home().resolve()
    isolation = harness.IsolationGuard.capture(real_home)
    active_claude_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR") or real_home / ".claude").resolve()
    active_settings = harness.FileSnapshot.of(active_claude_dir / "settings.json")
    user_path_before = windows_antigravity._capture_user_path_registry()

    root = Path(tempfile.mkdtemp(prefix="guardrail-accept-win-claude-")).resolve()
    home, bin_dir, workspace, releases = (root / name for name in ("home", "bin", "workspace", "releases"))
    binary = bin_dir / "guardrail.exe"
    claude_dir = home / ".claude"
    settings = claude_dir / "settings.json"
    audit_path = home / "AppData" / "Local" / "guardrail" / "audit.jsonl"
    operator_config = home / "AppData" / "Roaming" / "guardrail" / "waivers.toml"
    env = windows_opencode.build_opencode_isolated_env(iso_home=home, iso_bin=bin_dir)
    # Claude Code keeps per-session state under %TEMP%, which is inside the real
    # profile; point it at the disposable root like every other profile path.
    scratch = root / "tmp"
    env["TEMP"] = env["TMP"] = str(scratch)

    secret = "FAKE_ACCEPTANCE_" + secrets.token_hex(12)
    marker = "CLAUDE_ACCEPTANCE_" + secrets.token_hex(12)
    redactions = [secret, *(os.environ[name] for name in AUTH_ENV if os.environ.get(name))]
    replacements = windows_antigravity.build_windows_path_replacements(
        workspace=workspace, iso_home=home, temp_root=root, real_home=real_home,
    )
    status = harness.StageStatus
    stages = []
    evidence = []
    claude_version = "not invoked"
    live_session = ""
    live_observed = False

    def run(command, **kwargs):
        return harness.run_cmd(command, env=env, cwd=workspace, **kwargs)

    def guardrail(*args, **kwargs):
        return run([str(binary), *args], **kwargs)

    def audit():
        return harness.read_audit_records(audit_path)

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

    def note(name, outcome, expected, observed):
        stages.append(harness.StageResult(name, outcome, expected, observed))

    def prepare():
        for directory in (home, bin_dir, workspace, releases, scratch):
            directory.mkdir(parents=True)
        (workspace / ".env").write_text(f"FAKE_SECRET={secret}\n", encoding="utf-8", newline="\n")
        (workspace / "allowed.txt").write_text(marker + "\n", encoding="utf-8", newline="\n")
        initialized = run(["git", "init", "-q"])
        if initialized.returncode != 0:
            return False, initialized.stderr
        for version, prebuilt in ((V1_TAG, v1_binary), (V2_TAG, v2_binary)):
            source = prebuilt.resolve() if prebuilt else root / f"guardrail-{version}.exe"
            if prebuilt is None:
                _build_guardrail_binary(source, version)
            harness.stage_local_release(
                releases_root=releases, version=version, binary_path=source, os_name="windows", arch=arch,
            )
        return True, "two local release assets and checksum manifests staged"

    def install(version):
        command = [
            powershell, "-NoProfile", "-File", str(REPO_ROOT / "install.ps1"), "-Version", version,
            "-Dest", str(bin_dir), "-BaseUrl", str(releases), "-NoSetup",
        ]
        sums = releases / version / "SHA256SUMS"
        original = sums.read_bytes()
        before = harness.FileSnapshot.of(binary)
        try:
            sums.write_bytes(b"0" * 64 + original[64:])
            rejected = run(command, timeout=90)
            unchanged = harness.FileSnapshot.of(binary) == before
            sums.write_bytes(original)
            accepted = run(command, timeout=90)
        finally:
            sums.write_bytes(original)
            # install.ps1 adds -Dest to the real HKCU Path; put it back at once.
            windows_antigravity._restore_user_path_registry(user_path_before)
        actual = guardrail("version") if binary.is_file() else accepted
        mismatch = "CHECKSUM MISMATCH" in rejected.stdout + rejected.stderr
        matched = actual.stdout.strip() == f"guardrail {version}"
        ok = rejected.returncode == 1 and mismatch and unchanged and accepted.returncode == 0 and matched
        return ok, (
            f"bad checksum exit={rejected.returncode}, mismatch reported={mismatch}, "
            f"destination unchanged={unchanged}; valid install exit={accepted.returncode}, "
            f"version={actual.stdout.strip()!r}"
        )

    def enrollment():
        result = guardrail("doctor")
        line = next((l for l in result.stdout.splitlines() if l.startswith("approval mode:")), result.stderr)
        return "approval mode: prompt (" in result.stdout, line

    def registered():
        try:
            return claude_hook_registered(json.loads(settings.read_text(encoding="utf-8")), binary)
        except (OSError, ValueError):
            return False

    def plane_state():
        listing = guardrail("plane", "status").stdout.splitlines()
        return next((line for line in listing if line.startswith("claude:")), "claude: (no status line)")

    def enable():
        result = guardrail("setup", "--planes", "claude", timeout=90)
        state = plane_state()
        armed = registered() and state == "claude: guardrail hook registered"
        return result.returncode == 0 and armed, (
            f"setup exit={result.returncode}, isolated settings.json hook={registered()}, {state}"
        )

    def evidence_gate():
        return guardrail("selftest", "--evidence", "claude")

    def diagnostics():
        doctor = guardrail("doctor")
        selftest = guardrail("selftest", timeout=90)
        gate = evidence_gate()
        line = next((text for text in doctor.stdout.splitlines()
                     if text.startswith("claude settings:")), "claude settings: (no doctor line)")
        # Registration is not enforcement: selftest and fixture sessions are not
        # real Claude Code sessions, so the evidence gate must stay shut.
        ok = (
            selftest.returncode == 0 and "claude: probes pass" in selftest.stdout
            and line.startswith("claude settings: guardrail hook registered")
            and registered() and gate_shut(gate)
        )
        return ok, (
            f"selftest exit={selftest.returncode}, live-evidence gate exit={gate.returncode} "
            f"not-yet-observed={gate_shut(gate)}; {line}"
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
        records = [record for record in audit()
                   if record.get("session_id") == session and record.get("event") == "pre"]
        audited = records[-1] if records else {}
        return decision, audited.get("decision"), audited.get("rule_id"), result

    def bash(command):
        return direct("Bash", {"command": command})

    def ticketed(*cli_args):
        """Have the hook ask for an operator command, then run it to claim the ticket."""
        asked = bash("guardrail " + " ".join(cli_args))
        return asked, guardrail(*cli_args)

    # The fixture stages feed envelopes to the hook; no tool runs, so they
    # check the verdict the host would receive and nothing about the files.
    def deny():
        secret_deny = ("deny", "deny", "P4.secret-path")
        shell = bash("cat .env")
        read = direct("Read", {"file_path": str(workspace / ".env")})
        # A path with a separator. The bare `Get-Content .env` is not checked here.
        cmdlet = direct("PowerShell", {"command": "Get-Content .\\.env"})
        benign = bash("cat allowed.txt")
        ok = (
            all(probe[:3] == secret_deny and probe[3].returncode == 2 for probe in (shell, read, cmdlet))
            and benign[:2] == ("allow", "allow")
        )
        return ok, (
            f"Bash cat .env: exit={shell[3].returncode} audit={shell[1]}/{shell[2]}; "
            f"Read .env: exit={read[3].returncode} audit={read[1]}/{read[2]}; "
            f"PowerShell Get-Content .\\.env: exit={cmdlet[3].returncode} audit={cmdlet[1]}/{cmdlet[2]}; "
            f"Bash cat allowed.txt: {benign[0]}"
        )

    def host_ask():
        asked = bash("chmod 777 allowed.txt")
        reason = ""
        if asked[0] == "ask":
            reason = json.loads(asked[3].stdout)["hookSpecificOutput"].get("permissionDecisionReason", "")
        guided = "retry this exact tool call" in reason
        return asked[:3] == ("ask", "ask", "P1.chmod") and asked[3].returncode == 0 and guided, (
            f"hook exit={asked[3].returncode}, permissionDecision={asked[0]}, "
            f"audit={asked[1]}/{asked[2]}, retry guidance={guided}"
        )

    def approval_retry():
        before = len(audit())
        grant = ("egress", "grant", "--scope", "repo", "--host", PROBE_HOST)

        def fetch_refused():
            return fetch_refused_as_unapproved(guardrail("fetch", f"https://{PROBE_HOST}"))

        def persisted():
            return all(
                path.is_file() and PROBE_HOST in path.read_text(encoding="utf-8")
                for path in (workspace / "guardrail.toml", operator_config)
            )

        initial = bash(f"curl https://{PROBE_HOST}")
        fetch_before = fetch_refused()
        unasked = guardrail(*grant)
        refused = unasked.returncode == 2 and not persisted()
        requested, claimed = ticketed(*grant)
        fetch_after = fetch_refused()
        replayed = guardrail(*grant)
        host_asks = sum(record.get("transport") == "host-ask" for record in audit()[before:])
        ok = (
            initial[:3] == ("deny", "deny", "P6.egress") and fetch_before and refused
            and requested[0] == "ask" and requested[2] == "operator-action-ask"
            and claimed.returncode == 0 and persisted() and not fetch_after
            and replayed.returncode == 2 and host_asks >= 1
        )
        return ok, (
            f"initial={initial[0]}/{initial[2]}, grant without an ask refused={refused}, "
            f"grant hook={requested[0]}/{requested[2]}, grant cli exit={claimed.returncode}, "
            f"overlay and operator config persisted={persisted()}, "
            f"fetch refused as unapproved before={fetch_before} and after={fetch_after}, "
            f"replay exit={replayed.returncode}, host-ask audit={host_asks}"
        )

    def fixtures_leave_gate_shut():
        # Runs after the fixture stages and before the update replaces the
        # binary, so the fixture records are inside the gate's window.
        fixtures = [record for record in audit()
                    if str(record.get("session_id", "")).startswith("claude-fixture-")
                    and record.get("plane") == "claude" and record.get("event") == "pre"]
        gate = evidence_gate()
        return len(fixtures) >= 2 and gate_shut(gate), (
            f"{len(fixtures)} fixture pre-hook records in the window, live-evidence gate "
            f"exit={gate.returncode} not-yet-observed={gate_shut(gate)}"
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
        supplied = any(os.environ.get(name) for name in AUTH_ENV)
        try:
            if live_auth_from is not None:
                credentials, refusal = live_credentials(
                    live_auth_from, real_home, (active_claude_dir, (real_home / ".claude").resolve()),
                )
                if credentials is None:
                    return False, refusal
                auth_target.touch(exist_ok=False)
                shutil.copyfile(credentials, auth_target)
                supplied = True
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
        # A session that ran must have left its own state in the disposable
        # profile; if it did not, it resolved a home this run does not control.
        isolated_state = (home / ".claude.json").is_file() or (claude_dir / "projects").is_dir()
        if session and not isolated_state:
            return False, "claude reported a session but wrote no state under the isolated profile"
        unauthenticated = live_auth_status(events, supplied=supplied)
        if unauthenticated == status.FAIL:
            return unauthenticated, "the supplied credentials were rejected by the Claude Code runtime"
        if unauthenticated is not None:
            return unauthenticated, (
                f"isolated Claude Code runtime is not logged in (session reported={bool(session)}, "
                f"its state under the isolated profile={isolated_state}); "
                "supply --live-auth-from or an API key or OAuth token in the environment"
            )
        verdicts = has_live_verdicts(audit(), session)
        safe_output = marker in result.stdout
        no_leak = secret not in result.stdout + result.stderr
        gate = evidence_gate()
        return (
            result.returncode == 0 and verdicts and safe_output and no_leak and gate.returncode == 0
        ), (
            f"claude -p exit={result.returncode}, session reported={bool(session)}, "
            f"both pre-hook verdicts={verdicts}, safe command output={safe_output}, "
            f"secret absent={no_leak}, live-evidence gate exit={gate.returncode}, "
            f"its state under the isolated profile={isolated_state}"
        )

    def disable():
        document = json.loads(settings.read_text(encoding="utf-8"))
        user_hook = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo user-hook"}]}
        document["hooks"]["PreToolUse"].append(user_hook)
        document.setdefault("permissions", {}).setdefault("allow", []).append("Bash(ls:*)")
        document["model"] = "user-model-fixture"
        settings.write_text(json.dumps(document), encoding="utf-8")
        unasked = guardrail("plane", "disable", "claude")
        refused = unasked.returncode == 3 and registered()
        requested, result = ticketed("plane", "disable", "claude")
        remaining = json.loads(settings.read_text(encoding="utf-8"))
        hooks_preserved = remaining.get("hooks") == {"PreToolUse": [user_hook]}
        settings_preserved = (
            remaining.get("permissions") == {"allow": ["Bash(ls:*)"]}
            and remaining.get("model") == "user-model-fixture"
        )
        state = plane_state()
        replayed = guardrail("plane", "disable", "claude")
        ok = (
            refused and requested[0] == "ask" and requested[2] == "operator-action-ask"
            and result.returncode == 0 and not registered() and hooks_preserved and settings_preserved
            and state == "claude: present, hook NOT registered" and replayed.returncode == 3
        )
        return ok, (
            f"disable without an ask refused={refused}, hook={requested[0]}/{requested[2]}, "
            f"disable exit={result.returncode}, guardrail hooks removed={not registered()}, "
            f"user hook preserved={hooks_preserved}, user settings preserved={settings_preserved}, "
            f"replay exit={replayed.returncode}; {state}"
        )

    def recover():
        corrupt = b"{invalid Claude Code acceptance fixture\n"
        settings.write_bytes(corrupt)
        unasked = guardrail("recover", "claude-settings")
        refused = unasked.returncode == 2 and settings.read_bytes() == corrupt
        requested, result = ticketed("recover", "claude-settings")
        replayed = guardrail("recover", "claude-settings")
        backups = sorted(claude_dir.glob("settings.json.guardrail-recover-*"))
        backup = len(backups) == 1 and backups[0].read_bytes() == corrupt
        ok = (
            refused and requested[0] == "ask" and requested[2] == "operator-action-ask"
            and result.returncode == 0 and replayed.returncode == 2 and backup and registered()
        )
        return ok, (
            f"recover without an ask refused={refused}, hook={requested[0]}/{requested[2]}, "
            f"recover exit={result.returncode}, replay exit={replayed.returncode}, "
            f"byte-identical backup={backup}, hooks restored={registered()}"
        )

    def cleanup():
        windows_antigravity._restore_user_path_registry(user_path_before)
        user_path_clean = windows_antigravity._capture_user_path_registry() == user_path_before
        clean, diffs = isolation.verify_unchanged()
        active_clean = harness.FileSnapshot.of(active_claude_dir / "settings.json") == active_settings
        removed = not root.exists()
        ok = clean and active_clean and user_path_clean and (removed or keep_artifacts) and bool(evidence)
        return ok, (
            f"real profile unchanged={clean and active_clean}, HKCU Path unchanged={user_path_clean}, "
            f"temp cleaned={removed}, isolated audit records={len(evidence)}; " + ", ".join(diffs)
        )

    try:
        if stage("local_release", "stage two local releases", prepare) and stage(
            "install", "install.ps1 rejects a bad checksum and installs verified v1", lambda: install(V1_TAG),
        ):
            stage("enrollment", "ADR-0033 prompt posture on a fresh install", enrollment)
            note("enrollment_webauthn", status.OPERATOR_ASSISTED,
                 "a real authenticator for WebAuthn enrollment", "WebAuthn enrollment was not simulated")
            if stage("enablement", "register the Claude Code hooks in the isolated settings.json", enable):
                stage("host_hook_trust",
                      "selftest passes, doctor reports registration, the live-evidence gate reports not yet observed",
                      diagnostics)
                stage("harmless_deny",
                      "block fake secret reads through Bash, Read and PowerShell with P4.secret-path", deny)
                stage("host_ask", "return a native permission ask with exact-retry guidance", host_ask)
                stage("approval_retry",
                      "P6 deny and fetch refused, grant refused without an ask, harness-claimed host-ask grant "
                      "persists and unblocks the fetch, replay refused", approval_retry)
                stage("fixture_evidence_gate",
                      "fixture pre-hook records inside the window leave the live-evidence gate shut",
                      fixtures_leave_gate_shut)
                note("interactive_host_approval", status.OPERATOR_ASSISTED,
                     "an operator answering the Claude Code permission prompt",
                     "the permission prompt was not simulated; the harness claims each host-ask ticket itself")
                stage("update", "install.ps1 installs verified v2 and registration, selftest and the gate hold",
                      update)
                live_observed = stage(
                    "live_runtime_mediation",
                    "observe allowed and denied native calls in one real session and open the live-evidence gate",
                    live_probe,
                )
                if stage("disablement",
                         "refuse without an ask, remove the Guardrail hooks through a host-ask ticket, "
                         "preserve user configuration, refuse replay", disable):
                    stage("recovery",
                          "refuse without an ask, back up corrupt settings.json and restore registration, "
                          "refuse replay", recover)
        for record in audit():
            evidence.append(harness.sanitize_audit_record(
                record, path_replacements=replacements, extra_redactions=redactions,
                provenance=classify_provenance(record, live_session),
            ))
    finally:
        windows_antigravity._restore_user_path_registry(user_path_before)
        if not keep_artifacts:
            windows_opencode.remove_tree(root)
        stage("cleanup_isolation", "real profile and HKCU Path untouched, temporary root removed", cleanup)

    report = harness.build_report(
        plane="claude", os_name="windows", arch=arch, stages=stages, audit_evidence=evidence,
        live_runtime_session_observed=live_observed,
        environment={
            "guardrail_v1": V1_TAG, "guardrail_v2": V2_TAG, "host_binary": "claude",
            "host_version": claude_version, "os": f"{platform.system()} {platform.release()}",
            "shell": Path(powershell).name, "live_mode": live, "approval_mode": "prompt",
            "artifacts_dir": str(root) if keep_artifacts else "<removed>",
        },
    )
    return harness.report_exit_code(report["summary"]), report
