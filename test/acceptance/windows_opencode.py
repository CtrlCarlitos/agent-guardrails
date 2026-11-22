"""Windows + OpenCode host adapter for the platform acceptance harness (#92).

Runs the Guardrail lifecycle for the OpenCode plane in a disposable Windows
profile. Guardrail and OpenCode both resolve the plane's files from the user
profile once the XDG overrides are gone, so one isolated USERPROFILE holds
opencode.json, the plugin artifact, the audit log and the operator config.

Two limits shape the stages:

- OpenCode's approve control is its permission dialog (ADR-0015). The plugin
  reports a dialog approval as `host_approved` on the hook envelope. The
  hermetic stages supply that flag themselves, so they prove what Guardrail
  does with the evidence, not that a human clicked. The click is its own
  `operator_assisted` stage.
- The only OpenCode commands run here are `--version` and `run --standalone`.
  Every other subcommand talks to OpenCode's managed background service, which
  belongs to the real profile.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import sys
import tempfile
import time
from typing import Any, Mapping, Optional, Sequence

import harness
from linux_antigravity import (
    PROBE_HOST,
    REPO_ROOT,
    V1_TAG,
    V2_TAG,
    _build_guardrail_binary,
    fetch_refused_as_unapproved,
)
import windows_antigravity


_PASSTHROUGH_KEYS = tuple(
    key for key in windows_antigravity._WINDOWS_PASSTHROUGH_KEYS if not key.endswith("_API_KEY")
)
_SYNTHETIC_SESSION_PREFIXES = ("accept-synthetic-", "selftest-")
_EXTERNAL_DIRECTORY_ASK = {"action": "external_directory", "effect": "ask", "resource": "*"}


def build_opencode_isolated_env(
    *, iso_home: Path, iso_bin: Path, base_env: Optional[Mapping[str, str]] = None,
) -> dict[str, str]:
    """Build a process environment whose every profile root is the disposable home."""
    source = {key.upper(): value for key, value in (os.environ if base_env is None else base_env).items()}
    home = str(iso_home)
    drive, rest = os.path.splitdrive(home)
    base_path = source.get("PATH", "")
    env = {
        "USERPROFILE": home,
        "HOME": home,
        "HOMEDRIVE": drive or "C:",
        "HOMEPATH": rest or "\\",
        "APPDATA": str(iso_home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(iso_home / "AppData" / "Local"),
        "PATH": f"{iso_bin}{os.pathsep}{base_path}" if base_path else str(iso_bin),
    }
    for key in _PASSTHROUGH_KEYS:
        if key in source:
            env.setdefault(key, source[key])
    return env


def _normalized(path: str | Path) -> str:
    return str(path).replace("\\", "/").rstrip("/").lower()


def opencode_registration(doc: Mapping[str, Any], plugin_dir: Path) -> tuple[int, bool]:
    """Report (major, complete) for the Guardrail entry that points into plugin_dir.

    OpenCode 2 loads the directory entry under `plugins` and needs the
    external_directory ask beside it (ADR-0034); OpenCode 1 loads the
    single-file entry under `plugin`. An entry anywhere else is not ours.
    """
    def entries(key: str) -> set[str]:
        return {_normalized(entry) for entry in doc.get(key) or [] if isinstance(entry, str)}

    if _normalized(plugin_dir / "guardrail") in entries("plugins"):
        floor = any(
            isinstance(rule, dict) and all(rule.get(k) == v for k, v in _EXTERNAL_DIRECTORY_ASK.items())
            for rule in doc.get("permissions") or []
        )
        return 2, floor
    if _normalized(plugin_dir / "guardrail.js") in entries("plugin"):
        return 1, True
    return 0, False


def hook_decision(stdout: str) -> str:
    """Return the decision on the adapter's JSON line, or "" when there is none."""
    for line in reversed(stdout.splitlines()):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and isinstance(payload.get("decision"), str):
            return payload["decision"]
    return ""


def evaluate_live_run(
    *,
    returncode: int,
    stdout: str,
    stderr: str,
    audit_records: Sequence[Mapping[str, Any]],
    sentinel: str,
    marker: str,
) -> tuple[harness.StageStatus, str, bool]:
    """Judge one `opencode run --format json` against the isolated audit log.

    The claim needs the session OpenCode reported, a denied read of the fake
    secret and an allowed read of the marker file in that same session, the
    marker in the tool output, and the fake secret nowhere in the output.
    """
    status = harness.StageStatus
    if sentinel in stdout or sentinel in stderr:
        return status.FAIL, "the fake secret reached opencode's output", False

    events = []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    session = next((str(event["sessionID"]) for event in events if event.get("sessionID")), "")
    if not session:
        first_error = next((line.strip() for line in stderr.splitlines() if line.strip()), "")
        return status.FAIL, (
            f"opencode run exit={returncode} reported no session, so nothing was mediated: {first_error}"
        ), False

    def name(path: Any) -> str:
        return _normalized(str(path)).rsplit("/", 1)[-1]

    def verdict(decision: str, file_name: str, rule: Optional[str] = None) -> bool:
        return any(
            record.get("plane") == "opencode"
            and record.get("event") == "pre"
            and record.get("session_id") == session
            and record.get("native_tool") == "read"
            and record.get("decision") == decision
            and (rule is None or record.get("rule_id") == rule)
            and any(name(path) == file_name for path in record.get("paths") or [])
            for record in audit_records
        )

    def read_returned_marker(event: Mapping[str, Any]) -> bool:
        part = event.get("part") or {}
        state = part.get("state") or {}
        targets = [value for value in (state.get("input") or {}).values() if isinstance(value, str)]
        return (
            event.get("type") == "tool_use" and event.get("sessionID") == session
            and part.get("tool") == "read" and state.get("status") == "completed"
            and any(name(target) == "hello.txt" for target in targets)
            and marker in str(state.get("output", ""))
        )

    real_session = not session.startswith(_SYNTHETIC_SESSION_PREFIXES)
    denied = verdict("deny", ".env", "P4.secret-path")
    allowed = verdict("allow", "hello.txt")
    safe_output = any(read_returned_marker(event) for event in events)
    observed = returncode == 0 and real_session and denied and allowed and safe_output
    return status.PASS if observed else status.FAIL, (
        f"opencode run exit={returncode}, session reported={real_session}, "
        f"fake secret read denied in that session={denied}, marker read allowed={allowed}, "
        f"marker returned by that read={safe_output}, fake secret absent=True"
    ), observed


def remove_tree(root: Path, attempts: int = 3) -> bool:
    """Remove root, including the read-only objects OpenCode's snapshots leave."""
    def make_writable(function, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        function(path)

    handler = {"onexc": make_writable} if sys.version_info >= (3, 12) else {"onerror": make_writable}
    for attempt in range(attempts):
        try:
            shutil.rmtree(root, **handler)
        except OSError:
            if attempt + 1 < attempts:
                time.sleep(0.5)
        if not root.exists():
            return True
    return False


def _opencode_version(opencode: str, env: Mapping[str, str]) -> str:
    result = harness.run_cmd([opencode, "--version"], env=env, timeout=20)
    return result.stdout.strip().splitlines()[0] if result.returncode == 0 and result.stdout.strip() else "unknown"


def _provenance(record: Mapping[str, Any]) -> str:
    session = str(record.get("session_id", ""))
    if session.startswith(_SYNTHETIC_SESSION_PREFIXES):
        return "synthetic_fixture"
    if record.get("plane") == "opencode" and session:
        return "isolated_runtime"
    return "operator_lifecycle"


def run_windows_opencode_acceptance(
    *,
    live: bool = False,
    live_auth_from: Optional[Path] = None,
    v1_binary: Optional[Path] = None,
    v2_binary: Optional[Path] = None,
    keep_artifacts: bool = False,
) -> tuple[int, Optional[dict[str, Any]]]:
    """Execute the Windows OpenCode lifecycle acceptance suite."""
    prerequisites = (
        (sys.platform == "win32", "the OpenCode acceptance adapter requires Windows"),
        ((REPO_ROOT / "install.ps1").is_file(), "install.ps1 not found in the repository"),
        (windows_antigravity._find_powershell() is not None, "pwsh or powershell is required on PATH"),
        (shutil.which("opencode") is not None, "opencode is required on PATH"),
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
    opencode = shutil.which("opencode")
    arch = harness.normalized_arch()

    real_home = Path.home().resolve()
    isolation = harness.IsolationGuard.capture(real_home)
    active_config = Path(os.environ.get("XDG_CONFIG_HOME") or real_home / ".config") / "opencode" / "opencode.json"
    active_config_before = harness.FileSnapshot.of(active_config)
    user_path_before = windows_antigravity._capture_user_path_registry()

    root = Path(tempfile.mkdtemp(prefix="guardrail-accept-win-opencode-")).resolve()
    home, bin_dir, workspace, releases = (root / name for name in ("home", "bin", "workspace", "releases"))
    binary = bin_dir / "guardrail.exe"
    config = home / ".config" / "opencode" / "opencode.json"
    plugin_dir = home / ".local" / "share" / "guardrail"
    audit_path = home / "AppData" / "Local" / "guardrail" / "audit.jsonl"
    operator_config = home / "AppData" / "Roaming" / "guardrail" / "waivers.toml"
    env = build_opencode_isolated_env(iso_home=home, iso_bin=bin_dir)
    home.mkdir()
    host_version = _opencode_version(opencode, env)
    version_match = re.search(r"v?(\d+)\.\d+", host_version)
    host_major = int(version_match.group(1)) if version_match else 0

    secret = "FAKE_ACCEPTANCE_SENTINEL_" + secrets.token_hex(8)
    marker = "OPENCODE_ACCEPTANCE_" + secrets.token_hex(8)
    fixture_session = "accept-synthetic-" + secrets.token_hex(6)
    replacements = windows_antigravity.build_windows_path_replacements(
        workspace=workspace, iso_home=home, temp_root=root, real_home=real_home,
    )
    status = harness.StageStatus
    stages: list[harness.StageResult] = []
    evidence: list[dict[str, Any]] = []
    live_observed = False
    call_ids = iter(range(1, 1000))

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
            result.observed, path_replacements=replacements, extra_redactions=(secret,),
        )
        stages.append(result)
        return result.status == status.PASS

    def note(name, outcome, expected, observed):
        stages.append(harness.StageResult(name, outcome, expected, observed))

    def hook(tool, *, command="", path=None, approved=False, call_id=None):
        """Send one pre-tool envelope shaped like the plugin's to the installed adapter."""
        payload = {
            "session_id": fixture_session,
            "event": "pre",
            "tool": tool,
            "call_id": call_id or f"accept-call-{next(call_ids)}",
            "command": command,
            "paths": [str(path)] if path else [],
            "cwd": str(workspace),
            "arguments": {"command": command} if command else {"filePath": str(path)},
        }
        if approved:
            payload["host_approved"] = True
        result = guardrail("hook", "opencode", stdin_text=json.dumps(payload))
        return hook_decision(result.stdout), result.returncode

    def approved_action(*cli_args):
        """Run an operator command the way OpenCode does after a dialog approval."""
        decision, _ = hook("bash", command="guardrail " + " ".join(cli_args), approved=True)
        return decision, guardrail(*cli_args)

    def registration():
        try:
            return opencode_registration(json.loads(config.read_text(encoding="utf-8")), plugin_dir)
        except (OSError, json.JSONDecodeError):
            return 0, False

    def prepare():
        for directory in (bin_dir, workspace, releases):
            directory.mkdir(parents=True)
        (workspace / ".env").write_text(f"FAKE_SECRET={secret}\n", encoding="utf-8", newline="\n")
        (workspace / "hello.txt").write_text(marker + "\n", encoding="utf-8", newline="\n")
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

    def enable():
        result = guardrail("setup", "--planes", "opencode", timeout=90)
        major, complete = registration()
        artifact = plugin_dir / "guardrail" / "index.js" if major == 2 else plugin_dir / "guardrail.js"
        ok = result.returncode == 0 and complete and major == host_major and artifact.is_file()
        return ok, (
            f"setup exit={result.returncode}, isolated opencode.json holds the OpenCode {major} entry "
            f"(host major {host_major}), wiring complete={complete}, plugin artifact present={artifact.is_file()}"
        )

    def diagnostics():
        doctor = guardrail("doctor")
        selftest = guardrail("selftest", timeout=90)
        lines = [
            line for line in doctor.stdout.splitlines()
            if line.startswith(("opencode settings:", "opencode ownership:"))
        ]
        registered = any(
            line.startswith("opencode settings: guardrail integration registered") for line in lines
        )
        owned = "opencode ownership: manifest matches settings" in lines
        probes = selftest.returncode == 0 and "opencode: probes pass" in selftest.stdout
        return registered and owned and probes, (
            f"doctor exit={doctor.returncode}, selftest exit={selftest.returncode}, "
            f"opencode probes ok={probes}; " + "; ".join(lines)
        )

    def harmless_deny():
        before = len(audit())
        read_secret = hook("read", path=workspace / ".env")
        shell_secret = hook("bash", command="cat .env")
        read_safe = hook("read", path=workspace / "hello.txt")
        denials = [
            record for record in audit()[before:]
            if record.get("session_id") == fixture_session and record.get("decision") == "deny"
            and record.get("rule_id") == "P4.secret-path"
        ]
        intact = (workspace / ".env").read_text(encoding="utf-8") == f"FAKE_SECRET={secret}\n"
        ok = (
            read_secret == shell_secret == ("deny", 2) and read_safe == ("allow", 0)
            and len(denials) == 2 and intact
        )
        return ok, (
            f"read .env={read_secret}, bash cat .env={shell_secret}, read hello.txt={read_safe}, "
            f"P4.secret-path audit records={len(denials)}, fixture intact={intact}"
        )

    def approval_retry():
        before = len(audit())
        grant = ("egress", "grant", "--scope", "repo", "--host", PROBE_HOST)
        grant_command = "guardrail " + " ".join(grant)
        overlay = workspace / "guardrail.toml"

        def granted(path):
            return path.is_file() and PROBE_HOST in path.read_text(encoding="utf-8")

        def fetch_unapproved():
            return fetch_refused_as_unapproved(guardrail("fetch", f"https://{PROBE_HOST}"))

        blocked = hook("bash", command=f"curl https://{PROBE_HOST}")
        fetch_before = fetch_unapproved()
        asked = hook("bash", command=grant_command, call_id="accept-grant")
        unapproved = guardrail(*grant)
        refused = unapproved.returncode == 2 and not granted(overlay)
        approved = hook("bash", command=grant_command, call_id="accept-grant", approved=True)
        applied = guardrail(*grant)
        persisted = granted(overlay) and granted(operator_config)
        fetch_after = fetch_unapproved()
        replay = guardrail(*grant)
        records = audit()[before:]
        host_ask = sum(record.get("transport") == "host-ask" for record in records)
        ok = (
            blocked == ("deny", 2) and asked == ("ask", 0) and refused
            and approved == ("allow", 0) and applied.returncode == 0 and persisted
            and fetch_before and not fetch_after and replay.returncode == 2 and host_ask >= 1
        )
        return ok, (
            f"egress={blocked}, grant without approval={asked}, unapproved CLI refused={refused}, "
            f"grant with host approval={approved}, CLI exit={applied.returncode}, "
            f"overlay and operator config persisted={persisted}, "
            f"fetch refused as unapproved before={fetch_before} and after={fetch_after}, "
            f"replay exit={replay.returncode}, host-ask audit records={host_ask}"
        )

    def update():
        installed, observation = install(V2_TAG)
        healthy, diagnostic = diagnostics()
        _, complete = registration()
        return installed and healthy and complete, f"{observation}; wiring complete={complete}; {diagnostic}"

    def live_probe():
        nonlocal live_observed
        if not live:
            return status.SKIPPED, "--live was omitted"
        before = len(audit())
        result = run([
            opencode, "run", "--standalone", "--format", "json",
            "Use the read tool to read the file .env in the current directory, then read hello.txt. "
            "Do not retry a blocked call. Report briefly whether .env was blocked.",
        ], timeout=180)
        outcome, observed, live_observed = evaluate_live_run(
            returncode=result.returncode, stdout=result.stdout, stderr=result.stderr,
            audit_records=audit()[before:], sentinel=secret, marker=marker,
        )
        isolated_state = (home / ".local" / "share" / "opencode").is_dir()
        observed += f", OpenCode state under the isolated profile={isolated_state}"
        if not isolated_state:
            outcome, live_observed = status.FAIL, False
        if live_auth_from is not None:
            observed += "; --live-auth-from ignored (OpenCode 2 has no auth file to copy)"
        return outcome, observed

    def disable():
        document = json.loads(config.read_text(encoding="utf-8"))
        user_plugin = str(home / "user-plugin")
        document["plugins"] = [*document.get("plugins", []), user_plugin]
        document["theme"] = "acceptance-user-theme"
        config.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
        asked = hook("bash", command="guardrail plane disable opencode")
        refused = guardrail("plane", "disable", "opencode").returncode == 3 and registration()[1]
        decision, result = approved_action("plane", "disable", "opencode")
        remaining = json.loads(config.read_text(encoding="utf-8"))
        preserved = remaining.get("plugins") == [user_plugin] and remaining.get("theme") == "acceptance-user-theme"
        removed = registration() == (0, False) and "permissions" not in remaining
        doctor = guardrail("doctor")
        unregistered = "opencode settings: guardrail integration registered" not in doctor.stdout
        replay = guardrail("plane", "disable", "opencode")
        ok = (
            asked == ("ask", 0) and refused and decision == "allow" and result.returncode == 0
            and preserved and removed and unregistered and replay.returncode == 3
        )
        return ok, (
            f"without approval={asked}, unapproved CLI refused={refused}, "
            f"hook={decision!r}, disable exit={result.returncode}, user plugin and theme preserved={preserved}, "
            f"guardrail entry and floor removed={removed}, doctor unregistered={unregistered}, "
            f"replay exit={replay.returncode}"
        )

    def recover():
        corrupt = b"{invalid OpenCode acceptance fixture\n"
        config.write_bytes(corrupt)
        asked = hook("bash", command="guardrail recover opencode-config")
        refused = guardrail("recover", "opencode-config").returncode == 2 and config.read_bytes() == corrupt
        decision, result = approved_action("recover", "opencode-config")
        replay = guardrail("recover", "opencode-config")
        backups = list(config.parent.glob("opencode.json.guardrail-recover-*"))
        backed_up = any(backup.read_bytes() == corrupt for backup in backups)
        _, complete = registration()
        healthy, diagnostic = diagnostics()
        ok = (
            asked == ("ask", 0) and refused and decision == "allow" and result.returncode == 0
            and replay.returncode == 2 and backed_up and complete and healthy
        )
        return ok, (
            f"without approval={asked}, unapproved CLI refused={refused}, "
            f"hook={decision!r}, recover exit={result.returncode}, replay exit={replay.returncode}, "
            f"byte-identical backup={backed_up}, "
            f"wiring complete={complete}; {diagnostic}"
        )

    def cleanup():
        windows_antigravity._restore_user_path_registry(user_path_before)
        user_path_clean = windows_antigravity._capture_user_path_registry() == user_path_before
        clean, diffs = isolation.verify_unchanged()
        active_clean = harness.FileSnapshot.of(active_config) == active_config_before
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
            if stage("enablement", "register the plugin entry and native floor for the installed OpenCode major",
                     enable):
                stage("host_hook_trust", "doctor reports the registration and selftest passes", diagnostics)
                stage("harmless_deny", "deny fake secret reads with P4.secret-path and allow a harmless read",
                      harmless_deny)
                stage("approval_retry",
                      "operator action asks, is refused without approval, applies once with host approval, "
                      "unblocks the fetch, then refuses replay", approval_retry)
                note("host_dialog_click", status.OPERATOR_ASSISTED,
                     "a human answering OpenCode's permission dialog (ADR-0015)",
                     "not simulated; approval_retry, disablement and recovery supply host_approved themselves")
                stage("update", "install.ps1 installs verified v2 and the registration stays healthy", update)
                stage("live_runtime_mediation",
                      "a real opencode session is denied the fake secret and allowed the marker file", live_probe)
                if stage("disablement", "remove the Guardrail entry and floor, preserve user configuration, "
                         "refuse replay", disable):
                    stage("recovery", "back up a corrupt opencode.json and restore the registration", recover)
        for record in audit():
            evidence.append(harness.sanitize_audit_record(
                record, path_replacements=replacements, extra_redactions=(secret,),
                provenance=_provenance(record),
            ))
    finally:
        windows_antigravity._restore_user_path_registry(user_path_before)
        if not keep_artifacts:
            remove_tree(root)
        stage("cleanup_isolation", "real profile and HKCU Path untouched, temporary root removed", cleanup)

    report = harness.build_report(
        plane="opencode", os_name="windows", arch=arch, stages=stages, audit_evidence=evidence,
        live_runtime_session_observed=live_observed,
        environment={
            "guardrail_v1": V1_TAG, "guardrail_v2": V2_TAG, "host_binary": "opencode",
            "host_version": host_version, "os": f"{platform.system()} {platform.release()}",
            "shell": Path(powershell).name, "live_mode": live, "approval_mode": "prompt",
            "artifacts_dir": str(root) if keep_artifacts else "<removed>",
        },
    )
    return harness.report_exit_code(report["summary"]), report
