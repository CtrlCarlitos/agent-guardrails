"""Windows + Antigravity (agy) host adapter for the platform acceptance harness (#92).

Exercises the complete Guardrail lifecycle in a disposable isolated Windows
profile (USERPROFILE, APPDATA, LOCALAPPDATA, ANTIGRAVITY_APP_DATA_DIR):
  1. install                  (install.ps1 local staged release + checksum verification, User PATH restored)
  2. enrollment               (ADR-0033 prompt posture check)
  3. enrollment_webauthn      (explicitly operator_assisted; never simulated)
  4. enablement               (guardrail.exe setup --planes antigravity)
  5. host_hook_trust          (hooks.json owned entries + doctor + selftest)
  6. declarative_floor        (explicitly unsupported per ADR-0008)
  7. harmless_deny            (installed hook pre deny on fake .env for view_file + read_file)
  8. live_runtime_mediation   (skipped unless --live; real Windows agy -p in isolated profile)
  9. approval_retry           (P6 deny -> force_ask ticket -> host-ask grant -> allow -> replay refused)
 10. update                   (install.ps1 upgrade v1 -> v2 + doctor + selftest, User PATH restored)
 11. disablement              (ADR-0033 host-ask ticket plane disable + user config preserved + replay refused)
 12. recovery                 (corrupt hooks.json -> ADR-0033 host-ask recover -> backup + restored)
 13. cleanup_isolation        (real-home + HKCU User PATH untouched + disposable root removed)
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
import time
from typing import Any, Mapping, Optional

import harness
import linux_antigravity


V1_TAG = linux_antigravity.V1_TAG
V2_TAG = linux_antigravity.V2_TAG
REPO_ROOT = Path(__file__).resolve().parents[2]
PROBE_HOST = linux_antigravity.PROBE_HOST

_WINDOWS_PASSTHROUGH_KEYS: tuple[str, ...] = (
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "OS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "NUMBER_OF_PROCESSORS",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMDATA",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "SYSTEMDRIVE",
    "PSMODULEPATH",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
)


def build_windows_isolated_env(
    *,
    iso_home: Path,
    iso_bin: Path,
    iso_appdata: Path,
    iso_localappdata: Path,
    app_data: Path,
    base_env: Optional[Mapping[str, str]] = None,
) -> dict[str, str]:
    """Build an isolated Windows process environment with XDG overrides stripped."""
    src = dict(os.environ if base_env is None else base_env)
    # Match case-insensitively on Windows env dictionaries.
    upper_map = {k.upper(): v for k, v in src.items()}
    base_path = upper_map.get("PATH", "")

    home_str = str(iso_home)
    drive, rest = os.path.splitdrive(home_str)

    env: dict[str, str] = {
        "USERPROFILE": home_str,
        "HOME": home_str,
        "HOMEDRIVE": drive or "C:",
        "HOMEPATH": rest or "\\",
        "APPDATA": str(iso_appdata),
        "LOCALAPPDATA": str(iso_localappdata),
        "ANTIGRAVITY_APP_DATA_DIR": str(app_data),
        "PATH": f"{iso_bin}{os.pathsep}{base_path}" if base_path else str(iso_bin),
    }
    for key in _WINDOWS_PASSTHROUGH_KEYS:
        if key in upper_map and key not in env:
            env[key] = upper_map[key]
    return env


def build_windows_path_replacements(
    *,
    workspace: str | Path,
    iso_home: str | Path,
    temp_root: str | Path,
    real_home: str | Path,
) -> dict[str, str]:
    """Return path replacement pairs covering both Windows backslash and slash spellings."""
    pairs = (
        (str(workspace), "<WORKSPACE>"),
        (str(iso_home), "<ISOLATED_HOME>"),
        (str(temp_root), "<TEMP_ROOT>"),
        (str(real_home), "<REAL_HOME>"),
    )
    out: dict[str, str] = {}
    for raw, token in pairs:
        if not raw:
            continue
        variants = {
            raw,
            raw.replace("\\", "/"),
            raw.replace("/", "\\"),
        }
        # Include lowercased drive letter variants (git/pathutil on Windows).
        for v in list(variants):
            if len(v) >= 2 and v[1] == ":":
                variants.add(v[0].lower() + v[1:])
                variants.add(v[0].upper() + v[1:])
        for v in variants:
            out[v] = token
    return out


def hook_command_matches_binary(pre_cmd: str, installed_bin: str | Path) -> bool:
    """Report whether an Antigravity hook command references installed_bin across case/slashes."""
    norm_cmd = pre_cmd.replace("\\", "/").lower()
    norm_bin = str(installed_bin).replace("\\", "/").lower()
    return bool(norm_bin) and norm_bin in norm_cmd


def _capture_user_path_registry() -> tuple[bool, str, int]:
    """Snapshot HKCU\\Environment\\Path (exists, raw value, reg type) on Windows."""
    import winreg  # noqa: PLC0415

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ) as key:
        try:
            val, reg_type = winreg.QueryValueEx(key, "Path")
            return True, str(val), int(reg_type)
        except FileNotFoundError:
            return False, "", winreg.REG_EXPAND_SZ


def elevated_shell() -> bool:
    """Report whether this process is elevated; never true off Windows.

    Elevated, install.ps1 adds a Microsoft Defender exclusion for the binary it
    installs, and the disposable binary's exclusion would outlive the run (#678).
    """
    if sys.platform != "win32":
        return False
    import ctypes  # noqa: PLC0415

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def _restore_user_path_registry(snapshot: tuple[bool, str, int]) -> None:
    """Restore HKCU\\Environment\\Path to its pre-run snapshot and tell running programs.

    install.ps1 broadcasts its Path change, so Explorer and other listeners
    hold the disposable directory until the restore is broadcast too (#678).
    An unchanged value is left alone and nothing is broadcast.
    """
    import ctypes  # noqa: PLC0415

    if _capture_user_path_registry() == snapshot:
        return
    _write_user_path_registry(snapshot)
    hwnd_broadcast, wm_settingchange, smto_abortifhung = 0xFFFF, 0x001A, 0x0002
    ctypes.windll.user32.SendMessageTimeoutW(
        hwnd_broadcast, wm_settingchange, 0, "Environment", smto_abortifhung, 5000,
        ctypes.byref(ctypes.c_size_t()),
    )


def _write_user_path_registry(snapshot: tuple[bool, str, int]) -> None:
    import winreg  # noqa: PLC0415

    existed, val, reg_type = snapshot
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_SET_VALUE) as key:
        if existed:
            winreg.SetValueEx(key, "Path", 0, reg_type, val)
        else:
            try:
                winreg.DeleteValue(key, "Path")
            except FileNotFoundError:
                pass


def _find_powershell() -> Optional[str]:
    return shutil.which("pwsh") or shutil.which("powershell")


def _mint_and_run_host_ask_action(
    *,
    installed_bin: Path,
    command_str: str,
    cli_args: list[str],
    session_id: str,
    workspace: Path,
    env: Mapping[str, str],
) -> tuple[str, harness.CommandResult]:
    """Mint a prompt-mode ADR-0033 host-ask ticket via Antigravity pre-hook, then execute the CLI."""
    payload = json.dumps(
        {
            "conversationId": session_id,
            "workspacePaths": [str(workspace)],
            "toolCall": {
                "name": "run_command",
                "args": {"CommandLine": command_str, "Cwd": str(workspace)},
            },
        }
    )
    hook_res = harness.run_cmd(
        [str(installed_bin), "hook", "antigravity", "pre"],
        env=env,
        cwd=workspace,
        stdin_text=payload,
    )
    hook_decision = linux_antigravity._parse_decision(hook_res.stdout)
    cli_res = harness.run_cmd(
        [str(installed_bin), *cli_args],
        env=env,
        cwd=workspace,
    )
    return hook_decision, cli_res


def _rmtree_with_retry(target: Path, attempts: int = 3) -> bool:
    for i in range(attempts):
        try:
            shutil.rmtree(target)
            return not target.exists()
        except OSError:
            if i + 1 < attempts:
                time.sleep(0.5)
    return not target.exists()


def run_windows_antigravity_acceptance(
    *,
    live: bool = False,
    live_auth_from: Optional[Path] = None,
    v1_binary: Optional[Path] = None,
    v2_binary: Optional[Path] = None,
    keep_artifacts: bool = False,
) -> tuple[int, Optional[dict[str, Any]]]:
    """Execute the Windows Antigravity lifecycle acceptance suite."""
    if sys.platform != "win32":
        print("SKIP: windows_antigravity acceptance harness requires Windows", file=sys.stderr)
        return harness.EXIT_SKIP_PREREQ, None

    install_ps1 = REPO_ROOT / "install.ps1"
    if not install_ps1.is_file():
        print(f"SKIP: install.ps1 not found at {install_ps1}", file=sys.stderr)
        return harness.EXIT_SKIP_PREREQ, None

    ps_exe = _find_powershell()
    if ps_exe is None:
        print("SKIP: pwsh or powershell is required on PATH for the Windows Antigravity harness", file=sys.stderr)
        return harness.EXIT_SKIP_PREREQ, None

    agy_bin = shutil.which("agy")
    if agy_bin is None:
        print("SKIP: agy is required on PATH for the Windows Antigravity harness", file=sys.stderr)
        return harness.EXIT_SKIP_PREREQ, None

    if elevated_shell():
        print(
            "SKIP: run from a non-elevated shell: elevated, install.ps1 adds a Microsoft Defender "
            "exclusion for the disposable binary",
            file=sys.stderr,
        )
        return harness.EXIT_SKIP_PREREQ, None

    if (v1_binary is None or v2_binary is None) and shutil.which("go") is None:
        print("SKIP: go is required when --v1-binary/--v2-binary are not supplied", file=sys.stderr)
        return harness.EXIT_SKIP_PREREQ, None

    arch = harness.normalized_arch()
    agy_version = linux_antigravity._detect_agy_version(agy_bin)
    real_home = Path.home().resolve()
    isolation_guard = harness.IsolationGuard.capture(real_home)
    user_path_before = _capture_user_path_registry()

    temp_root = Path(tempfile.mkdtemp(prefix="guardrail-accept-win-agy-")).resolve()
    iso_home = temp_root / "home"
    iso_bin = temp_root / "bin"
    iso_appdata = iso_home / "AppData" / "Roaming"
    iso_localappdata = iso_home / "AppData" / "Local"
    app_data = temp_root / "agy_app_data"
    workspace = temp_root / "workspace"
    releases = temp_root / "releases"
    build_dir = temp_root / "build"

    for d in (iso_home, iso_bin, iso_appdata, iso_localappdata, app_data, workspace, releases, build_dir):
        d.mkdir(parents=True, exist_ok=True)

    env = build_windows_isolated_env(
        iso_home=iso_home,
        iso_bin=iso_bin,
        iso_appdata=iso_appdata,
        iso_localappdata=iso_localappdata,
        app_data=app_data,
    )
    installed_bin = iso_bin / "guardrail.exe"
    hooks_path = iso_home / ".gemini" / "config" / "hooks.json"
    audit_path = iso_localappdata / "guardrail" / "audit.jsonl"
    operator_path = iso_appdata / "guardrail" / "waivers.toml"

    sentinel = f"FAKE_ACCEPTANCE_SENTINEL_{secrets.token_hex(8)}"
    synthetic_session = f"accept-synthetic-{secrets.token_hex(6)}"
    path_replacements = build_windows_path_replacements(
        workspace=workspace,
        iso_home=iso_home,
        temp_root=temp_root,
        real_home=real_home,
    )

    try:
        # Initialize disposable workspace with harmless fake fixtures only.
        (workspace / ".env").write_text(f"FAKE_SECRET={sentinel}\n", encoding="utf-8", newline="\n")
        (workspace / "hello.txt").write_text("acceptance-ok\n", encoding="utf-8", newline="\n")
        git_init = harness.run_cmd(["git", "init", "-q", str(workspace)], env=env)
        if git_init.returncode != 0:
            if not keep_artifacts:
                _rmtree_with_retry(temp_root)
            print(f"FAIL: git init failed: {git_init.stderr}", file=sys.stderr)
            return harness.EXIT_FAIL, None

        # Stage local v1 and v2 Windows releases for offline install & update verification.
        try:
            v1_src = v1_binary.resolve() if v1_binary else (build_dir / f"guardrail-{V1_TAG}.exe")
            v2_src = v2_binary.resolve() if v2_binary else (build_dir / f"guardrail-{V2_TAG}.exe")
            if v1_binary is None:
                linux_antigravity._build_guardrail_binary(v1_src, V1_TAG)
            if v2_binary is None:
                linux_antigravity._build_guardrail_binary(v2_src, V2_TAG)
            harness.stage_local_release(
                releases_root=releases,
                version=V1_TAG,
                binary_path=v1_src,
                os_name="windows",
                arch=arch,
            )
            harness.stage_local_release(
                releases_root=releases,
                version=V2_TAG,
                binary_path=v2_src,
                os_name="windows",
                arch=arch,
            )
        except Exception as exc:
            if not keep_artifacts:
                _rmtree_with_retry(temp_root)
            print(f"FAIL: release staging failed: {exc}", file=sys.stderr)
            return harness.EXIT_FAIL, None

        stages: list[harness.StageResult] = []
        live_session_observed = False

        # 1. Install via install.ps1 (restoring HKCU\Environment\Path immediately after)
        def stage_install() -> harness.StageResult:
            try:
                res = harness.run_cmd(
                    [
                        ps_exe,
                        "-NoProfile",
                        "-File",
                        str(install_ps1),
                        "-Version",
                        V1_TAG,
                        "-Dest",
                        str(iso_bin),
                        "-BaseUrl",
                        str(releases),
                        "-NoSetup",
                    ],
                    env=env,
                    cwd=workspace,
                    timeout=90,
                )
            finally:
                _restore_user_path_registry(user_path_before)

            ver = harness.run_cmd([str(installed_bin), "version"], env=env, cwd=workspace)
            ok = (
                res.returncode == 0
                and installed_bin.is_file()
                and ver.returncode == 0
                and ver.stdout.strip() == f"guardrail {V1_TAG}"
            )
            return harness.StageResult(
                name="install",
                status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
                expected=f"install.ps1 installs checksum-verified {V1_TAG} guardrail.exe",
                observed=f"installed {ver.stdout.strip()!r} (install rc={res.returncode})",
                details={
                    "install_rc": res.returncode,
                    "version": ver.stdout.strip(),
                    "stderr_excerpt": harness.sanitize_text(
                        res.stderr.strip()[:300], path_replacements=path_replacements
                    ),
                },
            )

        stages.append(harness.run_stage("install", stage_install))

        # 2. Enrollment posture (ADR-0033 default prompt mode) + explicit WebAuthn operator-assisted stage
        def stage_enrollment() -> harness.StageResult:
            res = harness.run_cmd([str(installed_bin), "doctor"], env=env, cwd=workspace)
            combined = res.stdout + "\n" + res.stderr
            has_prompt = "prompt" in combined.lower()
            return harness.StageResult(
                name="enrollment",
                status=harness.StageStatus.PASS if has_prompt else harness.StageStatus.FAIL,
                expected="fresh install defaults to prompt approval mode (ADR-0033) without fabricated passkey",
                observed=(
                    "doctor reports prompt approval mode"
                    if has_prompt
                    else f"prompt mode not observed in doctor output (rc={res.returncode})"
                ),
                details={"doctor_rc": res.returncode, "approval_mode": "prompt" if has_prompt else "unknown"},
            )

        stages.append(harness.run_stage("enrollment", stage_enrollment))
        stages.append(
            harness.StageResult(
                name="enrollment_webauthn",
                status=harness.StageStatus.OPERATOR_ASSISTED,
                expected="WebAuthn/passkey enrollment requires real operator user verification",
                observed="not simulated; operator must run `guardrail operator enroll` in a real browser/authenticator session",
                details={"simulated": False},
            )
        )

        # 3. Enablement
        def stage_enablement() -> harness.StageResult:
            res = harness.run_cmd(
                [str(installed_bin), "setup", "--planes", "antigravity"],
                env=env,
                cwd=workspace,
                timeout=90,
            )
            hooks_ok = False
            pre_cmd = ""
            if hooks_path.is_file():
                try:
                    doc = json.loads(hooks_path.read_text(encoding="utf-8"))
                    g = doc.get("guardrail", {})
                    pre_groups = g.get("PreToolUse", [])
                    if g.get("enabled") is True and pre_groups:
                        pre_cmd = pre_groups[0]["hooks"][0]["command"]
                        hooks_ok = hook_command_matches_binary(pre_cmd, installed_bin)
                except Exception:
                    hooks_ok = False
            ok = res.returncode == 0 and hooks_ok
            return harness.StageResult(
                name="enablement",
                status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
                expected="guardrail setup --planes antigravity arms isolated hooks.json pointing to isolated guardrail.exe",
                observed=(
                    f"setup rc={res.returncode}; hooks.json enabled={hooks_ok}"
                    if ok
                    else f"setup rc={res.returncode}; hooks_ok={hooks_ok}; stderr={harness.sanitize_text(res.stderr.strip()[:300], path_replacements=path_replacements)}"
                ),
                details={
                    "setup_rc": res.returncode,
                    "hooks_registered": hooks_ok,
                    "pre_command": harness.sanitize_text(pre_cmd, path_replacements=path_replacements),
                },
            )

        stages.append(harness.run_stage("enablement", stage_enablement))

        # 4. Host hook trust + selftest + explicit unsupported declarative floor (ADR-0008)
        def stage_host_hook_trust() -> harness.StageResult:
            doc_res = harness.run_cmd([str(installed_bin), "doctor"], env=env, cwd=workspace)
            self_res = harness.run_cmd([str(installed_bin), "selftest"], env=env, cwd=workspace, timeout=90)
            hooks_valid = False
            owned_ids: list[str] = []
            if hooks_path.is_file():
                doc = json.loads(hooks_path.read_text(encoding="utf-8"))
                g = doc.get("guardrail", {})
                for phase in ("PreToolUse", "PostToolUse"):
                    for entry in g.get(phase, []):
                        if isinstance(entry, dict) and entry.get("id"):
                            owned_ids.append(str(entry["id"]))
                hooks_valid = (
                    g.get("enabled") is True
                    and "guardrail-antigravity-pre" in owned_ids
                    and "guardrail-antigravity-post" in owned_ids
                )
            registered_line = "antigravity settings: guardrail integration registered" in doc_res.stdout
            selftest_ok = self_res.returncode == 0 and "antigravity: probes pass" in self_res.stdout
            ok = hooks_valid and registered_line and selftest_ok
            return harness.StageResult(
                name="host_hook_trust",
                status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
                expected="hooks.json holds owned enabled entries, doctor reports registered, selftest passes",
                observed=(
                    f"hooks_valid={hooks_valid}, doctor_registered={registered_line}, selftest_rc={self_res.returncode}"
                ),
                details={
                    "owned_ids": owned_ids,
                    "doctor_rc": doc_res.returncode,
                    "selftest_rc": self_res.returncode,
                    "trust_surface": "hooks.json enabled flag (Antigravity has no separate trust store)",
                },
            )

        stages.append(harness.run_stage("host_hook_trust", stage_host_hook_trust))
        stages.append(
            harness.StageResult(
                name="declarative_floor",
                status=harness.StageStatus.UNSUPPORTED,
                expected="native declarative permission floor",
                observed="Antigravity has no declarative permission floor (ADR-0008)",
                details={"adr": "ADR-0008"},
            )
        )

        # 5. Harmless deny through installed hook binary (both view_file and agy 1.5.x read_file)
        def stage_harmless_deny() -> harness.StageResult:
            before_count = len(harness.read_audit_records(audit_path))
            probes = (
                ("view_file", {"AbsolutePath": str(workspace / ".env")}),
                ("read_file", {"Path": str(workspace / ".env")}),
            )
            decisions: dict[str, str] = {}
            rcs: dict[str, int] = {}
            for tool_name, tool_args in probes:
                payload = json.dumps(
                    {
                        "conversationId": synthetic_session,
                        "workspacePaths": [str(workspace)],
                        "toolCall": {"name": tool_name, "args": tool_args},
                    }
                )
                res = harness.run_cmd(
                    [str(installed_bin), "hook", "antigravity", "pre"],
                    env=env,
                    cwd=workspace,
                    stdin_text=payload,
                )
                rcs[tool_name] = res.returncode
                decisions[tool_name] = linux_antigravity._parse_decision(res.stdout)

            new_recs = harness.read_audit_records(audit_path)[before_count:]
            matching = [
                r
                for r in new_recs
                if r.get("session_id") == synthetic_session
                and r.get("decision") == "deny"
                and r.get("rule_id") == "P4.secret-path"
            ]
            env_intact = (workspace / ".env").read_text(encoding="utf-8") == f"FAKE_SECRET={sentinel}\n"
            ok = (
                all(rc == 0 for rc in rcs.values())
                and all(d == "deny" for d in decisions.values())
                and len(matching) >= 2
                and env_intact
            )
            return harness.StageResult(
                name="harmless_deny",
                status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
                expected="installed antigravity pre hook denies fake .env read via view_file and read_file with P4.secret-path",
                observed=f"rcs={rcs}, decisions={decisions}, matching_audit={len(matching)}, fixture_intact={env_intact}",
                details={"rcs": rcs, "decisions": decisions, "rule_id": "P4.secret-path"},
                evidence=[
                    harness.sanitize_audit_record(
                        r,
                        path_replacements=path_replacements,
                        extra_redactions=[sentinel],
                        provenance="synthetic",
                    )
                    for r in matching
                ],
            )

        stages.append(harness.run_stage("harmless_deny", stage_harmless_deny))

        # 6. Live runtime mediation (opt-in --live)
        if not live:
            stages.append(
                harness.StageResult(
                    name="live_runtime_mediation",
                    status=harness.StageStatus.SKIPPED,
                    expected="live Windows agy -p session dispatches tool calls to isolated guardrail hook",
                    observed="skipped (--live not set; run with --live to exercise real Windows agy runtime)",
                    details={"live_requested": False},
                )
            )
        else:
            def stage_live() -> harness.StageResult:
                nonlocal live_session_observed
                if live_auth_from is not None:
                    src_state = live_auth_from / "jetski_state.pbtxt"
                    if src_state.is_file():
                        dst_cli = iso_home / ".gemini" / "antigravity-cli"
                        dst_cli.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src_state, dst_cli / "jetski_state.pbtxt")
                before_count = len(harness.read_audit_records(audit_path))
                prompt = (
                    f"In {workspace}, try to read the file .env, then read hello.txt. "
                    "Report briefly whether .env was blocked or readable."
                )
                res = harness.run_cmd(
                    [
                        agy_bin,
                        "-p",
                        prompt,
                        "--disable-slash-commands",
                        "--output-format",
                        "json",
                        "--print-timeout",
                        "90s",
                    ],
                    env=env,
                    cwd=workspace,
                    timeout=110,
                )
                new_recs = harness.read_audit_records(audit_path)[before_count:]
                result, observed = linux_antigravity.evaluate_live_mediation(
                    returncode=res.returncode,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    audit_records=new_recs,
                    sentinel=sentinel,
                    path_replacements=path_replacements,
                )
                live_session_observed = observed
                return result

            stages.append(harness.run_stage("live_runtime_mediation", stage_live))

        # 7. Approval and retry (ADR-0033 prompt-mode host-ask ticket + egress retry + one-shot replay refusal)
        def stage_approval_retry() -> harness.StageResult:
            before_count = len(harness.read_audit_records(audit_path))
            curl_payload = json.dumps(
                {
                    "conversationId": synthetic_session,
                    "workspacePaths": [str(workspace)],
                    "toolCall": {
                        "name": "run_command",
                        "args": {"CommandLine": f"curl https://{PROBE_HOST}", "Cwd": str(workspace)},
                    },
                }
            )
            step_deny = harness.run_cmd(
                [str(installed_bin), "hook", "antigravity", "pre"],
                env=env,
                cwd=workspace,
                stdin_text=curl_payload,
            )
            d1 = linux_antigravity._parse_decision(step_deny.stdout)

            def fetch_refused() -> bool:
                return linux_antigravity.fetch_refused_as_unapproved(
                    harness.run_cmd(
                        [str(installed_bin), "fetch", f"https://{PROBE_HOST}"],
                        env=env,
                        cwd=workspace,
                    )
                )

            fetch_refused_before = fetch_refused()

            grant_cmd = f"guardrail egress grant --scope repo --host {PROBE_HOST}"
            d2, step_grant = _mint_and_run_host_ask_action(
                installed_bin=installed_bin,
                command_str=grant_cmd,
                cli_args=["egress", "grant", "--scope", "repo", "--host", PROBE_HOST],
                session_id=synthetic_session,
                workspace=workspace,
                env=env,
            )

            fetch_refused_after = fetch_refused()
            overlay_path = workspace / "guardrail.toml"
            overlay_has_host = overlay_path.is_file() and PROBE_HOST in overlay_path.read_text(encoding="utf-8")
            operator_has_host = operator_path.is_file() and PROBE_HOST in operator_path.read_text(encoding="utf-8")

            step_replay = harness.run_cmd(
                [str(installed_bin), "egress", "grant", "--scope", "repo", "--host", PROBE_HOST],
                env=env,
                cwd=workspace,
            )

            new_recs = harness.read_audit_records(audit_path)[before_count:]
            host_ask_recs = [r for r in new_recs if r.get("transport") == "host-ask"]
            ok = (
                d1 == "deny"
                and d2 == "force_ask"
                and step_grant.returncode == 0
                and overlay_has_host
                and operator_has_host
                and fetch_refused_before
                and not fetch_refused_after
                and step_replay.returncode == 2
                and len(host_ask_recs) >= 1
            )
            return harness.StageResult(
                name="approval_retry",
                status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
                expected="P6 deny + fetch refused as unapproved -> force_ask ticket -> host-ask grant persists overlay+operator -> fetch no longer refused -> replay refused",
                observed=(
                    f"initial={d1!r}, grant_hook={d2!r}, grant_cli_rc={step_grant.returncode}, "
                    f"overlay_persisted={overlay_has_host}, operator_persisted={operator_has_host}, "
                    f"fetch_refused_before={fetch_refused_before}, fetch_refused_after={fetch_refused_after}, "
                    f"replay_rc={step_replay.returncode}, host_ask_audit={len(host_ask_recs)}"
                ),
                details={
                    "initial_decision": d1,
                    "grant_hook_decision": d2,
                    "grant_cli_rc": step_grant.returncode,
                    "overlay_persisted": overlay_has_host,
                    "operator_persisted": operator_has_host,
                    "fetch_refused_before": fetch_refused_before,
                    "fetch_refused_after": fetch_refused_after,
                    "replay_rc": step_replay.returncode,
                    "transport": "host-ask",
                },
                evidence=[
                    harness.sanitize_audit_record(
                        r,
                        path_replacements=path_replacements,
                        extra_redactions=[sentinel],
                        provenance="operator_lifecycle",
                    )
                    for r in new_recs
                ],
            )

        stages.append(harness.run_stage("approval_retry", stage_approval_retry))

        # 8. Update (v1 -> v2 via local staged install.ps1 + doctor + selftest)
        def stage_update() -> harness.StageResult:
            try:
                res = harness.run_cmd(
                    [
                        ps_exe,
                        "-NoProfile",
                        "-File",
                        str(install_ps1),
                        "-Version",
                        V2_TAG,
                        "-Dest",
                        str(iso_bin),
                        "-BaseUrl",
                        str(releases),
                        "-NoSetup",
                    ],
                    env=env,
                    cwd=workspace,
                    timeout=90,
                )
            finally:
                _restore_user_path_registry(user_path_before)

            ver = harness.run_cmd([str(installed_bin), "version"], env=env, cwd=workspace)
            doc_res = harness.run_cmd([str(installed_bin), "doctor"], env=env, cwd=workspace)
            self_res = harness.run_cmd([str(installed_bin), "selftest"], env=env, cwd=workspace, timeout=90)
            ok = (
                res.returncode == 0
                and ver.stdout.strip() == f"guardrail {V2_TAG}"
                and "antigravity settings: guardrail integration registered" in doc_res.stdout
                and self_res.returncode == 0
            )
            return harness.StageResult(
                name="update",
                status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
                expected=f"install.ps1 updates {V1_TAG} -> {V2_TAG} and post-update doctor/selftest stay green",
                observed=(
                    f"update_rc={res.returncode}, version={ver.stdout.strip()!r}, "
                    f"doctor_rc={doc_res.returncode}, selftest_rc={self_res.returncode}"
                ),
                details={
                    "from_version": V1_TAG,
                    "to_version": ver.stdout.strip(),
                    "update_rc": res.returncode,
                    "doctor_rc": doc_res.returncode,
                    "selftest_rc": self_res.returncode,
                },
            )

        stages.append(harness.run_stage("update", stage_update))

        # 9. Disablement via ADR-0033 host-ask approval ticket + user config preservation + replay refusal
        def stage_disablement() -> harness.StageResult:
            if hooks_path.is_file():
                doc = json.loads(hooks_path.read_text(encoding="utf-8"))
                doc["user_sentinel"] = {"preserved": True}
                hooks_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")

            hook_decision, cli_res = _mint_and_run_host_ask_action(
                installed_bin=installed_bin,
                command_str="guardrail plane disable antigravity",
                cli_args=["plane", "disable", "antigravity"],
                session_id=synthetic_session,
                workspace=workspace,
                env=env,
            )
            sentinel_ok = False
            disabled_ok = False
            if hooks_path.is_file():
                after = json.loads(hooks_path.read_text(encoding="utf-8"))
                sentinel_ok = after.get("user_sentinel") == {"preserved": True}
                g = after.get("guardrail")
                disabled_ok = g is None or (isinstance(g, dict) and not g.get("PreToolUse"))
            doc_res = harness.run_cmd([str(installed_bin), "doctor"], env=env, cwd=workspace)
            not_registered = "antigravity settings: guardrail integration registered" not in doc_res.stdout
            replay_res = harness.run_cmd(
                [str(installed_bin), "plane", "disable", "antigravity"],
                env=env,
                cwd=workspace,
            )
            ok = (
                hook_decision == "force_ask"
                and cli_res.returncode == 0
                and sentinel_ok
                and disabled_ok
                and not_registered
                and replay_res.returncode == 3
            )
            return harness.StageResult(
                name="disablement",
                status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
                expected="host-ask ticket plane disable removes guardrail hooks, preserves user config, and refuses replay",
                observed=(
                    f"hook={hook_decision!r}, cli_rc={cli_res.returncode}, user_sentinel_preserved={sentinel_ok}, "
                    f"guardrail_removed={disabled_ok}, doctor_unregistered={not_registered}, replay_rc={replay_res.returncode}"
                ),
                details={
                    "hook_decision": hook_decision,
                    "cli_rc": cli_res.returncode,
                    "user_sentinel_preserved": sentinel_ok,
                    "guardrail_removed": disabled_ok,
                    "replay_rc": replay_res.returncode,
                    "transport": "host-ask (ADR-0033 ticket)",
                },
            )

        stages.append(harness.run_stage("disablement", stage_disablement))

        # 10. Recovery via ADR-0033 host-ask approval ticket (corrupt hooks.json -> backup + repair)
        def stage_recovery() -> harness.StageResult:
            corrupt_body = "{not valid json — acceptance recovery fixture\n"
            hooks_path.parent.mkdir(parents=True, exist_ok=True)
            hooks_path.write_text(corrupt_body, encoding="utf-8", newline="\n")

            hook_decision, cli_res = _mint_and_run_host_ask_action(
                installed_bin=installed_bin,
                command_str="guardrail recover antigravity-hooks",
                cli_args=["recover", "antigravity-hooks"],
                session_id=synthetic_session,
                workspace=workspace,
                env=env,
            )
            backups = sorted(hooks_path.parent.glob("hooks.json.guardrail-recover-*"))
            backup_matches = any(
                b.read_text(encoding="utf-8", errors="replace") == corrupt_body for b in backups
            )
            repaired_valid = False
            if hooks_path.is_file():
                try:
                    repaired = json.loads(hooks_path.read_text(encoding="utf-8"))
                    repaired_valid = repaired.get("guardrail", {}).get("enabled") is True
                except json.JSONDecodeError:
                    repaired_valid = False
            doc_res = harness.run_cmd([str(installed_bin), "doctor"], env=env, cwd=workspace)
            self_res = harness.run_cmd([str(installed_bin), "selftest"], env=env, cwd=workspace, timeout=90)
            ok = (
                hook_decision == "force_ask"
                and cli_res.returncode == 0
                and backup_matches
                and repaired_valid
                and "antigravity settings: guardrail integration registered" in doc_res.stdout
                and self_res.returncode == 0
            )
            return harness.StageResult(
                name="recovery",
                status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
                expected="host-ask recover antigravity-hooks backs up corrupt hooks.json and restores valid registration",
                observed=(
                    f"hook={hook_decision!r}, cli_rc={cli_res.returncode}, backups={len(backups)}, "
                    f"backup_matches={backup_matches}, repaired_valid={repaired_valid}, selftest_rc={self_res.returncode}"
                ),
                details={
                    "hook_decision": hook_decision,
                    "cli_rc": cli_res.returncode,
                    "backup_count": len(backups),
                    "backup_matches": backup_matches,
                    "repaired_valid": repaired_valid,
                    "selftest_rc": self_res.returncode,
                    "transport": "host-ask (ADR-0033 ticket)",
                },
            )

        stages.append(harness.run_stage("recovery", stage_recovery))

        # Collect sanitized audit records before tearing down temp_root.
        all_raw_audit = harness.read_audit_records(audit_path)
        sanitized_audit = [
            harness.sanitize_audit_record(
                rec,
                path_replacements=path_replacements,
                extra_redactions=[sentinel],
                provenance=linux_antigravity._classify_provenance(rec),
            )
            for rec in all_raw_audit
        ]

        # 11. Cleanup and isolation verification
        def stage_cleanup_isolation() -> harness.StageResult:
            _restore_user_path_registry(user_path_before)
            user_path_after = _capture_user_path_registry()
            user_path_clean = user_path_after == user_path_before
            real_home_clean, diffs = isolation_guard.verify_unchanged()
            if not keep_artifacts:
                cleaned = _rmtree_with_retry(temp_root)
            else:
                cleaned = True
            ok = real_home_clean and user_path_clean and cleaned and len(all_raw_audit) > 0
            return harness.StageResult(
                name="cleanup_isolation",
                status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
                expected="real user home and HKCU User PATH untouched, audit isolated in temp root, temp root cleaned up",
                observed=(
                    f"real_home_unchanged={real_home_clean}, user_path_unchanged={user_path_clean}, "
                    f"temp_cleaned={cleaned} (keep={keep_artifacts}), isolated_audit_records={len(all_raw_audit)}"
                ),
                details={
                    "real_home_unchanged": real_home_clean,
                    "real_home_diffs": diffs,
                    "user_path_unchanged": user_path_clean,
                    "keep_artifacts": keep_artifacts,
                    "artifacts_dir": str(temp_root) if keep_artifacts else "<removed>",
                    "isolated_audit_records": len(all_raw_audit),
                },
            )

        stages.append(harness.run_stage("cleanup_isolation", stage_cleanup_isolation))

        report = harness.build_report(
            plane="antigravity",
            os_name="windows",
            arch=arch,
            environment={
                "guardrail_v1": V1_TAG,
                "guardrail_v2": V2_TAG,
                "host_binary": "agy",
                "host_version": agy_version,
                "os": f"{platform.system()} {platform.release()}",
                "shell": Path(ps_exe).name,
                "live_mode": live,
                "approval_mode": "prompt",
            },
            stages=stages,
            audit_evidence=sanitized_audit,
            live_runtime_session_observed=live_session_observed,
        )
        return harness.report_exit_code(report["summary"]), report
    finally:
        _restore_user_path_registry(user_path_before)
