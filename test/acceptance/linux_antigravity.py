"""Linux + Antigravity (agy) host adapter for the platform acceptance harness (#92).

Exercises the complete Guardrail lifecycle in a disposable isolated HOME:
  1. install                  (install.sh local staged release + checksum verification)
  2. enrollment               (ADR-0033 prompt posture check)
  3. enrollment_webauthn      (explicitly operator_assisted; never simulated)
  4. enablement               (guardrail setup --planes antigravity)
  5. host_hook_trust          (hooks.json owned entries + doctor + selftest)
  6. declarative_floor        (explicitly unsupported per ADR-0008)
  7. harmless_deny            (installed binary hook pre deny on fake .env)
  8. live_runtime_mediation   (skipped unless --live; real agy -p in isolated home)
  9. approval_retry           (P6 deny -> force_ask ticket -> host-ask grant -> allow -> replay refused)
 10. update                   (install.sh upgrade v1 -> v2 + doctor + selftest)
 11. disablement              (real PTY plane disable + user config preserved)
 12. recovery                 (corrupt hooks.json -> real PTY recover antigravity-hooks -> backup + restored)
 13. cleanup_isolation        (real-home untouched + disposable root removed)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import stat
import sys
import tempfile
from typing import Any, Mapping, Optional, Sequence

import harness


V1_TAG = "v0.0.1-accept"
V2_TAG = "v0.0.2-accept"
REPO_ROOT = Path(__file__).resolve().parents[2]
PROBE_HOST = "accept-probe.invalid"


def _is_auth_error(output: str) -> bool:
    lower = output.lower()
    needles = (
        "not logged in",
        "not authenticated",
        "authentication required",
        "please authenticate",
        "login required",
        "unauthenticated",
        "missing credentials",
        "no credentials",
        "agy login",
        "sign in",
    )
    return any(n in lower for n in needles)


def evaluate_live_mediation(
    *,
    returncode: int,
    stdout: str,
    stderr: str,
    audit_records: Sequence[Mapping[str, Any]],
    sentinel: str,
    path_replacements: Mapping[str, str],
) -> tuple[harness.StageResult, bool]:
    """Evaluate a live agy -p run's output and isolated audit evidence."""
    combined = f"{stdout}\n{stderr}"
    if sentinel and sentinel in combined:
        return (
            harness.StageResult(
                name="live_runtime_mediation",
                status=harness.StageStatus.FAIL,
                expected="fake .env sentinel never appears in agy output and deny is recorded",
                observed="fake .env sentinel leaked into agy output",
                details={"returncode": returncode},
            ),
            False,
        )

    eligible: list[Mapping[str, Any]] = []
    for rec in audit_records:
        if rec.get("plane") != "antigravity":
            continue
        if rec.get("audit_kind") == "selftest":
            continue
        sid = str(rec.get("session_id") or "").strip()
        if not sid or sid.startswith("accept-synthetic-") or sid.startswith("selftest"):
            continue
        eligible.append(rec)

    sanitized = [
        harness.sanitize_audit_record(
            rec,
            path_replacements=path_replacements,
            extra_redactions=[sentinel] if sentinel else None,
            provenance="live_session",
        )
        for rec in eligible
    ]

    if not eligible and returncode != 0 and _is_auth_error(combined):
        return (
            harness.StageResult(
                name="live_runtime_mediation",
                status=harness.StageStatus.OPERATOR_ASSISTED,
                expected="authenticated isolated agy session dispatches tool calls to guardrail",
                observed=(
                    "agy reported missing authentication in isolated HOME; "
                    "pass --live-auth-from <disposable-auth-dir> or authenticate a disposable home"
                ),
                details={
                    "returncode": returncode,
                    "stderr_excerpt": harness.sanitize_text(
                        stderr.strip()[:400],
                        path_replacements=path_replacements,
                        extra_redactions=[sentinel] if sentinel else None,
                    ),
                },
            ),
            False,
        )

    denies_or_asks = [
        rec for rec in eligible if rec.get("decision") in ("deny", "ask")
    ]
    if not eligible:
        return (
            harness.StageResult(
                name="live_runtime_mediation",
                status=harness.StageStatus.FAIL,
                expected="at least one non-synthetic plane=antigravity audit record tied to a real session",
                observed=f"0 eligible plane=antigravity audit records observed (agy exit {returncode})",
                details={
                    "returncode": returncode,
                    "stderr_excerpt": harness.sanitize_text(
                        stderr.strip()[:400],
                        path_replacements=path_replacements,
                        extra_redactions=[sentinel] if sentinel else None,
                    ),
                },
            ),
            False,
        )

    if not denies_or_asks:
        return (
            harness.StageResult(
                name="live_runtime_mediation",
                status=harness.StageStatus.FAIL,
                expected="at least one deny or ask verdict from live agy session",
                observed=f"{len(eligible)} live record(s) observed, but 0 deny/ask verdicts",
                details={"returncode": returncode, "eligible_count": len(eligible)},
                evidence=sanitized,
            ),
            True,
        )

    sessions = sorted({str(r.get("session_id")) for r in eligible})
    rules = sorted({str(r.get("rule_id")) for r in denies_or_asks if r.get("rule_id")})
    return (
        harness.StageResult(
            name="live_runtime_mediation",
            status=harness.StageStatus.PASS,
            expected="real agy session triggers guardrail hook deny on fake .env with zero secret leak",
            observed=(
                f"{len(eligible)} live plane=antigravity record(s) across session(s) {sessions}; "
                f"{len(denies_or_asks)} deny/ask verdict(s) ({', '.join(rules) or 'recorded'}); sentinel absent from output"
            ),
            details={
                "returncode": returncode,
                "sessions": sessions,
                "eligible_count": len(eligible),
                "guarded_count": len(denies_or_asks),
                "rules": rules,
            },
            evidence=sanitized,
        ),
        True,
    )


def fetch_refused_as_unapproved(result: harness.CommandResult) -> bool:
    """Report whether `guardrail fetch` refused its host for lacking a grant.

    The pre-hook allows the fetch command for any host (#678), so a hook
    verdict says nothing about the grant. The fetch command itself is what the
    grant unblocks. The probe host is RFC 2606 `.invalid`, so a granted fetch
    still fails, at name resolution, with a different message.
    """
    return result.returncode != 0 and "unapproved host" in result.stderr


def _build_guardrail_binary(out_path: Path, version: str) -> None:
    res = harness.run_cmd(
        [
            "go",
            "build",
            "-ldflags",
            f"-X main.version={version}",
            "-o",
            str(out_path),
            "./cmd/guardrail",
        ],
        cwd=REPO_ROOT,
        timeout=180,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"go build ({version}) failed (exit {res.returncode}): {res.stderr.strip()}"
        )


def _detect_agy_version(agy_path: str) -> str:
    res = harness.run_cmd([agy_path, "--version"], timeout=10)
    if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip().splitlines()[0]
    return "unknown"


def _isolated_env(
    *,
    iso_home: Path,
    iso_bin: Path,
    xdg_config: Path,
    xdg_state: Path,
    xdg_data: Path,
    app_data: Path,
) -> dict[str, str]:
    base_path = os.environ.get("PATH", "/usr/bin:/bin")
    env: dict[str, str] = {
        "HOME": str(iso_home),
        "USER": os.environ.get("USER", "acceptance"),
        "LOGNAME": os.environ.get("LOGNAME", "acceptance"),
        "PATH": f"{iso_bin}{os.pathsep}{base_path}",
        "SHELL": os.environ.get("SHELL", "/bin/sh"),
        "TERM": os.environ.get("TERM", "xterm-256color"),
        "XDG_CONFIG_HOME": str(xdg_config),
        "XDG_STATE_HOME": str(xdg_state),
        "XDG_DATA_HOME": str(xdg_data),
        "ANTIGRAVITY_APP_DATA_DIR": str(app_data),
    }
    for passthrough in ("LANG", "LC_ALL", "TMPDIR", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        if passthrough in os.environ:
            env[passthrough] = os.environ[passthrough]
    return env


def run_linux_antigravity_acceptance(
    *,
    live: bool = False,
    live_auth_from: Optional[Path] = None,
    v1_binary: Optional[Path] = None,
    v2_binary: Optional[Path] = None,
    keep_artifacts: bool = False,
) -> tuple[int, Optional[dict[str, Any]]]:
    """Execute the Linux Antigravity lifecycle acceptance suite."""
    if not sys.platform.startswith("linux"):
        print("SKIP: linux_antigravity acceptance harness requires Linux", file=sys.stderr)
        return harness.EXIT_SKIP_PREREQ, None

    install_sh = REPO_ROOT / "install.sh"
    if not install_sh.is_file():
        print(f"SKIP: install.sh not found at {install_sh}", file=sys.stderr)
        return harness.EXIT_SKIP_PREREQ, None

    agy_bin = shutil.which("agy")
    if agy_bin is None:
        print("SKIP: agy is required on PATH for the Linux Antigravity harness", file=sys.stderr)
        return harness.EXIT_SKIP_PREREQ, None

    if (v1_binary is None or v2_binary is None) and shutil.which("go") is None:
        print("SKIP: go is required when --v1-binary/--v2-binary are not supplied", file=sys.stderr)
        return harness.EXIT_SKIP_PREREQ, None

    arch = harness.normalized_arch()
    agy_version = _detect_agy_version(agy_bin)
    real_home = Path.home().resolve()
    isolation_guard = harness.IsolationGuard.capture(real_home)

    temp_root = Path(tempfile.mkdtemp(prefix="guardrail-accept-linux-agy-")).resolve()
    iso_home = temp_root / "home"
    iso_bin = temp_root / "bin"
    xdg_config = temp_root / "xdg_config"
    xdg_state = temp_root / "xdg_state"
    xdg_data = temp_root / "xdg_data"
    app_data = temp_root / "app_data"
    workspace = temp_root / "workspace"
    releases = temp_root / "releases"
    build_dir = temp_root / "build"

    for d in (iso_home, iso_bin, xdg_config, xdg_state, xdg_data, app_data, workspace, releases, build_dir):
        d.mkdir(parents=True, exist_ok=True)

    env = _isolated_env(
        iso_home=iso_home,
        iso_bin=iso_bin,
        xdg_config=xdg_config,
        xdg_state=xdg_state,
        xdg_data=xdg_data,
        app_data=app_data,
    )
    installed_bin = iso_bin / "guardrail"
    hooks_path = iso_home / ".gemini" / "config" / "hooks.json"
    audit_path = xdg_state / "guardrail" / "audit.jsonl"

    sentinel = f"FAKE_ACCEPTANCE_SENTINEL_{secrets.token_hex(8)}"
    synthetic_session = f"accept-synthetic-{secrets.token_hex(6)}"
    path_replacements = {
        str(workspace): "<WORKSPACE>",
        str(iso_home): "<ISOLATED_HOME>",
        str(temp_root): "<TEMP_ROOT>",
        str(real_home): "<REAL_HOME>",
    }

    # Initialize disposable workspace with harmless fake fixtures only.
    (workspace / ".env").write_text(f"FAKE_SECRET={sentinel}\n", encoding="utf-8", newline="\n")
    (workspace / "hello.txt").write_text("acceptance-ok\n", encoding="utf-8", newline="\n")
    git_init = harness.run_cmd(["git", "init", "-q", str(workspace)], env=env)
    if git_init.returncode != 0:
        shutil.rmtree(temp_root, ignore_errors=True)
        print(f"FAIL: git init failed: {git_init.stderr}", file=sys.stderr)
        return harness.EXIT_FAIL, None

    # Stage local v1 and v2 releases for offline install & update verification.
    try:
        v1_src = v1_binary.resolve() if v1_binary else (build_dir / f"guardrail-{V1_TAG}")
        v2_src = v2_binary.resolve() if v2_binary else (build_dir / f"guardrail-{V2_TAG}")
        if v1_binary is None:
            _build_guardrail_binary(v1_src, V1_TAG)
        if v2_binary is None:
            _build_guardrail_binary(v2_src, V2_TAG)
        harness.stage_local_release(
            releases_root=releases,
            version=V1_TAG,
            binary_path=v1_src,
            os_name="linux",
            arch=arch,
        )
        harness.stage_local_release(
            releases_root=releases,
            version=V2_TAG,
            binary_path=v2_src,
            os_name="linux",
            arch=arch,
        )
    except Exception as exc:
        if not keep_artifacts:
            shutil.rmtree(temp_root, ignore_errors=True)
        print(f"FAIL: release staging failed: {exc}", file=sys.stderr)
        return harness.EXIT_FAIL, None

    stages: list[harness.StageResult] = []
    live_session_observed = False

    # 1. Install
    def stage_install() -> harness.StageResult:
        res = harness.run_cmd(
            [
                "sh",
                str(install_sh),
                "--version",
                V1_TAG,
                "--dest",
                str(iso_bin),
                "--base-url",
                str(releases),
                "--no-setup",
            ],
            env=env,
            cwd=workspace,
        )
        ver = harness.run_cmd([str(installed_bin), "version"], env=env, cwd=workspace)
        mode = stat.S_IMODE(installed_bin.stat().st_mode) if installed_bin.exists() else 0
        ok = (
            res.returncode == 0
            and installed_bin.is_file()
            and mode == 0o755
            and ver.returncode == 0
            and ver.stdout.strip() == f"guardrail {V1_TAG}"
        )
        return harness.StageResult(
            name="install",
            status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
            expected=f"install.sh installs checksum-verified {V1_TAG} with mode 0755",
            observed=(
                f"installed {ver.stdout.strip()!r} mode={oct(mode)} (install rc={res.returncode})"
            ),
            details={"install_rc": res.returncode, "version": ver.stdout.strip(), "mode": oct(mode)},
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
                    hooks_ok = str(installed_bin) in pre_cmd
            except Exception:
                hooks_ok = False
        ok = res.returncode == 0 and hooks_ok
        return harness.StageResult(
            name="enablement",
            status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
            expected="guardrail setup --planes antigravity arms isolated hooks.json pointing to isolated binary",
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
        self_res = harness.run_cmd([str(installed_bin), "selftest"], env=env, cwd=workspace)
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

    # 5. Harmless deny through installed hook binary
    def stage_harmless_deny() -> harness.StageResult:
        before_count = len(harness.read_audit_records(audit_path))
        payload = json.dumps(
            {
                "conversationId": synthetic_session,
                "workspacePaths": [str(workspace)],
                "toolCall": {
                    "name": "view_file",
                    "args": {"AbsolutePath": str(workspace / ".env")},
                },
            }
        )
        res = harness.run_cmd(
            [str(installed_bin), "hook", "antigravity", "pre"],
            env=env,
            cwd=workspace,
            stdin_text=payload,
        )
        decision = ""
        try:
            decision = json.loads(res.stdout).get("decision", "")
        except json.JSONDecodeError:
            pass
        new_recs = harness.read_audit_records(audit_path)[before_count:]
        matching = [
            r
            for r in new_recs
            if r.get("session_id") == synthetic_session
            and r.get("decision") == "deny"
            and r.get("rule_id") == "P4.secret-path"
        ]
        env_intact = (workspace / ".env").read_text(encoding="utf-8") == f"FAKE_SECRET={sentinel}\n"
        ok = res.returncode == 0 and decision == "deny" and len(matching) >= 1 and env_intact
        return harness.StageResult(
            name="harmless_deny",
            status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
            expected="installed antigravity pre hook denies fake .env read with P4.secret-path",
            observed=f"hook rc={res.returncode}, decision={decision!r}, matching_audit={len(matching)}, fixture_intact={env_intact}",
            details={"hook_rc": res.returncode, "decision": decision, "rule_id": "P4.secret-path"},
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
                expected="live agy -p session dispatches tool calls to isolated guardrail hook",
                observed="skipped (--live not set; run with --live to exercise real agy runtime)",
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
            result, observed = evaluate_live_mediation(
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
        grant_cmd = f"guardrail egress grant --scope repo --host {PROBE_HOST}"
        grant_payload = json.dumps(
            {
                "conversationId": synthetic_session,
                "workspacePaths": [str(workspace)],
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": grant_cmd, "Cwd": str(workspace)},
                },
            }
        )

        # (a) Initial egress denied
        step_deny = harness.run_cmd(
            [str(installed_bin), "hook", "antigravity", "pre"],
            env=env,
            cwd=workspace,
            stdin_text=curl_payload,
        )
        d1 = _parse_decision(step_deny.stdout)

        def fetch_refused() -> bool:
            return fetch_refused_as_unapproved(
                harness.run_cmd(
                    [str(installed_bin), "fetch", f"https://{PROBE_HOST}"],
                    env=env,
                    cwd=workspace,
                )
            )

        fetch_refused_before = fetch_refused()

        # (b) Canonical operator command returns force_ask and mints approval ticket
        step_ask = harness.run_cmd(
            [str(installed_bin), "hook", "antigravity", "pre"],
            env=env,
            cwd=workspace,
            stdin_text=grant_payload,
        )
        d2 = _parse_decision(step_ask.stdout)

        # (c) TTY-less CLI claims the host-ask ticket
        step_grant = harness.run_cmd(
            [str(installed_bin), "egress", "grant", "--scope", "repo", "--host", PROBE_HOST],
            env=env,
            cwd=workspace,
        )

        # (d) The sanctioned web-host path (`guardrail fetch`) no longer refuses
        # PROBE_HOST as unapproved, and both overlay guardrail.toml and
        # operator.toml persist it.
        fetch_refused_after = fetch_refused()
        overlay_path = workspace / "guardrail.toml"
        operator_path = xdg_config / "guardrail" / "waivers.toml"
        overlay_has_host = overlay_path.is_file() and PROBE_HOST in overlay_path.read_text(encoding="utf-8")
        operator_has_host = operator_path.is_file() and PROBE_HOST in operator_path.read_text(encoding="utf-8")

        # (e) One-shot ticket replay without a fresh hook ask must be refused
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

    # 8. Update (v1 -> v2 via local staged install.sh + doctor + selftest)
    def stage_update() -> harness.StageResult:
        res = harness.run_cmd(
            [
                "sh",
                str(install_sh),
                "--version",
                V2_TAG,
                "--dest",
                str(iso_bin),
                "--base-url",
                str(releases),
            ],
            env=env,
            cwd=workspace,
        )
        ver = harness.run_cmd([str(installed_bin), "version"], env=env, cwd=workspace)
        doc_res = harness.run_cmd([str(installed_bin), "doctor"], env=env, cwd=workspace)
        self_res = harness.run_cmd([str(installed_bin), "selftest"], env=env, cwd=workspace)
        ok = (
            res.returncode == 0
            and ver.stdout.strip() == f"guardrail {V2_TAG}"
            and "antigravity settings: guardrail integration registered" in doc_res.stdout
            and self_res.returncode == 0
        )
        return harness.StageResult(
            name="update",
            status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
            expected=f"install.sh updates {V1_TAG} -> {V2_TAG} and post-update doctor/selftest stay green",
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

    # 9. Disablement via real Linux PTY + user config preservation
    def stage_disablement() -> harness.StageResult:
        if hooks_path.is_file():
            doc = json.loads(hooks_path.read_text(encoding="utf-8"))
            doc["user_sentinel"] = {"preserved": True}
            hooks_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")

        pty_res = harness.run_in_pty(
            [str(installed_bin), "plane", "disable", "antigravity"],
            env=env,
            cwd=workspace,
            prompt_responses=[("[y/N]", "y\n")],
            timeout=30,
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
        ok = pty_res.returncode == 0 and sentinel_ok and disabled_ok and not_registered
        return harness.StageResult(
            name="disablement",
            status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
            expected="PTY plane disable antigravity removes guardrail hooks while preserving user config",
            observed=(
                f"pty_rc={pty_res.returncode}, user_sentinel_preserved={sentinel_ok}, "
                f"guardrail_removed={disabled_ok}, doctor_unregistered={not_registered}"
            ),
            details={
                "pty_rc": pty_res.returncode,
                "user_sentinel_preserved": sentinel_ok,
                "guardrail_removed": disabled_ok,
                "transport": "terminal-prompt (real PTY)",
            },
        )

    stages.append(harness.run_stage("disablement", stage_disablement))

    # 10. Recovery via real Linux PTY (corrupt hooks.json -> backup + repair)
    def stage_recovery() -> harness.StageResult:
        corrupt_body = "{not valid json — acceptance recovery fixture\n"
        hooks_path.parent.mkdir(parents=True, exist_ok=True)
        hooks_path.write_text(corrupt_body, encoding="utf-8", newline="\n")

        pty_res = harness.run_in_pty(
            [str(installed_bin), "recover", "antigravity-hooks"],
            env=env,
            cwd=workspace,
            prompt_responses=[("[y/N]", "y\n")],
            timeout=30,
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
        self_res = harness.run_cmd([str(installed_bin), "selftest"], env=env, cwd=workspace)
        ok = (
            pty_res.returncode == 0
            and backup_matches
            and repaired_valid
            and "antigravity settings: guardrail integration registered" in doc_res.stdout
            and self_res.returncode == 0
        )
        return harness.StageResult(
            name="recovery",
            status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
            expected="PTY recover antigravity-hooks backs up corrupt hooks.json and restores valid registration",
            observed=(
                f"pty_rc={pty_res.returncode}, backups={len(backups)}, backup_matches={backup_matches}, "
                f"repaired_valid={repaired_valid}, selftest_rc={self_res.returncode}"
            ),
            details={
                "pty_rc": pty_res.returncode,
                "backup_count": len(backups),
                "backup_matches": backup_matches,
                "repaired_valid": repaired_valid,
                "selftest_rc": self_res.returncode,
                "transport": "terminal-prompt (real PTY)",
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
            provenance=_classify_provenance(rec),
        )
        for rec in all_raw_audit
    ]

    # 11. Cleanup and isolation verification
    def stage_cleanup_isolation() -> harness.StageResult:
        real_home_clean, diffs = isolation_guard.verify_unchanged()
        cleaned = False
        if not keep_artifacts:
            shutil.rmtree(temp_root, ignore_errors=False)
            cleaned = not temp_root.exists()
        else:
            cleaned = True
        ok = real_home_clean and cleaned and len(all_raw_audit) > 0
        return harness.StageResult(
            name="cleanup_isolation",
            status=harness.StageStatus.PASS if ok else harness.StageStatus.FAIL,
            expected="real user home untouched, audit isolated in temp root, temp root cleaned up",
            observed=(
                f"real_home_unchanged={real_home_clean}, temp_cleaned={cleaned} (keep={keep_artifacts}), "
                f"isolated_audit_records={len(all_raw_audit)}"
            ),
            details={
                "real_home_unchanged": real_home_clean,
                "real_home_diffs": diffs,
                "keep_artifacts": keep_artifacts,
                "artifacts_dir": str(temp_root) if keep_artifacts else "<removed>",
                "isolated_audit_records": len(all_raw_audit),
            },
        )

    stages.append(harness.run_stage("cleanup_isolation", stage_cleanup_isolation))

    report = harness.build_report(
        plane="antigravity",
        os_name="linux",
        arch=arch,
        environment={
            "guardrail_v1": V1_TAG,
            "guardrail_v2": V2_TAG,
            "host_binary": "agy",
            "host_version": agy_version,
            "os": f"{platform.system()} {platform.release()}",
            "shell": env["SHELL"],
            "live_mode": live,
            "approval_mode": "prompt",
        },
        stages=stages,
        audit_evidence=sanitized_audit,
        live_runtime_session_observed=live_session_observed,
    )
    return harness.report_exit_code(report["summary"]), report


def _parse_decision(stdout: str) -> str:
    try:
        return str(json.loads(stdout).get("decision", ""))
    except json.JSONDecodeError:
        return ""


def _classify_provenance(rec: Mapping[str, Any]) -> str:
    if rec.get("plane") == "operator":
        return "operator_lifecycle"
    sid = str(rec.get("session_id") or "")
    if (
        rec.get("audit_kind") == "selftest"
        or not sid
        or sid.startswith("accept-synthetic-")
        or sid.startswith("selftest")
    ):
        return "synthetic"
    return "live_session"
