"""Unit tests for the platform acceptance harness (#92).

These tests are cross-platform (Linux, macOS, Windows) and run in CI without
requiring network access, credentials, or external agent binaries.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness  # noqa: E402
import linux_antigravity  # noqa: E402
import windows_antigravity  # noqa: E402


class LinuxCodexTests(unittest.TestCase):
    def test_cli_accepts_codex_host(self):
        self.assertEqual(harness.build_arg_parser().parse_args(["--host", "codex"]).host, "codex")

    def test_live_requires_both_native_verdicts_in_the_reported_thread(self):
        import linux_codex

        records = [
            {"plane": "codex", "event": "pre", "session_id": "thread", "tool": "exec_command",
             "decision": "allow", "command": "cat allowed.txt"},
            {"plane": "codex", "event": "pre", "session_id": "other", "tool": "exec_command",
             "decision": "deny", "rule_id": "P4.secret-path", "command": "cat .env"},
        ]
        self.assertFalse(linux_codex.has_live_verdicts(records, "thread"))
        records[1]["session_id"] = "thread"
        self.assertTrue(linux_codex.has_live_verdicts(records, "thread"))
        records[1]["command"] = "cat .env.other"
        self.assertFalse(linux_codex.has_live_verdicts(records, "thread"))


class LinuxClaudeTests(unittest.TestCase):
    SESSION = "0b5c1d2e-3f40-4a51-8b62-c7d8e9f0a1b2"

    def test_cli_accepts_claude_host(self):
        self.assertEqual(harness.build_arg_parser().parse_args(["--host", "claude"]).host, "claude")

    def test_live_requires_both_native_verdicts_in_the_reported_session(self):
        import linux_claude

        records = [
            {"plane": "claude", "event": "pre", "session_id": self.SESSION, "tool": "Bash",
             "decision": "allow", "command": "cat allowed.txt"},
            {"plane": "claude", "event": "pre", "session_id": "other", "tool": "Bash",
             "decision": "deny", "rule_id": "P4.secret-path", "command": "cat .env"},
        ]
        self.assertFalse(linux_claude.has_live_verdicts(records, self.SESSION))
        records[1]["session_id"] = self.SESSION
        self.assertTrue(linux_claude.has_live_verdicts(records, self.SESSION))
        records[1]["rule_id"] = "P3.unresolved"
        self.assertFalse(linux_claude.has_live_verdicts(records, self.SESSION))
        self.assertFalse(linux_claude.has_live_verdicts(records, ""))

    def test_live_accepts_the_read_tool_but_not_other_planes_or_post_events(self):
        import linux_claude

        records = [
            {"plane": "claude", "event": "pre", "session_id": self.SESSION, "tool": "Read",
             "decision": "allow", "paths": ["/work/allowed.txt"]},
            {"plane": "claude", "event": "pre", "session_id": self.SESSION, "tool": "Read",
             "decision": "deny", "rule_id": "P4.secret-path", "paths": ["/work/.env"]},
        ]
        self.assertTrue(linux_claude.has_live_verdicts(records, self.SESSION))
        records[1]["paths"] = ["/work/.env.example"]
        self.assertFalse(linux_claude.has_live_verdicts(records, self.SESSION))
        records[1]["paths"] = ["/work/.env"]
        records[0]["event"] = "post"
        self.assertFalse(linux_claude.has_live_verdicts(records, self.SESSION))
        records[0]["event"] = "pre"
        records[0]["plane"] = "codex"
        self.assertFalse(linux_claude.has_live_verdicts(records, self.SESSION))

    def test_unauthenticated_stream_is_recognized_and_a_normal_stream_is_not(self):
        import linux_claude

        init = {"type": "system", "subtype": "init", "session_id": self.SESSION}
        rejected = [
            init,
            {"type": "assistant", "error": "authentication_failed", "session_id": self.SESSION},
            {"type": "result", "is_error": True, "result": "Not logged in · Please run /login"},
        ]
        self.assertTrue(linux_claude.live_auth_missing(rejected))
        self.assertEqual(linux_claude.reported_session(rejected), self.SESSION)
        answered = [init, {"type": "assistant"}, {"type": "result", "is_error": False, "result": "done"}]
        self.assertFalse(linux_claude.live_auth_missing(answered))
        self.assertEqual(linux_claude.reported_session([]), "")

    def test_only_the_reported_session_is_labelled_runtime_evidence(self):
        import linux_claude

        classify = linux_claude.classify_provenance
        self.assertEqual(classify({"plane": "claude", "session_id": self.SESSION}, self.SESSION),
                         "isolated_runtime")
        # The harness runs operator commands itself; no operator approved them.
        self.assertEqual(classify({"plane": "operator", "event": "operator-action"}, self.SESSION),
                         "harness_driven_lifecycle")
        # A selftest record can carry no session id at all; it is still a fixture.
        for record in ({"plane": "claude"}, {"plane": "claude", "session_id": "claude-fixture-ab"},
                       {"plane": "codex", "session_id": self.SESSION}):
            self.assertEqual(classify(record, self.SESSION), "synthetic_fixture")
        self.assertEqual(classify({"plane": "claude", "session_id": self.SESSION}, ""),
                         "synthetic_fixture")

    def test_evidence_gate_is_shut_only_on_the_not_observed_verdict(self):
        import linux_claude

        shut = harness.CommandResult(1, "claude: live mediation not yet observed; the registered hook\n", "")
        broken = harness.CommandResult(1, "", "guardrail: evidence unavailable: cannot stat running binary\n")
        opened = harness.CommandResult(0, "claude: live mediation observed (heuristic)\n", "")
        self.assertTrue(linux_claude.gate_shut(shut))
        self.assertFalse(linux_claude.gate_shut(broken))
        self.assertFalse(linux_claude.gate_shut(opened))

    def test_live_credentials_refuse_real_state_and_unusable_sources(self):
        import linux_claude

        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            real_home = base / "home"
            real_claude = real_home / ".claude"
            disposable = base / "disposable"
            empty = base / "empty"
            for directory in (real_claude, disposable, empty):
                directory.mkdir(parents=True)
            (real_claude / ".credentials.json").write_text("{}", encoding="utf-8")
            (disposable / ".credentials.json").write_text("{}", encoding="utf-8")

            def resolve(source):
                return linux_claude.live_credentials(source, real_home, (real_claude,))

            self.assertEqual(resolve(disposable), (disposable / ".credentials.json", ""))
            for refused in (real_home, real_claude, real_claude / "nested"):
                path, error = resolve(refused)
                self.assertIsNone(path)
                self.assertIn("disposable", error)
            path, error = resolve(empty)
            self.assertIsNone(path)
            self.assertIn(".credentials.json", error)

    def test_live_credentials_refuse_a_symlinked_credentials_file(self):
        import linux_claude

        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve()
            real_claude = base / "home" / ".claude"
            linked = base / "linked"
            for directory in (real_claude, linked):
                directory.mkdir(parents=True)
            (real_claude / ".credentials.json").write_text("{}", encoding="utf-8")
            try:
                (linked / ".credentials.json").symlink_to(real_claude / ".credentials.json")
            except OSError as error:
                # Windows refuses symlinks without elevation or Developer Mode
                # (#677). Only this case needs one; CI's Windows runner has it.
                self.skipTest(
                    f"this account cannot create a symlink, so the symlinked-credentials refusal "
                    f"is NOT covered on this host: {error}"
                )
            path, error = linux_claude.live_credentials(linked, base / "home", (real_claude,))
            self.assertIsNone(path)
            self.assertIn(".credentials.json", error)

    def test_rejected_supplied_credentials_fail_instead_of_asking_for_an_operator(self):
        import linux_claude

        rejected = [{"type": "assistant", "error": "authentication_failed"}]
        status = harness.StageStatus
        self.assertEqual(linux_claude.live_auth_status(rejected, supplied=False), status.OPERATOR_ASSISTED)
        self.assertEqual(linux_claude.live_auth_status(rejected, supplied=True), status.FAIL)
        self.assertIsNone(linux_claude.live_auth_status([{"type": "assistant"}], supplied=True))

    def test_hook_registration_requires_this_binary_on_the_pre_tool_event(self):
        import linux_claude

        binary = "/iso/bin/guardrail"
        mine = {"matcher": "*", "hooks": [{"type": "command", "command": f"{binary} hook claude"}]}
        other = {"matcher": "*", "hooks": [{"type": "command", "command": "/usr/bin/guardrail hook claude"}]}
        self.assertTrue(linux_claude.hook_registered({"hooks": {"PreToolUse": [mine]}}, binary))
        self.assertFalse(linux_claude.hook_registered({"hooks": {"PreToolUse": [other]}}, binary))
        self.assertFalse(linux_claude.hook_registered({"hooks": {"PostToolUse": [mine]}}, binary))
        self.assertFalse(linux_claude.hook_registered({}, binary))
class LinuxOpencodeTests(unittest.TestCase):
    SESSION = "ses_dff072e41ffew6FeaTBFYcJa6A"

    def test_cli_accepts_opencode_host(self):
        self.assertEqual(harness.build_arg_parser().parse_args(["--host", "opencode"]).host, "opencode")

    def test_isolation_guard_watches_the_real_opencode_config(self):
        self.assertIn(Path(".config") / "opencode" / "opencode.json",
                      harness.IsolationGuard.WATCHED_RELATIVE_PATHS)

    def test_live_requires_both_native_verdicts_in_the_reported_session(self):
        import linux_opencode

        records = [
            {"plane": "opencode", "event": "pre", "session_id": self.SESSION, "tool": "Bash",
             "decision": "allow", "command": "cat allowed.txt"},
            {"plane": "opencode", "event": "pre", "session_id": "ses_other", "tool": "Bash",
             "decision": "deny", "rule_id": "P4.secret-path", "command": "cat .env"},
        ]
        self.assertFalse(linux_opencode.has_live_verdicts(records, self.SESSION))
        records[1]["session_id"] = self.SESSION
        self.assertTrue(linux_opencode.has_live_verdicts(records, self.SESSION))
        records[1]["rule_id"] = "P3.unresolved"
        self.assertFalse(linux_opencode.has_live_verdicts(records, self.SESSION))
        records[1]["rule_id"] = "P4.secret-path"
        for key, wrong in (("plane", "claude"), ("event", "post"), ("decision", "ask")):
            original = records[0][key]
            records[0][key] = wrong
            self.assertFalse(linux_opencode.has_live_verdicts(records, self.SESSION), key)
            records[0][key] = original
        records[1]["event"] = "post"
        self.assertFalse(linux_opencode.has_live_verdicts(records, self.SESSION))
        records[1]["event"] = "pre"
        self.assertTrue(linux_opencode.has_live_verdicts(records, self.SESSION))
        self.assertFalse(linux_opencode.has_live_verdicts(records, ""))

    def _live(self, *, returncode=0, events=None, records=None, output=""):
        import linux_opencode

        def tool(status, **state):
            return {"type": "tool_use", "sessionID": self.SESSION,
                    "part": {"type": "tool", "tool": "shell", "state": {"status": status, **state}}}

        if events is None:
            events = [tool("completed", output="MARKER\n"), tool("error", error="denied")]
        if records is None:
            records = [
                {"plane": "opencode", "event": "pre", "session_id": self.SESSION,
                 "decision": "allow", "command": "cat allowed.txt"},
                {"plane": "opencode", "event": "pre", "session_id": self.SESSION,
                 "decision": "deny", "rule_id": "P4.secret-path", "command": "cat .env"},
            ]
        return linux_opencode.judge_live(
            returncode=returncode, events=events, records=records, output=output,
            secret="SECRET", marker="MARKER",
        )

    def test_live_judgement_passes_only_with_every_condition(self):
        status = harness.StageStatus
        self.assertEqual(self._live()[0], status.PASS)
        self.assertEqual(self._live(returncode=1)[0], status.FAIL)
        self.assertEqual(self._live(output="leaked SECRET")[0], status.FAIL)
        self.assertEqual(self._live(records=[])[0], status.FAIL)

    def test_live_judgement_without_tool_calls_never_hides_a_failure(self):
        status = harness.StageStatus
        idle = [{"type": "text", "sessionID": self.SESSION, "part": {"text": "no model"}}]
        self.assertEqual(self._live(events=idle, records=[])[0], status.OPERATOR_ASSISTED)
        # A crash, a leak, or hook traffic the event stream did not show is a failure.
        self.assertEqual(self._live(events=idle, records=[], returncode=1)[0], status.FAIL)
        self.assertEqual(self._live(events=idle, records=[], output="SECRET")[0], status.FAIL)
        self.assertEqual(self._live(events=idle)[0], status.FAIL)

    def test_run_events_with_an_unexpected_part_shape_are_ignored(self):
        import linux_opencode

        odd = [{"type": "tool_use", "sessionID": self.SESSION, "part": "not-an-object"},
               {"type": "tool_use", "sessionID": self.SESSION, "part": {"state": "done"}}]
        self.assertEqual(linux_opencode.tool_calls(odd), 0)
        self.assertFalse(linux_opencode.safe_output(odd, "MARKER"))

    def test_live_accepts_the_read_tool_by_exact_file_name(self):
        import linux_opencode

        records = [
            {"plane": "opencode", "event": "pre", "session_id": self.SESSION, "tool": "Read",
             "decision": "allow", "paths": ["/work/allowed.txt"]},
            {"plane": "opencode", "event": "pre", "session_id": self.SESSION, "tool": "Read",
             "decision": "deny", "rule_id": "P4.secret-path", "paths": ["/work/.env.example"]},
        ]
        self.assertFalse(linux_opencode.has_live_verdicts(records, self.SESSION))
        records[1]["paths"] = ["/work/.env"]
        self.assertTrue(linux_opencode.has_live_verdicts(records, self.SESSION))

    def test_run_events_yield_the_session_tool_calls_and_safe_output(self):
        import linux_opencode

        def tool(status, **state):
            return {"type": "tool_use", "sessionID": self.SESSION,
                    "part": {"type": "tool", "tool": "shell", "state": {"status": status, **state}}}

        events = [
            {"type": "step_start", "sessionID": self.SESSION},
            tool("completed", output="MARKER\n"),
            tool("error", error="guardrail: Guardrail denied this action"),
        ]
        self.assertEqual(linux_opencode.reported_session(events), self.SESSION)
        self.assertEqual(linux_opencode.tool_calls(events), 2)
        self.assertTrue(linux_opencode.safe_output(events, "MARKER"))
        # The marker must come back from a completed tool call, not from prose or an error.
        self.assertFalse(linux_opencode.safe_output(
            [{"type": "text", "part": {"text": "MARKER"}}, tool("error", error="MARKER")], "MARKER"))
        self.assertEqual(linux_opencode.reported_session([{"type": "text"}]), "")
        self.assertEqual(linux_opencode.tool_calls([{"type": "text"}]), 0)

    def test_plugin_registration_matches_either_major_and_ignores_user_plugins(self):
        import linux_opencode

        registered = linux_opencode.plugin_registered
        self.assertTrue(registered({"plugins": ["/iso/data/guardrail/guardrail"]}))
        self.assertTrue(registered({"plugin": ["/iso/data/guardrail/guardrail.js"]}))
        self.assertFalse(registered({"plugins": ["/user/plugin-fixture"], "theme": "x"}))
        self.assertFalse(registered({"plugins": ["/user/not-guardrail.js"]}))
        self.assertFalse(registered({}))

    def test_only_the_reported_session_is_labelled_runtime_evidence(self):
        import linux_opencode

        classify = linux_opencode.classify_provenance
        self.assertEqual(classify({"plane": "opencode", "session_id": self.SESSION}, self.SESSION),
                         "isolated_runtime")
        # The harness runs operator commands itself; no operator approved them.
        self.assertEqual(classify({"plane": "operator"}, self.SESSION), "harness_driven_lifecycle")
        for record in ({"plane": "opencode"}, {"plane": "opencode", "session_id": "opencode-fixture-ab"},
                       {"plane": "claude", "session_id": self.SESSION}):
            self.assertEqual(classify(record, self.SESSION), "synthetic_fixture")
        self.assertEqual(classify({"plane": "opencode", "session_id": self.SESSION}, ""),
                         "synthetic_fixture")


class StageSummaryAndExitCodeTests(unittest.TestCase):
    def test_distinguishes_statuses_and_computes_exit_zero_without_failures(self):
        stages = [
            harness.StageResult(name="install", status=harness.StageStatus.PASS, expected="ok", observed="ok"),
            harness.StageResult(name="enrollment", status=harness.StageStatus.OPERATOR_ASSISTED, expected="passkey", observed="operator assisted"),
            harness.StageResult(name="declarative_floor", status=harness.StageStatus.UNSUPPORTED, expected="none", observed="ADR-0008"),
            harness.StageResult(name="live_runtime_mediation", status=harness.StageStatus.SKIPPED, expected="live", observed="--live not set"),
        ]
        summary = harness.summarize_stages(stages)
        self.assertEqual(summary["pass"], 1)
        self.assertEqual(summary["fail"], 0)
        self.assertEqual(summary["operator_assisted"], 1)
        self.assertEqual(summary["unsupported"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertTrue(summary["overall_pass"])
        self.assertEqual(harness.report_exit_code(summary), 0)

    def test_any_failed_stage_yields_exit_one(self):
        stages = [
            harness.StageResult(name="install", status=harness.StageStatus.PASS, expected="ok", observed="ok"),
            harness.StageResult(name="harmless_deny", status=harness.StageStatus.FAIL, expected="deny", observed="allow"),
        ]
        summary = harness.summarize_stages(stages)
        self.assertFalse(summary["overall_pass"])
        self.assertEqual(summary["fail"], 1)
        self.assertEqual(harness.report_exit_code(summary), 1)

    def test_build_report_never_claims_universal_mediation_or_simulated_webauthn(self):
        stages = [
            harness.StageResult(name="install", status=harness.StageStatus.PASS, expected="ok", observed="ok"),
        ]
        report = harness.build_report(
            plane="antigravity",
            os_name="linux",
            arch="amd64",
            environment={"guardrail_version": "v0.0.1-accept", "host_binary": "agy", "live_mode": False},
            stages=stages,
            audit_evidence=[],
            live_runtime_session_observed=False,
        )
        self.assertEqual(report["schema_version"], 1)
        self.assertFalse(report["claims"]["universal_mediation_implied"])
        self.assertFalse(report["claims"]["webauthn_live_validated"])
        self.assertFalse(report["claims"]["live_runtime_session_observed"])


class SanitizationTests(unittest.TestCase):
    def test_sanitize_text_redacts_secrets_and_normalizes_paths(self):
        replacements = {
            "/tmp/guardrail-accept-xyz/home": "<ISOLATED_HOME>",
            "/tmp/guardrail-accept-xyz/workspace": "<WORKSPACE>",
            "/home/realuser": "<REAL_HOME>",
        }
        raw = (
            "cat /tmp/guardrail-accept-xyz/workspace/.env "
            "token=supersecretvalue123 "
            "ghp_1234567890abcdefghijklmno "
            "AKIA1234567890ABCDEF "
            "Bearer my-jwt-token "
            "FAKE_ACCEPTANCE_SENTINEL_deadbeef "
            "/home/realuser/.gemini/config/hooks.json"
        )
        sanitized = harness.sanitize_text(
            raw,
            path_replacements=replacements,
            extra_redactions=["FAKE_ACCEPTANCE_SENTINEL_deadbeef"],
        )
        self.assertIn("<WORKSPACE>/.env", sanitized)
        self.assertIn("<REAL_HOME>/.gemini/config/hooks.json", sanitized)
        self.assertNotIn("supersecretvalue123", sanitized)
        self.assertNotIn("ghp_1234567890abcdefghijklmno", sanitized)
        self.assertNotIn("AKIA1234567890ABCDEF", sanitized)
        self.assertNotIn("my-jwt-token", sanitized)
        self.assertNotIn("FAKE_ACCEPTANCE_SENTINEL_deadbeef", sanitized)
        self.assertNotIn("/home/realuser", sanitized)

    def test_sanitize_audit_record_strips_raw_paths_and_tags_provenance(self):
        rec = {
            "ts": "2026-11-20T14:00:00Z",
            "session_id": "conv-live-123",
            "plane": "antigravity",
            "tool": "Read",
            "native_tool": "view_file",
            "capability": "read_discovery",
            "event": "pre",
            "paths": ["/tmp/iso/workspace/.env"],
            "repo_root": "/tmp/iso/workspace",
            "command": "cat /tmp/iso/workspace/.env token=secret123",
            "decision": "deny",
            "rule_id": "P4.file-secrets",
            "reason": "blocked secret read at /tmp/iso/workspace/.env",
        }
        cleaned = harness.sanitize_audit_record(
            rec,
            path_replacements={"/tmp/iso/workspace": "<WORKSPACE>"},
            provenance="live_session",
        )
        self.assertEqual(cleaned["provenance"], "live_session")
        self.assertEqual(cleaned["paths"], ["<WORKSPACE>/.env"])
        self.assertEqual(cleaned["repo_root"], "<WORKSPACE>")
        self.assertNotIn("secret123", cleaned["command"])
        self.assertEqual(cleaned["decision"], "deny")
        self.assertEqual(cleaned["rule_id"], "P4.file-secrets")


class IsolationGuardTests(unittest.TestCase):
    def test_detects_untouched_and_modified_real_home_files(self):
        with tempfile.TemporaryDirectory() as td:
            real_home = Path(td) / "real-home"
            hooks = real_home / ".gemini" / "config" / "hooks.json"
            hooks.parent.mkdir(parents=True)
            hooks.write_text('{"user": true}\n', encoding="utf-8")

            guard = harness.IsolationGuard.capture(real_home)
            ok, diffs = guard.verify_unchanged()
            self.assertTrue(ok)
            self.assertEqual(diffs, [])

            # Modify the real file — guard must catch it.
            hooks.write_text('{"tampered": true}\n', encoding="utf-8")
            ok2, diffs2 = guard.verify_unchanged()
            self.assertFalse(ok2)
            self.assertEqual(len(diffs2), 1)
            self.assertIn("hooks.json", diffs2[0])

    def test_detects_newly_created_real_home_file(self):
        with tempfile.TemporaryDirectory() as td:
            real_home = Path(td) / "real-home"
            real_home.mkdir()
            guard = harness.IsolationGuard.capture(real_home)
            ok, diffs = guard.verify_unchanged()
            self.assertTrue(ok)

            op = real_home / ".config" / "guardrail" / "waivers.toml"
            op.parent.mkdir(parents=True)
            op.write_text('approval = "prompt"\n', encoding="utf-8")
            ok2, diffs2 = guard.verify_unchanged()
            self.assertFalse(ok2)
            self.assertIn("waivers.toml", diffs2[0])


class LocalReleaseStagingTests(unittest.TestCase):
    def test_stage_local_release_writes_asset_and_matching_sha256sums(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src_bin = root / "guardrail-src"
            payload = b"#!/bin/sh\necho guardrail v0.0.1-accept\n"
            src_bin.write_bytes(payload)

            releases = root / "releases"
            asset_path, sums_path = harness.stage_local_release(
                releases_root=releases,
                version="v0.0.1-accept",
                binary_path=src_bin,
                os_name="linux",
                arch="amd64",
            )
            self.assertEqual(asset_path, releases / "v0.0.1-accept" / "guardrail_linux_amd64")
            self.assertTrue(asset_path.is_file())
            self.assertTrue(sums_path.is_file())
            want_sha = hashlib.sha256(payload).hexdigest()
            self.assertEqual(sums_path.read_text(encoding="utf-8").strip(), f"{want_sha}  guardrail_linux_amd64")


class LiveMediationEvaluationTests(unittest.TestCase):
    def test_rejects_synthetic_or_empty_session_ids(self):
        records = [
            {
                "ts": "2026-11-20T14:00:00Z",
                "session_id": "",
                "plane": "antigravity",
                "native_tool": "view_file",
                "decision": "deny",
                "rule_id": "P4.file-secrets",
            },
            {
                "ts": "2026-11-20T14:00:01Z",
                "session_id": "selftest-probe",
                "plane": "antigravity",
                "native_tool": "view_file",
                "decision": "deny",
                "rule_id": "P4.file-secrets",
                "audit_kind": "selftest",
            },
        ]
        result, observed = linux_antigravity.evaluate_live_mediation(
            returncode=0,
            stdout='{"result":"blocked"}',
            stderr="",
            audit_records=records,
            sentinel="FAKE_ACCEPTANCE_SENTINEL_1234",
            path_replacements={},
        )
        self.assertEqual(result.status, harness.StageStatus.FAIL)
        self.assertFalse(observed)

    def test_fails_if_fake_secret_sentinel_leaked_in_output(self):
        records = [
            {
                "ts": "2026-11-20T14:00:00Z",
                "session_id": "conv-real-999",
                "plane": "antigravity",
                "native_tool": "view_file",
                "decision": "deny",
                "rule_id": "P4.file-secrets",
            },
        ]
        result, observed = linux_antigravity.evaluate_live_mediation(
            returncode=0,
            stdout="The file contains FAKE_ACCEPTANCE_SENTINEL_1234",
            stderr="",
            audit_records=records,
            sentinel="FAKE_ACCEPTANCE_SENTINEL_1234",
            path_replacements={},
        )
        self.assertEqual(result.status, harness.StageStatus.FAIL)
        self.assertFalse(observed)
        self.assertIn("sentinel", result.observed.lower())

    def test_marks_unauthenticated_agy_as_operator_assisted(self):
        result, observed = linux_antigravity.evaluate_live_mediation(
            returncode=1,
            stdout="",
            stderr="Error: not logged in; please authenticate with agy login",
            audit_records=[],
            sentinel="FAKE_ACCEPTANCE_SENTINEL_1234",
            path_replacements={},
        )
        self.assertEqual(result.status, harness.StageStatus.OPERATOR_ASSISTED)
        self.assertFalse(observed)

    def test_passes_with_real_session_deny_and_no_leak(self):
        records = [
            {
                "ts": "2026-11-20T14:00:00Z",
                "session_id": "conv-real-abc123",
                "plane": "antigravity",
                "tool": "Read",
                "native_tool": "view_file",
                "event": "pre",
                "decision": "deny",
                "rule_id": "P4.file-secrets",
                "paths": ["/tmp/iso/workspace/.env"],
            },
        ]
        result, observed = linux_antigravity.evaluate_live_mediation(
            returncode=0,
            stdout='{"result":"I could not read .env because guardrail blocked it."}',
            stderr="",
            audit_records=records,
            sentinel="FAKE_ACCEPTANCE_SENTINEL_1234",
            path_replacements={"/tmp/iso/workspace": "<WORKSPACE>"},
        )
        self.assertEqual(result.status, harness.StageStatus.PASS)
        self.assertTrue(observed)
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(result.evidence[0]["provenance"], "live_session")
        self.assertEqual(result.evidence[0]["session_id"], "conv-real-abc123")

    def test_classify_provenance_marks_selftest_sessions_synthetic(self):
        self.assertEqual(
            linux_antigravity._classify_provenance({"plane": "antigravity", "session_id": "selftest-1795207810535854327"}),
            "synthetic",
        )
        self.assertEqual(
            linux_antigravity._classify_provenance({"plane": "antigravity", "session_id": "accept-synthetic-abc123"}),
            "synthetic",
        )
        self.assertEqual(
            linux_antigravity._classify_provenance({"plane": "operator", "session_id": "terminal"}),
            "operator_lifecycle",
        )
        self.assertEqual(
            linux_antigravity._classify_provenance({"plane": "antigravity", "session_id": "conv-real-1234"}),
            "live_session",
        )


class PtyRunnerTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX PTY test")
    def test_run_in_pty_answers_prompt_and_captures_output(self):
        code = (
            "import sys; "
            "assert sys.stdin.isatty(), 'not a tty'; "
            "sys.stdout.write('Approve test action? [y/N] '); sys.stdout.flush(); "
            "ans = sys.stdin.readline().strip(); "
            "print('GOT:' + ans)"
        )
        res = harness.run_in_pty(
            [sys.executable, "-c", code],
            prompt_responses=[("[y/N]", "y\n")],
            timeout=10,
        )
        self.assertEqual(res.returncode, 0, msg=res.output)
        self.assertIn("GOT:y", res.output)


class WindowsAntigravityTests(unittest.TestCase):
    def test_stage_local_release_windows_uses_exe_suffix(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src_bin = root / "guardrail-src.exe"
            payload = b"MZ-acceptance-fixture"
            src_bin.write_bytes(payload)

            releases = root / "releases"
            asset_path, sums_path = harness.stage_local_release(
                releases_root=releases,
                version="v0.0.1-accept",
                binary_path=src_bin,
                os_name="windows",
                arch="amd64",
            )
            self.assertEqual(asset_path, releases / "v0.0.1-accept" / "guardrail_windows_amd64.exe")
            self.assertTrue(asset_path.is_file())
            want_sha = hashlib.sha256(payload).hexdigest()
            self.assertEqual(
                sums_path.read_text(encoding="utf-8").strip(),
                f"{want_sha}  guardrail_windows_amd64.exe",
            )

    def test_windows_isolated_env_sets_windows_roots_and_strips_xdg(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            env = windows_antigravity.build_windows_isolated_env(
                iso_home=root / "home",
                iso_bin=root / "bin",
                iso_appdata=root / "appdata",
                iso_localappdata=root / "localappdata",
                app_data=root / "agy_app_data",
                base_env={
                    "PATH": r"C:\Windows\System32",
                    "SYSTEMROOT": r"C:\Windows",
                    "XDG_CONFIG_HOME": "/should/not/leak",
                    "XDG_STATE_HOME": "/should/not/leak",
                    "XDG_DATA_HOME": "/should/not/leak",
                },
            )
            self.assertEqual(env["USERPROFILE"], str(root / "home"))
            self.assertEqual(env["HOME"], str(root / "home"))
            self.assertEqual(env["APPDATA"], str(root / "appdata"))
            self.assertEqual(env["LOCALAPPDATA"], str(root / "localappdata"))
            self.assertEqual(env["ANTIGRAVITY_APP_DATA_DIR"], str(root / "agy_app_data"))
            self.assertTrue(env["PATH"].startswith(str(root / "bin") + os.pathsep))
            self.assertEqual(env["SYSTEMROOT"], r"C:\Windows")
            self.assertNotIn("XDG_CONFIG_HOME", env)
            self.assertNotIn("XDG_STATE_HOME", env)
            self.assertNotIn("XDG_DATA_HOME", env)

    def test_windows_path_replacements_scrub_backslash_and_slash_spellings(self):
        replacements = windows_antigravity.build_windows_path_replacements(
            workspace=r"C:\Temp\iso\workspace",
            iso_home=r"C:\Temp\iso\home",
            temp_root=r"C:\Temp\iso",
            real_home=r"C:\Users\realuser",
        )
        raw = (
            r"blocked C:\Temp\iso\workspace\.env and C:/Temp/iso/workspace/.env "
            r"real=C:\Users\realuser\AppData\Roaming\guardrail\waivers.toml "
            r"real2=C:/Users/realuser/.gemini/config/hooks.json"
        )
        cleaned = harness.sanitize_text(raw, path_replacements=replacements)
        self.assertNotIn("realuser", cleaned)
        self.assertNotIn(r"C:\Temp\iso", cleaned)
        self.assertNotIn("C:/Temp/iso", cleaned)
        self.assertIn("<WORKSPACE>", cleaned)
        self.assertIn("<REAL_HOME>", cleaned)

    def test_isolation_guard_watches_windows_appdata_waivers(self):
        with tempfile.TemporaryDirectory() as td:
            real_home = Path(td) / "real-home"
            real_home.mkdir()
            guard = harness.IsolationGuard.capture(real_home)
            ok, diffs = guard.verify_unchanged()
            self.assertTrue(ok, msg=diffs)

            waivers = real_home / "AppData" / "Roaming" / "guardrail" / "waivers.toml"
            waivers.parent.mkdir(parents=True)
            waivers.write_text('approval = "prompt"\n', encoding="utf-8")
            ok2, diffs2 = guard.verify_unchanged()
            self.assertFalse(ok2)
            self.assertTrue(any("waivers.toml" in d for d in diffs2), msg=diffs2)

    def test_hook_command_matches_binary_across_slashes_and_case(self):
        bin_path = r"C:\Temp\iso\bin\guardrail.exe"
        self.assertTrue(
            windows_antigravity.hook_command_matches_binary(
                r"C:\Temp\iso\bin\guardrail.exe hook antigravity pre",
                bin_path,
            )
        )
        self.assertTrue(
            windows_antigravity.hook_command_matches_binary(
                "c:/temp/iso/bin/guardrail.exe hook antigravity pre",
                bin_path,
            )
        )
        self.assertFalse(
            windows_antigravity.hook_command_matches_binary(
                r"C:\Other\guardrail.exe hook antigravity pre",
                bin_path,
            )
        )

    def test_harness_selects_windows_and_linux_antigravity_runners(self):
        self.assertEqual(harness.select_antigravity_runner("win32"), "windows_antigravity")
        self.assertEqual(harness.select_antigravity_runner("linux"), "linux_antigravity")

    def test_fetch_refusal_is_the_unapproved_host_message_not_any_failure(self):
        refused = harness.CommandResult(
            1, "", "web fetch to an unapproved host requires operator approval: accept-probe.invalid.\n",
        )
        # After a grant the fetch passes policy and fails at name resolution.
        resolved_no_further = harness.CommandResult(1, "", "guardrail: fetch failed\n")
        succeeded = harness.CommandResult(0, "<html>", "")
        self.assertTrue(linux_antigravity.fetch_refused_as_unapproved(refused))
        self.assertFalse(linux_antigravity.fetch_refused_as_unapproved(resolved_no_further))
        self.assertFalse(linux_antigravity.fetch_refused_as_unapproved(succeeded))

    def test_elevated_shell_is_never_reported_off_windows(self):
        if sys.platform == "win32":
            self.assertIsInstance(windows_antigravity.elevated_shell(), bool)
        else:
            self.assertFalse(windows_antigravity.elevated_shell())


class WindowsOpencodeTests(unittest.TestCase):
    SESSION = "ses_dff0f0e53ffeEdeVkiqdHhem27"
    SENTINEL = "FAKE_ACCEPTANCE_SENTINEL_0123"
    MARKER = "OPENCODE_ACCEPTANCE_4567"

    def _events(self, *, session=None, hello_output=None, env_error="guardrail: denied (P4.secret-path)"):
        session = self.SESSION if session is None else session
        hello_output = f"1: {self.MARKER}" if hello_output is None else hello_output
        lines = [
            {"type": "step_start", "sessionID": session, "part": {"type": "step-start"}},
            {"type": "tool_use", "sessionID": session, "part": {
                "tool": "read", "state": {"status": "error", "input": {"path": ".env"}, "error": env_error}}},
            {"type": "tool_use", "sessionID": session, "part": {
                "tool": "read", "state": {"status": "completed", "input": {"path": "hello.txt"},
                                          "output": hello_output}}},
            {"type": "text", "sessionID": session, "part": {"type": "text", "text": ".env was blocked"}},
        ]
        return "\n".join(json.dumps(line) for line in lines) + "\n"

    def _audit(self, session=None):
        session = self.SESSION if session is None else session
        return [
            {"plane": "opencode", "event": "pre", "session_id": session, "native_tool": "read",
             "decision": "deny", "rule_id": "P4.secret-path", "paths": [".env"]},
            {"plane": "opencode", "event": "pre", "session_id": session, "native_tool": "read",
             "decision": "allow", "paths": ["hello.txt"]},
        ]

    def _evaluate(self, **overrides):
        import windows_opencode

        args = {
            "returncode": 0, "stdout": self._events(), "stderr": "", "audit_records": self._audit(),
            "sentinel": self.SENTINEL, "marker": self.MARKER,
        }
        args.update(overrides)
        return windows_opencode.evaluate_live_run(**args)

    def test_cli_accepts_opencode_host(self):
        self.assertEqual(harness.build_arg_parser().parse_args(["--host", "opencode"]).host, "opencode")

    def test_runner_reports_missing_prerequisite_off_windows(self):
        import windows_opencode

        if sys.platform == "win32":
            self.skipTest("the non-Windows prerequisite exit is only observable off Windows")
        code, report = windows_opencode.run_windows_opencode_acceptance()
        self.assertEqual(code, harness.EXIT_SKIP_PREREQ)
        self.assertIsNone(report)

    def test_isolated_env_points_every_root_at_the_disposable_profile(self):
        import windows_opencode

        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / "home"
            env = windows_opencode.build_opencode_isolated_env(
                iso_home=home,
                iso_bin=Path(td) / "bin",
                base_env={
                    "Path": r"C:\Windows\System32",
                    "SystemRoot": r"C:\Windows",
                    "XDG_CONFIG_HOME": "/should/not/leak",
                    "XDG_DATA_HOME": "/should/not/leak",
                    "XDG_STATE_HOME": "/should/not/leak",
                    "OPENCODE_CONFIG": "/should/not/leak/opencode.json",
                    "ANTHROPIC_API_KEY": "should-not-leak",
                    "GUARDRAIL_CONFIG": "/should/not/leak",
                },
            )
            self.assertEqual(env["USERPROFILE"], str(home))
            self.assertEqual(env["APPDATA"], str(home / "AppData" / "Roaming"))
            self.assertEqual(env["LOCALAPPDATA"], str(home / "AppData" / "Local"))
            self.assertTrue(env["PATH"].startswith(str(Path(td) / "bin") + os.pathsep))
            self.assertEqual(env["SYSTEMROOT"], r"C:\Windows")
            leaked = [key for key, value in env.items() if "should" in value]
            self.assertEqual(leaked, [])
            self.assertNotIn("ANTIGRAVITY_APP_DATA_DIR", env)

    def test_registration_requires_the_isolated_v2_plugins_entry_and_floor(self):
        import windows_opencode

        plugin_dir = Path(r"C:\Temp\iso\home\.local\share\guardrail")
        floor = [{"action": "external_directory", "effect": "ask", "resource": "*"}]
        v2 = {"plugins": [str(plugin_dir / "guardrail")], "permissions": floor}
        self.assertEqual(windows_opencode.opencode_registration(v2, plugin_dir), (2, True))
        slashes = {"plugins": ["c:/temp/iso/home/.local/share/guardrail/guardrail"], "permissions": floor}
        self.assertEqual(windows_opencode.opencode_registration(slashes, plugin_dir), (2, True))
        self.assertEqual(
            windows_opencode.opencode_registration({"plugins": v2["plugins"]}, plugin_dir), (2, False),
            "a V2 entry without the external_directory ask is not the generated wiring",
        )
        narrowed = [{"action": "external_directory", "effect": "ask", "resource": "C:/one/dir"}]
        self.assertEqual(
            windows_opencode.opencode_registration({"plugins": v2["plugins"], "permissions": narrowed}, plugin_dir),
            (2, False),
        )
        real_home = {"plugins": [r"C:\Users\realuser\.local\share\guardrail\guardrail"], "permissions": floor}
        self.assertEqual(windows_opencode.opencode_registration(real_home, plugin_dir), (0, False))
        v1 = {"plugin": [str(plugin_dir / "guardrail.js")]}
        self.assertEqual(windows_opencode.opencode_registration(v1, plugin_dir), (1, True))
        self.assertEqual(windows_opencode.opencode_registration({}, plugin_dir), (0, False))

    def test_hook_decision_reads_the_adapter_json_line(self):
        import windows_opencode

        self.assertEqual(windows_opencode.hook_decision('{"decision":"deny","reason":"x"}\n'), "deny")
        self.assertEqual(windows_opencode.hook_decision("warning\n{\"decision\":\"ask\"}\n"), "ask")
        self.assertEqual(windows_opencode.hook_decision("not json"), "")

    def test_live_run_passes_with_both_verdicts_in_the_reported_session(self):
        status, observed, live = self._evaluate()
        self.assertEqual(status, harness.StageStatus.PASS, msg=observed)
        self.assertTrue(live)

    def test_live_run_rejects_verdicts_from_another_session(self):
        status, observed, live = self._evaluate(audit_records=self._audit("ses_other"))
        self.assertEqual(status, harness.StageStatus.FAIL, msg=observed)
        self.assertFalse(live)

    def test_live_run_rejects_a_synthetic_session(self):
        session = "selftest-1795312077585336800"
        status, _, live = self._evaluate(stdout=self._events(session=session), audit_records=self._audit(session))
        self.assertEqual(status, harness.StageStatus.FAIL)
        self.assertFalse(live)

    def test_live_run_fails_when_the_fake_secret_leaks(self):
        leaked = self._events(env_error=f"FAKE_SECRET={self.SENTINEL}")
        status, observed, live = self._evaluate(stdout=leaked)
        self.assertEqual(status, harness.StageStatus.FAIL)
        self.assertFalse(live)
        self.assertNotIn(self.SENTINEL, observed)

    def test_live_run_requires_the_allowed_read_to_return_the_marker(self):
        status, _, live = self._evaluate(stdout=self._events(hello_output="1: something else"))
        self.assertEqual(status, harness.StageStatus.FAIL)
        self.assertFalse(live)

    def test_live_run_without_a_session_fails_whatever_the_exit_code(self):
        for returncode in (0, 1, 124):
            status, observed, live = self._evaluate(
                returncode=returncode, stdout="", stderr="Error: startup failed", audit_records=[],
            )
            self.assertEqual(status, harness.StageStatus.FAIL, msg=observed)
            self.assertIn("startup failed", observed)
            self.assertFalse(live)

    def test_live_run_rejects_the_marker_from_another_tool(self):
        events = [json.loads(line) for line in self._events().splitlines()]
        events[2]["part"]["tool"] = "bash"
        events[2]["part"]["state"]["input"] = {"command": "cat hello.txt"}
        stdout = "\n".join(json.dumps(event) for event in events)
        status, _, live = self._evaluate(stdout=stdout)
        self.assertEqual(status, harness.StageStatus.FAIL)
        self.assertFalse(live)

    def test_live_run_matches_whole_file_names_on_pre_events_only(self):
        lookalike = self._audit()
        lookalike[0]["paths"] = ["backup.env"]
        self.assertEqual(self._evaluate(audit_records=lookalike)[0], harness.StageStatus.FAIL)
        post = self._audit()
        post[1]["event"] = "post"
        self.assertEqual(self._evaluate(audit_records=post)[0], harness.StageStatus.FAIL)
        absolute = self._audit()
        absolute[0]["paths"] = [r"C:\Temp\iso\workspace\.env"]
        self.assertEqual(self._evaluate(audit_records=absolute)[0], harness.StageStatus.PASS)

    def test_isolation_guard_watches_the_real_opencode_config_and_plugin(self):
        with tempfile.TemporaryDirectory() as td:
            real_home = Path(td) / "real-home"
            real_home.mkdir()
            guard = harness.IsolationGuard.capture(real_home)
            for relative in (
                Path(".config") / "opencode" / "opencode.json",
                Path(".local") / "share" / "guardrail" / "guardrail" / "index.js",
            ):
                target = real_home / relative
                target.parent.mkdir(parents=True)
                target.write_text("{}\n", encoding="utf-8")
                ok, diffs = guard.verify_unchanged()
                self.assertFalse(ok)
                self.assertTrue(any(relative.as_posix() in d for d in diffs), msg=diffs)
                target.unlink()

    def test_remove_tree_deletes_read_only_files(self):
        import stat
        import windows_opencode

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            locked = root / "snapshot" / "objects" / "ab"
            locked.mkdir(parents=True)
            blob = locked / "cdef"
            blob.write_bytes(b"x")
            blob.chmod(stat.S_IREAD)
            self.assertTrue(windows_opencode.remove_tree(root))
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
