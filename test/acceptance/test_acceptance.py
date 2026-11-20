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


if __name__ == "__main__":
    unittest.main()
