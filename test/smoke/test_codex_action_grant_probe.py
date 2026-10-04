import unittest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from codex_action_grant_probe import pre_hook_decisions, post_hook_feedback, native_hook_findings


class NativeVerdictTests(unittest.TestCase):
    def test_generated_windows_hooks_do_not_require_parent_environment_flag(self):
        deny = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}'
        pre = [{"exit": 0, "stdout": deny if blocked else ""} for blocked in (True, True, False, True, False, True)]
        post = [{"exit": 0, "stdout": '{"decision":"block","reason":"malformed.go"}'}]
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            (workspace / "malformed.go").write_text("this is not go\n")
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(native_hook_findings(pre, post, windows=True, workspace=workspace), [])

    def test_post_feedback_uses_selected_transport(self):
        self.assertTrue(post_hook_feedback({"exit": 2, "stderr": "malformed.go"}, structured=False))
        self.assertTrue(post_hook_feedback({"exit": 0, "stdout": '{"decision":"block","reason":"malformed.go"}'}, structured=True))
        self.assertFalse(post_hook_feedback({"exit": 0, "stderr": "malformed.go", "stdout": '{}'}, structured=True))

    def test_exit_status_transport(self):
        self.assertEqual(pre_hook_decisions([{"exit": code} for code in (2, 2, 0, 2, 0, 2)], structured=False),
                         ["deny", "deny", "allow", "deny", "allow", "deny"])

    def test_structured_transport_requires_explicit_deny(self):
        deny = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}'
        self.assertEqual(pre_hook_decisions([{"exit": 0, "stdout": deny}, {"exit": 0, "stdout": ""}], structured=True),
                         ["deny", "allow"])

    def test_invalid_output_never_counts_as_allow(self):
        for value in ('{', '{"hookSpecificOutput":{"permissionDecision":"ask"}}', '{}'):
            self.assertEqual(pre_hook_decisions([{"exit": 0, "stdout": value}], structured=True), ["invalid"])


if __name__ == "__main__":
    unittest.main()
