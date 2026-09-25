import json
import unittest

from codex_execution_contract import summarize_case, contract_cases


class ExecutionContractTests(unittest.TestCase):
    def setUp(self):
        self.case = {"id": "call_0", "args": {"cmd": "echo GR_EXEC_0", "workdir": "/other", "shell": "/bin/sh"}, "marker": "GR_EXEC_0"}
        self.event = {"hook_event_name": "PreToolUse", "tool_use_id": "call_0", "tool_name": "Bash", "cwd": "/session", "tool_input": {"command": "echo GR_EXEC_0"}}

    def test_omitted_shell_and_workdir_are_not_inferred_from_request(self):
        result = summarize_case(self.case, [self.event], "GR_EXEC_0\n/other")
        self.assertTrue(result["executed"])
        self.assertEqual(result["hook_count"], 1)
        self.assertFalse(result["execution_context_available"])
        self.assertEqual(result["hook_input"], self.event)

    def test_error_mentioning_command_is_not_execution(self):
        result = summarize_case(self.case, [self.event], "Command blocked: echo GR_EXEC_0")
        self.assertFalse(result["executed"])

    def test_code_mode_json_output_is_decoded_before_matching(self):
        result = summarize_case(self.case, [self.event], json.dumps({"output": "GR_EXEC_0\n/other", "exit_code": 0}))
        self.assertTrue(result["executed"])

    def test_code_mode_wrapper_and_host_generated_id(self):
        event = {**self.event, "tool_use_id": "exec-generated-id"}
        output = "Script completed\nWall time 0.7 seconds\nOutput:\n\n" + json.dumps({"output": "GR_EXEC_0\n/other", "exit_code": 0})
        result = summarize_case(self.case, [event], output, code_mode=True)
        self.assertTrue(result["executed"])
        self.assertTrue(result["dispatch_complete"])
        self.assertEqual(result["hook_input"]["tool_use_id"], "exec-generated-id")

    def test_code_mode_duplicate_events_in_one_request_window_fail(self):
        event = {**self.event, "tool_use_id": "exec-generated-id"}
        result = summarize_case(self.case, [event, event], "GR_EXEC_0", code_mode=True)
        self.assertFalse(result["dispatch_complete"])

    def test_missing_or_duplicate_dispatch_is_not_healthy(self):
        for events in ([], [self.event, self.event]):
            result = summarize_case(self.case, events, "GR_EXEC_0")
            self.assertFalse(result["dispatch_complete"])

    def test_unrelated_post_event_is_not_pre_dispatch(self):
        post = {**self.event, "hook_event_name": "PostToolUse"}
        result = summarize_case(self.case, [post], "GR_EXEC_0")
        self.assertEqual(result["hook_count"], 0)

    def test_model_arguments_are_not_host_execution_metadata(self):
        event = {**self.event, "tool_input": {"command": "echo GR_EXEC_0", "shell": "/bin/sh", "workdir": "/other"}}
        result = summarize_case(self.case, [event], "GR_EXEC_0")
        self.assertFalse(result["execution_context_available"])

    def test_cases_compare_identical_text_across_directories_and_shells(self):
        cases = contract_cases("/session", "/session/space dir", ["/bin/bash", "/bin/sh"])
        self.assertEqual(len(cases), 6)
        self.assertEqual(len({case["args"]["cmd"] for case in cases}), 1)
        self.assertEqual({case["args"]["workdir"] for case in cases}, {"/session", "/session/space dir"})
        self.assertEqual(len({case["id"] for case in cases}), 6)


if __name__ == "__main__":
    unittest.main()
