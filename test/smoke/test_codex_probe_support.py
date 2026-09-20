import sys
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import codex_probe_support as support


class CodexProbeSupportTests(unittest.TestCase):
    @staticmethod
    def temporary_directory(prefix="probe-"):
        parent = Path(__file__).resolve().parent / ".test-tmp"
        parent.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(prefix=prefix, dir=parent)

    def test_windows_wrapper_is_cmd_and_uses_current_interpreter(self):
        with self.temporary_directory(prefix="guardrail probe % path ") as raw:
            root = Path(raw)
            wrapper = support.write_guardrail_wrapper(
                root,
                Path(r"C:\Program Files\Guardrail\guardrail.exe"),
                root / "hooks.jsonl",
                windows=True,
                python_executable=Path(sys.executable),
            )
            self.assertEqual(wrapper.suffix, ".cmd")
            command = wrapper.read_text(encoding="utf-8")
            self.assertIn(f'"{str(Path(sys.executable)).replace("%", "%%")}"', command)
            self.assertIn("%*", command)
            self.assertNotIn("python3", command)
            self.assertTrue(wrapper.with_suffix(".py").is_file())

    def test_posix_wrapper_uses_current_interpreter_not_python3(self):
        with self.temporary_directory() as raw:
            wrapper = support.write_guardrail_wrapper(
                Path(raw),
                Path("/opt/Guard Rail/guardrail"),
                Path(raw) / "hooks.jsonl",
                windows=False,
                python_executable="/opt/Python Current/python",
            )
            command = wrapper.read_text(encoding="utf-8")
            self.assertTrue(command.startswith("#!/bin/sh\nexec "))
            self.assertIn("'/opt/Python Current/python'", command)
            self.assertNotIn("python3", command)

    def test_toml_escapes_windows_paths_and_uses_sys_executable(self):
        rendered = support.render_codex_config(
            catalog_path=Path(r"C:\Users\Agent User\probe\model-catalog.json"),
            server_port=1234,
            restricted=False,
            python_executable=Path(r"C:\Program Files\Python\python.exe"),
            mcp_script=Path(r"C:\repo\test\fixtures\codex\mcp_server.py"),
            mcp_marker=Path(r"C:\Temp\probe marker"),
        )
        parsed = tomllib.loads(rendered)
        self.assertEqual(parsed["model_catalog_json"], r"C:\Users\Agent User\probe\model-catalog.json")
        self.assertEqual(parsed["mcp_servers"]["fixture"]["command"], r"C:\Program Files\Python\python.exe")
        self.assertEqual(parsed["mcp_servers"]["fixture"]["args"][1], r"C:\Temp\probe marker")

    def test_windows_interactive_control_uses_ctrl_z_not_ctrl_d(self):
        command, eof = support.interactive_probe_controls(windows=True)
        self.assertIn("$input | Set-Content", command)
        self.assertNotIn("cmd.exe", command.lower())
        self.assertEqual(eof, "\x1a\r\n")
        self.assertNotIn("\x04", eof)
        self.assertEqual(support.interactive_probe_controls(windows=False), ("cat > stdin.txt", "\x04"))

    def test_windows_command_resolution_skips_extensionless_posix_shim(self):
        paths = {
            "codex": r"C:\npm\codex",
            "codex.cmd": r"C:\npm\codex.cmd",
        }
        resolved = support.resolve_command("codex", windows=True, which=paths.get)
        self.assertEqual(resolved, r"C:\npm\codex.cmd")

    def test_timeout_becomes_a_reportable_completed_process(self):
        def timeout(*_, **__):
            raise subprocess.TimeoutExpired(["codex"], 180, output=b"partial", stderr=b"waiting")

        result = support.run_probe_command(["codex"], env={}, timeout=180, run=timeout)
        self.assertEqual(result.returncode, 124)
        self.assertEqual(result.stdout, "partial")
        self.assertIn("timed out after 180s", result.stderr)
        self.assertEqual(support.probe_timeout(windows=True), 180)
        self.assertEqual(support.probe_timeout(windows=False), 90)


if __name__ == "__main__":
    unittest.main()
