"""Cross-platform construction helpers for the deterministic Codex probe."""

import json
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
from typing import Optional, Tuple


def resolve_command(name: str, *, windows: bool, which=shutil.which) -> Optional[str]:
    """Resolve a command, preferring launchable Windows file extensions."""
    candidates = [name]
    if windows:
        candidates = [name + suffix for suffix in (".exe", ".cmd", ".bat", ".com")] + [name]
    for candidate in candidates:
        resolved = which(candidate)
        if resolved:
            return resolved
    return None


def probe_timeout(*, windows: bool) -> int:
    """Allow for Windows process and Defender startup overhead."""
    return 180 if windows else 90


def run_probe_command(command, *, env, timeout: int, run=subprocess.run):
    """Run Codex and turn a timeout into inspectable retained evidence."""
    try:
        return run(
            command,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        def text(value):
            if value is None:
                return ""
            if isinstance(value, bytes):
                return value.decode(errors="replace")
            return value

        return subprocess.CompletedProcess(
            command,
            124,
            stdout=text(error.stdout),
            stderr=text(error.stderr) + f"\nguardrail probe: Codex timed out after {timeout}s\n",
        )


def toml_string(value: object) -> str:
    """Return a TOML basic string with Windows backslashes escaped."""
    return json.dumps(str(value), ensure_ascii=False)


def write_guardrail_wrapper(
    root: Path,
    binary: Path,
    log: Path,
    *,
    windows: bool,
    python_executable: Optional[object] = None,
) -> Path:
    """Write an inspectable Python logger plus an OS-native launcher."""
    interpreter = str(python_executable or sys.executable)
    script = root / "guardrail-probe.py"
    script.write_text(
        "import json\n"
        "from pathlib import Path\n"
        "import subprocess\n"
        "import sys\n"
        f"BINARY = {str(Path(binary).resolve())!r}\n"
        f"LOG = {str(Path(log).resolve())!r}\n"
        "raw = sys.stdin.buffer.read()\n"
        "process = subprocess.run([BINARY, *sys.argv[1:]], input=raw, capture_output=True)\n"
        "entry = {'input': json.loads(raw), 'exit': process.returncode, "
        "'stderr': process.stderr.decode(errors='replace')}\n"
        "with Path(LOG).open('a', encoding='utf-8', newline='') as stream:\n"
        "    stream.write(json.dumps(entry) + '\\n')\n"
        "sys.stdout.buffer.write(process.stdout)\n"
        "sys.stderr.buffer.write(process.stderr)\n"
        "raise SystemExit(process.returncode)\n",
        encoding="utf-8",
        newline="\n",
    )

    if windows:
        wrapper = root / "guardrail-probe.cmd"
        # Percent signs in literal batch paths must be doubled. Delayed
        # expansion is never enabled, so exclamation marks remain data.
        python_arg = interpreter.replace("%", "%%")
        script_arg = str(script.resolve()).replace("%", "%%")
        wrapper.write_text(
            f'@echo off\r\n"{python_arg}" "{script_arg}" %*\r\nexit /b %errorlevel%\r\n',
            encoding="utf-8",
            newline="",
        )
        return wrapper

    wrapper = root / "guardrail-probe"
    wrapper.write_text(
        "#!/bin/sh\nexec "
        + shlex.quote(interpreter)
        + " "
        + shlex.quote(str(script.resolve()))
        + ' "$@"\n',
        encoding="utf-8",
        newline="\n",
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return wrapper


def render_codex_config(
    *,
    catalog_path: Path,
    server_port: int,
    restricted: bool,
    python_executable: Path,
    mcp_script: Path,
    mcp_marker: Path,
) -> str:
    """Render the disposable Codex config with TOML-safe absolute paths."""
    return f'''model = "codex-fixture"
web_search = "{'disabled' if restricted else 'cached'}"
model_provider = "fixture"
model_catalog_json = {toml_string(catalog_path)}
[model_providers.fixture]
name = "Deterministic local fixture"
base_url = "http://127.0.0.1:{server_port}/v1"
wire_api = "responses"
requires_openai_auth = false
[features]
shell_snapshot = false
shell_tool = {'false' if restricted else 'true'}
[mcp_servers.fixture]
command = {toml_string(python_executable)}
args = [{toml_string(mcp_script)}, {toml_string(mcp_marker)}]
'''


def interactive_probe_controls(*, windows: bool) -> Tuple[str, str]:
    """Return an interactive capture command and the host's terminal EOF input."""
    if windows:
        return ("$input | Set-Content stdin.txt", "\x1a\r\n")
    return ("cat > stdin.txt", "\x04")
