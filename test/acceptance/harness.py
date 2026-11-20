#!/usr/bin/env python3
"""Reusable platform acceptance harness core (#92).

Provides the stage runner contract, status taxonomy, real-home isolation guard,
local release staging, Linux PTY prompt driver, audit sanitizer, structured
report builder, and CLI entrypoint. Host- and OS-specific lifecycle adapters
register in HOST_RUNNERS.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, Optional, Sequence


EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_SKIP_PREREQ = 77


class StageStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNSUPPORTED = "unsupported"
    OPERATOR_ASSISTED = "operator_assisted"
    SKIPPED = "skipped"


@dataclass
class StageResult:
    name: str
    status: StageStatus
    expected: str
    observed: str
    duration_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "expected": self.expected,
            "observed": self.observed,
            "duration_ms": round(self.duration_ms, 2),
            "details": self.details,
            "evidence": self.evidence,
        }


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass
class PtyResult:
    returncode: int
    output: str
    timed_out: bool = False


_REDACT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----"),
    re.compile(
        r"(?i)(?:--|-)?(?:pass(?:word)?|secret|token|api[_-]?key|authorization|bearer)"
        r"[\"']?\s*[:=]\s*[\"']?(?:(?:bearer|basic)\s+)?[^\s\"']+[\"']?"
    ),
    re.compile(r"(?i)(?:authorization\s+)?bearer\s+[^\s\"']+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
)


def sanitize_text(
    text: str,
    *,
    path_replacements: Optional[Mapping[str, str]] = None,
    extra_redactions: Optional[Sequence[str]] = None,
) -> str:
    """Normalize local paths and redact secret-like tokens before reporting."""
    out = text
    if path_replacements:
        for raw_path in sorted(path_replacements.keys(), key=len, reverse=True):
            if raw_path:
                out = out.replace(raw_path, path_replacements[raw_path])
    if extra_redactions:
        for literal in extra_redactions:
            if literal:
                out = out.replace(literal, "<redacted>")
    for pattern in _REDACT_PATTERNS:
        out = pattern.sub("<redacted>", out)
    return out


def sanitize_audit_record(
    record: Mapping[str, Any],
    *,
    path_replacements: Optional[Mapping[str, str]] = None,
    extra_redactions: Optional[Sequence[str]] = None,
    provenance: str = "synthetic",
) -> dict[str, Any]:
    """Return a sanitized copy of an audit.jsonl record tagged with provenance."""
    keep_verbatim = (
        "ts",
        "call_id",
        "guardrail_version",
        "session_id",
        "plane",
        "tool",
        "native_tool",
        "capability",
        "input_shape",
        "audit_kind",
        "event",
        "decision",
        "rule_id",
        "origin_rule_id",
        "operator_action",
        "request_id",
        "transport",
        "hook_ms",
        "startup_ms",
        "input_keys",
    )
    cleaned: dict[str, Any] = {"provenance": provenance}
    for key in keep_verbatim:
        if key in record and record[key] not in (None, "", []):
            cleaned[key] = record[key]
    for text_key in ("command", "repo_root", "reason"):
        val = record.get(text_key)
        if isinstance(val, str) and val:
            cleaned[text_key] = sanitize_text(
                val,
                path_replacements=path_replacements,
                extra_redactions=extra_redactions,
            )
    paths = record.get("paths")
    if isinstance(paths, list) and paths:
        cleaned["paths"] = [
            sanitize_text(
                str(p),
                path_replacements=path_replacements,
                extra_redactions=extra_redactions,
            )
            for p in paths
        ]
    return cleaned


def read_audit_records(audit_path: Path) -> list[dict[str, Any]]:
    """Read well-formed JSONL records from audit.jsonl (empty if absent)."""
    if not audit_path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in audit_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


def summarize_stages(stages: Sequence[StageResult]) -> dict[str, Any]:
    """Count stage statuses and compute overall_pass (zero failures)."""
    counts = {status.value: 0 for status in StageStatus}
    for stage in stages:
        counts[stage.status.value] += 1
    return {
        **counts,
        "total": len(stages),
        "overall_pass": counts[StageStatus.FAIL.value] == 0,
    }


def report_exit_code(summary: Mapping[str, Any]) -> int:
    return EXIT_PASS if summary.get("overall_pass") else EXIT_FAIL


def build_report(
    *,
    plane: str,
    os_name: str,
    arch: str,
    environment: Mapping[str, Any],
    stages: Sequence[StageResult],
    audit_evidence: Sequence[Mapping[str, Any]],
    live_runtime_session_observed: bool,
) -> dict[str, Any]:
    """Assemble the schema-v1 acceptance report with explicit claim bounds."""
    summary = summarize_stages(stages)
    return {
        "schema_version": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "target": {
            "plane": plane,
            "os": os_name,
            "arch": arch,
        },
        "environment": dict(environment),
        "claims": {
            "universal_mediation_implied": False,
            "webauthn_live_validated": False,
            "live_runtime_session_observed": bool(live_runtime_session_observed),
        },
        "summary": summary,
        "stages": [stage.to_dict() for stage in stages],
        "audit_evidence": [dict(rec) for rec in audit_evidence],
    }


@dataclass(frozen=True)
class FileSnapshot:
    exists: bool
    size: int = 0
    mtime_ns: int = 0
    sha256: str = ""

    @classmethod
    def of(cls, path: Path) -> "FileSnapshot":
        if not path.exists():
            return cls(exists=False)
        stat = path.stat()
        digest = ""
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return cls(
            exists=True,
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
            sha256=digest,
        )


class IsolationGuard:
    """Snapshots real-home config files to prove the harness never mutates them."""

    WATCHED_RELATIVE_PATHS: tuple[Path, ...] = (
        Path(".gemini") / "config" / "hooks.json",
        Path(".config") / "guardrail" / "waivers.toml",
        Path(".claude") / "settings.json",
        Path(".codex") / "hooks.json",
    )

    def __init__(self, real_home: Path, snapshots: Mapping[Path, FileSnapshot]) -> None:
        self.real_home = real_home
        self.snapshots = dict(snapshots)

    @classmethod
    def capture(cls, real_home: Path) -> "IsolationGuard":
        snaps: dict[Path, FileSnapshot] = {}
        for rel in cls.WATCHED_RELATIVE_PATHS:
            snaps[rel] = FileSnapshot.of(real_home / rel)
        return cls(real_home, snaps)

    def verify_unchanged(self) -> tuple[bool, list[str]]:
        diffs: list[str] = []
        for rel, before in self.snapshots.items():
            after = FileSnapshot.of(self.real_home / rel)
            if before != after:
                diffs.append(
                    f"{rel.as_posix()}: before(exists={before.exists}, size={before.size}) "
                    f"!= after(exists={after.exists}, size={after.size})"
                )
        return (len(diffs) == 0, diffs)


def stage_local_release(
    *,
    releases_root: Path,
    version: str,
    binary_path: Path,
    os_name: str,
    arch: str,
) -> tuple[Path, Path]:
    """Stage one release binary + SHA256SUMS in install.sh's --base-url layout."""
    asset = f"guardrail_{os_name}_{arch}"
    if os_name == "windows":
        asset += ".exe"
    version_dir = releases_root / version
    version_dir.mkdir(parents=True, exist_ok=True)
    dest = version_dir / asset
    data = binary_path.read_bytes()
    dest.write_bytes(data)
    if os.name != "nt":
        dest.chmod(0o755)
    digest = hashlib.sha256(data).hexdigest()
    sums_path = version_dir / "SHA256SUMS"
    sums_path.write_text(f"{digest}  {asset}\n", encoding="utf-8", newline="\n")
    return dest, sums_path


def run_cmd(
    cmd: Sequence[str],
    *,
    env: Optional[Mapping[str, str]] = None,
    cwd: Optional[Path] = None,
    stdin_text: Optional[str] = None,
    timeout: int = 60,
) -> CommandResult:
    """Execute a subprocess cleanly without inheriting the operator's stdin."""
    try:
        proc = subprocess.run(
            list(cmd),
            env=dict(env) if env is not None else None,
            cwd=str(cwd) if cwd is not None else None,
            input=stdin_text,
            stdin=subprocess.DEVNULL if stdin_text is None else None,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CommandResult(proc.returncode, proc.stdout, proc.stderr, timed_out=False)
    except subprocess.TimeoutExpired as exc:
        def _decode(val: Any) -> str:
            if val is None:
                return ""
            if isinstance(val, bytes):
                return val.decode("utf-8", errors="replace")
            return str(val)

        return CommandResult(
            124,
            _decode(exc.stdout),
            _decode(exc.stderr) + f"\nharness: timed out after {timeout}s\n",
            timed_out=True,
        )


def run_in_pty(
    cmd: Sequence[str],
    *,
    env: Optional[Mapping[str, str]] = None,
    cwd: Optional[Path] = None,
    prompt_responses: Optional[Sequence[tuple[str, str]]] = None,
    timeout: int = 30,
) -> PtyResult:
    """Run a command attached to a real POSIX PTY and answer configured prompts."""
    if os.name == "nt":
        raise NotImplementedError("run_in_pty is POSIX-only")
    import pty  # noqa: PLC0415

    master_fd, slave_fd = pty.openpty()
    pending = list(prompt_responses or [])
    answered_idx = 0
    chunks: list[str] = []
    timed_out = False

    try:
        proc = subprocess.Popen(
            list(cmd),
            env=dict(env) if env is not None else None,
            cwd=str(cwd) if cwd is not None else None,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            start_new_session=True,
            close_fds=True,
        )
    except Exception:
        os.close(master_fd)
        os.close(slave_fd)
        raise

    os.close(slave_fd)
    deadline = time.monotonic() + timeout

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break

            ready, _, _ = select.select([master_fd], [], [], min(0.2, remaining))
            if ready:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    # On Linux, reading the master PTY after the slave closes raises EIO.
                    break
                if not data:
                    break
                chunks.append(data.decode("utf-8", errors="replace"))
                combined = "".join(chunks)
                while answered_idx < len(pending):
                    needle, reply = pending[answered_idx]
                    if needle in combined:
                        os.write(master_fd, reply.encode("utf-8"))
                        answered_idx += 1
                    else:
                        break
            elif proc.poll() is not None:
                # Drain any buffered bytes after process exit.
                while True:
                    r2, _, _ = select.select([master_fd], [], [], 0.05)
                    if not r2:
                        break
                    try:
                        data = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    chunks.append(data.decode("utf-8", errors="replace"))
                break

        try:
            rc = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            rc = 124
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    if timed_out and rc == 0:
        rc = 124
    return PtyResult(returncode=rc, output="".join(chunks), timed_out=timed_out)


def normalized_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return machine


def run_stage(
    name: str,
    fn: Callable[[], StageResult],
) -> StageResult:
    """Measure a stage's duration and turn unexpected exceptions into FAIL results."""
    start = time.monotonic()
    try:
        res = fn()
    except Exception as exc:  # pragma: no cover - defensive fallback
        res = StageResult(
            name=name,
            status=StageStatus.FAIL,
            expected="stage completes without unhandled error",
            observed=f"unhandled {type(exc).__name__}: {exc}",
        )
    res.duration_ms = (time.monotonic() - start) * 1000.0
    return res


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Guardrail platform acceptance harness (#92)."
    )
    parser.add_argument(
        "--host",
        default="antigravity",
        choices=("antigravity",),
        help="Target host plane to exercise (default: antigravity).",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run the opt-in live host runtime mediation stage (invokes real host CLI).",
    )
    parser.add_argument(
        "--live-auth-from",
        type=Path,
        default=None,
        help=(
            "Optional path to a disposable host state dir whose non-hook auth state "
            "may be copied into the isolated home for --live runs."
        ),
    )
    parser.add_argument(
        "--v1-binary",
        type=Path,
        default=None,
        help="Optional prebuilt Guardrail v1 binary (default: built from repo).",
    )
    parser.add_argument(
        "--v2-binary",
        type=Path,
        default=None,
        help="Optional prebuilt Guardrail v2 binary (default: built from repo).",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Write sanitized JSON report to this path (also printed to stdout).",
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Retain the isolated temp workspace after the run for inspection.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.host == "antigravity":
        import linux_antigravity  # noqa: PLC0415

        code, report = linux_antigravity.run_linux_antigravity_acceptance(
            live=args.live,
            live_auth_from=args.live_auth_from,
            v1_binary=args.v1_binary,
            v2_binary=args.v2_binary,
            keep_artifacts=args.keep_artifacts,
        )
    else:
        print(f"unsupported host: {args.host}", file=sys.stderr)
        return EXIT_SKIP_PREREQ

    if report is not None:
        encoded = json.dumps(report, indent=2, sort_keys=False) + "\n"
        if args.report is not None:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(encoded, encoding="utf-8", newline="\n")
        sys.stdout.write(encoded)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
