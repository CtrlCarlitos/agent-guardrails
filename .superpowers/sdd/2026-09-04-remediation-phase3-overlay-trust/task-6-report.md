# Task 6 Report: Protect Operator Config

## Status

Implemented synchronized Engine and Declarative floor protection for the
operator-owned Guardrail config and waiver file.

## RED

Focused command:

```text
/usr/local/go/bin/go test ./internal/engine ./internal/genconfig -run 'TestOperatorConfigIsProtected|Test(Claude|Opencode)ConfigProtectsOperatorConfig' -v
```

The focused run failed as expected:

- Direct `Write` and `Edit` calls for both operator-config path forms returned
  the weaker out-of-repo `ask` Verdict instead of `P5.self-config` deny.
- `cp` and in-place `sed` command mutators targeting those paths were allowed.
- Claude's generated `permissions.deny` omitted both native edit patterns.
- OpenCode's generated `permission.edit` omitted both native deny patterns.

## GREEN

The same focused command passed after implementation and `gofmt`.

Complete focused package commands:

```text
/usr/local/go/bin/go test ./internal/engine
/usr/local/go/bin/go test ./internal/genconfig
```

Result: PASS.

Full-suite command, run once after implementation and self-review:

```text
make test
```

Result: PASS for all packages, including `test/adversarial`.

## Files

- `internal/engine/rules_path.go`: added `**/.config/guardrail/**` and
  `**/guardrail/waivers.toml` to `selfConfigGlobs`.
- `internal/engine/rules_path_test.go`: covered direct `Write`/`Edit`, Bash
  mutators, and allowed reads for both path forms.
- `internal/genconfig/claude.go`: added the same two patterns to
  `selfConfigGlobsFloor`.
- `internal/genconfig/claude_test.go`: verified both patterns appear as Claude
  native `Edit(...)` denies.
- `internal/genconfig/opencode_test.go`: verified both patterns appear as
  OpenCode native edit denies.
- `.superpowers/sdd/2026-09-04-remediation-phase3-overlay-trust/task-6-report.md`:
  recorded task evidence and review.

## Self-Review

- Engine and Declarative floor lists contain the same two new patterns; no
  existing pattern or Verdict was changed.
- Each pattern is independently exercised: the directory-wide pattern protects
  an arbitrary operator config file, while the narrow pattern protects
  `guardrail/waivers.toml` outside `.config`.
- File-tool coverage checks both `Write` and `Edit`; command coverage checks
  destination extraction for `cp` and in-place mutation through `sed -i`.
- Read calls still return no Verdict for these paths, preserving the existing
  write-only gate absent another rule.
- Claude and OpenCode consume the shared floor list through their generated
  native permission formats, so both deny the new paths when the Engine is
  unavailable.
- Antigravity remains unchanged because its native `hooks.json` has no
  declarative permission mechanism, as documented in ADR-0008; its Engine hook
  receives the new Engine protection while available.
- Removing either new Engine glob or either floor glob causes its corresponding
  behavioral tests to fail.
- `gofmt` and `git diff --check` completed cleanly.

## Concerns

- Antigravity cannot enforce any declarative floor when the Engine is
  unavailable because the plane exposes no native permission layer (ADR-0008).
