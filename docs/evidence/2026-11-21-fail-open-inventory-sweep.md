# Fail-open inventory sweep (2026-11-15 baseline + 2026-11-21 delta at `87dfe09`)

## Claim

Every allow-on-missing, unparsed, or uninvoked path across `internal/` and `cmd/` at `87dfe09` is either justified by an accepted ADR or fixed with a regression test — including the newly discovered `applyWorktreeProvenance` compound-command / `-C` / redirection bypass (O4) closed in this sweep.

## Context

- Guardrail: `main` at `3573078` (2026-11-15 baseline sweep) through `87dfe09` (2026-11-21 Windows delta sweep)
- Runtime / plane: Claude Code, OpenCode (`v2.3.2`), Antigravity (`agy 1.5.11`), Codex (`codex-cli 0.170.0`)
- OS / shell: Windows 11 (`LAB-DOT-WIN-HOM`, Go `1.26`, `pwsh`) and Linux/macOS CI

## Method

1. Grepped every non-test `policy.Allow` return in `internal/` and `cmd/` (`git grep -n "policy\.Allow" -- internal/ cmd/ ":!*_test.go"`) and audited every commit touching `internal/` and `cmd/` since the 2026-11-15 sweep (`git log --oneline 3573078..87dfe09 -- internal/ cmd/`).
2. Re-ran the `#146` binary-replacement engine tests and Codex `write_stdin` contract/adapter tests on Windows:
   ```
   go test -v ./internal/engine/ -run "EnforcementBinary|BinaryReplace|KeptPreviousBinary|NamingTheBinary|InstallingGuardrailOver" -count=1
   go test -v ./internal/adapter/ -run TestCodex -count=1
   ```
3. Probed `applyWorktreeProvenance` (ADR-0039, `#638`) through the real Claude hook (`TestWindowsAndPOSIXSessionCreatedWorktreeRemoval`) with compound commands, variable expansions, redirections, environment overrides, and `git -C <otherRepo>`.

## Observation

### Baseline sweep (2026-11-15, `3573078`) — all closed

- **O1** (`internal/adapter/claude.go`): Claude `permission_mode: "auto"` was not treated as host-auto-approving → fixed in PR #578 (`eb02ac6`).
- **O2** (`internal/engine/evaluate.go`): unknown Antigravity native tools allowed under audit posture → fixed in PR #579 (`17f733d`).
- **O3** (`cmd/guardrail/daemon.go`): engine-daemon fast path swallowed overlay/operator load errors and skipped P7 trifecta & degraded-allow recording → fixed in PR #580 (`31998f0`).
- **Justified defaults without ADR**: unmatched parsed commands and `CapabilitySafeControl` tools → recorded in [ADR-0036](../adr/0036-unmatched-commands-and-safe-control-allow.md) (PR #581, `e3edb7b`).
- **Codex native floor drift**: `planeFloorDrift` did not diagnose `rules/guardrail.rules` independently → fixed in PR #582 (`9a6c04c`).

### Checklist items re-verified on Windows (2026-11-20 & 2026-11-21)

- **#149 (Claude Windows hook quoting)** & **#111 (PowerShell cmdlet rules)**: closed and covered by `TestWindows…` suites.
- **#146 (binary replacement via `Copy-Item` / POSIX writes / deletes)**: 10/10 engine tests PASS on Windows (`ok github.com/CtrlCarlitos/agent-guardrails/internal/engine 0.862s`). Defender exclusion scoping belongs to the dotfiles repo.
- **Codex Windows `PreToolUse` dispatch**: verified live on Windows 11 with `codex-cli 0.170.0` (2026-11-20, session `01a1f77d-761a-7cd0-8f30-6bb8c61d604a`, real `plane=codex` audit record written via `commandWindows` PowerShell → `guardrail-hook.cmd` → `guardrail.exe`).
- **Codex `write_stdin`**: remains fail-closed `CapabilityDeny` (`internal/planecontract/codex.go:19`, `internal/adapter/codex.go:125`, `TestCodex` PASS on Windows). Any future Codex pre-delivery hook or child-mediation proof is tracked separately in #587.

### Delta sweep finding O4 (2026-11-21, `87dfe09`) — RED measured before fix

`cmd/guardrail/provenance.go`'s `commandArgv` walked only the first `*syntax.CallExpr` and ignored redirections, env overrides, `-C` directory shifts, and non-literal parts. Measured RED output on `TestWindowsAndPOSIXSessionCreatedWorktreeRemoval`:

```
--- FAIL: TestWindowsAndPOSIXSessionCreatedWorktreeRemoval/compound_command_smuggling_second_worktree_remove
    provenance_test.go:122: decision=""; compound worktree remove must not inherit provenance allow
--- FAIL: TestWindowsAndPOSIXSessionCreatedWorktreeRemoval/compound_command_smuggling_another_ask
    provenance_test.go:131: decision=""; compound command with git branch -D must not inherit provenance allow
--- FAIL: TestWindowsAndPOSIXSessionCreatedWorktreeRemoval/git_-C_into_another_repo_must_not_match_cwd_creation
    provenance_test.go:150: decision=""; git -C into a different repo must not match cwd provenance
--- FAIL: TestWindowsAndPOSIXSessionCreatedWorktreeRemoval/redirection_or_env_override_on_remove_must_not_inherit_provenance
    provenance_test.go:163: "git worktree remove .worktrees/feat > out.txt": decision=""; want ask
```

Every other `policy.Allow` site added since `3573078` (`night.State.Matches` #83, `TrustSnapshot` #131, `proof.json` #110, `delivery` #610/#633, `agy 1.5.x` #650, inline literal interpreter #635) failed closed as designed.

## Consequence

Tightened `cmd/guardrail/provenance.go` (`simpleCommandArgv`, `staticWordText`, `worktreeTarget`) so ADR-0039 worktree provenance relaxes only a single, simple, un-redirected, assignment-free, static-literal `git [-C dir] worktree remove [-f|--force] [--] <path>` call resolved against its effective `-C` directory, and wired `applyWorktreeProvenance` before audit recording on the daemon path (`cmd/guardrail/daemon.go`) for audit parity. Pinned with 7 new subtests in `TestWindowsAndPOSIXSessionCreatedWorktreeRemoval`.

## Links

- Issue: #151 (closes umbrella inventory; remaining Codex child-mediation proof tracked in #587)
- Prior PRs: #578, #579, #580, #581, #582, #388, #400, #638
- ADRs: [ADR-0014](../adr/0014-codex-native-hooks-and-blocked-asks.md), [ADR-0022](../adr/0022-degraded-mode-floor-fallback.md), [ADR-0028](../adr/0028-settings-files-are-user-owned-hooks-only.md), [ADR-0036](../adr/0036-unmatched-commands-and-safe-control-allow.md), [ADR-0039](../adr/0039-session-provenance-worktree-cleanup.md)
