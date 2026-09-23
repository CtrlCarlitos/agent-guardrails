# Reset Phase 1 Execution & Verification Checklist

Operational runbook for the operator executing Phase 1 of [ADR-0028](adr/0028-settings-files-are-user-owned-hooks-only.md) (Hard Reset: settings files go hooks-only; policy lives in Engine).

> [!IMPORTANT]
> **Do not edit `OPERATIONS.md`.** That file is being actively edited by Codex (#2) for the grant ceremony. This standalone checklist guides the Phase 1 execution without merge collisions.

---

## 1. Principles & Context

As recorded in [ADR-0028](adr/0028-settings-files-are-user-owned-hooks-only.md) and consolidated in [#282](https://github.com/CtrlCarlitos/agent-guardrails/issues/282):
1. **Settings files belong to the user.**
2. **The machinery is the guardrail.** Enforcement lives in the Engine; hooks route tool calls to the Engine.
3. **Guardrail-owned writes to settings are the exception** and must be minimal, small, and stable (hook registrations only).
4. **Antigravity is the working existence proof**: zero floor, `matcher: "*"` in hooks, >27,000 evaluations in production with zero drift.
5. **The loud-outage posture replaces silent floor coverage**: when the Engine cannot be reached, the outage must be prominently announced, not masked by drifting, incomplete static rules.

---

## 2. Preconditions & Gate Check

Before retiring declarative floor entries on any plane, verify all prerequisites:

- [ ] **P0: Rulings recorded (#282)**:
  - M1 approved (cwd/parent/repo-root deletion semantic).
  - M3 refined (`gh auth logout` gets an ask; login/refresh without scope flags remain deliberate #228 divergence).
  - M4 (`dd` non-device) and C1 (`git clean --dry-run`) retired as coarse-floor false positives.
  - Codex confirmed as the named exception plane (floor stays primary).
- [ ] **P1: Engine gains M1**:
  - Semantic working-tree deletion rule landed in Engine ([PR #288](https://github.com/CtrlCarlitos/agent-guardrails/pull/288)).
  - Denies recursive/forced `rm` where target resolves to cwd, parent of cwd, ancestor of cwd, or repo root.
  - Subdirectory deletions within cwd and safe-root siblings remain permitted.
  - **P1 gates every retirement phase.**
- [ ] **P2: Engine gains M2** (Required for Phase C / Claude):
  - `gh ssh-key add|delete` and `gh gpg-key add|delete` ask in the Engine.
  - Durable account-level access must not depend on argument path spelling.
- [ ] **Loud-Outage Posture Available**:
  - Engine health check implemented in `cmd/guardrail/engine_health.go`.
  - `doctor` reports `engine health: reachable (self-spawn ok)`.
  - `SessionStart` hook carries `engineHealthPosture` advisory.

---

## 3. Plane Retirement Overview

| Phase | Plane | Action | Prerequisites | Outage Posture |
|---|---|---|---|---|
| **A** | **Antigravity** | None (already hooks-only) | None (ADR-0008) | Loud advisory / unmediated |
| **B** | **OpenCode** | Retire all 218 deployed entries | P1 + Posture acceptance | Bash fails closed; reads/edits ungated |
| **C** | **Claude Code** | Retire all 243 generated entries | P1 + P2 + Posture acceptance | Ungated window (#151 accepted exposure) |
| **D** | **Codex** | **EXCLUDED — floor stays indefinitely** | Doctor-observed hook dispatch | Native floor primary (openai/codex#24453) |

> **Planes retire independently.** Do not batch them into a single monolithic switch. Execute Phase B (OpenCode) first, verify, then execute Phase C (Claude).

---

## 4. Phase B: OpenCode Runbook

OpenCode retires first. Its missing-rules list is completely empty (100% covered by the Engine).

### 4.1 Recorded Posture Acceptance
- **Mode 1 (Engine alive)**: Engine governs; floor was already inert.
- **Mode 2 (Engine unreachable, plugin alive)**: Bash tool calls fail closed via the plugin regardless of floor. With floor retired, `read` and `edit` tool calls proceed **ungated** during the outage window. The operator accepts this window deliberately.
- **Mode 3 (Plugin missing/broken)**: Integration explicitly disabled by operator.

### 4.2 Configuration File Coordinates
- **Linux / macOS**: `~/.config/opencode/opencode.json` (or `$XDG_CONFIG_HOME/opencode/opencode.json`)
- **Windows**: `%USERPROFILE%\.config\opencode\opencode.json`
- **Plugin binary**: `~/.local/share/guardrail/guardrail.js` (or `$XDG_DATA_HOME/guardrail/guardrail.js`)

### 4.3 Step-by-Step Execution

1. **Backup existing config**:
   ```bash
   cp ~/.config/opencode/opencode.json ~/.config/opencode/opencode.json.bak
   ```
2. **Inspect pre-reset state**:
   ```bash
   guardrail doctor
   ```
   *Expected report*:
   ```text
   opencode settings: guardrail integration registered
   engine health: reachable (self-spawn ok)
   ```
3. **Edit `opencode.json`**:
   Remove the entire `"permission"` dictionary (`bash`, `read`, `edit`). Retain only user settings and the `"plugin"` array:
   ```json
   {
     "$schema": "https://opencode.ai/config.json",
     "plugin": [
       "/home/username/.local/share/guardrail/guardrail.js"
     ]
   }
   ```
   *(On Windows, use the appropriate `%USERPROFILE%` path).*

4. **Verify with `guardrail doctor`**:
   ```bash
   guardrail doctor
   ```
   *Expected report*:
   - `opencode settings: guardrail integration registered` (verifies plugin is present and registered).
   - `engine health: reachable (self-spawn ok)`.
   - No warnings about unparseable config.

5. **Verify runtime enforcement**:
   Start an OpenCode session:
   - Run a safe command (`git status`): allowed.
   - Run a destructive command (`rm -rf .`): denied by M1 (`P1.rm-rf`).
   - Attempt to read a secret (`cat ~/.ssh/id_ed25519`): denied by `P4.secret-path`.

6. **Verify `guardrail selftest`**:
   ```bash
   guardrail selftest
   ```
   *Expected*: All probes pass.

### 4.4 Rollback Procedure (OpenCode)
If any regression or unexpected tool failure occurs:
```bash
# Option 1: Restore backup file
cp ~/.config/opencode/opencode.json.bak ~/.config/opencode/opencode.json

# Option 2: Regenerate via lifecycle
guardrail plane enable opencode
```

---

## 5. Phase C: Claude Code Runbook

Claude Code retires second, after M1 and M2 are in the Engine.

### 5.1 Recorded Posture Acceptance
- **Claude Code hook spawn failure (#151)**: Claude Code silently no-ops a failed hook spawn. During an Engine outage, tool calls proceed ungated until the Engine is restored.
- The operator consciously accepts this bounded window in exchange for minimal, user-owned settings files.
- The **loud-outage posture** ensures that outages are announced at `SessionStart` rather than masked.

### 5.2 Configuration File Coordinates
- **Linux / macOS**: `~/.claude/settings.json`
- **Windows**: `%USERPROFILE%\.claude\settings.json`

### 5.3 Step-by-Step Execution

1. **Backup existing config**:
   ```bash
   cp ~/.claude/settings.json ~/.claude/settings.json.bak
   ```
2. **Inspect pre-reset state**:
   ```bash
   guardrail doctor
   ```
   *Expected report*:
   ```text
   claude settings: guardrail hook registered
   engine health: reachable (self-spawn ok)
   ```
3. **Edit `settings.json`**:
   Remove the `"permissions"` dictionary (`allow`, `deny`, `ask`). Retain user-owned preferences and the 3 guardrail hook entries:
   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "id": "guardrail-claude-pre",
           "matcher": "*",
           "hooks": [
             {
               "type": "command",
               "command": "guardrail hook claude",
               "timeout": 10
             }
           ]
         }
       ],
       "PostToolUse": [
         {
           "id": "guardrail-claude-post",
           "matcher": "Write|Edit|MultiEdit",
           "hooks": [
             {
               "type": "command",
               "command": "guardrail hook claude"
             }
           ]
         }
       ],
       "SessionStart": [
         {
           "id": "guardrail-claude-session-start",
           "matcher": "startup|clear|compact",
           "hooks": [
             {
               "type": "command",
               "command": "guardrail hook claude"
             }
           ]
         }
       ]
     }
   }
   ```
   *(Preserve user preferences like theme, model, editor settings, or custom tools).*

4. **Verify with `guardrail doctor`**:
   ```bash
   guardrail doctor
   ```
   *Expected report*:
   - `claude settings: guardrail hook registered`
   - `engine health: reachable (self-spawn ok)`
   - No unmarked hook warnings.

5. **Verify `SessionStart` behavior**:
   - **Healthy Engine**: Start a new Claude session (`claude`). The `SessionStart` posture should be completely silent.
   - **Simulated Outage**: Temporarily rename or invalidate the binary path in a test environment. Start a session:
     ```text
     GUARDRAIL IS NOT ENFORCING. The engine could not be started (...), and this plane
     does not fail closed when its hook cannot run — it silently proceeds. For the rest of
     this session, tool calls are running UNGATED: destructive commands, secret-tier reads,
     out-of-repo writes and self-config edits are all unchecked, and nothing is being
     recorded in the audit log.
     ...
     ```

6. **Verify runtime enforcement**:
   - `rm -rf .`: denied by Engine (`P1.rm-rf` / M1).
   - `cat ~/.ssh/id_rsa`: denied by Engine (`P4.secret-path`).
   - `guardrail fetch <url>`: allowed by egress policy.

7. **Verify `guardrail selftest`**:
   ```bash
   guardrail selftest --evidence claude
   ```
   *Expected*: Probes pass and mediation evidence confirms active session enforcement.

### 5.4 Rollback Procedure (Claude)
If any regression or unmediated leakage occurs:
```bash
# Option 1: Restore backup file
cp ~/.claude/settings.json.bak ~/.claude/settings.json

# Option 2: Regenerate via lifecycle
guardrail plane enable claude
```

---

## 6. Phase A: Antigravity (Already at Target)

- **Status**: Running hook-only with zero floor entries since [ADR-0008](adr/0008-antigravity-no-declarative-floor.md).
- **Config**: `%USERPROFILE%\.gemini\config\hooks.json` (or `~/.gemini/config/hooks.json`).
- **Hook matcher**: `matcher: "*"` for `PreToolUse`.
- **Action**: No configuration edits required.
- **Verification**:
  ```bash
  guardrail doctor
  guardrail selftest
  ```
  *Expected*: `antigravity settings: guardrail integration registered`, 7/7 selftest probes pass.

---

## 7. Phase D: Codex (The Named Exception Plane)

> [!WARNING]
> **DO NOT RETIRE CODEX'S FLOOR.**
> Codex is excluded from floor retirement per ADR-0028 § "Codex: the exception plane".

### 7.1 Reason for Exception
- Pre-hooks do not dispatch on Windows ([openai/codex#24453](https://github.com/openai/codex/issues/24453)).
- `guardrail doctor --codex-hooks` reports `runtime dispatch observed: no` and `runtime coverage claim: none`.
- Codex's 32-rule native floor at `~/.codex/rules/guardrail.rules` is deployed byte-identical to `CodexRules()` and is the **only command enforcement** on Windows.
- Removing Codex's floor would leave the plane completely unmediated.

### 7.2 Measurable Retirement Condition
Codex floor retirement is gated on a **measurable condition, not a calendar date**:
1. Upstream issue #24453 is resolved by OpenAI.
2. `guardrail doctor --codex-hooks` observes live runtime dispatch:
   ```text
   runtime dispatch observed: yes
   ```
3. Only after this check turns green will Codex be scheduled for floor retirement.

---

## 8. Verification & Acceptance Matrix

| Check | OpenCode | Claude Code | Antigravity | Codex |
|---|---|---|---|---|
| **Floor entries** | 0 | 0 | 0 | 32 (kept) |
| **Hook entries** | 1 (`plugin`) | 3 (`hooks`) | 2 (`guardrail`) | 3 (`hooks`) |
| **`doctor` settings line** | `guardrail integration registered` | `guardrail hook registered` | `guardrail integration registered` | `guardrail hooks registered, unenforced...` |
| **`doctor` engine health** | `reachable (self-spawn ok)` | `reachable (self-spawn ok)` | `reachable (self-spawn ok)` | `reachable (self-spawn ok)` |
| **Healthy SessionStart** | Silent | Silent | Silent | N/A |
| **Outage SessionStart** | Bash fails closed; read/edit ungated | Loud warning banner | Loud warning banner | Floor enforces |
| **`selftest`** | Pass | Pass | Pass (7 probes) | Pass (native rules) |

---

## 9. Contradiction Analysis (#282 Audit)

Before execution, this checklist was audited against ADR-0028 and the #282 consolidation:
- **No contradictions found**:
  - OpenCode executes before Claude: matches ADR-0028 § "Retirement phases".
  - Codex excluded: matches ADR-0028 § "Codex: the exception plane".
  - Antigravity unchanged: matches ADR-0028 Phase A.
  - Accepted outage exposures (OpenCode mode-2 reads/edits; Claude #151 spawn failure) explicitly recorded.
  - M1 and M2 prerequisites match P1 and P2 in ADR-0028.
