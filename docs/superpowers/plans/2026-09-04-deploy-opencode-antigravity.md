# Deploy opencode + Antigravity via the chezmoi Installer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Q11c for real — `install_agent_guardrails()` (built in Plan 3b for Claude only) also wires opencode and Antigravity, so `chezmoi apply` registers `guardrail` on all three planes, not just one.

**Architecture:** Pure extension, no new machinery. Plan 3b's function already downloads, checksum-verifies, and installs the binary once; this plan adds two more guarded blocks to that same function — `command -v opencode` → `guardrail gen-config opencode --merge`, `command -v agy` → `guardrail gen-config antigravity --merge` — mirroring the existing `command -v claude` block exactly. Work happens on a chezmoi branch, same as Plan 3b; **`chezmoi apply` stays Carlitos's own action**, and per the Antigravity adapter's own "first-live-session verification is load-bearing" flag, Task 6 explicitly asks him to run one real Antigravity session before trusting that plane.

**Tech Stack:** chezmoi Go templates, bash, PowerShell. No agent-guardrails code changes — the binary already supports all three `gen-config` planes (`v0.7.0-dev`).

**Spec:** `../../../DESIGN.md` Q11b, Q11c. Builds directly on `docs/superpowers/plans/2026-09-04-chezmoi-installer-and-smoke.md` (Plan 3b) — read that plan's Task 6 (`install_agent_guardrails()`'s current body) before touching anything here.

## Global Constraints

- **Do not run `chezmoi apply`.** Branch, commit, stop — same as Plan 3b Task 10.
- **Guard each plane independently.** `command -v opencode` / `command -v agy` — a machine without one tool still gets the others wired.
- **Reuse the pinned version already in place** (`GUARDRAIL_VERSION="v0.4.1"` as of Plan 3b's hotfix follow-up) — don't bump it here; this plan only adds `gen-config` calls for the binary that's already being downloaded.
- **`gen-config` failures warn and continue**, matching the existing Claude block's `|| warn ...` pattern — a broken opencode/antigravity wiring must never abort the rest of the installer run.
- Every step's shell/PowerShell is literal. Conventional Commits, one commit per task, on the branch only.
- Verified current state: `install_agent_guardrails()` in `run_onchange_install_packages.sh.tmpl` (Plan 3b Task 6) ends with:
  ```bash
      if command -v claude &>/dev/null; then
          info "Configuring guardrail for Claude Code..."
          "$dest" gen-config claude --merge "$HOME/.claude/settings.json" --binary "$dest" \
              || warn "guardrail: gen-config claude --merge failed - continuing"
      fi
  }
  ```
  `guardrail gen-config opencode --merge <path> --binary <bin> --plugin-dir <dir>` deploys the embedded plugin to `<dir>/guardrail.js` and merges `permission`+`plugin` into `<path>` (Plan 5). `guardrail gen-config antigravity --merge <path> --binary <bin>` merges the `{"guardrail":{"enabled":true,"PreToolUse":[...],"PostToolUse":[...]}}` fragment into `<path>` (Plan 6, superseded shape — confirmed working by the Plan 6 executor's own regression test).

---

### Task 1: Extend `install_agent_guardrails()` for opencode (bash)

**Files (chezmoi, branch `add-guardrail-opencode-antigravity`):**
- Modify: `run_onchange_install_packages.sh.tmpl`

- [ ] **Step 1: Branch**

```bash
cd ~/.local/share/chezmoi
git checkout main && git pull --ff-only
git checkout -b add-guardrail-opencode-antigravity
```

- [ ] **Step 2: Add the opencode block**

In `install_agent_guardrails()`, immediately after the existing `if command -v claude &>/dev/null; then ... fi` block and before the function's closing `}`, add:

```bash
    # Wire into OpenCode: declarative permission.{bash,read,edit} + the
    # embedded plugin (deployed alongside opencode.json, outside opencode's
    # own config tree so it can't be mistaken for something opencode scans).
    if command -v opencode &>/dev/null; then
        info "Configuring guardrail for OpenCode..."
        mkdir -p "$HOME/.local/share/guardrail"
        "$dest" gen-config opencode \
            --merge "$HOME/.config/opencode/opencode.json" \
            --binary "$dest" \
            --plugin-dir "$HOME/.local/share/guardrail" \
            || warn "guardrail: gen-config opencode --merge failed - continuing"
    fi
```

- [ ] **Step 3: Validate the render**

Run:
```bash
chezmoi execute-template < run_onchange_install_packages.sh.tmpl > /tmp/rendered.sh
grep -A6 'Wire into OpenCode' /tmp/rendered.sh
shellcheck /tmp/rendered.sh 2>&1 | grep -A2 'gen-config opencode' || echo "no new shellcheck findings in this block"
```
Expected: the block renders with `$dest` resolved as a shell variable reference (not a template placeholder — it's plain bash, not `{{ }}`); no new shellcheck errors.

- [ ] **Step 4: Hand-run against the real installed opencode (if present on this machine)**

```bash
test -f "$HOME/.local/bin/guardrail" && command -v opencode &>/dev/null && {
  cp "$HOME/.config/opencode/opencode.json" /tmp/opencode.json.bak 2>/dev/null || true
  "$HOME/.local/bin/guardrail" gen-config opencode --merge "$HOME/.config/opencode/opencode.json" --binary "$HOME/.local/bin/guardrail" --plugin-dir "$HOME/.local/share/guardrail"
  grep -q 'guardrail.js' "$HOME/.config/opencode/opencode.json" && echo "opencode.json updated"
  test -f "$HOME/.local/share/guardrail/guardrail.js" && echo "plugin deployed"
  # restore, since this is a hand-run rehearsal, not the real install
  test -f /tmp/opencode.json.bak && cp /tmp/opencode.json.bak "$HOME/.config/opencode/opencode.json"
} || echo "guardrail binary or opencode not present on this machine yet - skip this rehearsal, the render check in Step 3 is sufficient"
```
Expected: if `guardrail` is already installed (Plan 3b landed earlier in this project), `opencode.json` gets a `permission` block + the plugin path; the plugin file appears at `~/.local/share/guardrail/guardrail.js`; then both are restored to their pre-rehearsal state since this is a dry run, not the real install (the real one happens via Task 6's `chezmoi apply`).

- [ ] **Step 5: Commit (branch)**

```bash
git add run_onchange_install_packages.sh.tmpl
git commit -m "packages: install_agent_guardrails wires OpenCode (permission block + embedded plugin)"
```

---

### Task 2: Extend `install_agent_guardrails()` for Antigravity (bash)

**Files (chezmoi, same branch):**
- Modify: `run_onchange_install_packages.sh.tmpl`

- [ ] **Step 1: Add the Antigravity block**

Immediately after Task 1's opencode block, still inside `install_agent_guardrails()`:

```bash
    # Wire into Antigravity: global hooks.json. No declarative floor exists
    # for this plane (see agent-guardrails ADR-0008) - the hook registration
    # IS the entire enforcement surface, so this is the only guardrail
    # coverage Antigravity gets.
    if command -v agy &>/dev/null; then
        info "Configuring guardrail for Antigravity..."
        mkdir -p "$HOME/.gemini/config"
        "$dest" gen-config antigravity \
            --merge "$HOME/.gemini/config/hooks.json" \
            --binary "$dest" \
            || warn "guardrail: gen-config antigravity --merge failed - continuing"
    fi
```

- [ ] **Step 2: Validate the render**

Run:
```bash
chezmoi execute-template < run_onchange_install_packages.sh.tmpl > /tmp/rendered.sh
grep -A6 'Wire into Antigravity' /tmp/rendered.sh
shellcheck /tmp/rendered.sh 2>&1 | grep -A2 'gen-config antigravity' || echo "no new shellcheck findings in this block"
```

- [ ] **Step 3: Hand-run against the real machine, if `agy` and the binary are present**

```bash
test -f "$HOME/.local/bin/guardrail" && command -v agy &>/dev/null && {
  mkdir -p "$HOME/.gemini/config"
  cp "$HOME/.gemini/config/hooks.json" /tmp/hooks.json.bak 2>/dev/null || true
  "$HOME/.local/bin/guardrail" gen-config antigravity --merge "$HOME/.gemini/config/hooks.json" --binary "$HOME/.local/bin/guardrail"
  grep -q 'guardrail-antigravity-pre' "$HOME/.gemini/config/hooks.json" && echo "hooks.json updated"
  test -f /tmp/hooks.json.bak && cp /tmp/hooks.json.bak "$HOME/.gemini/config/hooks.json" || rm -f "$HOME/.gemini/config/hooks.json"
} || echo "guardrail binary or agy not present yet - skip this rehearsal"
```
Expected: same rehearsal-then-restore pattern as Task 1 Step 4.

- [ ] **Step 4: Commit (branch)**

```bash
git add run_onchange_install_packages.sh.tmpl
git commit -m "packages: install_agent_guardrails wires Antigravity (global hooks.json)"
```

---

### Task 3: Mirror both blocks in the Windows installer

**Files (chezmoi, same branch):**
- Modify: `run_onchange_install_packages.ps1.tmpl`

**Interfaces:**
- Locate the existing guardrail-install block (Plan 3b Task 7 — the `{{- if $install_guardrail }} ... {{- end }}` block ending with the Claude `gen-config` call via `Invoke-Quietly`). Add two more `Invoke-Quietly`-wrapped calls inside that same `if` block, guarded by `Get-Command opencode`/`Get-Command agy`.

- [ ] **Step 1: Add both blocks**

Immediately after the existing Claude `Invoke-Quietly -Description "guardrail gen-config claude" -Action { ... }` block, still inside the outer `{{- if $install_guardrail }}` block:

```powershell
    if ((Test-Path $guardrailExe) -and (Get-Command opencode -ErrorAction SilentlyContinue)) {
        Write-Host "  Configuring guardrail for OpenCode..." -ForegroundColor Yellow
        $ocPluginDir = "$env:USERPROFILE\.local\share\guardrail"
        New-Item -ItemType Directory -Force -Path $ocPluginDir | Out-Null
        Invoke-Quietly -Description "guardrail gen-config opencode" -Action {
            & $using:guardrailExe gen-config opencode `
                --merge "$env:USERPROFILE\.config\opencode\opencode.json" `
                --binary $using:guardrailExe `
                --plugin-dir $using:ocPluginDir
        }
    }

    if ((Test-Path $guardrailExe) -and (Get-Command agy -ErrorAction SilentlyContinue)) {
        Write-Host "  Configuring guardrail for Antigravity..." -ForegroundColor Yellow
        New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.gemini\config" | Out-Null
        Invoke-Quietly -Description "guardrail gen-config antigravity" -Action {
            & $using:guardrailExe gen-config antigravity `
                --merge "$env:USERPROFILE\.gemini\config\hooks.json" `
                --binary $using:guardrailExe
        }
    }
```

(Match the exact `$guardrailExe`/`$using:` variable-capture style Plan 3b Task 7 already established for the Claude block in this same file — if that block uses a different variable name or capture idiom than shown here, follow what's actually on disk, not this draft.)

- [ ] **Step 2: Validate**

```bash
chezmoi execute-template < run_onchange_install_packages.ps1.tmpl > /tmp/rendered.ps1
pwsh -NoProfile -Command '$null=[ScriptBlock]::Create((Get-Content -Raw /tmp/rendered.ps1)); "parses ok"' 2>/dev/null || echo "pwsh not present - review by hand against the existing Claude block's exact style"
```

- [ ] **Step 3: Commit (branch)**

```bash
git add run_onchange_install_packages.ps1.tmpl
git commit -m "packages: Windows installer wires OpenCode + Antigravity alongside Claude"
```

---

### Task 4: Extend `scripts/update_ai_tools.{sh,ps1}` section 1c

**Files (chezmoi, same branch):**
- Modify: `scripts/update_ai_tools.sh`
- Modify: `scripts/update_ai_tools.ps1`

**Interfaces:**
- Section 1c (added by Plan 3b Task 8) currently re-downloads the binary if the pinned version differs, then re-runs `gen-config claude --merge`. Add the same `command -v opencode`/`command -v agy` guarded `gen-config` calls used in Tasks 1–2, so a manual `~/scripts/update_ai_tools.sh` run re-syncs all three planes, not just Claude.

- [ ] **Step 1: Extend `update_ai_tools.sh`**

At the end of section 1c (after the existing `if command -v claude >/dev/null 2>&1 && [ -x "$guardrail_dest" ]; then ... fi` block), add:

```bash
if command -v opencode >/dev/null 2>&1 && [ -x "$guardrail_dest" ]; then
    mkdir -p "$HOME/.local/share/guardrail"
    "$guardrail_dest" gen-config opencode --merge "$HOME/.config/opencode/opencode.json" --binary "$guardrail_dest" --plugin-dir "$HOME/.local/share/guardrail" || true
fi
if command -v agy >/dev/null 2>&1 && [ -x "$guardrail_dest" ]; then
    mkdir -p "$HOME/.gemini/config"
    "$guardrail_dest" gen-config antigravity --merge "$HOME/.gemini/config/hooks.json" --binary "$guardrail_dest" || true
fi
```

- [ ] **Step 2: Extend `update_ai_tools.ps1`**

Mirror the same two guarded blocks (`Get-Command opencode`/`Get-Command agy`) in section 1c of the PowerShell twin, matching whatever `$guardrailDest`-equivalent variable that file already uses.

- [ ] **Step 3: Validate**

```bash
bash -n scripts/update_ai_tools.sh && echo "sh ok"
pwsh -NoProfile -Command '$null=[ScriptBlock]::Create((Get-Content -Raw scripts/update_ai_tools.ps1)); "ps ok"' 2>/dev/null || echo "review ps1 by hand"
```

- [ ] **Step 4: Commit (branch)**

```bash
git add scripts/update_ai_tools.sh scripts/update_ai_tools.ps1
git commit -m "update_ai_tools: refresh OpenCode + Antigravity wiring alongside Claude"
```

---

### Task 5: `docs/tool-parity.md` + `docs/guardrail-install.md`

**Files (chezmoi, same branch):**
- Modify: `docs/tool-parity.md`
- Modify: `docs/guardrail-install.md`

- [ ] **Step 1: Update the guardrail row/blockquote in `docs/tool-parity.md`**

The existing `guardrail` row (added by Plan 3b Task 9) should note it now also wires opencode and Antigravity, not just Claude. Update the row's "Upgrade Method" cell or the blockquote below the table to say so in one sentence.

- [ ] **Step 2: Update `docs/guardrail-install.md`**

Add to its TL;DR: "Wires all three planes it supports today: Claude (`settings.json` hooks + permissions), OpenCode (`opencode.json` permission block + the embedded plugin), Antigravity (global `hooks.json`, no declarative floor — see agent-guardrails ADR-0008). Each plane's wiring is independently guarded on that tool being present."

- [ ] **Step 3: Commit (branch)**

```bash
git add docs/tool-parity.md docs/guardrail-install.md
git commit -m "docs: guardrail now wires OpenCode + Antigravity, not just Claude"
```

---

### Task 6: Stop; hand Carlitos the review/merge/apply steps — including the load-bearing Antigravity check

**Files:** none.

- [ ] **Step 1: Confirm the branch state**

```bash
cd ~/.local/share/chezmoi
git log --oneline main..add-guardrail-opencode-antigravity
git status
```

- [ ] **Step 2: Print this block verbatim for Carlitos**

```
OpenCode + Antigravity wiring is on branch `add-guardrail-opencode-antigravity`
in ~/.local/share/chezmoi, NOT merged, NOT applied. To land it:

  cd ~/.local/share/chezmoi
  git log -p main..add-guardrail-opencode-antigravity   # review every hunk
  git checkout main && git merge --ff-only add-guardrail-opencode-antigravity
  chezmoi diff       # expect: ~/.config/opencode/opencode.json (permission + plugin),
                      #   ~/.local/share/guardrail/guardrail.js (new),
                      #   ~/.gemini/config/hooks.json (new or merged)
  chezmoi apply

Then verify each plane:

  guardrail doctor                      # still says "guardrail hook registered", no WARNING
  grep guardrail-antigravity-pre ~/.gemini/config/hooks.json    # present

IMPORTANT — the Antigravity adapter's own report flagged this as load-bearing:
the hooks.json wrapper shape, the id-key tolerance, and whether Antigravity
even sends Cwd/workspacePaths were all inferred from a reference file that
never exercises those fields, not confirmed against a live session. Please
run ONE real Antigravity session after applying — try a command guardrail
should deny (e.g. ask it to `rm -rf` something outside the repo) and confirm
it's actually blocked, not silently allowed. Same for OpenCode: try one
destructive command there too. Report back what you see; if either doesn't
fire, that's the next thing to fix, not recipes/sync.
```

---

## Self-Review

**1. Spec coverage.** OpenCode wiring (Task 1, 3, 4), Antigravity wiring (Task 2, 3, 4), docs updated (Task 5), landing handed to Carlitos with the explicit live-verification ask his own executor flagged as load-bearing (Task 6). Nothing in agent-guardrails changes — this plan is pure deployment, as scoped.

**2. Placeholder scan.** No `TBD`/"handle appropriately". Task 3's PowerShell block explicitly says to match whatever variable-capture idiom is actually on disk rather than assume this draft's names are exact — a real "verify against reality" instruction, consistent with every prior plan's discipline, not a placeholder.

**3. Type/interface consistency.** No Go code touched. Every `gen-config` invocation here uses exactly the CLI surface Plans 5–6 already built and tested (`gen-config opencode --merge --binary --plugin-dir`, `gen-config antigravity --merge --binary`) — no new flags, no signature assumptions beyond what's shipped in `v0.7.0-dev`.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-04-deploy-opencode-antigravity.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
