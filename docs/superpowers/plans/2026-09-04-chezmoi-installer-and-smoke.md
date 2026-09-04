# chezmoi Installer + doctor Unmarked-Entry Warning + real-Claude Smoke — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get `guardrail` installed and wired to Claude Code globally by `chezmoi apply`: a new `install_agent_guardrails()` step in the dotfiles installer downloads the pinned `v0.3.1` release binary, checksum-verifies it, drops it at `~/.local/bin/guardrail`, and runs `guardrail gen-config claude --merge ~/.claude/settings.json`. Plus the Plan 3 ruling-6 follow-up (a `doctor` warning for unmarked guardrail-like hook entries) and a manual `make smoke` that drives a real `claude` session against a known deny/allow.

**Architecture:** Cross-repo. **agent-guardrails** (`~/projects/CtrlCarlitos/agent-guardrails`, branch `main`): a small `doctor` change + a smoke harness + a `v0.3.1` tag. **chezmoi** (`~/.local/share/chezmoi`, on a feature branch `add-guardrail-installer`, **left for Carlitos to review/merge/apply — do NOT run `chezmoi apply`**): `install_agent_guardrails()` mirroring the existing `install_agent_skills()`, a dedicated `install_guardrail` toggle (default true), a `~/scripts/update_ai_tools.*` section, and docs. The installer introduces checksum verification of a downloaded asset — the first such pattern in that repo.

**Tech Stack:** Go 1.23+ (`/usr/local/go/bin/go` locally). chezmoi Go templates (`.tmpl`), bash, PowerShell. `curl` + `sha256sum` (Linux/mac), `Invoke-WebRequest` + `Get-FileHash` + `Unblock-File` (Windows). No new agent-guardrails deps.

**Spec:** `../../../DESIGN.md` (esp. Q11b, Q16, Q19, Q20). This is the renumbered "Plan 3b". Prior: `2026-09-04-owned-entry-merge-and-ci-release.md` (Plan 3), `2026-09-03-claude-genconfig-and-doctor.md` (Plan 2).

## Global Constraints

- **Do not run `chezmoi apply`.** Arc B lands on a branch in `~/.local/share/chezmoi` and stops. `chezmoi apply` modifies `~/.claude/settings.json` live and is Carlitos's call — Task 10 hands him the steps.
- **Pinned release version is `v0.3.1`** (cut in Task 4). The installer and `update_ai_tools.*` both hardcode it, each with a "keep in sync" comment (they are plain scripts / a template — no shared source).
- **Never install an unverified binary.** If the `sha256sum -c` / `Get-FileHash` check fails, `warn` and return without touching `~/.local/bin`.
- Install target: `~/.local/bin/guardrail` (Linux/mac/WSL — already a chezmoi-managed, on-PATH bin dir via `dot_local/bin/`). Windows: `%USERPROFILE%\.local\bin\guardrail.exe` with User-PATH persistence, following the `Install-Gum` pattern in `run_onchange_install_packages.ps1.tmpl`.
- The hook command registered in `settings.json` uses the **absolute** binary path (`--binary "$HOME/.local/bin/guardrail"`), so the hook does not depend on PATH.
- Idempotent: the installer skips the download when `guardrail version` already reports the pinned version; re-runs `gen-config --merge` regardless (it is idempotent per Plan 3's owned-entry merge).
- chezmoi tasks are validated by `chezmoi execute-template` + `shellcheck` / PowerShell parse + a hand-run of the rendered function against the real release — **not** by `chezmoi apply`.
- Every code step is literal. `gofmt -w` before agent-guardrails commits. Conventional Commits, one commit per task. In chezmoi, commit on the branch only.
- Verified state (from prior recon; chezmoi unchanged this whole project):
  - `run_onchange_install_packages.sh.tmpl` — `net_timeout <secs> <cmd...>` helper (uses `timeout`/`gtimeout`, falls back to bare exec). `install_agent_skills()` is a function called from the **apt branch** (inside `{{- if $install_ai_tools }}` → `if command -v npm`) and the **brew branch** (same shape). GitHub-release download idiom: `curl -s --max-time 30 https://api.github.com/repos/<o>/<r>/releases/latest | grep -Po '"tag_name": "v\K[^"]*'` then `net_timeout <n> curl -fLo <file> <releases/download/...>`; **no checksum anywhere**. Claude guard: `if command -v claude &>/dev/null`.
  - `run_onchange_install_packages.ps1.tmpl` — `Invoke-WithTimeout -Description -Seconds -Action {}` (Start-Job + poll + Stop-Job), `Invoke-Quietly -Description -Action {}` (try/catch). `Install-Gum` downloads a GitHub release zip via `Invoke-RestMethod` (latest) + `Invoke-WebRequest -OutFile`, `Expand-Archive`, `Copy-Item`, then persists PATH via `[System.Environment]::SetEnvironmentVariable("Path", "$userPath;$gumDir", "User")`. **No `Unblock-File` anywhere.** OpenCode config is edited with `ConvertFrom-Json` / `Add-Member` / `ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8`.
  - `.chezmoi.toml.tmpl` — `[data.packages]` toggles via `<name> = {{ if $interactive }}{{ promptBoolOnce . "packages.<name>" "<prompt>?" <default> }}{{ else }}false{{ end }}`. `$interactive := and (not $isDevcontainer) (not (env "CI"))`. Existing: `install_core/modern/fonts/ai_tools/desktop/antigravity`. Both `.tmpl` installers re-declare `{{ $install_ai_tools := false }} ... {{ if hasKey . "packages" }}{{ $install_ai_tools = .packages.install_ai_tools }} ... {{ end }}` at the top.
  - `scripts/update_ai_tools.sh` — numbered `#`-comment sections: `# 1.` NPM/Codex, `# 1a.` Superpowers-for-agy, `# 1b.` curated skills (guard `if command -v npx`), `# 2.` Claude Code, `# 3.` OpenCode, `# 4.` Playwright. `.ps1` mirrors it. Both carry a "keep in sync with install_agent_skills()" note. Deployed to `~/scripts/`.
  - `docs/tool-parity.md` — `## AI Coding Tools` section, table header `| Tool | Linux (Mint/Ubuntu) | macOS | Windows (Host) | WSL (Ubuntu) | Devcontainer | Upgrade Method |`, one row per tool, then explanatory blockquotes.
  - `.chezmoiignore` excludes `docs/**`, `install.sh/ps1`, `.claude/**`, `scripts/update-versions.sh`; `scripts/*.ps1` on non-Windows, `scripts/*.sh` on Windows. `scripts/update_ai_tools.{sh,ps1}` are NOT ignored (deploy to `~/scripts/`).
  - agent-guardrails `v0.3.0` release assets: `guardrail_{linux,darwin,windows}_{amd64,arm64}` (windows `.exe`) + `SHA256SUMS`. `guardrail version` prints `guardrail v0.3.0`.
  - `cmd/guardrail/doctor.go` (post-Plan-3): `claudeSettingsState() string` parses `~/.claude/settings.json`, returns `"guardrail hook registered"` when `hooksHaveOwnedGroup(doc)` (any `hooks.<event>[].id` with prefix `guardrail-`), else `"present, hook NOT registered"`; `errors.Is(err, fs.ErrNotExist)` → `"no settings.json"`, other read error → `"unreadable: <err>"`; parse failure → substring fallback.

---

## Arc A — agent-guardrails: doctor warning, smoke harness, `v0.3.1`

### Task 1: `doctor` — warn on unmarked guardrail-like hook entries (Plan 3 ruling 6)

**Files:**
- Modify: `cmd/guardrail/doctor.go`
- Modify: `cmd/guardrail/doctor_test.go`

**Interfaces:**
- `func unmarkedGuardrailGroups(doc map[string]any) int` — count of hook groups (any event) whose serialized JSON contains `"guardrail hook "` (i.e. a guardrail hook command) but which are **not** `ownedByGuardrail` (no `id` with prefix `guardrail-`).
- `cmdDoctor`: after the `claude settings:` line, if the settings parsed and `unmarkedGuardrailGroups > 0`, print:
  `  WARNING: <n> unmarked guardrail-like hook entr{y,ies} in settings.json — invisible to doctor and will be forked by the next merge. Remove them, or re-run the installer.`

- [ ] **Step 1: Write the failing test**

Add to `cmd/guardrail/doctor_test.go`:

```go
func TestDoctorWarnsOnUnmarkedEntry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	writeClaudeSettings(t, home, `{"hooks":{"PreToolUse":[
		{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[{"type":"command","command":"/x/guardrail hook claude"}]},
		{"matcher":"Bash","hooks":[{"type":"command","command":"/old/guardrail hook claude"}]}
	]}}`)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "unmarked guardrail-like") {
		t.Fatalf("want an unmarked-entry warning:\n%s", out.String())
	}
}

func TestDoctorNoWarnWhenOnlyOwned(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	writeClaudeSettings(t, home, `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[{"type":"command","command":"/x/guardrail hook claude"}]}]}}`)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if strings.Contains(out.String(), "unmarked") {
		t.Fatalf("should not warn when the only entry is owned:\n%s", out.String())
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run 'TestDoctorWarns|TestDoctorNoWarn' -v`
Expected: FAIL — no warning emitted.

- [ ] **Step 3: Write minimal implementation**

In `cmd/guardrail/doctor.go`, add `"encoding/json"` (already there from Plan 3). Add:

```go
func unmarkedGuardrailGroups(doc map[string]any) int {
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		return 0
	}
	n := 0
	for _, ev := range hooks {
		groups, ok := ev.([]any)
		if !ok {
			continue
		}
		for _, g := range groups {
			m, ok := g.(map[string]any)
			if !ok {
				continue
			}
			if id, _ := m["id"].(string); strings.HasPrefix(id, "guardrail-") {
				continue
			}
			if b, _ := json.Marshal(m); strings.Contains(string(b), "guardrail hook ") {
				n++
			}
		}
	}
	return n
}
```

In `cmdDoctor`, replace the final `fmt.Fprintf(stdout, "claude settings: %s\n", claudeSettingsState())` + `return 0` with:

```go
	fmt.Fprintf(stdout, "claude settings: %s\n", claudeSettingsState())
	if home, err := os.UserHomeDir(); err == nil {
		if raw, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json")); err == nil {
			var doc map[string]any
			if json.Unmarshal(raw, &doc) == nil {
				if n := unmarkedGuardrailGroups(doc); n > 0 {
					plural := "entry"
					if n > 1 {
						plural = "entries"
					}
					fmt.Fprintf(stdout, "  WARNING: %d unmarked guardrail-like hook %s in settings.json — invisible to doctor and will be forked by the next merge. Remove them, or re-run the installer.\n", n, plural)
				}
			}
		}
	}
	return 0
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat(cli): doctor warns on unmarked guardrail-like hook entries (Plan 3 ruling 6)"
```

---

### Task 2: `test/smoke/claude_smoke.sh` — real-Claude smoke harness

**Files:**
- Create: `test/smoke/claude_smoke.sh`
- Create: `test/smoke/README.md`

**Interfaces:**
- `test/smoke/claude_smoke.sh` — bash, `set -euo pipefail`. Env: `GUARDRAIL_BIN` (default: `command -v guardrail`), `CLAUDE_BIN` (default: `command -v claude`). Exits `0` on both checks passing, `1` otherwise, `77` (skip) if `claude` or `guardrail` is missing.
- Flow: make a temp dir with `git init`; write a `guardrail.toml` (empty `[slots]`); `"$GUARDRAIL_BIN" gen-config claude --merge "$tmp/.claude/settings.json" --binary "$GUARDRAIL_BIN"`; point Claude at it via `CLAUDE_CONFIG_DIR="$tmp/.claude"` (and `--settings` if the installed `claude` supports it — detect with `claude --help`); run two headless prompts with `claude -p`:
  1. deny: ask it to run `rm -rf /tmp/guardrail-smoke-nope` (a path outside the temp repo) — assert the transcript/stderr shows a guardrail block (`grep -qi 'guardrail'`), OR the command did not run (the target dir, if pre-created, still exists).
  2. allow: ask it to run `echo smoke-ok` — assert `smoke-ok` appears and no guardrail block.

- [ ] **Step 1: Write the harness**

`test/smoke/claude_smoke.sh`:

```bash
#!/usr/bin/env bash
# Best-effort end-to-end smoke: does the generated Claude settings.json actually
# make a real `claude` session block a destructive command? Requires network +
# a working `claude` login and SPENDS TOKENS. Not run in CI. `make smoke`.
set -euo pipefail

GUARDRAIL_BIN="${GUARDRAIL_BIN:-$(command -v guardrail || true)}"
CLAUDE_BIN="${CLAUDE_BIN:-$(command -v claude || true)}"
[ -x "$GUARDRAIL_BIN" ] || { echo "SKIP: guardrail not found"; exit 77; }
[ -x "$CLAUDE_BIN" ]    || { echo "SKIP: claude not found";    exit 77; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
( cd "$tmp" && git init -q && git config user.email t@t && git config user.name t )
printf '[slots]\n' > "$tmp/guardrail.toml"
mkdir -p "$tmp/.claude"

"$GUARDRAIL_BIN" gen-config claude --merge "$tmp/.claude/settings.json" --binary "$GUARDRAIL_BIN"
grep -q '"id": "guardrail-claude-pre"' "$tmp/.claude/settings.json" || { echo "FAIL: settings.json not written"; exit 1; }

export CLAUDE_CONFIG_DIR="$tmp/.claude"
run_claude() { ( cd "$tmp" && "$CLAUDE_BIN" -p "$1" --permission-mode acceptEdits 2>&1 || true ); }

echo "== deny check =="
deny_out="$(run_claude 'Run exactly this shell command and nothing else: rm -rf /tmp/guardrail-smoke-nope')"
echo "$deny_out"
if echo "$deny_out" | grep -qi 'guardrail'; then
  echo "PASS: guardrail surfaced on the destructive command"
else
  echo "FAIL: no guardrail block observed"; exit 1
fi

echo "== allow check =="
allow_out="$(run_claude 'Run exactly this shell command and nothing else: echo smoke-ok')"
echo "$allow_out"
if echo "$allow_out" | grep -q 'smoke-ok' && ! echo "$allow_out" | grep -qi 'guardrail: '; then
  echo "PASS: benign command ran without a block"
else
  echo "FAIL: benign command was blocked or did not run"; exit 1
fi

echo "SMOKE OK"
```

`test/smoke/README.md`:

```markdown
# Smoke test

`make smoke` runs `claude_smoke.sh`: it generates a throwaway Claude `settings.json`
with `guardrail gen-config claude --merge`, then runs a real `claude -p` session
against one destructive prompt (expected: blocked) and one benign prompt (expected:
runs). It needs a working `claude` login and **spends tokens**. Not in CI.

Exit codes: 0 pass, 1 fail, 77 skipped (claude or guardrail not on PATH).

The assertions are deliberately loose — Claude's phrasing varies. A "FAIL: no
guardrail block observed" with the model simply refusing on its own is a weak
signal, not necessarily a regression; inspect the transcript.
```

- [ ] **Step 2: Make it executable; stub-validate the shell logic**

Run:
```bash
chmod +x test/smoke/claude_smoke.sh
bash -n test/smoke/claude_smoke.sh   # syntax
# fake claude on PATH that echoes a canned "blocked" transcript for the deny prompt
d="$(mktemp -d)"
cat > "$d/claude" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *rm\ -rf*) echo "I tried to run that but: guardrail: recursive/forced rm ... blocked";;
  *echo\ smoke-ok*) echo "smoke-ok";;
  *--help*) echo "usage: claude -p PROMPT";;
esac
EOF
chmod +x "$d/claude"
GUARDRAIL_BIN="$(command -v true)" CLAUDE_BIN="$d/claude" PATH="$d:$PATH" bash test/smoke/claude_smoke.sh || true
```
Expected: with the real `guardrail` absent the script SKIPs (77); if you point `GUARDRAIL_BIN` at a built `guardrail` and keep the fake `claude`, the deny check PASSes on the canned "guardrail: ... blocked" line and the allow check PASSes on `smoke-ok`. This validates the harness's parsing without spending tokens.

- [ ] **Step 3: Commit**

```bash
git add test/smoke/
git commit -m "test: best-effort real-claude smoke harness (manual, spends tokens)"
```

---

### Task 3: `make smoke` target + README note

**Files:**
- Modify: `Makefile`
- Modify: `README.md`

- [ ] **Step 1: Add the target**

Append to `Makefile` (and add `smoke` to the `.PHONY` list):

```make
smoke:
	./test/smoke/claude_smoke.sh
```

- [ ] **Step 2: README**

Under Status (or a new "Testing" note), add:

```markdown
`make smoke` runs a best-effort end-to-end check against a real `claude` session
(needs a login, spends tokens, not in CI) — see `test/smoke/README.md`.
```

- [ ] **Step 3: Verify the target dispatches**

Run: `make smoke; echo "exit=$?"`
Expected: the script runs; `exit=77` (SKIP) if `claude` is not on PATH — that is acceptable for this step. Do **not** spend tokens here unless Carlitos asks.

- [ ] **Step 4: Commit**

```bash
git add Makefile README.md
git commit -m "build: make smoke; document the real-claude smoke test"
```

---

### Task 4: Cut `v0.3.1`

**Files:** none (release action).

- [ ] **Step 1: Full green**

Run: `make check && /usr/local/go/bin/go test ./...`
Expected: all pass.

- [ ] **Step 2: Push, confirm CI**

```bash
git push origin main
gh run list --branch main --limit 2   # CI: completed / success
```

- [ ] **Step 3: Tag and release**

```bash
git tag v0.3.1
git push origin v0.3.1
gh run list --workflow Release --limit 1   # completed / success
gh release view v0.3.1                      # 7 assets: 6 binaries + SHA256SUMS
```

- [ ] **Step 4: Capture the checksum for the plan's records**

Run:
```bash
gh release download v0.3.1 -p SHA256SUMS -D /tmp/grv31 && cat /tmp/grv31/SHA256SUMS
```
Note the `guardrail_linux_amd64` line — the chezmoi installer verifies against exactly this file, so no value needs to be copied into the installer, but confirm the file exists and lists all 6.

---

## Arc B — chezmoi: `install_agent_guardrails()` (on a branch, not applied)

> Work happens in `~/.local/share/chezmoi`. Create the branch first; **never run `chezmoi apply`**; Task 10 hands Carlitos the review/merge/apply steps.

### Task 5: Branch + `install_guardrail` toggle

**Files (in `~/.local/share/chezmoi`):**
- Modify: `.chezmoi.toml.tmpl`
- Modify: `run_onchange_install_packages.sh.tmpl` (top-of-file template var block)
- Modify: `run_onchange_install_packages.ps1.tmpl` (top-of-file template var block)

- [ ] **Step 1: Branch**

```bash
cd ~/.local/share/chezmoi
git checkout -b add-guardrail-installer
```

- [ ] **Step 2: Add the toggle to `.chezmoi.toml.tmpl`**

In the `[data.packages]` block, after the `install_ai_tools` line, add:

```
    # Agent guardrails (agent-guardrails release binary + Claude gen-config).
    # Modifies ~/.claude/settings.json hooks — separate opt-in from install_ai_tools.
    install_guardrail = {{ if $interactive }}{{ promptBoolOnce . "packages.install_guardrail" "Install agent guardrails (hook enforcement for Claude Code)?" true }}{{ else }}false{{ end }}
```

- [ ] **Step 3: Wire the template var in both installers**

In `run_onchange_install_packages.sh.tmpl`, in the block that sets `{{ $install_ai_tools := false }}` … `{{ if hasKey . "packages" }}` … `{{ end }}`, add alongside the siblings:

```
{{- $install_guardrail := false -}}
...
  {{- $install_guardrail = .packages.install_guardrail -}}
```

Do the identical addition in `run_onchange_install_packages.ps1.tmpl`'s equivalent block.

- [ ] **Step 4: Validate render**

```bash
chezmoi execute-template < .chezmoi.toml.tmpl | grep install_guardrail
chezmoi execute-template < run_onchange_install_packages.sh.tmpl > /tmp/rendered.sh && echo "sh renders"
chezmoi execute-template < run_onchange_install_packages.ps1.tmpl > /tmp/rendered.ps1 && echo "ps1 renders"
```
Expected: the toggle appears; both templates render without a Go-template error.

- [ ] **Step 5: Commit (branch)**

```bash
git add .chezmoi.toml.tmpl run_onchange_install_packages.sh.tmpl run_onchange_install_packages.ps1.tmpl
git commit -m "packages: add install_guardrail toggle (default true)"
```

---

### Task 6: `install_agent_guardrails()` in `run_onchange_install_packages.sh.tmpl`

**Files (chezmoi):**
- Modify: `run_onchange_install_packages.sh.tmpl`

**Interfaces:**
- A shell function `install_agent_guardrails()` defined next to `install_agent_skills()`.
- A pinned version, near the top of the script body: `GUARDRAIL_VERSION="v0.3.1"` (plain shell var in the rendered script; add a `# keep in sync with scripts/update_ai_tools.sh` comment).
- Called from the apt branch and the brew branch, right after the `install_agent_skills` call, wrapped `{{- if $install_guardrail }} ... {{- end }}`.

- [ ] **Step 1: Add the pinned version**

Near the other version pins / early in the script body (rendered shell, not template-gated), add:

```bash
# agent-guardrails release to install. Keep in sync with scripts/update_ai_tools.sh.
GUARDRAIL_VERSION="v0.3.1"
GUARDRAIL_REPO="CtrlCarlitos/agent-guardrails"
```

- [ ] **Step 2: Add the function**

Place immediately after `install_agent_skills() { ... }`:

```bash
# agent-guardrails: a single static Go binary ("guardrail") that enforces the
# shared hook policy. Installed from the pinned GitHub release, checksum-verified
# (the first asset-checksum check in this repo), then wired into Claude Code by
# `guardrail gen-config claude --merge`. Idempotent: skips the download when the
# installed binary already reports GUARDRAIL_VERSION; always re-runs gen-config
# (its owned-entry merge is safe to repeat).
install_agent_guardrails() {
    local ver="$GUARDRAIL_VERSION" repo="$GUARDRAIL_REPO"
    local dest="$HOME/.local/bin/guardrail"

    if command -v guardrail &>/dev/null && [ "$(guardrail version 2>/dev/null)" = "guardrail ${ver}" ]; then
        info "guardrail ${ver} already installed"
    else
        local os arch
        case "$(uname -s)" in
            Linux)  os="linux" ;;
            Darwin) os="darwin" ;;
            *) warn "guardrail: unsupported OS $(uname -s) - skipping"; return ;;
        esac
        case "$(uname -m)" in
            x86_64|amd64) arch="amd64" ;;
            aarch64|arm64) arch="arm64" ;;
            *) warn "guardrail: unsupported arch $(uname -m) - skipping"; return ;;
        esac
        local asset="guardrail_${os}_${arch}"
        local base="https://github.com/${repo}/releases/download/${ver}"
        local tmp; tmp="$(mktemp -d)"

        info "Installing guardrail ${ver} (${asset})..."
        if ! net_timeout 180 curl -fLo "$tmp/$asset" "${base}/${asset}"; then
            warn "guardrail: download failed or timed out - skipping"; rm -rf "$tmp"; return
        fi
        if ! net_timeout 60 curl -fLo "$tmp/SHA256SUMS" "${base}/SHA256SUMS"; then
            warn "guardrail: SHA256SUMS download failed - skipping (won't install unverified)"; rm -rf "$tmp"; return
        fi
        if ! ( cd "$tmp" && grep " ${asset}\$" SHA256SUMS | sha256sum -c - ); then
            warn "guardrail: CHECKSUM MISMATCH for ${asset} - not installing"; rm -rf "$tmp"; return
        fi
        mkdir -p "$HOME/.local/bin"
        install -m 0755 "$tmp/$asset" "$dest"
        rm -rf "$tmp"
        info "guardrail installed to $dest"
    fi

    # Wire into Claude Code (no-op-safe if claude is absent or already wired).
    if command -v claude &>/dev/null; then
        info "Configuring guardrail for Claude Code..."
        "$dest" gen-config claude --merge "$HOME/.claude/settings.json" --binary "$dest" \
            || warn "guardrail: gen-config claude --merge failed - continuing"
    fi
}
```

- [ ] **Step 3: Call it from both branches**

In the apt branch, immediately after the `install_agent_skills` call:

```bash
{{- if $install_guardrail }}
        # agent-guardrails hook-enforcement binary - see install_agent_guardrails above.
        install_agent_guardrails
{{- end }}
```

Add the identical block after the `install_agent_skills` call in the brew branch.

Note on gating: `install_agent_guardrails` is deliberately **not** nested under `{{ if $install_ai_tools }}` in the template — but the call sites sit inside the `if command -v npm` / `$install_ai_tools` region in both branches today. Move the two call blocks to just before that region closes but still inside `install_apt` / `install_brew`, OR (simpler) accept that `install_guardrail` effectively also requires `install_ai_tools=true` on the same machine and document that in Task 9's parity note. Choose the documented-coupling option unless it is trivial to hoist; record the choice.

- [ ] **Step 4: Validate**

```bash
chezmoi execute-template < run_onchange_install_packages.sh.tmpl > /tmp/rendered.sh
shellcheck /tmp/rendered.sh | grep -A2 install_agent_guardrails || echo "no new shellcheck errors in the function"
# hand-run the function body against the real release:
bash -c '
  set -e
  GUARDRAIL_VERSION=v0.3.1; GUARDRAIL_REPO=CtrlCarlitos/agent-guardrails
  net_timeout() { shift; "$@"; }
  info(){ echo "[i] $*"; }; warn(){ echo "[w] $*"; }
  '"$(sed -n "/^install_agent_guardrails()/,/^}/p" /tmp/rendered.sh)"'
  HOME=$(mktemp -d) install_agent_guardrails
  "$HOME/.local/bin/guardrail" version
'
```
Expected: downloads `guardrail_linux_amd64`, checksum `OK`, installs, `guardrail version` → `guardrail v0.3.1`. (claude absent in the scratch HOME → gen-config skipped, fine.)

- [ ] **Step 5: Commit (branch)**

```bash
git add run_onchange_install_packages.sh.tmpl
git commit -m "packages: install_agent_guardrails() - pinned release binary, checksum-verified, gen-config wire"
```

---

### Task 7: `run_onchange_install_packages.ps1.tmpl` — Windows equivalent

**Files (chezmoi):**
- Modify: `run_onchange_install_packages.ps1.tmpl`

**Interfaces:**
- An inline block (not a function — matches the Windows skills block style) under `{{- if $install_guardrail }}`, placed next to the Windows skills-install block.
- Pinned: `$guardrailVersion = "v0.3.1"` near the top.
- Target: `$env:USERPROFILE\.local\bin\guardrail.exe`, PATH-persisted like `Install-Gum`.
- `Unblock-File` on the downloaded exe (new to this repo).

- [ ] **Step 1: Add the block**

```powershell
{{- if $install_guardrail }}
    # agent-guardrails hook-enforcement binary (guardrail.exe), pinned + checksum-verified.
    # Keep $guardrailVersion in sync with scripts/update_ai_tools.ps1.
    $guardrailVersion = "v0.3.1"
    $guardrailRepo    = "CtrlCarlitos/agent-guardrails"
    $guardrailDir     = "$env:USERPROFILE\.local\bin"
    $guardrailExe     = "$guardrailDir\guardrail.exe"

    $haveVer = ""
    if (Get-Command guardrail -ErrorAction SilentlyContinue) { $haveVer = (guardrail version 2>$null) }
    if ($haveVer -eq "guardrail $guardrailVersion") {
        Write-Host "  guardrail $guardrailVersion already installed" -ForegroundColor Green
    } else {
        $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
        $asset = "guardrail_windows_$arch.exe"
        $base  = "https://github.com/$guardrailRepo/releases/download/$guardrailVersion"
        $tmp   = New-Item -ItemType Directory -Force -Path "$env:TEMP\guardrail-dl-$([guid]::NewGuid())"
        try {
            Invoke-WithTimeout -Description "guardrail download" -Seconds 180 -Action {
                Invoke-WebRequest -Uri "$using:base/$using:asset" -OutFile "$using:tmp\$using:asset" -UseBasicParsing
                Invoke-WebRequest -Uri "$using:base/SHA256SUMS"   -OutFile "$using:tmp\SHA256SUMS"    -UseBasicParsing
            }
            $want = (Select-String -Path "$tmp\SHA256SUMS" -Pattern ([regex]::Escape($asset))).Line.Split(" ")[0].Trim()
            $got  = (Get-FileHash -Algorithm SHA256 "$tmp\$asset").Hash.ToLower()
            if ($want -and ($got -eq $want.ToLower())) {
                New-Item -ItemType Directory -Force -Path $guardrailDir | Out-Null
                Copy-Item "$tmp\$asset" $guardrailExe -Force
                Unblock-File $guardrailExe
                $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
                if ($userPath -notlike "*$guardrailDir*") {
                    [System.Environment]::SetEnvironmentVariable("Path", "$userPath;$guardrailDir", "User")
                }
                Write-Host "  guardrail $guardrailVersion installed to $guardrailExe" -ForegroundColor Green
            } else {
                Write-Host "  Warning: guardrail checksum mismatch - not installing" -ForegroundColor Red
            }
        } catch {
            Write-Host "  Warning: guardrail install failed - $_" -ForegroundColor Red
        } finally {
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if ((Test-Path $guardrailExe) -and (Get-Command claude -ErrorAction SilentlyContinue)) {
        Write-Host "  Configuring guardrail for Claude Code..." -ForegroundColor Yellow
        Invoke-Quietly -Description "guardrail gen-config claude" -Action {
            & $using:guardrailExe gen-config claude --merge "$env:USERPROFILE\.claude\settings.json" --binary $using:guardrailExe
        }
    }
{{- end }}
```

(If `Invoke-Quietly`'s scriptblock cannot see `$guardrailExe`, inline the path or use `$script:` scope — verify against the repo's existing `Invoke-Quietly` calls and match their variable-capture style.)

- [ ] **Step 2: Validate**

```bash
chezmoi execute-template < run_onchange_install_packages.ps1.tmpl > /tmp/rendered.ps1
pwsh -NoProfile -Command '$null=[ScriptBlock]::Create((Get-Content -Raw /tmp/rendered.ps1)); "parses ok"' 2>/dev/null \
  || echo "pwsh not present - review the block by hand against Install-Gum and the skills block"
```
Expected: parses, or a hand review confirming it matches the `Install-Gum` download/verify/PATH pattern and the Windows skills block's `Invoke-WithTimeout` usage.

- [ ] **Step 3: Commit (branch)**

```bash
git add run_onchange_install_packages.ps1.tmpl
git commit -m "packages: guardrail.exe install for Windows (checksum + Unblock-File + PATH persist)"
```

---

### Task 8: `scripts/update_ai_tools.{sh,ps1}` — section 1c

**Files (chezmoi):**
- Modify: `scripts/update_ai_tools.sh`
- Modify: `scripts/update_ai_tools.ps1`

- [ ] **Step 1: `update_ai_tools.sh`**

Between the `# 1b.` skills section and `# 2. Claude Code`, insert:

```bash
# 1c. Agent guardrails (agent-guardrails release binary + Claude gen-config).
#     Keep GUARDRAIL_VERSION in sync with run_onchange_install_packages.sh.tmpl.
GUARDRAIL_VERSION="v0.3.1"
GUARDRAIL_REPO="CtrlCarlitos/agent-guardrails"
guardrail_dest="$HOME/.local/bin/guardrail"
if [ "$(command -v guardrail >/dev/null 2>&1 && guardrail version 2>/dev/null)" != "guardrail ${GUARDRAIL_VERSION}" ]; then
    case "$(uname -s)" in Linux) gos=linux ;; Darwin) gos=darwin ;; *) gos= ;; esac
    case "$(uname -m)" in x86_64|amd64) garch=amd64 ;; aarch64|arm64) garch=arm64 ;; *) garch= ;; esac
    if [ -n "$gos" ] && [ -n "$garch" ]; then
        gtmp="$(mktemp -d)"
        gbase="https://github.com/${GUARDRAIL_REPO}/releases/download/${GUARDRAIL_VERSION}"
        if curl -fLo "$gtmp/guardrail_${gos}_${garch}" "${gbase}/guardrail_${gos}_${garch}" \
           && curl -fLo "$gtmp/SHA256SUMS" "${gbase}/SHA256SUMS" \
           && ( cd "$gtmp" && grep " guardrail_${gos}_${garch}\$" SHA256SUMS | sha256sum -c - ); then
            mkdir -p "$HOME/.local/bin"
            install -m 0755 "$gtmp/guardrail_${gos}_${garch}" "$guardrail_dest"
            echo "  guardrail updated to ${GUARDRAIL_VERSION}"
        else
            echo "  guardrail update failed or checksum mismatch - skipping"
        fi
        rm -rf "$gtmp"
    fi
fi
if command -v claude >/dev/null 2>&1 && [ -x "$guardrail_dest" ]; then
    "$guardrail_dest" gen-config claude --merge "$HOME/.claude/settings.json" --binary "$guardrail_dest" || true
fi
```

- [ ] **Step 2: `update_ai_tools.ps1`**

Add a matching `# 1c.` section before `# 2. Claude Code` using `Invoke-WebRequest` + `Get-FileHash` + `Copy-Item` + the `gen-config` call, mirroring Task 7's block (no `Invoke-WithTimeout` needed here — this is the manual updater; keep it simple with a `try/catch`).

- [ ] **Step 3: Validate**

```bash
bash -n scripts/update_ai_tools.sh && echo "sh ok"
pwsh -NoProfile -Command '$null=[ScriptBlock]::Create((Get-Content -Raw scripts/update_ai_tools.ps1)); "ps ok"' 2>/dev/null || echo "review ps1 by hand"
```

- [ ] **Step 4: Commit (branch)**

```bash
git add scripts/update_ai_tools.sh scripts/update_ai_tools.ps1
git commit -m "update_ai_tools: section 1c - refresh the guardrail binary + re-run gen-config"
```

---

### Task 9: `docs/tool-parity.md` row + `docs/guardrail-install.md`

**Files (chezmoi):**
- Modify: `docs/tool-parity.md`
- Create: `docs/guardrail-install.md`

- [ ] **Step 1: Add the parity row**

In the `## AI Coding Tools` table, add a row matching the 7-column header:

```
| guardrail | GitHub release binary → `~/.local/bin` (checksum-verified) | same | GitHub release `.exe` → `%USERPROFILE%\.local\bin` (checksum + Unblock-File) | same as Linux | not installed (no `claude` there) | bump `GUARDRAIL_VERSION` in `run_onchange_install_packages.*.tmpl` + `scripts/update_ai_tools.*`, re-`chezmoi apply` |
```

Add a blockquote after the table's existing notes:

```markdown
> **guardrail** is gated by `install_guardrail` (default true). It downloads the
> pinned `CtrlCarlitos/agent-guardrails` release, verifies it against the release
> `SHA256SUMS` (the only checksum-verified download in this repo), installs it to
> `~/.local/bin/guardrail`, and runs `guardrail gen-config claude --merge
> ~/.claude/settings.json` to register the hook + a coarse permissions floor.
> On a given machine it also effectively needs `install_ai_tools=true` because the
> installer call sites live in that region — see docs/guardrail-install.md.
```

- [ ] **Step 2: Write `docs/guardrail-install.md`**

```markdown
# guardrail install strategy

_Added 2026-09-04 with Plan 3b of the agent-guardrails project._

## TL;DR

- `install_guardrail` toggle (default true), separate from `install_ai_tools`
  because it modifies `~/.claude/settings.json` hooks, not just drops files.
- Downloads the **pinned** `CtrlCarlitos/agent-guardrails` release
  (`GUARDRAIL_VERSION`, currently `v0.3.1`) — no "latest", per DESIGN.md Q16.
- **Checksum-verified** against the release `SHA256SUMS` before install. First
  asset-checksum check in this repo; never installs an unverified binary.
- Installs to `~/.local/bin/guardrail` (Linux/mac/WSL) /
  `%USERPROFILE%\.local\bin\guardrail.exe` (Windows, `Unblock-File`d, User PATH
  persisted).
- Wires Claude via `guardrail gen-config claude --merge ~/.claude/settings.json
  --binary <abs path>`. The merge is marker-based (guardrail-owned hook groups
  carry `"id": "guardrail-claude-*"`) so re-runs and version bumps rebind rather
  than fork — see agent-guardrails ADR-0004.
- Idempotent: download skipped when `guardrail version` already matches; gen-config
  always re-run (safe).

## Bumping the version

1. Tag a new `agent-guardrails` release (CI publishes the binaries + SHA256SUMS).
2. Update `GUARDRAIL_VERSION` in `run_onchange_install_packages.sh.tmpl`,
   `run_onchange_install_packages.ps1.tmpl`, `scripts/update_ai_tools.sh`,
   `scripts/update_ai_tools.ps1` (they are not templated from one source).
3. Commit → `chezmoi apply` re-fires the `run_onchange` script.

## Not done / open

- opencode + Antigravity wiring (their `gen-config` planes ship in later
  agent-guardrails plans; this step is Claude-only).
- A dedicated `guardrail` uninstall path.
```

- [ ] **Step 3: Validate**

```bash
chezmoi execute-template < docs/tool-parity.md >/dev/null 2>&1 || true   # docs aren't templates; just check it's readable
grep -q '| guardrail |' docs/tool-parity.md && echo "row added"
```

- [ ] **Step 4: Commit (branch)**

```bash
git add docs/tool-parity.md docs/guardrail-install.md
git commit -m "docs: guardrail install strategy + tool-parity row"
```

---

### Task 10: Stop; hand Carlitos the review/merge/apply steps

**Files:** none.

- [ ] **Step 1: Confirm the branch state**

```bash
cd ~/.local/share/chezmoi
git log --oneline main..add-guardrail-installer   # ~5 commits
git status                                        # clean
```

- [ ] **Step 2: Do NOT merge, do NOT apply.** Print this block verbatim into the execution report for Carlitos:

```
The chezmoi installer is on branch `add-guardrail-installer` in ~/.local/share/chezmoi,
NOT merged, NOT applied. To land it:

  cd ~/.local/share/chezmoi
  git log -p main..add-guardrail-installer          # review every hunk
  git checkout main && git merge --ff-only add-guardrail-installer
  chezmoi diff                                       # preview — expect changes to
                                                     #   ~/.claude/settings.json (hooks + permissions)
                                                     #   ~/.local/bin/guardrail (new)
  chezmoi apply
  guardrail doctor                                   # expect: "guardrail hook registered", no WARNING
  guardrail version                                  # expect: guardrail v0.3.1

To back out: `git checkout ~/.claude/settings.json` is not possible (not chezmoi-managed);
instead re-run with install_guardrail=false is a no-op — remove the guardrail `hooks`
block from ~/.claude/settings.json by hand, or keep a pre-merge backup.
```

---

## Arc C — wrap-up (agent-guardrails)

### Task 11: HANDOFF + README + self-review

**Files:**
- Modify: `docs/HANDOFF-2026-09-03.md`
- Modify: `README.md`

- [ ] **Step 1: HANDOFF plan table**

Mark Plan 3b:

```
| **3b** | chezmoi installer + doctor unmarked-entry warning + `make smoke`. | **agent-guardrails side DONE** (`v0.3.1`, doctor warning, smoke harness). **chezmoi side: committed on branch `add-guardrail-installer`, awaiting Carlitos review/merge/`chezmoi apply`.** Plan: `docs/superpowers/plans/2026-09-04-chezmoi-installer-and-smoke.md`. |
```

Add to the resume section: "If the chezmoi branch is merged and applied, `guardrail doctor` on any machine should show `guardrail hook registered` with no WARNING. Next: Plan 4 (policy modules P2/P5/P6/P7/P10)."

- [ ] **Step 2: README Status**

Note that Claude is now installable globally via dotfiles (pending the chezmoi merge), `v0.3.1` is current, and `make smoke` exists.

- [ ] **Step 3: Commit + push**

```bash
gofmt -w .
git add README.md docs/HANDOFF-2026-09-03.md
git commit -m "docs: Plan 3b - installer committed (chezmoi branch), doctor warning, smoke harness"
git push origin main
```

---

## Self-Review

**1. Spec coverage.**

| Item | Task |
|---|---|
| Plan 3 ruling 6 — doctor warns on unmarked guardrail-like hook entries | 1 |
| `make smoke` driving real `claude` against deny + allow | 2, 3 |
| Pinned release version (Q16) — `v0.3.1`, no "latest" | 4, 6, 7, 8 |
| Download + **checksum-verify** the release asset (Q20) | 6, 7, 8 |
| Install to `~/.local/bin/guardrail` / Windows `.local\bin` + `Unblock-File` (Q20) | 6, 7 |
| `guardrail gen-config claude --merge ~/.claude/settings.json` at install (Q11b, Q18) | 6, 7 |
| `.sh.tmpl` + `.ps1.tmpl` twins, gated by a toggle | 5, 6, 7 |
| `~/scripts/update_ai_tools.*` refresh section | 8 |
| `docs/tool-parity.md` row + design note | 9 |
| Idempotent (skip download when version matches; safe re-merge) | 6, 7, 8 |
| chezmoi work left for Carlitos to review/merge/apply | 10 |

Deferred, by design: opencode + Antigravity `gen-config`/wiring (their planes are Plans 5–6); a real automated end-to-end test in CI (impossible without a `claude` login — `make smoke` is the manual substitute per Q12's "thin real-agent smoke suite behind a target"); the `install_guardrail`-without-`install_ai_tools` call-site hoist (Task 6 Step 3 chooses documented coupling unless trivial).

**2. Placeholder scan.** No `TBD`/"handle errors"/"similar to". `make dist` was noted as pre-Task-10 in Plan 3; here `make smoke` is fully created in Task 2–3. The Windows `Invoke-Quietly` variable-capture caveat (Task 7) is a real "verify against existing usage" instruction, not a placeholder — the block is complete and runnable as written for the common case.

**3. Type / interface consistency.**
- `cmd/guardrail/doctor.go` — new `unmarkedGuardrailGroups(map[string]any) int`; reuses `ownedByGuardrail` semantics inline (checking `id` prefix `guardrail-`), consistent with `genconfig.ownedByGuardrail` and `hooksHaveOwnedGroup` from Plan 3. `cmdDoctor` gains a trailing block; signature unchanged.
- `test/smoke/claude_smoke.sh` — env contract `GUARDRAIL_BIN` / `CLAUDE_BIN`; exit codes 0/1/77. `Makefile` `smoke` target invokes it directly.
- chezmoi: `GUARDRAIL_VERSION` / `GUARDRAIL_REPO` shell vars in `run_onchange_install_packages.sh.tmpl` and `scripts/update_ai_tools.sh`; `$guardrailVersion` / `$guardrailRepo` in the `.ps1` pair. Four copies, each with a "keep in sync" comment (Task 6, 7, 8) — matches how the repo already duplicates the skills list between the installer and `update_ai_tools`.
- `install_agent_guardrails()` uses the repo's existing `net_timeout`, `info`, `warn` helpers (verified present). Windows block uses `Invoke-WithTimeout`, `Invoke-Quietly` (verified present).
- The hook command written by `gen-config --binary "$HOME/.local/bin/guardrail"` is an absolute path — matches the Plan 3 golden's `command` shape (`<binary> hook claude`) and the owned `id` markers, so `guardrail doctor` post-apply reports "registered" with no unmarked WARNING.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-04-chezmoi-installer-and-smoke.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task via `superpowers:subagent-driven-development`, review between tasks. Note Arc B tasks touch a second repo (`~/.local/share/chezmoi`) on a branch.

**2. Inline Execution** — `superpowers:executing-plans`, batch with checkpoints.

**Which approach?**
