# OpenCode 2 Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the opencode plane to OpenCode 2 (`ctx.tool.hook("execute.before")`, directory plugin, native `permissions` array) while OpenCode 1.19.x behavior stays byte-for-byte unchanged.

**Architecture:** One embedded dual-major plugin file (`server()` for V1, `setup(ctx)` for V2, Superpowers-style plain-object default export) keeps the ADR-0007 wire format so the Go adapter does not change; V2 native tool/arg names are translated to the V1-native names the engine contract already knows. Config emission is selected by a detected major: V1 keeps today's fragment (`plugin` entry only), V2 writes a `plugins` directory entry plus a one-entry `permissions` array restoring V1's ask-before-external-directory semantics.

**Tech Stack:** Go 1.26 (repo), embedded JS plugin run under Bun (V1) / Bun (V2), Node used by the test harness.

**Spec:** Issue #534 with its 2026-11-13 arming comment; ADR-0007/0011/0015; upstream docs https://opencode.ai/docs/build/plugins/migrate-v1, /docs/plugins, /docs/permissions, /v2/docs/migrate-v1; live findings comment on #534 (2026-11-13).

## Global Constraints

- V1 behavior must not change: on a detected V1 (or undetectable) binary, `plane enable opencode`, `sync`, `gen-config` write exactly what they write today (`plugin: [<abs path to guardrail.js>]`, single file under the state root / `.guardrail/`), and the plugin's V1 code path behaves identically.
- Throw-to-block is preserved on V2 via `ctx.tool.hook("execute.before", ...)` throwing.
- The V2 artifact is a directory (`guardrail/index.js`); V2 skips configured single-file plugin paths.
- V2 config: `plugins: [<abs dir>]` + `permissions: [{"action":"external_directory","resource":"*","effect":"ask"}]`. No floor resurrection (ADR-0028 stands; `external_directory` restores a host default V1 had, it does not mirror Engine policy).
- Package rename `@opencode-ai/plugin` → `@opencode/plugin` does not touch our plugin (it imports only `node:*` builtins; stays dependency-free).
- `continue_loop_on_deny`: repo has no reliance (verified by grep); nothing to port.
- Conventional commits, TDD (failing test first), gofmt clean, `go vet ./...` clean, `go test ./...` green on Linux and Windows before push. Windows-only tests must be named `TestWindows…`.
- Engine verdicts/exit codes are stated only after running them in-session.

## Review Focus

- A V2 binary whose `--version` output changes shape again — detection must degrade to unknown (→ V1 emission + loud note), never mis-wire.
- `opencode.json` holding BOTH guardrail entries (a machine that flipped majors) — enable must converge to the detected major's entries, not append duplicates.
- Operator-owned `plugins`/`permissions` entries — merge/absorb/removal must never touch entries guardrail did not write (manifest discipline, ADR-0028 amendment 1).
- V2 `execute.before` delivering a tool name the contract does not know (`experimental_image_generate`, `schedule`, …) — envelope still evaluates as unknown → ask; never crashes the plugin.
- `setup()` invoked by V1 (1.18.18+ observed) with a V1-shaped ctx — must return quietly; V1 is served by the named export.

---

### Task 1: Major detection

**Files:**
- Create: `cmd/guardrail/opencode_major.go`
- Test: `cmd/guardrail/opencode_major_test.go`

**Interfaces:**
- Produces: `parseOpencodeMajor(output string) int` (1, 2, or 0=unknown); `opencodeMajor() int` (runs `opencode --version` from `exec.LookPath("opencode")`, caches in a package var, overridable seam `opencodeMajorProbe func() (string, error)`).

- [ ] **Step 1: Write failing tests** — `parseOpencodeMajor("1.19.5")==1`, `("opencode v2.3.0")==2`, `("2.0.0-beta-17236")==2`, `("opencode")==0`, `("")==0`, `("guardrail 9.9")==0` (only majors 1 and 2 are known). Also `opencodeMajor()` returns 0 when the seam errors.
- [ ] **Step 2: Run** `go test ./cmd/guardrail/ -run TestParseOpencodeMajor -v` — expect FAIL (undefined).
- [ ] **Step 3: Implement** — scan for the first `v?<digit>.<digit>` token, parse leading integer, return it only when 1 or 2.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(opencode): detect the installed opencode major (#534)`

### Task 2: V2 config fragment + merge machinery

**Files:**
- Modify: `internal/genconfig/legacy_floor.go` (add `OpencodeConfigV2`), `internal/genconfig/merge.go`, `internal/genconfig/manifest.go`
- Test: `internal/genconfig/opencode_v2_test.go`

**Interfaces:**
- Produces: `OpencodeConfigV2(pluginDir string) Fragment` → `{"plugins": []string{pluginDir}, "permissions": []any{map[string]any{"action":"external_directory","resource":"*","effect":"ask"}}}`; `OpencodeV2PermissionRules()` returning that one-entry slice (used by removal fallback); absorption of guardrail entries from both `plugin` and `plugins` keys; `manifestKind("plugins")=="plugin"`.

- [ ] **Step 1: Failing tests:** fragment shape; merge into a doc with an operator `plugins` entry appends guardrail's without touching it; merge removes a prior guardrail `plugins` entry before appending (replace, not duplicate); merge absorbs a V1 `plugin: guardrail.js` entry when the V2 fragment lands (major flip convergence) and vice versa; manifest records array entries under `permissions` and `plugins`; `RemovePlaneFromReporting` removes exactly the generated `permissions`/`plugins` entries (manifest path) and only exact matches (fallback path); operator-edited `external_directory` rule left alone and reported `Edited`.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** — extend `absorbGuardrailPluginEntries` to both keys (match basename `guardrail.js` and basename `guardrail` on `plugins`); call it for `plugins` in `mergeInto` when plane is opencode/""; add `plugins` to `manifestKind`; extend the opencode branch of `removeByInBandMarkers` + `removeGeneratedMatches` with `OpencodeV2PermissionRules` and the `plugins` basename.
- [ ] **Step 4: Run** `go test ./internal/genconfig/ -run 'OpencodeV2|Merge|Manifest|Removal' -v` — PASS (existing tests too).
- [ ] **Step 5: Commit** `feat(opencode): V2 config fragment — plugins directory entry and external_directory ask (#534)`

### Task 3: Dual-major plugin source

**Files:**
- Modify: `internal/genconfig/opencode_plugin.js`, `internal/genconfig/opencode_embed.go` (if it names exports)
- Test: `internal/genconfig/opencode_plugin_v2_test.go` (Node harness, pattern of `plugin_failure_log_test.go`); update the runner scripts in `opencode_degraded_test.go`, `plugin_failure_log_test.go`, `opencode_test.go`, `plugin_timing_log_test.go` to load V1 via `loaded.GuardrailPlugin` (named export) or `loaded.default.server`.

**Interfaces:**
- Produces (JS): named export `GuardrailPlugin` (V1, unchanged signature); default export `{ id: "guardrail", server: <V1 factory>, setup }`; `setup(ctx)` registers `ctx.tool.hook("execute.before", handler)`; V2 tool-name map `{shell:"bash", patch:"apply_patch", subagent:"task"}` (others pass through); V2 arg projection uses `input.path` for read/edit/write/patch, `input.command` for shell; envelope `{session_id: event.sessionID, event:"pre", tool: <translated>, cwd: ctx.location.directory, arguments: event.input, call_id: event.id, host_approved?}`; host-approval correlation from `ctx.event.subscribe({types:["permission.asked","permission.replied"]})`: `asked.source?.id` (callID) ↔ `asked.id` ↔ `replied.requestID`, replies `once|always` mark the callID approved; `setup` returns quietly when `ctx.tool?.hook` is not a function (V1-shaped ctx).

- [ ] **Step 1: Failing tests (Node):** (a) default export is an object with `id==="guardrail"`, `server` and `setup` functions; (b) `setup({tool:{hook:async(n,f)=>{captured=[n,f]}}})` registers `execute.before`; (c) firing it with `{tool:"shell", input:{command:"rm -rf /"}, sessionID:"s1", id:"c1"}` against the fake-engine harness produces a thrown error containing the engine's deny reason (fail-closed path already proven; assert the envelope the engine received used `tool:"bash"` and `command` — use the GO_WANT_OPENCODE_ENGINE_HELPER capture); (d) V1-shaped ctx `{}` → setup returns without throwing; (e) `read` with `input:{path:"/repo/.env"}` reaches the engine as paths `[path]`; (f) host-approval: feed `permission.asked {id:"per_1", source:{type:"tool", id:"c9"}}` then `permission.replied {requestID:"per_1", reply:"once"}` through a stub event stream, then fire execute.before with `id:"c9"` and assert envelope `host_approved===true` exactly once.
- [ ] **Step 2: Run** `go test ./internal/genconfig/ -run 'OpencodePlugin' -v` — new FAIL, updated old PASS.
- [ ] **Step 3: Implement** the JS per Interfaces; keep every existing helper untouched; V1 hook body unchanged.
- [ ] **Step 4: Run** — PASS all.
- [ ] **Step 5: Commit** `feat(opencode): dual-major plugin — server() for V1, setup()+ctx.tool.hook for V2 (#534)`

### Task 4: plane enable/status by detected major

**Files:**
- Modify: `cmd/guardrail/plane.go` (enable branch ~L283-302, `planeIntegrationRegistered` opencode branch, status), `cmd/guardrail/setup_drift.go` if drift needs the V2 shape
- Test: `cmd/guardrail/plane_opencode_v2_test.go`

**Interfaces:**
- Consumes: Task 1 `opencodeMajor()`, Task 2 `OpencodeConfigV2`.
- Produces: enable writes `<state>/guardrail/index.js` + `OpencodeConfigV2(<state>/guardrail)` on major 2; major 1/0 writes today's single file + `OpencodeConfig` (unchanged); major 0 additionally prints a stderr note naming the V1 assumption and remedy; `planeIntegrationRegistered` accepts either shape (but reports which); status prints `opencode: registered (major 2, plugins entry)` style detail.

- [ ] **Step 1: Failing tests:** with the seam forced to 2 — enable writes `<state>/guardrail/index.js` (dir not file), merges `plugins:[<state>/guardrail]` + the permissions entry, writes no `plugin` key; forced to 1 — output identical to today's golden behavior (existing tests cover; add one asserting no `plugins` key); forced to 0 — V1 writes + the note on stderr; registered check true for a V2-shaped config, and status names the shape; a config holding the opposite major's guardrail entry converges (absorbed) rather than duplicating.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./cmd/guardrail/ -run 'Plane|Setup' -v` — PASS.
- [ ] **Step 5: Commit** `feat(opencode): wire plane enable by detected major — directory plugin + native permissions on V2 (#534)`

### Task 5: sync and gen-config select the major

**Files:**
- Modify: `cmd/guardrail/genconfig.go`, `cmd/guardrail/sync.go`
- Test: `cmd/guardrail/genconfig_v2_test.go`, extend sync tests

**Interfaces:**
- Produces: `--major <1|2>` flag (default: auto-detect; unknown → V1 + stderr note). V2 sync writes `<repo>/.guardrail/guardrail/index.js` and the V2 fragment into the repo `opencode.json`; V1 sync unchanged.

- [ ] **Step 1: Failing tests** per flag × major; unknown-major note; V1 path byte-identical to today.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(opencode): gen-config/sync emit V2 shapes when major 2 detected (#534)`

### Task 6: doctor — both MCP shapes, major reporting, loud mismatch

**Files:**
- Modify: `internal/coverage/mcp.go` (`readOpencodeMCP`), `cmd/guardrail/doctor.go` (status lines), `cmd/guardrail/doctor_mcp_coverage.go`
- Test: `internal/coverage/mcp_test.go` (extend), `cmd/guardrail/doctor_opencode_v2_test.go`

**Interfaces:**
- Produces: `readOpencodeMCP` parses `mcp.<name>` (`enabled`, default true) and `mcp.servers.<name>` (`disabled`, default false) with V1 precedence when both name the same server; doctor prints `opencode: major 2 (v2.3.0)` when detectable and the installed entry shape, and a warning (exit 1 under `--coverage opencode --mcp`? no — plain doctor warning) when the installed guardrail entry shape contradicts the detected major, with the remedy `guardrail plane enable opencode`.

- [ ] **Step 1: Failing tests:** V2 `{"mcp":{"servers":{"serena":{"type":"local","command":["uvx"],"disabled":false}}}}` lists serena; `disabled:true` skips; V1+V2 same name → V1 wins; doctor mismatch warning text.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(opencode): doctor reads both MCP shapes and reports the detected major (#534)`

### Task 7: ADR, CHANGELOG, README

**Files:**
- Create: `docs/adr/0034-opencode-dual-major-port.md`
- Modify: `docs/adr/0007`, `0011`, `0015` (one-line "OpenCode 2:" pointers to 0034; 0015 also records the V2 event names), `CHANGELOG.md` (Unreleased), `README.md` (planes table opencode row)

- [ ] **Step 1: Write ADR-0034** — dual-major single file; V2 hook event shape (source-cited); tool/arg translation table; `external_directory` as host-default restoration, not floor resurrection; chosen configured-directory over discovery (one manifest mechanism, precise removal) with discovery noted as operator option; V1 file artifact kept because V1 path entries are file-shaped; setup() V1-invocation guard.
- [ ] **Step 2: Pointers + changelog + README row.**
- [ ] **Step 3: Commit** `docs: ADR-0034 — the opencode dual-major port (#534)`

### Task 8: full verification

- [ ] `gofmt -l .` empty; `go vet ./...`; `go test ./... -count=1` on Linux; WSL recipe from HANDOFF if reachable; `scripts/validation_contract` mapping vs `.github/workflows/ci.yml`; remove `dist/` if built.

### Task 9: live smoke — scratch OpenCode 2 (v2.3.0)

- [ ] Isolated `$HOME` rig + mock OpenAI-compatible provider (Node http server returning fixed tool calls). Cases: (1) `opencode run` issues `read` on `~/.ssh/id_ed25519` → plugin throws, tool never runs (deny); (2) `shell git push origin main` → ask (permission.asked observed / non-interactive client rejects); (3) benign `read` → executes (allow); (4) single-file plugin path configured → V2 log shows the skip warning; (5) `opencode plugin list` shows the configured guardrail dir. Record raw evidence in #534.

### Task 10: live V1 regression — 1.19.5 binary

- [ ] Same mock-provider rig, real `/home/carlitos/.opencode/bin/opencode` with scratch HOME: V1 loads the dual-major plugin via the generated config (`plugin:` single-file entry), deny/ask/allow behave as before, and `guardrail selftest` opencode probes pass. Record in #534.

### Task 11: PR

- [ ] Push branch, open PR (body: root cause, per-OS verification, smoke evidence links), watch checks to green, report. Merge/release decisions per operator.
