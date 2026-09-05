# Phase 3 Whole-Review Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the cross-task security gaps found by the Phase 3 whole-review before publishing `v0.11.0-dev`.

**Architecture:** Extend the two-file Operator-config handshake to project egress entries, centralize plane-specific hook failure emission, and strengthen path/native-floor enforcement at their existing boundaries. Preserve the Guardrail Policy as static tool-call enforcement rather than claiming to be an operating-system sandbox.

**Tech Stack:** Go 1.25, BurntSushi TOML, `mvdan.cc/sh`, standard-library JSON/filesystem APIs, existing adversarial subprocess harness.

**Spec:** `docs/superpowers/specs/2026-09-05-phase3-whole-review-hardening-design.md`

## Global Constraints

- Work directly on `main`; do not create a worktree.
- Use `export PATH=$PATH:/usr/local/go/bin`; add no dependencies.
- Follow TDD for every behavior change and commit each task separately.
- Never change or remove an existing `test/adversarial/corpus.json` expectation.
- Keep `*` and `**` egress entries forbidden even with Operator authorization.
- External `safe_roots` remain ungrantable and are always dropped.
- Claude and OpenCode keep their current fail-closed process contracts; Antigravity pre failures use deny JSON and exit 0, while post failures use `{}` and exit 0.
- Do not push, tag, merge/apply the chezmoi branch, or bump the installer pin until all task and whole-phase reviews pass.
- Arbitrary same-user code that conceals a dynamically constructed target is outside the static Engine's threat model and must be documented without claiming full sandboxing.

---

### Task 1: Require Exact Operator Grants For Egress Entries

**Files:**
- Modify: `internal/policy/operator.go`
- Modify: `internal/policy/operator_test.go`
- Modify: `internal/policy/merge.go`
- Modify: `internal/policy/merge_test.go`

**Interfaces:**
- `RepoGrant` gains an `EgressAllowlist []string` field with TOML key
  `egress_allowlist`.
- `func (o *OperatorConfig) AllowsEgress(repoRoot, entry string) bool` performs nil-safe, exact-string membership after exact cleaned repository lookup.
- `Merge` appends an Overlay egress entry only when `AllowsEgress` returns true; exact `*` and `**` are rejected first.

- [ ] **Step 1: Add failing Operator-config tests**

Add tests proving that a TOML grant such as:

```toml
["/absolute/repo"]
egress_allowlist = ["api.example.com", "*.trusted.example"]
```

authorizes only those exact strings for only that exact repository. Cover nil configs, sibling/prefix repositories, case/spelling mismatches, and `*`/`**` remaining unusable at Merge time.

- [ ] **Step 2: Run the focused RED test**

Run: `/usr/local/go/bin/go test ./internal/policy -run 'TestOperatorConfig.*Egress|TestMerge.*Egress' -count=1`

Expected: compile failure for the absent field/method or an ungranted exact host being appended.

- [ ] **Step 3: Implement the exact grant**

Add the field and method, then replace unconditional non-total-wildcard appending with:

```go
if entry == "*" || entry == "**" {
	// deterministic forbidden-wildcard warning
	continue
}
if !op.AllowsEgress(repoRoot, entry) {
	// deterministic not-authorized warning naming the requested entry
	continue
}
m.Slots.EgressAllowlist = append(m.Slots.EgressAllowlist, entry)
```

Do not authorize egress via a Boolean grant or the `P6.egress` Waiver.

- [ ] **Step 4: Verify GREEN and regressions**

Run:

```bash
/usr/local/go/bin/go test ./internal/policy -count=1
/usr/local/go/bin/go test ./internal/engine -run 'Test.*Egress' -count=1
```

Expected: PASS; Base egress entries remain unchanged and ungranted Overlay entries are absent with stable warnings.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/operator.go internal/policy/operator_test.go internal/policy/merge.go internal/policy/merge_test.go
git commit -m "fix(policy): require operator grants for egress entries"
```

---

### Task 2: Fail Closed Through Antigravity's Native Contract

**Files:**
- Modify: `cmd/guardrail/hook.go`
- Modify: `cmd/guardrail/hook_test.go`
- Modify: `internal/adapter/antigravity_test.go` only if contract coverage belongs beside the emitter

**Interfaces:**
- A local `failClosed(reason string) int` boundary in `cmdHook` routes failures by the already parsed plane and actual Antigravity phase.
- Antigravity `pre`: sanitized deny JSON, exit 0.
- Antigravity `post`: `{}`, exit 0.
- Claude/OpenCode: sanitized stderr, exit 2.

- [ ] **Step 1: Add failing table tests**

Cover malformed payload, malformed Overlay TOML, an Overlay over `maxOverlayBytes`, and a Merge error from an `allow` rule. For each Antigravity pre case, assert exit 0 and decoded `decision == "deny"` with a nonempty sanitized reason. For corresponding post failures, assert exactly `{}\n` and exit 0. Retain Claude/OpenCode exit-2 assertions.

- [ ] **Step 2: Run the focused RED test**

Run: `/usr/local/go/bin/go test ./cmd/guardrail -run 'TestHookAntigravity.*Fail' -count=1 -v`

Expected: setup failures return exit 2 with empty Antigravity stdout, and malformed post incorrectly emits pre-style deny JSON.

- [ ] **Step 3: Centralize failure emission**

Create the closure after `plane` and `antigravityPhase` are known. Route parse, Base-load, Overlay-load, and Merge failures through it. Use `adapter.EmitAntigravity(denyVerdict, antigravityPhase, stdout)` for Antigravity; do not force phase `"pre"`. Keep accumulated sanitized stderr behavior for the command-hook planes.

- [ ] **Step 4: Verify GREEN**

Run:

```bash
/usr/local/go/bin/go test ./cmd/guardrail -run 'TestHookAntigravity|TestHook.*Fail' -count=1
/usr/local/go/bin/go test ./internal/adapter -run TestEmitAntigravity -count=1
```

Expected: PASS with unchanged successful pre/post wire output.

- [ ] **Step 5: Commit**

```bash
git add cmd/guardrail/hook.go cmd/guardrail/hook_test.go internal/adapter/antigravity_test.go
git commit -m "fix(hook): fail closed through Antigravity responses"
```

---

### Task 3: Resolve Protected Symlink Targets And Visible Opaque Writes

**Files:**
- Modify: `internal/engine/rules_path.go`
- Modify: `internal/engine/rules_path_test.go`
- Modify: `test/adversarial/corpus.json`

**Interfaces:**
- Existing path candidates are resolved whether they originate inside or outside `RepoRoot`.
- Resolved read targets are checked against `SecretAllow` and `SecretGlobs` before the existing in-repository escape Verdict.
- Resolved write targets are checked against `selfConfigGlobs`.
- Opaque interpreter commands with visible literal Operator-config path markers return `P5.self-config`; direct read tools remain readable.

- [ ] **Step 1: Add failing path regressions**

Use `t.TempDir` and real symlinks to prove:

- `Read /tmp/innocent` denies as `P4.secret-path` when it resolves to an SSH/private-key path;
- `Write` and known Bash mutators through an outside-repository alias to `.../guardrail/waivers.toml` deny as `P5.self-config`;
- a symlink to a benign outside path retains existing behavior;
- `cat` of Operator config remains readable under Task 6's write-only rule.

Add opaque-executor cases for at least `python3 -c`, `node -e`, `perl -e`, and `pwsh -Command` whose literal code names `/.config/guardrail/` or `/guardrail/waivers.toml`. Add controls where code without those markers is unchanged.

- [ ] **Step 2: Run the focused RED test**

Run: `/usr/local/go/bin/go test ./internal/engine -run 'Test(OutsideRepoSymlink|OperatorConfig.*Opaque|OperatorConfig.*Alias)' -count=1 -v`

Expected: aliases and opaque writes are allowed before the fix.

- [ ] **Step 3: Implement shared resolved-target checks**

Resolve an existing candidate with `filepath.EvalSymlinks(resolvePath(candidate, tc.CWD))`. Re-run secret matching on the resolved slash-normalized path, respecting `SecretAllow` before `SecretGlobs`. In `checkSelfConfig`, resolve each write candidate and test both lexical and resolved forms.

Add a small interpreter predicate for visible opaque executors (`python*`, `node`, `perl`, `ruby`, `php`, `lua`, `awk`, `powershell`, `pwsh`). For only those executors, scan normalized literal arguments for the two Operator-config path markers and return `P5.self-config`. Do not claim detection when the path is dynamically assembled without either marker.

- [ ] **Step 4: Add adversarial deny entries and verify GREEN**

Append, never modify, corpus entries for outside-repository secret symlink access where the corpus format can represent it; keep real-filesystem alias setup in unit tests if the corpus cannot. Add the visible Python Operator-config write as a deny regression through an integration test if materialization is needed.

Run:

```bash
/usr/local/go/bin/go test ./internal/engine -count=1
/usr/local/go/bin/go test ./test/adversarial -count=1
```

Expected: PASS; existing corpus distribution only gains deny entries.

- [ ] **Step 5: Commit**

```bash
git add internal/engine/rules_path.go internal/engine/rules_path_test.go test/adversarial/
git commit -m "fix(engine): protect resolved secret and operator paths"
```

---

### Task 4: Make OpenCode Permission Merging Monotonic

**Files:**
- Modify: `internal/genconfig/merge.go`
- Modify: `internal/genconfig/merge_test.go`
- Modify: `internal/genconfig/opencode_test.go`
- Modify: `test/fixtures/opencode/settings-floor.golden.json` if canonical ordering changes

**Interfaces:**
- OpenCode `permission.bash`, `permission.read`, and `permission.edit` objects serialize in increasing Verdict strength: unknown/allow, ask, deny; lexical order breaks ties.
- Exact-key collisions keep the stricter of existing and generated values.
- Non-permission JSON and Claude/Antigravity merge behavior are unchanged.

- [ ] **Step 1: Add failing native-semantics tests**

Merge retained rules including `"/**": "allow"`, `"/home/**": "allow"`, `"~/**": "allow"`, broad `ask`, broad `deny`, and exact collisions. Parse emitted key order and evaluate matches with a test helper that mirrors OpenCode's documented `findLast` semantics. Require generated Operator-config and secret denies to win broad allows, while retained denies still tighten generated allow/ask entries. Verify a second merge is byte-idempotent.

- [ ] **Step 2: Run the focused RED test**

Run: `/usr/local/go/bin/go test ./internal/genconfig -run 'TestMergeIntoOpencode.*(Precedence|Idempotent|Collision)' -count=1 -v`

Expected: lexically later retained broad allows win or exact generated values weaken stricter retained values.

- [ ] **Step 3: Implement ordered permission serialization**

Special-case fragments containing singular `permission` in `MergeInto`. Preserve all keys, but merge exact permission entries with rank `allow < ask < deny`. Wrap each rule object in a narrow `json.Marshaler` that emits keys sorted by the same rank and then lexically. Unknown existing values sort before recognized Verdicts and remain preserved. Do not change plural Claude `permissions` handling.

- [ ] **Step 4: Verify GREEN and golden output**

Run:

```bash
/usr/local/go/bin/go test ./internal/genconfig -count=1
/usr/local/go/bin/go test ./test -run 'TestGenConfig(Opencode|Claude|Antigravity)Golden' -count=1
```

If the standalone OpenCode floor ordering changes, regenerate through `make golden`, inspect the diff, and retain only expected fixture changes.

- [ ] **Step 5: Commit**

```bash
git add internal/genconfig/ test/fixtures/opencode/settings-floor.golden.json
git commit -m "fix(genconfig): preserve the OpenCode permission floor"
```

---

### Task 5: Normalize Relative Safe Roots And Sanitize Sync Output

**Files:**
- Modify: `internal/policy/merge.go`
- Modify: `internal/policy/merge_test.go`
- Modify: `cmd/guardrail/sync.go`
- Modify: `cmd/guardrail/sync_test.go`

**Interfaces:**
- Accepted relative `safe_roots` are stored as `filepath.Clean(filepath.Join(repoRoot, requested))`.
- Accepted absolute in-repository roots remain cleaned absolute paths.
- `cmdSync` and `syncPlane` pass every dynamic terminal value through `adapter.SanitizeForDisplay`; warning lists are not count- or length-capped.

- [ ] **Step 1: Add failing safe-root tests**

Require `"tmp"` to become `<repoRoot>/tmp`, `"."` to become `<repoRoot>`, cleaned absolute in-repository roots to stay absolute, non-existent descendants to work, and symlink escapes to remain dropped. Add an end-to-end path check that consumes the merged roots rather than asserting only the Merge slice.

- [ ] **Step 2: Add failing sync display tests**

Use valid hostile TOML values containing newline, tab, and DEL in refused fields and paths. Assert each warning/error/status occupies one physical line, complete dispositions survive, every Merge warning is present, and successful target paths cannot forge extra `synced ...` lines.

- [ ] **Step 3: Run RED**

Run:

```bash
/usr/local/go/bin/go test ./internal/policy -run 'TestMergeSafeRoots' -count=1
/usr/local/go/bin/go test ./cmd/guardrail -run 'TestSync.*Sanit' -count=1
```

Expected: relative roots remain relative and sync emits forged lines.

- [ ] **Step 4: Implement and verify GREEN**

Store the cleaned absolute lexical candidate after resolved containment validation. Import `internal/adapter` in `sync.go` and sanitize dynamic arguments independently from fixed labels so fixed status text cannot be truncated or hidden.

Run:

```bash
/usr/local/go/bin/go test ./internal/policy ./cmd/guardrail -count=1
```

Expected: PASS with no model-sanitizer behavior change.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/merge.go internal/policy/merge_test.go cmd/guardrail/sync.go cmd/guardrail/sync_test.go
git commit -m "fix(policy): normalize safe roots and sync diagnostics"
```

---

### Task 6: Align Documentation, Corpus, And Repository Hygiene

**Files:**
- Modify: `docs/adr/0010-operator-scoped-loosening.md`
- Modify: `docs/operator-config.md`
- Modify: `guardrail.toml.example`
- Modify: `CONTEXT.md`
- Modify: `README.md`
- Modify: `docs/HANDOFF-2026-09-03.md`
- Modify: `docs/reviews/2026-09-04-adversarial-review.md`
- Modify: `test/adversarial/overlay_test.go`
- Modify: `test/adversarial/corpus.json`
- Delete: `.superpowers/sdd/2026-09-04-remediation-phase3-overlay-trust/task-6-report.md`
- Delete: `.superpowers/sdd/2026-09-04-remediation-phase3-overlay-trust/task-7-report.md`

**Interfaces:**
- Operator config examples include exact `egress_allowlist` grants.
- H-5 is marked fixed only after Task 3 regressions pass.
- Documentation states the static tool-call threat boundary and keeps Phase 2 outstanding.

- [ ] **Step 1: Extend the hostile Overlay integration test**

Add an exact destination such as `evil.example.com` to the hostile Overlay and prove it remains denied without a matching Operator grant. Add a paired exact-grant test proving only the granted destination is accepted. Continue using audit-backed Verdict classification; exit status alone is insufficient.

- [ ] **Step 2: Append corpus cases and validate invariants**

Append exact-host egress and any representable H-5/Operator-config attacks as `deny`. Compare the pre-task prefix byte-for-byte as parsed and report before/after allow/ask/deny counts. Never rewrite existing entries.

- [ ] **Step 3: Update trust-model documentation**

Document per-entry egress grants, forbidden total wildcards, H-5 resolved-target behavior, and the non-sandbox same-user-code limit. Replace prohibited terminology (`exception`, `waiver file`, `global config`, `allowlist` when naming Operator config) with canonical terms. Keep `CONTEXT.md` glossary-only.

Correct review annotations: mark original H-5 `[FIXED — Phase 3 hardening]` with the resolved-target test reference; retain every Phase 2 finding as outstanding. State Claude-only SessionStart behavior accurately.

- [ ] **Step 4: Remove workflow artifacts**

Delete the two accidentally tracked `.superpowers/sdd/` reports. Confirm `git ls-files '.superpowers/**'` returns no paths. Keep ignored local task ledgers/reports out of the commit.

- [ ] **Step 5: Run final verification**

Run:

```bash
jq empty test/adversarial/corpus.json
/usr/local/go/bin/go test ./test/adversarial -count=1 -v
make check
/usr/local/go/bin/go test ./... -count=1
git diff --check
```

Expected: all pass; no existing corpus expectation changed; no installer or chezmoi file changed.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "docs: align Phase 3 with whole-review hardening"
```

---

### Task 7: Re-review And Publish Phase 3

**Files:** No planned source changes. Any review finding receives a separate focused TDD fix commit and re-review.

**Interfaces:** Publication gate only.

- [ ] **Step 1: Run task reviews**

Review every Task 1-6 diff against this plan and the design. Fix and re-review all Critical and Important findings.

- [ ] **Step 2: Run a fresh two-axis whole-phase review**

Review `aa66b99...HEAD` independently for documented standards and Phase 3 specification/security compliance. Verify prior whole-review findings explicitly.

- [ ] **Step 3: Run publication verification**

Run fresh, uncached commands:

```bash
make check
/usr/local/go/bin/go test ./... -count=1
git status --short --branch
git diff --check aa66b99...HEAD
```

Expected: all checks pass and the worktree is clean.

- [ ] **Step 4: Publish**

Only after review and verification are clean:

```bash
git push origin main
git tag v0.11.0-dev
git push origin v0.11.0-dev
```

Confirm `v0.11.0-dev` resolves to the reviewed HEAD. Do not bump the installer pin or modify/push/apply the chezmoi branch.
