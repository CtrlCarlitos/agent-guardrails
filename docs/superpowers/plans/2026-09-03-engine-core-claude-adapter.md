# Engine Core + Claude Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `guardrail` binary whose `hook claude` subcommand blocks destructive shell commands (P1) and secret-file access (P4) in a real Claude Code session, driven by an embedded Base policy merged with an optional per-repo `guardrail.toml` Overlay, with every decision written to a JSONL audit log.

**Architecture:** `guardrail hook claude` reads a Claude Code hook JSON payload on stdin, normalizes it to an `engine.ToolCall`, loads the merged `policy.Policy` (embedded Base ∪ repo Overlay), evaluates it through rule modules that use a real shell tokenizer (`mvdan.cc/sh`), appends one `audit.Record`, and emits Claude's hook response contract (exit 0 = allow, exit 2 + stderr = deny, stdout JSON = ask). Rule logic lives in `internal/engine`; policy data/merge in `internal/policy`; the plane-specific I/O in `internal/adapter`.

**Tech Stack:** Go 1.23+ (installed at `/usr/local/go/bin/go`, currently 1.25.0 — add to PATH or invoke by full path); `mvdan.cc/sh/v3/syntax` (shell parser); `github.com/BurntSushi/toml` (Overlay parsing); `github.com/bmatcuk/doublestar/v4` (`**` globs); stdlib `testing`.

**Spec:** `../../../DESIGN.md` (repo-root `DESIGN.md`); terminology in repo-root `CONTEXT.md`; rationale in `../../adr/`.

## Global Constraints

- Module path: `github.com/CtrlCarlitos/agent-guardrails`.
- Go version floor: `go 1.23` in `go.mod` (dev machine has 1.25.0).
- **Fail closed.** Any unparseable payload, unparseable command, or recovered panic in a rule module resolves to `ask` with a logged reason — never `allow`.
- **No silent downgrade.** An Overlay may add `ask`/`deny` rules, extend slot lists, and `waive` a named rule (logged); an Overlay rule with `decision = "allow"` is a hard error at merge time.
- **Verdict severity order:** `deny` > `ask` > `allow`. When multiple rules hit, the most severe wins.
- Audit log is best-effort: a write failure is reported to stderr and never changes the verdict or exit code.
- Every code step shows the real code. Minimal implementations are expected (TDD) but must be literal, not described.
- Commit after every task with a Conventional Commits message. Run `gofmt -w` on touched files before every commit.
- Binaries invoked as subprocesses (`git`) use an explicit arg list, never a shell string.

---

### Task 1: Bootstrap — module, dependencies, CLI entrypoint, `version`

**Files:**
- Create: `go.mod`
- Create: `cmd/guardrail/main.go`
- Create: `cmd/guardrail/run.go`
- Create: `cmd/guardrail/run_test.go`
- Create: `Makefile`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int` in `package main` — full CLI dispatch; `main()` is a one-liner wrapper. `args` excludes the program name.
  - `var version = "dev"` in `package main` — overridable via `-ldflags "-X main.version=..."`.

- [ ] **Step 1: Write `go.mod`**

```
module github.com/CtrlCarlitos/agent-guardrails

go 1.23

require (
	github.com/BurntSushi/toml v1.4.0
	github.com/bmatcuk/doublestar/v4 v4.7.1
	mvdan.cc/sh/v3 v3.10.0
)
```

- [ ] **Step 2: Download dependencies**

Run: `/usr/local/go/bin/go mod download && /usr/local/go/bin/go mod tidy`
Expected: `go.sum` created, no errors. (If versions above 404, run `/usr/local/go/bin/go get mvdan.cc/sh/v3@latest github.com/BurntSushi/toml@latest github.com/bmatcuk/doublestar/v4@latest` and let the resolver pick.)

- [ ] **Step 3: Write the failing test**

`cmd/guardrail/run_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"version"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "guardrail") {
		t.Fatalf("stdout = %q, want it to contain %q", out.String(), "guardrail")
	}
}

func TestRunUnknownSubcommand(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"frobnicate"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "unknown subcommand") {
		t.Fatalf("stderr = %q, want it to mention %q", errb.String(), "unknown subcommand")
	}
}

func TestRunNoArgs(t *testing.T) {
	var out, errb bytes.Buffer
	code := run(nil, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestRun -v`
Expected: FAIL — `run` and `version` undefined (build error).

- [ ] **Step 5: Write minimal implementation**

`cmd/guardrail/main.go`:

```go
package main

import (
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
```

`cmd/guardrail/run.go`:

```go
package main

import (
	"fmt"
	"io"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: no subcommand (try: version, hook)")
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "guardrail %s\n", version)
		return 0
	default:
		fmt.Fprintf(stderr, "guardrail: unknown subcommand %q\n", args[0])
		return 2
	}
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestRun -v`
Expected: PASS (all three).

- [ ] **Step 7: Write the `Makefile`**

```make
GO ?= /usr/local/go/bin/go
VERSION ?= dev

.PHONY: build test fmt
build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o guardrail ./cmd/guardrail

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...
```

- [ ] **Step 8: Verify build**

Run: `make build && ./guardrail version`
Expected: prints `guardrail dev`.

- [ ] **Step 9: Commit**

```bash
gofmt -w cmd/guardrail/
git add go.mod go.sum cmd/guardrail/ Makefile
git commit -m "feat: CLI entrypoint with version subcommand and testable run()"
```

---

### Task 2: Core policy types — Decision, Verdict, Rule, Policy, Slots

**Files:**
- Create: `internal/policy/policy.go`
- Create: `internal/policy/policy_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type Decision string` with consts `Allow Decision = "allow"`, `Ask = "ask"`, `Deny = "deny"`.
  - `func (d Decision) Severity() int` — allow 0, ask 1, deny 2, unknown -1.
  - `func (d Decision) Blocks() bool` — true for `deny`.
  - `type Verdict struct { Decision Decision; RuleID string; Reason string }`
  - `func (v Verdict) IsZero() bool` — true when `Decision == ""`.
  - `type Rule struct { ID string; Tool string; Pattern string; Decision Decision; Reason string }`
  - `type Slots struct { SafeRoots []string; SecretGlobs []string; SecretAllow []string; EgressAllowlist []string; AuditLog string }`
  - `type Policy struct { Slots Slots; Rules []Rule; Waived map[string]bool }`

- [ ] **Step 1: Write the failing test**

`internal/policy/policy_test.go`:

```go
package policy

import "testing"

func TestDecisionSeverity(t *testing.T) {
	cases := map[Decision]int{Allow: 0, Ask: 1, Deny: 2, Decision("x"): -1}
	for d, want := range cases {
		if got := d.Severity(); got != want {
			t.Errorf("%q.Severity() = %d, want %d", d, got, want)
		}
	}
}

func TestDecisionBlocks(t *testing.T) {
	if !Deny.Blocks() {
		t.Error("Deny should block")
	}
	if Ask.Blocks() || Allow.Blocks() {
		t.Error("only Deny blocks")
	}
}

func TestVerdictIsZero(t *testing.T) {
	if !(Verdict{}).IsZero() {
		t.Error("empty Verdict should be zero")
	}
	if (Verdict{Decision: Allow}).IsZero() {
		t.Error("Verdict with a decision is not zero")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/policy/ -v`
Expected: FAIL — build error, types undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/policy/policy.go`:

```go
// Package policy defines the guardrail policy model: the shipped Base policy,
// a project's Overlay, and the merge of the two.
package policy

type Decision string

const (
	Allow Decision = "allow"
	Ask   Decision = "ask"
	Deny  Decision = "deny"
)

func (d Decision) Severity() int {
	switch d {
	case Allow:
		return 0
	case Ask:
		return 1
	case Deny:
		return 2
	default:
		return -1
	}
}

func (d Decision) Blocks() bool { return d == Deny }

// Verdict is the outcome of evaluating one attempted tool call.
type Verdict struct {
	Decision Decision
	RuleID   string
	Reason   string
}

func (v Verdict) IsZero() bool { return v.Decision == "" }

// Rule is a data-driven policy rule (used for Overlay [[rules]]; the Base's
// core checks are code in internal/engine).
type Rule struct {
	ID       string
	Tool     string
	Pattern  string
	Decision Decision
	Reason   string
}

// Slots are the parameterized values a Base policy leaves for an Overlay to fill.
type Slots struct {
	SafeRoots       []string
	SecretGlobs     []string
	SecretAllow     []string
	EgressAllowlist []string
	AuditLog        string
}

// Policy is a fully merged, ready-to-evaluate policy.
type Policy struct {
	Slots  Slots
	Rules  []Rule
	Waived map[string]bool
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/policy/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/policy/
git add internal/policy/
git commit -m "feat(policy): core types — Decision, Verdict, Rule, Slots, Policy"
```

---

### Task 3: Normalized ToolCall type

**Files:**
- Create: `internal/engine/toolcall.go`
- Create: `internal/engine/toolcall_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type ToolCall struct { Plane string; Event string; Tool string; Command string; Paths []string; SessionID string; CWD string; RepoRoot string; Raw json.RawMessage }`
  - `func (tc ToolCall) IsBash() bool` — true when `Tool` is `"Bash"` (case-insensitive) or `Command != ""`.
  - `Event` values: `"pre"`, `"post"`.

- [ ] **Step 1: Write the failing test**

`internal/engine/toolcall_test.go`:

```go
package engine

import "testing"

func TestToolCallIsBash(t *testing.T) {
	if !(ToolCall{Tool: "Bash"}).IsBash() {
		t.Error("Tool=Bash is bash")
	}
	if !(ToolCall{Tool: "bash"}).IsBash() {
		t.Error("case-insensitive")
	}
	if !(ToolCall{Command: "ls"}).IsBash() {
		t.Error("a command string implies bash")
	}
	if (ToolCall{Tool: "Read", Paths: []string{"x"}}).IsBash() {
		t.Error("Read is not bash")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestToolCall -v`
Expected: FAIL — `ToolCall` undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/engine/toolcall.go`:

```go
// Package engine normalizes attempted tool calls and evaluates them against a policy.
package engine

import (
	"encoding/json"
	"strings"
)

// ToolCall is a plane-agnostic view of one attempted tool call.
type ToolCall struct {
	Plane     string // "claude", "opencode", "antigravity"
	Event     string // "pre" or "post"
	Tool      string // normalized tool name, e.g. "Bash", "Read", "Edit", "Write"
	Command   string // shell command, when the tool is a shell
	Paths     []string
	SessionID string
	CWD       string
	RepoRoot  string // git top-level for CWD, or CWD if not a repo
	Raw       json.RawMessage
}

func (tc ToolCall) IsBash() bool {
	return strings.EqualFold(tc.Tool, "bash") || tc.Command != ""
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestToolCall -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "feat(engine): normalized ToolCall type"
```

---

### Task 4: Tokenizer — compound-command split

**Files:**
- Create: `internal/engine/tokenize.go`
- Create: `internal/engine/tokenize_test.go`

**Interfaces:**
- Consumes: `mvdan.cc/sh/v3/syntax`.
- Produces:
  - `type Simple struct { Argv []string; Redirects []string }` — one command that will actually execute. `Redirects` holds the target words of `>`, `>>`, `2>` redirections.
  - `func splitSimples(src string) ([]Simple, error)` — every simple command anywhere in the parse tree (across `&& || ; |`, newlines, `$(...)`, backticks, `<(...)`), plus its redirect targets. Returns an error on parse failure (caller fails closed). Unexported; `Normalize` (Task 5) is the public entry.

- [ ] **Step 1: Write the failing test**

`internal/engine/tokenize_test.go`:

```go
package engine

import (
	"reflect"
	"testing"
)

func argvs(ss []Simple) [][]string {
	out := make([][]string, len(ss))
	for i, s := range ss {
		out[i] = s.Argv
	}
	return out
}

func TestSplitSimples(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{`ls`, [][]string{{"ls"}}},
		{`ls -la`, [][]string{{"ls", "-la"}}},
		{`ls && rm -rf .`, [][]string{{"ls"}, {"rm", "-rf", "."}}},
		{`a | b | c`, [][]string{{"a"}, {"b"}, {"c"}}},
		{"a\nb", [][]string{{"a"}, {"b"}}},
		{`foo; bar`, [][]string{{"foo"}, {"bar"}}},
		{`echo $(rm -rf /)`, [][]string{{"rm", "-rf", "/"}, {"echo", "$(rm -rf /)"}}},
	}
	for _, c := range cases {
		got, err := splitSimples(c.src)
		if err != nil {
			t.Fatalf("splitSimples(%q) error: %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("splitSimples(%q) argv = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestSplitSimplesRedirect(t *testing.T) {
	got, err := splitSimples(`echo hi > out.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Redirects) != 1 || got[0].Redirects[0] != "out.txt" {
		t.Fatalf("redirects = %+v, want [out.txt]", got)
	}
}

func TestSplitSimplesParseError(t *testing.T) {
	if _, err := splitSimples(`echo "unterminated`); err == nil {
		t.Fatal("want parse error for unterminated string")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestSplitSimples -v`
Expected: FAIL — `splitSimples` undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/engine/tokenize.go`:

```go
package engine

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func splitSimples(src string) ([]Simple, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, err
	}
	printer := syntax.NewPrinter()
	var out []Simple
	syntax.Walk(f, func(node syntax.Node) bool {
		ce, ok := node.(*syntax.CallExpr)
		if !ok || len(ce.Args) == 0 {
			return true
		}
		s := Simple{}
		for _, w := range ce.Args {
			var b strings.Builder
			_ = printer.Print(&b, w)
			s.Argv = append(s.Argv, b.String())
		}
		for _, r := range ce.Redirs {
			if r.Word == nil {
				continue
			}
			var b strings.Builder
			_ = printer.Print(&b, r.Word)
			s.Redirects = append(s.Redirects, b.String())
		}
		out = append(out, s)
		return true
	})
	return out, nil
}
```

Note: `syntax.Walk` visits nested `CallExpr` nodes (inside `$(...)`, `<(...)`, pipes) automatically, so the inner command is emitted before the outer. The outer's argv keeps the literal `$(...)` word because the printer renders the whole `Word`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestSplitSimples -v`
Expected: PASS. If the `echo $(rm -rf /)` ordering differs, adjust the expected slice to match the actual walk order and keep both entries.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "feat(engine): shell tokenizer — split compound commands into simples"
```

---

### Task 5: Tokenizer — wrapper stripping and runner unwrapping

**Files:**
- Modify: `internal/engine/tokenize.go`
- Modify: `internal/engine/tokenize_test.go`

**Interfaces:**
- Consumes: `splitSimples` (Task 4).
- Produces:
  - `func Normalize(command string) ([]Simple, error)` — public. Runs `splitSimples`, then for each `Simple`: strips leading no-op wrappers (`timeout <dur>`, `time`, `nice [-n N]`, `nohup`, `env VAR=VAL...`, bare `xargs`) in place; and for command *runners* that execute their trailing arguments (`npx`, `uvx`, `bunx`, `sudo`-less `docker run`, `docker exec`, `make`, `just`, `devbox run`, `mise exec`, `nix run`), appends an additional `Simple` for the inner command (argv after the runner + its own flags/image) while keeping the runner `Simple` too.
  - Runners list is a package var `var runnerHeads = map[string]int{...}` mapping the head to how many leading tokens to drop before the inner argv starts (`docker run` drops `["docker","run","<image>"]` → value handled specially; keep simple: for `docker`, if `argv[1]=="run"||argv[1]=="exec"`, inner starts after the first non-flag token following it).

- [ ] **Step 1: Write the failing test**

Add to `tokenize_test.go`:

```go
func TestNormalizeStripsWrappers(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{`timeout 5 rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`time git status`, [][]string{{"git", "status"}}},
		{`nice -n 10 make`, [][]string{{"make"}}},
		{`nohup ./server &`, [][]string{{"./server"}}},
		{`env FOO=1 BAR=2 curl example.com`, [][]string{{"curl", "example.com"}}},
	}
	for _, c := range cases {
		got, err := Normalize(c.src)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("Normalize(%q) = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestNormalizeUnwrapsRunners(t *testing.T) {
	got, err := Normalize(`docker run --rm alpine rm -rf /data`)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range got {
		if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/data"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an inner {rm -rf /data} simple, got %v", argvs(got))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestNormalize -v`
Expected: FAIL — `Normalize` undefined.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/engine/tokenize.go`:

```go
import "strings" // already imported

var noopWrappers = map[string]bool{
	"time": true, "nohup": true, "xargs": true,
}

// Normalize returns every command that will actually execute, with no-op
// wrappers stripped and argument-executing runners unwrapped.
func Normalize(command string) ([]Simple, error) {
	base, err := splitSimples(command)
	if err != nil {
		return nil, err
	}
	var out []Simple
	for _, s := range base {
		out = append(out, stripAndUnwrap(s)...)
	}
	return out, nil
}

func stripAndUnwrap(s Simple) []Simple {
	argv := s.Argv
	for len(argv) > 0 {
		head := argv[0]
		switch {
		case head == "timeout" && len(argv) >= 2:
			argv = argv[2:] // drop "timeout" + duration
		case head == "nice" && len(argv) >= 3 && argv[1] == "-n":
			argv = argv[3:]
		case head == "nice":
			argv = argv[1:]
		case noopWrappers[head]:
			argv = argv[1:]
		case head == "env":
			i := 1
			for i < len(argv) && strings.Contains(argv[i], "=") {
				i++
			}
			argv = argv[i:]
		default:
			goto done
		}
	}
done:
	if len(argv) == 0 {
		return nil
	}
	result := []Simple{{Argv: argv, Redirects: s.Redirects}}
	if inner := runnerInner(argv); inner != nil {
		result = append(result, Simple{Argv: inner})
	}
	return result
}

func runnerInner(argv []string) []string {
	switch argv[0] {
	case "npx", "uvx", "bunx", "make", "just":
		if len(argv) > 1 {
			return argv[1:]
		}
	case "docker":
		if len(argv) > 2 && (argv[1] == "run" || argv[1] == "exec") {
			i := 2
			for i < len(argv) && strings.HasPrefix(argv[i], "-") {
				i++
			}
			if i+1 < len(argv) {
				return argv[i+1:] // skip the image/container token
			}
		}
	case "devbox", "mise", "nix":
		if len(argv) > 2 {
			return argv[2:]
		}
	}
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestNormalize -v`
Expected: PASS. (`nohup ./server &` — the `&` is a background operator, not part of the CallExpr, so argv is `["./server"]`.)

- [ ] **Step 5: Run the whole engine package**

Run: `/usr/local/go/bin/go test ./internal/engine/ -v`
Expected: PASS (Tasks 3–5).

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "feat(engine): strip no-op wrappers, unwrap argument-executing runners"
```

---

### Task 6: P1 module — recursive delete / disk-destroying commands

**Files:**
- Create: `internal/engine/rules_bash.go`
- Create: `internal/engine/rules_bash_test.go`

**Interfaces:**
- Consumes: `Normalize` (Task 5), `ToolCall` (Task 3), `policy.Policy` / `policy.Verdict` (Task 2).
- Produces:
  - `func checkBash(tc ToolCall, pol *policy.Policy) *policy.Verdict` — returns the most severe hit, or `nil`. This task implements: `rm` with a recursive/force flag targeting a path outside the safe set → `deny` (`ID "P1.rm-rf"`); `dd of=/dev/*` → `deny` (`P1.dd`); `mkfs*`/`mke2fs`/`wipefs` → `deny` (`P1.mkfs`); `shred`/`srm` → `deny` (`P1.shred`).
  - Helper `func withinSafe(target, repoRoot string, safeRoots []string) bool`.

- [ ] **Step 1: Write the failing test**

`internal/engine/rules_bash_test.go`:

```go
package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func bashPol() *policy.Policy {
	return &policy.Policy{Slots: policy.Slots{SafeRoots: []string{"/repo/tmp"}}, Waived: map[string]bool{}}
}

func evalBash(t *testing.T, cmd string) *policy.Verdict {
	t.Helper()
	return checkBash(ToolCall{Tool: "Bash", Command: cmd, CWD: "/repo", RepoRoot: "/repo"}, bashPol())
}

func TestCheckBashDestructive(t *testing.T) {
	deny := []string{
		`rm -rf /`,
		`rm -rf ~`,
		`rm -r --force /etc`,
		`rm -fr /var/lib`,
		`dd if=/dev/zero of=/dev/sda`,
		`mkfs.ext4 /dev/sdb1`,
		`wipefs -a /dev/sdc`,
		`shred -u secrets`,
		`ls && rm -rf /`,
	}
	for _, c := range deny {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
}

func TestCheckBashAllows(t *testing.T) {
	ok := []string{
		`rm file.txt`,
		`rm -rf /repo/tmp/build`,
		`rm -rf ./node_modules`, // inside repo root
		`ls -la`,
		`dd if=in of=out.img`,
	}
	for _, c := range ok {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestCheckBash -v`
Expected: FAIL — `checkBash` undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/engine/rules_bash.go`:

```go
package engine

import (
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func checkBash(tc ToolCall, pol *policy.Policy) *policy.Verdict {
	if !tc.IsBash() {
		return nil
	}
	simples, err := Normalize(tc.Command)
	if err != nil {
		return &policy.Verdict{Decision: policy.Ask, RuleID: "tokenize-failed",
			Reason: "could not parse shell command; failing closed to ask"}
	}
	var worst *policy.Verdict
	take := func(v *policy.Verdict) {
		if v == nil {
			return
		}
		if pol.Waived[v.RuleID] {
			return
		}
		if worst == nil || v.Decision.Severity() > worst.Decision.Severity() {
			worst = v
		}
	}
	for _, s := range simples {
		if len(s.Argv) == 0 {
			continue
		}
		take(checkRmRf(s, tc, pol))
		take(checkDiskDestroyers(s))
	}
	return worst
}

func hasAnyFlag(argv []string, short string, long ...string) bool {
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "--") {
			for _, l := range long {
				if a == l {
					return true
				}
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if strings.ContainsAny(a[1:], short) {
				return true
			}
		}
	}
	return false
}

func nonFlagArgs(argv []string) []string {
	var out []string
	for _, a := range argv[1:] {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

func checkRmRf(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict {
	if s.Argv[0] != "rm" {
		return nil
	}
	if !hasAnyFlag(s.Argv, "rf", "--recursive", "--force", "-R") {
		// need at least one of recursive OR force to be dangerous
		return nil
	}
	recursive := hasAnyFlag(s.Argv, "rR", "--recursive")
	force := hasAnyFlag(s.Argv, "f", "--force")
	if !recursive && !force {
		return nil
	}
	for _, raw := range nonFlagArgs(s.Argv) {
		if !withinSafe(resolvePath(raw, tc.CWD), tc.RepoRoot, pol.Slots.SafeRoots) {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.rm-rf",
				Reason: "recursive/forced rm of a path outside the repo and configured safe roots: " + raw}
		}
	}
	return nil
}

func checkDiskDestroyers(s Simple) *policy.Verdict {
	head := s.Argv[0]
	switch {
	case head == "dd":
		for _, a := range s.Argv[1:] {
			if strings.HasPrefix(a, "of=/dev/") {
				return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.dd",
					Reason: "dd writing to a raw device: " + a}
			}
		}
	case head == "mkfs" || strings.HasPrefix(head, "mkfs.") || head == "mke2fs" || head == "wipefs":
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.mkfs",
			Reason: "filesystem-destroying command: " + head}
	case head == "shred" || head == "srm":
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.shred",
			Reason: "irreversible secure-delete command: " + head}
	}
	return nil
}

func resolvePath(p, cwd string) string {
	if strings.HasPrefix(p, "~") {
		return p // treat "~" as outside any safe root; do not expand
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(cwd, p))
}

func withinSafe(target, repoRoot string, safeRoots []string) bool {
	if target == "~" || strings.HasPrefix(target, "~/") || target == "/" {
		return false
	}
	roots := append([]string{repoRoot}, safeRoots...)
	for _, r := range roots {
		if r == "" {
			continue
		}
		rr := filepath.Clean(r)
		if target == rr || strings.HasPrefix(target, rr+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestCheckBash -v`
Expected: PASS. (`rm -rf ./node_modules` resolves to `/repo/node_modules`, under `RepoRoot=/repo` → allowed. `rm -rf /repo/tmp/build` under SafeRoots → allowed.)

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "feat(engine): P1 — deny rm -rf outside safe roots, dd/mkfs/shred"
```

---

### Task 7: P1 module — destructive git and docker

**Files:**
- Modify: `internal/engine/rules_bash.go`
- Modify: `internal/engine/rules_bash_test.go`

**Interfaces:**
- Consumes: everything from Task 6.
- Produces: `checkBash` additionally detects — `git push` with `-f`/`--force` → `deny` (`P1.git-push-force`); `git clean` with `-f`/`--force`/`-x`/`-d` → `deny` (`P1.git-clean`); `docker compose down` → `deny` (`P1.docker-down`); `docker system|network|volume prune` → `deny` (`P1.docker-prune`); `docker rm|kill|volume rm|network rm` whose original command text contains `$(` or a backtick → `deny` (`P1.docker-substituted`).
- New helper: `func commandHasSubstitution(cmd string) bool`.

- [ ] **Step 1: Write the failing test**

Add to `rules_bash_test.go`:

```go
func TestCheckBashGitDocker(t *testing.T) {
	deny := []string{
		`git push --force origin main`,
		`git push -f`,
		`git clean -fd`,
		`git clean -x`,
		`docker compose down`,
		`docker system prune -af`,
		`docker network prune`,
		`docker rm $(docker ps -aq)`,
		"docker rm `docker ps -aq`",
	}
	for _, c := range deny {
		if v := evalBash(t, c); v == nil || v.Decision != policy.Deny {
			t.Errorf("%q -> %+v, want deny", c, v)
		}
	}
	ok := []string{
		`git push origin main`,
		`git clean -n`,
		`docker rm my-container`,
		`docker compose up -d`,
	}
	for _, c := range ok {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestCheckBashGitDocker -v`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

Add to `rules_bash.go`. In `checkBash`, inside the `for _, s := range simples` loop, add:

```go
		take(checkGit(s))
		take(checkDocker(s, tc.Command))
```

Then:

```go
func checkGit(s Simple) *policy.Verdict {
	if s.Argv[0] != "git" || len(s.Argv) < 2 {
		return nil
	}
	sub := gitSubcommand(s.Argv)
	switch sub {
	case "push":
		if hasAnyFlag(s.Argv, "f", "--force") {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.git-push-force",
				Reason: "git push --force overwrites remote history"}
		}
	case "clean":
		if hasAnyFlag(s.Argv, "fxd", "--force") {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.git-clean",
				Reason: "git clean -f/-x/-d deletes untracked files irrecoverably"}
		}
	}
	return nil
}

func gitSubcommand(argv []string) string {
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if a == "-C" { // handled as flag above only if prefixed; -C takes a value
			continue
		}
		return a
	}
	return ""
}

func checkDocker(s Simple, rawCmd string) *policy.Verdict {
	if s.Argv[0] != "docker" || len(s.Argv) < 2 {
		return nil
	}
	joined := strings.Join(s.Argv[1:], " ")
	switch {
	case strings.HasPrefix(joined, "compose down"):
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-down",
			Reason: "docker compose down tears down a whole stack"}
	case strings.HasPrefix(joined, "system prune"),
		strings.HasPrefix(joined, "network prune"),
		strings.HasPrefix(joined, "volume prune"):
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-prune",
			Reason: "docker prune removes resources with unverifiable scope"}
	}
	first := s.Argv[1]
	target := strings.HasPrefix(joined, "rm ") || strings.HasPrefix(joined, "kill ") ||
		strings.HasPrefix(joined, "volume rm") || strings.HasPrefix(joined, "network rm")
	if (first == "rm" || first == "kill" || first == "volume" || first == "network") && target &&
		commandHasSubstitution(rawCmd) {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.docker-substituted",
			Reason: "docker rm/kill with a command-substituted target list"}
	}
	return nil
}

func commandHasSubstitution(cmd string) bool {
	return strings.Contains(cmd, "$(") || strings.Contains(cmd, "`")
}
```

Adjust `hasAnyFlag` calls: `git clean -fd` → short flags `fd`; the call `hasAnyFlag(s.Argv, "fxd", "--force")` returns true if any of `f`,`x`,`d` present. `git clean -n` → not matched. Good.

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestCheckBash -v`
Expected: PASS (Task 6 + Task 7).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "feat(engine): P1 — deny git push --force, git clean, docker teardown/prune/substituted-rm"
```

---

### Task 8: P1 module — ask-tier commands

**Files:**
- Modify: `internal/engine/rules_bash.go`
- Modify: `internal/engine/rules_bash_test.go`

**Interfaces:**
- Consumes: Task 7 state.
- Produces: `checkBash` additionally returns `ask` for — `chmod` with `-R`/`--recursive` or a `777` mode (`P1.chmod`); `chown -R` (`P1.chown`); `find` argv containing `-delete` or `-exec rm` (`P1.find-delete`); `truncate` (`P1.truncate`); any `Simple.Redirects` target that is not under a safe root (`P1.redirect`); `kill -9`/`killall`/`pkill` (`P1.kill`). And `deny` for `sudo`/`su`/`doas` as the head (`P1.privesc`).

- [ ] **Step 1: Write the failing test**

Add to `rules_bash_test.go`:

```go
func TestCheckBashAskTier(t *testing.T) {
	ask := map[string]string{
		`chmod -R 755 /repo`:        "P1.chmod",
		`chmod 777 script.sh`:       "P1.chmod",
		`chown -R me:me /var/www`:   "P1.chown",
		`find . -name '*.tmp' -delete`: "P1.find-delete",
		`truncate -s 0 app.log`:     "P1.truncate",
		`echo x > /etc/hosts`:       "P1.redirect",
		`kill -9 1234`:              "P1.kill",
		`pkill -f server`:           "P1.kill",
	}
	for c, id := range ask {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Ask || v.RuleID != id {
			t.Errorf("%q -> %+v, want ask/%s", c, v, id)
		}
	}
}

func TestCheckBashPrivesc(t *testing.T) {
	for _, c := range []string{`sudo rm x`, `su -`, `doas pkg_add x`} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P1.privesc" {
			t.Errorf("%q -> %+v, want deny/P1.privesc", c, v)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run 'TestCheckBashAskTier|TestCheckBashPrivesc' -v`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

In `checkBash`'s loop add `take(checkAskTier(s, tc, pol))`. Then:

```go
func checkAskTier(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict {
	head := s.Argv[0]
	switch head {
	case "sudo", "su", "doas":
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.privesc",
			Reason: "privilege escalation removes every other guardrail's ground truth"}
	case "chmod":
		if hasAnyFlag(s.Argv, "R", "--recursive") {
			return ask("P1.chmod", "recursive chmod")
		}
		for _, a := range nonFlagArgs(s.Argv) {
			if a == "777" || a == "0777" {
				return ask("P1.chmod", "chmod 777 widens permissions dangerously")
			}
		}
	case "chown":
		if hasAnyFlag(s.Argv, "R", "--recursive") {
			return ask("P1.chown", "recursive chown")
		}
	case "find":
		for i, a := range s.Argv {
			if a == "-delete" {
				return ask("P1.find-delete", "find -delete is a bulk deletion primitive")
			}
			if a == "-exec" && i+1 < len(s.Argv) && s.Argv[i+1] == "rm" {
				return ask("P1.find-delete", "find -exec rm is a bulk deletion primitive")
			}
		}
	case "truncate":
		return ask("P1.truncate", "truncate destroys file contents with no diff")
	case "kill":
		if hasAnyFlag(s.Argv, "9") {
			return ask("P1.kill", "kill -9 can corrupt the target process's state")
		}
	case "killall", "pkill":
		return ask("P1.kill", "killall/pkill can terminate unrelated work")
	}
	for _, r := range s.Redirects {
		if !withinSafe(resolvePath(r, tc.CWD), tc.RepoRoot, pol.Slots.SafeRoots) {
			return ask("P1.redirect", "output redirection onto a path outside the repo/safe roots: "+r)
		}
	}
	return nil
}

func ask(id, reason string) *policy.Verdict {
	return &policy.Verdict{Decision: policy.Ask, RuleID: id, Reason: reason}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestCheckBash -v`
Expected: PASS (Tasks 6–8). Note `echo x > /etc/hosts` → the redirect target `/etc/hosts` is outside → `ask`.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "feat(engine): P1 — ask on chmod -R/777, chown -R, find -delete, truncate, redirect, kill; deny sudo"
```

---

### Task 9: P4 module — secret-path denial

**Files:**
- Create: `internal/engine/rules_path.go`
- Create: `internal/engine/rules_path_test.go`

**Interfaces:**
- Consumes: `Normalize` (Task 5), `ToolCall`, `policy` types, `github.com/bmatcuk/doublestar/v4`.
- Produces:
  - `func checkPaths(tc ToolCall, pol *policy.Policy) *policy.Verdict` — for file tools (`Tool` in `Read`/`Edit`/`Write`/`MultiEdit`, case-insensitive) over `tc.Paths`, and for bash simples whose head is a reader (`cat`,`head`,`tail`,`grep`,`egrep`,`fgrep`,`sed`,`awk`,`less`,`more`,`bat`,`xxd`,`od`,`strings`) over their non-flag args — deny (`P4.secret-path`) when the path matches any `pol.Slots.SecretGlobs` and does not match any `pol.Slots.SecretAllow`.
  - `func matchesAnyGlob(path string, globs []string) bool` — uses `doublestar.Match`; also matches against the path's `basename` so bare-name globs like `id_rsa*` hit.

- [ ] **Step 1: Write the failing test**

`internal/engine/rules_path_test.go`:

```go
package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func pathPol() *policy.Policy {
	return &policy.Policy{
		Slots: policy.Slots{
			SecretGlobs: []string{
				"**/.env", ".env.*", "**/.env.*",
				"**/.ssh/**", "**/.aws/**", "**/.netrc",
				"id_rsa*", "id_ed25519*", "*.pem", "*.key",
				"**/.claude.json", "service-account*.json",
			},
			SecretAllow: []string{"**/.env.example", ".env.example"},
		},
		Waived: map[string]bool{},
	}
}

func TestCheckPathsFileTool(t *testing.T) {
	deny := []string{
		"/home/u/.ssh/id_rsa",
		"/home/u/project/.env",
		"/home/u/project/.env.production",
		"/home/u/.aws/credentials",
		"secrets/server.pem",
		"/home/u/.claude.json",
	}
	for _, p := range deny {
		tc := ToolCall{Tool: "Read", Paths: []string{p}}
		v := checkPaths(tc, pathPol())
		if v == nil || v.Decision != policy.Deny {
			t.Errorf("Read %q -> %+v, want deny", p, v)
		}
	}
	ok := []string{"/home/u/project/.env.example", "src/main.go", "README.md"}
	for _, p := range ok {
		tc := ToolCall{Tool: "Read", Paths: []string{p}}
		if v := checkPaths(tc, pathPol()); v != nil {
			t.Errorf("Read %q -> %+v, want nil", p, v)
		}
	}
}

func TestCheckPathsBashReader(t *testing.T) {
	tc := ToolCall{Tool: "Bash", Command: `cat ~/.aws/credentials`}
	if v := checkPaths(tc, pathPol()); v == nil || v.Decision != policy.Deny {
		t.Errorf("cat credentials -> %+v, want deny", v)
	}
	tc = ToolCall{Tool: "Bash", Command: `grep -r TODO src/`}
	if v := checkPaths(tc, pathPol()); v != nil {
		t.Errorf("grep src -> %+v, want nil", v)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestCheckPaths -v`
Expected: FAIL — `checkPaths` undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/engine/rules_path.go`:

```go
package engine

import (
	"path"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

var pathReaders = map[string]bool{
	"cat": true, "head": true, "tail": true, "grep": true, "egrep": true, "fgrep": true,
	"sed": true, "awk": true, "less": true, "more": true, "bat": true, "xxd": true,
	"od": true, "strings": true,
}

func isFileTool(tool string) bool {
	switch strings.ToLower(tool) {
	case "read", "edit", "write", "multiedit":
		return true
	}
	return false
}

func checkPaths(tc ToolCall, pol *policy.Policy) *policy.Verdict {
	var candidates []string
	if isFileTool(tc.Tool) {
		candidates = append(candidates, tc.Paths...)
	}
	if tc.IsBash() {
		simples, err := Normalize(tc.Command)
		if err == nil {
			for _, s := range simples {
				if len(s.Argv) > 0 && pathReaders[s.Argv[0]] {
					candidates = append(candidates, nonFlagArgs(s.Argv)...)
				}
			}
		}
	}
	for _, c := range candidates {
		c = strings.TrimPrefix(c, "~/")
		c = strings.TrimPrefix(c, "~")
		if matchesAnyGlob(c, pol.Slots.SecretAllow) {
			continue
		}
		if matchesAnyGlob(c, pol.Slots.SecretGlobs) {
			if pol.Waived["P4.secret-path"] {
				return nil
			}
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P4.secret-path",
				Reason: "access to a credential/secret path: " + c}
		}
	}
	return nil
}

func matchesAnyGlob(p string, globs []string) bool {
	p = strings.TrimPrefix(p, "./")
	base := path.Base(p)
	for _, g := range globs {
		if ok, _ := doublestar.Match(g, p); ok {
			return true
		}
		if ok, _ := doublestar.Match(g, base); ok {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestCheckPaths -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "feat(engine): P4 — deny secret-path access via file tools and shell readers"
```

---

### Task 10: P4 module — symlink-escape detection

**Files:**
- Modify: `internal/engine/rules_path.go`
- Modify: `internal/engine/rules_path_test.go`

**Interfaces:**
- Consumes: Task 9 state.
- Produces: `checkPaths` also denies (`P4.symlink-escape`) when a candidate path, resolved with `filepath.EvalSymlinks`, lands outside `tc.RepoRoot` while the un-resolved path was inside it, or the resolved path matches a `SecretGlob`. Absolute candidates and a missing `RepoRoot` skip this check.

- [ ] **Step 1: Write the failing test**

Add to `rules_path_test.go`:

```go
import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckPathsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows")
	}
	repo := t.TempDir()
	outside := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, "innocent.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	tc := ToolCall{Tool: "Edit", Paths: []string{link}, RepoRoot: repo, CWD: repo}
	v := checkPaths(tc, pathPol())
	if v == nil || v.RuleID != "P4.symlink-escape" {
		t.Fatalf("-> %+v, want deny/P4.symlink-escape", v)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestCheckPathsSymlink -v`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation**

In `rules_path.go`, add `"path/filepath"` to imports. In `checkPaths`, after the `matchesAnyGlob(c, SecretGlobs)` block (still inside the `for _, c := range candidates` loop), add:

```go
		if v := checkSymlinkEscape(c, tc); v != nil {
			return v
		}
```

Then:

```go
func checkSymlinkEscape(cand string, tc ToolCall) *policy.Verdict {
	if tc.RepoRoot == "" || filepath.IsAbs(cand) && !strings.HasPrefix(filepath.Clean(cand), filepath.Clean(tc.RepoRoot)) {
		// only guard paths that claim to be inside the repo
		if !strings.HasPrefix(filepath.Clean(cand), filepath.Clean(tc.RepoRoot)) {
			return nil
		}
	}
	abs := cand
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(tc.CWD, cand)
	}
	if !strings.HasPrefix(filepath.Clean(abs), filepath.Clean(tc.RepoRoot)+string(filepath.Separator)) {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil // nonexistent target: nothing to resolve yet
	}
	root := filepath.Clean(tc.RepoRoot) + string(filepath.Separator)
	if !strings.HasPrefix(filepath.Clean(resolved)+string(filepath.Separator), root) {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P4.symlink-escape",
			Reason: "a path inside the repo resolves outside it via symlink: " + cand}
	}
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestCheckPaths -v`
Expected: PASS (Tasks 9–10).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "feat(engine): P4 — deny in-repo paths that symlink-escape the worktree"
```

---

### Task 11: Base policy — embedded TOML

**Files:**
- Create: `internal/policy/base.toml`
- Create: `internal/policy/base.go`
- Create: `internal/policy/base_test.go`

**Interfaces:**
- Consumes: `github.com/BurntSushi/toml`, `embed`.
- Produces:
  - `func LoadBase() (*Policy, error)` — parses the embedded `base.toml` into a `Policy` (`Waived` initialized to an empty map).
  - `base.toml` schema: `[slots]` table with `safe_roots`, `secret_globs`, `secret_allow`, `egress_allowlist` string arrays and `audit_log` string; optional `[[rules]]` array of `{ id, tool, pattern, decision, reason }`.

- [ ] **Step 1: Write `base.toml`**

```toml
# The shipped Base policy. Universal rules only — anything project-specific
# belongs in a repo's guardrail.toml Overlay.

[slots]
safe_roots       = []
egress_allowlist = []
audit_log        = ""

secret_globs = [
  "**/.env", ".env.*", "**/.env.*",
  "**/.ssh/**", "**/.aws/**", "**/.config/gcloud/**",
  "**/.kube/config", "**/.netrc", "**/.npmrc", "**/.pypirc",
  "**/.docker/config.json", "**/.git-credentials",
  "id_rsa*", "id_ed25519*", "*.pem", "*.key",
  "service-account*.json", "**/.claude.json",
  "/root/.ssh/**",
]

secret_allow = [
  "**/.env.example", ".env.example", "**/.env.sample", ".env.sample",
]
```

- [ ] **Step 2: Write the failing test**

`internal/policy/base_test.go`:

```go
package policy

import (
	"slices"
	"testing"
)

func TestLoadBase(t *testing.T) {
	p, err := LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Slots.SecretGlobs) < 12 {
		t.Errorf("SecretGlobs = %d entries, want >= 12", len(p.Slots.SecretGlobs))
	}
	if !slices.Contains(p.Slots.SecretAllow, ".env.example") {
		t.Errorf("SecretAllow missing .env.example: %v", p.Slots.SecretAllow)
	}
	if p.Waived == nil {
		t.Error("Waived must be a non-nil map")
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/policy/ -run TestLoadBase -v`
Expected: FAIL — `LoadBase` undefined.

- [ ] **Step 4: Write minimal implementation**

`internal/policy/base.go`:

```go
package policy

import (
	_ "embed"

	"github.com/BurntSushi/toml"
)

//go:embed base.toml
var baseTOML []byte

type fileShape struct {
	Slots struct {
		SafeRoots       []string `toml:"safe_roots"`
		SecretGlobs     []string `toml:"secret_globs"`
		SecretAllow     []string `toml:"secret_allow"`
		EgressAllowlist []string `toml:"egress_allowlist"`
		AuditLog        string   `toml:"audit_log"`
	} `toml:"slots"`
	Rules []struct {
		ID       string `toml:"id"`
		Tool     string `toml:"tool"`
		Pattern  string `toml:"pattern"`
		Decision string `toml:"decision"`
		Reason   string `toml:"reason"`
	} `toml:"rules"`
}

func (f fileShape) toPolicy() *Policy {
	p := &Policy{
		Slots: Slots{
			SafeRoots:       f.Slots.SafeRoots,
			SecretGlobs:     f.Slots.SecretGlobs,
			SecretAllow:     f.Slots.SecretAllow,
			EgressAllowlist: f.Slots.EgressAllowlist,
			AuditLog:        f.Slots.AuditLog,
		},
		Waived: map[string]bool{},
	}
	for _, r := range f.Rules {
		p.Rules = append(p.Rules, Rule{
			ID: r.ID, Tool: r.Tool, Pattern: r.Pattern,
			Decision: Decision(r.Decision), Reason: r.Reason,
		})
	}
	return p
}

func LoadBase() (*Policy, error) {
	var f fileShape
	if err := toml.Unmarshal(baseTOML, &f); err != nil {
		return nil, err
	}
	return f.toPolicy(), nil
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/policy/ -run TestLoadBase -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/policy/
git add internal/policy/
git commit -m "feat(policy): embedded Base policy loaded from base.toml"
```

---

### Task 12: Overlay discovery and parsing

**Files:**
- Create: `internal/policy/config.go`
- Create: `internal/policy/config_test.go`

**Interfaces:**
- Consumes: `os/exec` (`git`), `github.com/BurntSushi/toml`.
- Produces:
  - `type Overlay struct { EngineMinVersion string; AuditLog string; SafeRoots []string; SecretGlobs []string; SecretAllow []string; EgressAllowlist []string; Rules []Rule; Waive []string; Path string }`
  - `func FindOverlayPath(cwd string) (string, bool)` — `$GUARDRAIL_CONFIG` if set and non-empty → `(that, true)` regardless of existence; else `git -C <cwd> rev-parse --show-toplevel` → `<root>/guardrail.toml` if it exists → `(that, true)`; else `("", false)`.
  - `func LoadOverlay(pth string) (*Overlay, error)` — parse TOML; a nonexistent path returns `(&Overlay{Path: pth}, nil)` (empty overlay, not an error) **only** when it came from git-root discovery; when it came from `$GUARDRAIL_CONFIG` and is missing, return an error. To keep the signature simple, `LoadOverlay` returns `(nil, nil)` for a nonexistent file and lets the caller decide; `FindOverlayPath` already guarantees existence for the git-root case.

  Final decision for a clean contract: `FindOverlayPath` returns a path only when the file exists (git-root case) or when `$GUARDRAIL_CONFIG` is set (trusting the user). `LoadOverlay(pth)`: if the file does not exist → return `(nil, error)`. Caller treats "no overlay path" as empty overlay and a present-but-unreadable path as fatal.

- [ ] **Step 1: Write the failing test**

`internal/policy/config_test.go`:

```go
package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func gitInit(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q"}, {"config", "user.email", "t@t"}, {"config", "user.name", "t"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestFindOverlayPathGitRoot(t *testing.T) {
	root := t.TempDir()
	gitInit(t, root)
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(root, "guardrail.toml")
	if err := os.WriteFile(cfg, []byte("engine_min_version = \"0.1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := FindOverlayPath(sub)
	if !ok || got != cfg {
		t.Fatalf("FindOverlayPath(%q) = %q,%v; want %q,true", sub, got, ok, cfg)
	}
}

func TestFindOverlayPathEnvOverride(t *testing.T) {
	t.Setenv("GUARDRAIL_CONFIG", "/tmp/custom.toml")
	got, ok := FindOverlayPath("/anywhere")
	if !ok || got != "/tmp/custom.toml" {
		t.Fatalf("got %q,%v", got, ok)
	}
}

func TestFindOverlayPathNone(t *testing.T) {
	t.Setenv("GUARDRAIL_CONFIG", "")
	dir := t.TempDir() // not a git repo
	if got, ok := FindOverlayPath(dir); ok {
		t.Fatalf("want no overlay, got %q", got)
	}
}

func TestLoadOverlay(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "guardrail.toml")
	os.WriteFile(p, []byte(`
engine_min_version = "1.2"
audit_log = ".agents/guardrail.jsonl"

[slots]
safe_roots = ["./tmp"]
egress_allowlist = ["api.example.com"]

[[rules]]
id = "proj.tf"
pattern = "terraform apply*"
decision = "ask"
reason = "infra change"

waive = ["P6.curl-egress"]
`), 0o644)
	ov, err := LoadOverlay(p)
	if err != nil {
		t.Fatal(err)
	}
	if ov.EngineMinVersion != "1.2" || ov.AuditLog != ".agents/guardrail.jsonl" {
		t.Errorf("scalars wrong: %+v", ov)
	}
	if len(ov.SafeRoots) != 1 || ov.SafeRoots[0] != "./tmp" {
		t.Errorf("safe_roots wrong: %v", ov.SafeRoots)
	}
	if len(ov.Rules) != 1 || ov.Rules[0].Decision != Ask {
		t.Errorf("rules wrong: %+v", ov.Rules)
	}
	if len(ov.Waive) != 1 || ov.Waive[0] != "P6.curl-egress" {
		t.Errorf("waive wrong: %v", ov.Waive)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/policy/ -run 'Overlay' -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/policy/config.go`:

```go
package policy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Overlay struct {
	EngineMinVersion string
	AuditLog         string
	SafeRoots        []string
	SecretGlobs      []string
	SecretAllow      []string
	EgressAllowlist  []string
	Rules            []Rule
	Waive            []string
	Path             string
}

func FindOverlayPath(cwd string) (string, bool) {
	if v := os.Getenv("GUARDRAIL_CONFIG"); v != "" {
		return v, true
	}
	cmd := exec.Command("git", "-C", cwd, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	root := strings.TrimSpace(string(out))
	cfg := filepath.Join(root, "guardrail.toml")
	if _, err := os.Stat(cfg); err != nil {
		return "", false
	}
	return cfg, true
}

func LoadOverlay(pth string) (*Overlay, error) {
	raw, err := os.ReadFile(pth)
	if err != nil {
		return nil, fmt.Errorf("reading overlay %s: %w", pth, err)
	}
	var f struct {
		EngineMinVersion string `toml:"engine_min_version"`
		AuditLog         string `toml:"audit_log"`
		Waive            []string `toml:"waive"`
		Slots            struct {
			SafeRoots       []string `toml:"safe_roots"`
			SecretGlobs     []string `toml:"secret_globs"`
			SecretAllow     []string `toml:"secret_allow"`
			EgressAllowlist []string `toml:"egress_allowlist"`
		} `toml:"slots"`
		Rules []struct {
			ID       string `toml:"id"`
			Tool     string `toml:"tool"`
			Pattern  string `toml:"pattern"`
			Decision string `toml:"decision"`
			Reason   string `toml:"reason"`
		} `toml:"rules"`
	}
	if err := toml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing overlay %s: %w", pth, err)
	}
	ov := &Overlay{
		EngineMinVersion: f.EngineMinVersion,
		AuditLog:         f.AuditLog,
		SafeRoots:        f.Slots.SafeRoots,
		SecretGlobs:      f.Slots.SecretGlobs,
		SecretAllow:      f.Slots.SecretAllow,
		EgressAllowlist:  f.Slots.EgressAllowlist,
		Waive:            f.Waive,
		Path:             pth,
	}
	for _, r := range f.Rules {
		ov.Rules = append(ov.Rules, Rule{
			ID: r.ID, Tool: r.Tool, Pattern: r.Pattern,
			Decision: Decision(r.Decision), Reason: r.Reason,
		})
	}
	return ov, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/policy/ -run 'Overlay' -v`
Expected: PASS. (Requires `git` on PATH — it is.)

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/policy/
git add internal/policy/
git commit -m "feat(policy): overlay discovery (git root / GUARDRAIL_CONFIG) and TOML parsing"
```

---

### Task 13: Merge — Base ∪ Overlay, waivers, no downgrade

**Files:**
- Create: `internal/policy/merge.go`
- Create: `internal/policy/merge_test.go`

**Interfaces:**
- Consumes: Tasks 2, 11, 12.
- Produces:
  - `func Merge(base *Policy, ov *Overlay, binaryVersion string) (*Policy, []string, error)` — returns the merged policy, a slice of human-readable warnings (currently: an `engine_min_version` newer than `binaryVersion`, and one line per active waiver), and an error if any Overlay rule has `Decision == Allow`.
  - Merge semantics: slot string-slices are **appended** (base entries first, then overlay); `AuditLog` is overlay-wins when non-empty; overlay `Rules` are appended to base `Rules`; `Waive` entries populate `merged.Waived`.
  - `func versionOlder(bin, min string) bool` — dotted numeric compare; non-numeric or empty → `false` (never warn).

- [ ] **Step 1: Write the failing test**

`internal/policy/merge_test.go`:

```go
package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestMergeAppendsSlots(t *testing.T) {
	base := &Policy{Slots: Slots{SafeRoots: []string{"/repo"}, SecretGlobs: []string{"**/.env"}}, Waived: map[string]bool{}}
	ov := &Overlay{SafeRoots: []string{"./tmp"}, SecretGlobs: []string{"*.p12"}}
	m, _, err := Merge(base, ov, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Slots.SafeRoots, []string{"/repo", "./tmp"}) {
		t.Errorf("SafeRoots = %v", m.Slots.SafeRoots)
	}
	if !slices.Equal(m.Slots.SecretGlobs, []string{"**/.env", "*.p12"}) {
		t.Errorf("SecretGlobs = %v", m.Slots.SecretGlobs)
	}
}

func TestMergeWaivers(t *testing.T) {
	base := &Policy{Waived: map[string]bool{}}
	ov := &Overlay{Waive: []string{"P6.curl-egress"}}
	m, warns, err := Merge(base, ov, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Waived["P6.curl-egress"] {
		t.Error("waiver not recorded")
	}
	if !slices.ContainsFunc(warns, func(s string) bool { return strings.Contains(s, "P6.curl-egress") }) {
		t.Errorf("no warning for active waiver: %v", warns)
	}
}

func TestMergeRejectsAllowRule(t *testing.T) {
	base := &Policy{Waived: map[string]bool{}}
	ov := &Overlay{Rules: []Rule{{ID: "x", Decision: Allow, Pattern: "curl *"}}}
	if _, _, err := Merge(base, ov, "1.0.0"); err == nil {
		t.Fatal("want error for an overlay allow rule")
	}
}

func TestMergeMinVersionWarning(t *testing.T) {
	base := &Policy{Waived: map[string]bool{}}
	ov := &Overlay{EngineMinVersion: "2.5.0"}
	_, warns, err := Merge(base, ov, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(warns, func(s string) bool { return strings.Contains(s, "2.5.0") }) {
		t.Errorf("no min-version warning: %v", warns)
	}
}

func TestVersionOlder(t *testing.T) {
	if !versionOlder("1.0.0", "1.2.0") {
		t.Error("1.0.0 < 1.2.0")
	}
	if versionOlder("2.0.0", "1.9.9") {
		t.Error("2.0.0 !< 1.9.9")
	}
	if versionOlder("dev", "1.0.0") {
		t.Error("non-numeric never warns")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/policy/ -run 'Merge|VersionOlder' -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/policy/merge.go`:

```go
package policy

import (
	"fmt"
	"strconv"
	"strings"
)

func Merge(base *Policy, ov *Overlay, binaryVersion string) (*Policy, []string, error) {
	m := &Policy{
		Slots: Slots{
			SafeRoots:       append(append([]string{}, base.Slots.SafeRoots...), overlaySafe(ov)...),
			SecretGlobs:     append(append([]string{}, base.Slots.SecretGlobs...), overlayGlobs(ov)...),
			SecretAllow:     append(append([]string{}, base.Slots.SecretAllow...), overlayAllow(ov)...),
			EgressAllowlist: append(append([]string{}, base.Slots.EgressAllowlist...), overlayEgress(ov)...),
			AuditLog:        base.Slots.AuditLog,
		},
		Rules:  append([]Rule{}, base.Rules...),
		Waived: map[string]bool{},
	}
	for k, v := range base.Waived {
		m.Waived[k] = v
	}
	var warns []string
	if ov != nil {
		if ov.AuditLog != "" {
			m.Slots.AuditLog = ov.AuditLog
		}
		for _, r := range ov.Rules {
			if r.Decision == Allow {
				return nil, nil, fmt.Errorf("overlay rule %q uses decision=allow; overlays may only add ask/deny (use slots or waive to loosen)", r.ID)
			}
			m.Rules = append(m.Rules, r)
		}
		for _, w := range ov.Waive {
			m.Waived[w] = true
			warns = append(warns, "guardrail: rule "+w+" is WAIVED by this repo's guardrail.toml")
		}
		if ov.EngineMinVersion != "" && versionOlder(binaryVersion, ov.EngineMinVersion) {
			warns = append(warns, fmt.Sprintf("guardrail: binary %s is older than this repo's engine_min_version %s", binaryVersion, ov.EngineMinVersion))
		}
	}
	return m, warns, nil
}

func overlaySafe(ov *Overlay) []string   { if ov == nil { return nil }; return ov.SafeRoots }
func overlayGlobs(ov *Overlay) []string  { if ov == nil { return nil }; return ov.SecretGlobs }
func overlayAllow(ov *Overlay) []string  { if ov == nil { return nil }; return ov.SecretAllow }
func overlayEgress(ov *Overlay) []string { if ov == nil { return nil }; return ov.EgressAllowlist }

func versionOlder(bin, min string) bool {
	bp, ok1 := parseVer(bin)
	mp, ok2 := parseVer(min)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if bp[i] != mp[i] {
			return bp[i] < mp[i]
		}
	}
	return false
}

func parseVer(s string) ([3]int, bool) {
	s = strings.TrimPrefix(s, "v")
	parts := strings.SplitN(s, ".", 3)
	var out [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(strings.TrimSuffixFunc(parts[i], func(r rune) bool { return r < '0' || r > '9' }))
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/policy/ -v`
Expected: PASS (Tasks 2, 11, 12, 13).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/policy/
git add internal/policy/
git commit -m "feat(policy): Merge — append slots, record waivers, reject overlay allow, min-version warn"
```

---

### Task 14: Evaluate — tie modules together with fail-closed recovery

**Files:**
- Create: `internal/engine/evaluate.go`
- Create: `internal/engine/evaluate_test.go`

**Interfaces:**
- Consumes: `checkBash` (Tasks 6–8), `checkPaths` (Tasks 9–10), overlay `Rules` matching, `policy` types.
- Produces:
  - `func Evaluate(tc ToolCall, pol *policy.Policy) policy.Verdict` — runs `checkPaths`, `checkBash`, and `matchOverlayRules`; returns the most severe non-waived `Verdict`; returns `{Allow, "", ""}` when nothing hits; wraps the module calls in `recover()` so a panic yields `{Ask, "panic-recovered", ...}`.
  - `func matchOverlayRules(tc ToolCall, pol *policy.Policy) *policy.Verdict` — for each `pol.Rules` entry, if `Tool` empty or matches `tc.Tool` (case-insensitive) and `pattern` (glob via `doublestar.Match`) matches `tc.Command` (or any `tc.Paths`), return that verdict (skipping waived IDs).

- [ ] **Step 1: Write the failing test**

`internal/engine/evaluate_test.go`:

```go
package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func fullPol() *policy.Policy {
	p := pathPol()
	p.Slots.SafeRoots = []string{"/repo/tmp"}
	p.Rules = []policy.Rule{
		{ID: "proj.tf", Pattern: "terraform apply*", Decision: policy.Ask, Reason: "infra"},
	}
	return p
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		tc   ToolCall
		want policy.Decision
		id   string
	}{
		{ToolCall{Tool: "Bash", Command: "ls -la", CWD: "/repo", RepoRoot: "/repo"}, policy.Allow, ""},
		{ToolCall{Tool: "Bash", Command: "rm -rf /", CWD: "/repo", RepoRoot: "/repo"}, policy.Deny, "P1.rm-rf"},
		{ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}, policy.Deny, "P4.secret-path"},
		{ToolCall{Tool: "Bash", Command: "chmod -R 777 /repo", CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "P1.chmod"},
		{ToolCall{Tool: "Bash", Command: "terraform apply -auto-approve", CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "proj.tf"},
		{ToolCall{Tool: "Bash", Command: `echo "oops`, CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "tokenize-failed"},
	}
	for _, c := range cases {
		v := Evaluate(c.tc, fullPol())
		if v.Decision != c.want || (c.id != "" && v.RuleID != c.id) {
			t.Errorf("Evaluate(%q) = %+v, want %s/%s", c.tc.Command+c.tc.Tool, v, c.want, c.id)
		}
	}
}

func TestEvaluateWaived(t *testing.T) {
	p := fullPol()
	p.Waived["P1.rm-rf"] = true
	v := Evaluate(ToolCall{Tool: "Bash", Command: "rm -rf /etc", CWD: "/repo", RepoRoot: "/repo"}, p)
	if v.Decision != policy.Allow {
		t.Fatalf("waived rule still fired: %+v", v)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/engine/ -run TestEvaluate -v`
Expected: FAIL — `Evaluate` undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/engine/evaluate.go`:

```go
package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

func Evaluate(tc ToolCall, pol *policy.Policy) (out policy.Verdict) {
	defer func() {
		if r := recover(); r != nil {
			out = policy.Verdict{Decision: policy.Ask, RuleID: "panic-recovered",
				Reason: "guardrail hit an internal error; failing closed to ask"}
		}
	}()

	hits := []*policy.Verdict{
		checkPaths(tc, pol),
		checkBash(tc, pol),
		matchOverlayRules(tc, pol),
	}
	var worst *policy.Verdict
	for _, h := range hits {
		if h == nil || pol.Waived[h.RuleID] {
			continue
		}
		if worst == nil || h.Decision.Severity() > worst.Decision.Severity() {
			worst = h
		}
	}
	if worst == nil {
		return policy.Verdict{Decision: policy.Allow}
	}
	return *worst
}

func matchOverlayRules(tc ToolCall, pol *policy.Policy) *policy.Verdict {
	for _, r := range pol.Rules {
		if r.Tool != "" && !strings.EqualFold(r.Tool, tc.Tool) {
			continue
		}
		if r.Pattern == "" {
			continue
		}
		subjects := append([]string{tc.Command}, tc.Paths...)
		for _, s := range subjects {
			if s == "" {
				continue
			}
			if ok, _ := doublestar.Match(r.Pattern, s); ok {
				return &policy.Verdict{Decision: r.Decision, RuleID: r.ID, Reason: r.Reason}
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/engine/ -v`
Expected: PASS (all engine tests).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/
git add internal/engine/
git commit -m "feat(engine): Evaluate — combine P1/P4/overlay rules, most-severe wins, fail-closed recover"
```

---

### Task 15: Audit log — path resolution, JSONL append, redaction

**Files:**
- Create: `internal/audit/audit.go`
- Create: `internal/audit/audit_test.go`

**Interfaces:**
- Consumes: stdlib only.
- Produces:
  - `type Record struct { TS string `json:"ts"`; SessionID string `json:"session_id,omitempty"`; Plane string `json:"plane"`; Tool string `json:"tool"`; Event string `json:"event,omitempty"`; Command string `json:"command,omitempty"`; Paths []string `json:"paths,omitempty"`; Decision string `json:"decision"`; RuleID string `json:"rule_id,omitempty"`; Reason string `json:"reason,omitempty"`; Waivers []string `json:"waivers,omitempty"` }`
  - `func DefaultPath(override string) string` — `override` if non-empty; else Windows → `%LOCALAPPDATA%\guardrail\audit.jsonl`; else `${XDG_STATE_HOME:-$HOME/.local/state}/guardrail/audit.jsonl`.
  - `func Write(rec Record, path string) error` — set `rec.TS` to RFC3339 if empty, redact `rec.Command`, `os.MkdirAll(dir, 0o700)`, append one line JSON with mode `0o600`.
  - `func redact(s string) string` — masks `KEY=value` / `token: value` pairs for keys matching `(?i)(pass(word)?|secret|token|api[_-]?key|authorization|bearer)`, plus `AKIA[0-9A-Z]{16}`, `ghp_[A-Za-z0-9]{20,}`, `xox[baprs]-[A-Za-z0-9-]+`, and PEM `-----BEGIN[^-]+-----` blocks → `«redacted»`.

- [ ] **Step 1: Write the failing test**

`internal/audit/audit_test.go`:

```go
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteAppendsJSONL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d", "audit.jsonl")
	for i := 0; i < 2; i++ {
		if err := Write(Record{Plane: "claude", Tool: "Bash", Decision: "deny", RuleID: "P1.rm-rf"}, p); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d", len(lines))
	}
	var rec Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.TS == "" || rec.Decision != "deny" {
		t.Fatalf("bad record: %+v", rec)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
		}
	}
}

func TestRedact(t *testing.T) {
	in := `curl -H "Authorization: Bearer sk-abcdef123456" https://x --data AWS_SECRET=AKIAIOSFODNN7EXAMPLE`
	out := redact(in)
	if strings.Contains(out, "sk-abcdef123456") || strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("secrets leaked: %s", out)
	}
}

func TestDefaultPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Setenv("XDG_STATE_HOME", "/xdg")
		if got := DefaultPath(""); got != "/xdg/guardrail/audit.jsonl" {
			t.Fatalf("got %q", got)
		}
	}
	if got := DefaultPath("/explicit/x.jsonl"); got != "/explicit/x.jsonl" {
		t.Fatalf("override ignored: %q", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/audit/ -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

`internal/audit/audit.go`:

```go
// Package audit appends one JSONL record per guardrail decision.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

type Record struct {
	TS        string   `json:"ts"`
	SessionID string   `json:"session_id,omitempty"`
	Plane     string   `json:"plane"`
	Tool      string   `json:"tool"`
	Event     string   `json:"event,omitempty"`
	Command   string   `json:"command,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	Decision  string   `json:"decision"`
	RuleID    string   `json:"rule_id,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Waivers   []string `json:"waivers,omitempty"`
}

func DefaultPath(override string) string {
	if override != "" {
		return override
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "guardrail", "audit.jsonl")
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "guardrail", "audit.jsonl")
}

var redactors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(pass(word)?|secret|token|api[_-]?key|authorization|bearer)(["']?\s*[:=]\s*["']?|\s+)[^\s"']+`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]+`),
	regexp.MustCompile(`-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----`),
}

func redact(s string) string {
	for _, re := range redactors {
		s = re.ReplaceAllString(s, "«redacted»")
	}
	return s
}

func Write(rec Record, path string) error {
	if rec.TS == "" {
		rec.TS = time.Now().UTC().Format(time.RFC3339)
	}
	rec.Command = redact(rec.Command)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return err
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/audit/ -v`
Expected: PASS. Tighten the redactor regex if `TestRedact` still shows a token.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/audit/
git add internal/audit/
git commit -m "feat(audit): JSONL append with XDG/LOCALAPPDATA path resolution and secret redaction"
```

---

### Task 16: Claude adapter — parse a hook payload into a ToolCall

**Files:**
- Create: `internal/adapter/claude.go`
- Create: `internal/adapter/claude_test.go`
- Create: `test/fixtures/claude/bash-rm-rf.json`
- Create: `test/fixtures/claude/bash-ls.json`
- Create: `test/fixtures/claude/read-env.json`
- Create: `test/fixtures/claude/bash-git-commit.json`

**Interfaces:**
- Consumes: `engine.ToolCall`, `os/exec` (`git`), stdlib `encoding/json`.
- Produces:
  - `func ParseClaude(r io.Reader) (engine.ToolCall, error)` — decodes Claude's hook JSON: `session_id`, `cwd`, `hook_event_name` (`PreToolUse`→`"pre"`, `PostToolUse`→`"post"`, other→`"pre"`), `tool_name`, `tool_input.command`, `tool_input.file_path`. Sets `Plane="claude"`, `RepoRoot` from `git -C cwd rev-parse --show-toplevel` (fallback: `cwd`). Keeps the raw bytes in `Raw`.

- [ ] **Step 1: Write the fixtures**

`test/fixtures/claude/bash-rm-rf.json`:

```json
{"session_id":"s1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}
```

`test/fixtures/claude/bash-ls.json`:

```json
{"session_id":"s1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}
```

`test/fixtures/claude/read-env.json`:

```json
{"session_id":"s1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/home/u/proj/.env"}}
```

`test/fixtures/claude/bash-git-commit.json`:

```json
{"session_id":"s1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git commit -m wip"}}
```

- [ ] **Step 2: Write the failing test**

`internal/adapter/claude_test.go`:

```go
package adapter

import (
	"os"
	"testing"
)

func TestParseClaudeBash(t *testing.T) {
	f, err := os.Open("../../test/fixtures/claude/bash-rm-rf.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tc, err := ParseClaude(f)
	if err != nil {
		t.Fatal(err)
	}
	if tc.Plane != "claude" || tc.Tool != "Bash" || tc.Command != "rm -rf /" || tc.Event != "pre" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
	if tc.SessionID != "s1" {
		t.Errorf("session id = %q", tc.SessionID)
	}
}

func TestParseClaudeRead(t *testing.T) {
	f, _ := os.Open("../../test/fixtures/claude/read-env.json")
	defer f.Close()
	tc, err := ParseClaude(f)
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "Read" || len(tc.Paths) != 1 || tc.Paths[0] != "/home/u/proj/.env" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -run TestParseClaude -v`
Expected: FAIL — `ParseClaude` undefined.

- [ ] **Step 4: Write minimal implementation**

`internal/adapter/claude.go`:

```go
// Package adapter translates each plane's native hook payload/response and the engine.
package adapter

import (
	"encoding/json"
	"io"
	"os/exec"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
)

type claudePayload struct {
	SessionID     string `json:"session_id"`
	CWD           string `json:"cwd"`
	HookEventName string `json:"hook_event_name"`
	ToolName      string `json:"tool_name"`
	ToolInput     struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
	} `json:"tool_input"`
}

func ParseClaude(r io.Reader) (engine.ToolCall, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return engine.ToolCall{}, err
	}
	var p claudePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return engine.ToolCall{}, err
	}
	event := "pre"
	if p.HookEventName == "PostToolUse" {
		event = "post"
	}
	tc := engine.ToolCall{
		Plane:     "claude",
		Event:     event,
		Tool:      p.ToolName,
		Command:   p.ToolInput.Command,
		SessionID: p.SessionID,
		CWD:       p.CWD,
		Raw:       raw,
	}
	if p.ToolInput.FilePath != "" {
		tc.Paths = []string{p.ToolInput.FilePath}
	}
	tc.RepoRoot = repoRoot(p.CWD)
	return tc, nil
}

func repoRoot(cwd string) string {
	if cwd == "" {
		return ""
	}
	out, err := exec.Command("git", "-C", cwd, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return cwd
	}
	return strings.TrimSpace(string(out))
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -run TestParseClaude -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/adapter/
git add internal/adapter/ test/fixtures/
git commit -m "feat(adapter): parse Claude Code hook payloads into ToolCall + fixtures"
```

---

### Task 17: Claude adapter — emit the hook response contract

**Files:**
- Modify: `internal/adapter/claude.go`
- Create: `internal/adapter/claude_emit_test.go`

**Interfaces:**
- Consumes: `policy.Verdict`.
- Produces:
  - `func EmitClaude(v policy.Verdict, event string, stdout, stderr io.Writer) int` —
    - `Allow` → write nothing, return `0`.
    - `Deny` → write `"guardrail: " + v.Reason` to `stderr`, return `2`.
    - `Ask` → write to `stdout` the JSON `{"hookSpecificOutput":{"hookEventName":<PreToolUse|PostToolUse>,"permissionDecision":"ask","permissionDecisionReason":<reason>}}`, return `0`.
    - `event` `"post"` → map to `"PostToolUse"`, else `"PreToolUse"`.

- [ ] **Step 1: Write the failing test**

`internal/adapter/claude_emit_test.go`:

```go
package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestEmitClaudeAllow(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitClaude(policy.Verdict{Decision: policy.Allow}, "pre", &out, &errb)
	if code != 0 || out.Len() != 0 || errb.Len() != 0 {
		t.Fatalf("allow: code=%d out=%q err=%q", code, out.String(), errb.String())
	}
}

func TestEmitClaudeDeny(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitClaude(policy.Verdict{Decision: policy.Deny, Reason: "no"}, "pre", &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "no") {
		t.Fatalf("deny: code=%d err=%q", code, errb.String())
	}
}

func TestEmitClaudeAsk(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitClaude(policy.Verdict{Decision: policy.Ask, Reason: "confirm?"}, "pre", &out, &errb)
	if code != 0 {
		t.Fatalf("ask code=%d", code)
	}
	var got struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	h := got.HookSpecificOutput
	if h.HookEventName != "PreToolUse" || h.PermissionDecision != "ask" || h.PermissionDecisionReason != "confirm?" {
		t.Fatalf("bad ask json: %+v", h)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -run TestEmitClaude -v`
Expected: FAIL — `EmitClaude` undefined.

- [ ] **Step 3: Write minimal implementation**

Append to `internal/adapter/claude.go`:

```go
import "github.com/CtrlCarlitos/agent-guardrails/internal/policy" // add to import block
import "fmt"                                                       // add to import block

func EmitClaude(v policy.Verdict, event string, stdout, stderr io.Writer) int {
	switch v.Decision {
	case policy.Deny:
		fmt.Fprintf(stderr, "guardrail: %s\n", v.Reason)
		return 2
	case policy.Ask:
		hookEvent := "PreToolUse"
		if event == "post" {
			hookEvent = "PostToolUse"
		}
		payload := map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            hookEvent,
				"permissionDecision":       "ask",
				"permissionDecisionReason": v.Reason,
			},
		}
		b, _ := json.Marshal(payload)
		stdout.Write(append(b, '\n'))
		return 0
	default:
		return 0
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./internal/adapter/ -v`
Expected: PASS (Tasks 16–17).

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/adapter/
git add internal/adapter/
git commit -m "feat(adapter): emit Claude hook response — exit 2 deny, JSON ask, silent allow"
```

---

### Task 18: Wire `guardrail hook claude` end to end

**Files:**
- Create: `cmd/guardrail/hook.go`
- Create: `cmd/guardrail/hook_test.go`
- Modify: `cmd/guardrail/run.go`

**Interfaces:**
- Consumes: `adapter.ParseClaude` / `adapter.EmitClaude`, `policy.LoadBase` / `FindOverlayPath` / `LoadOverlay` / `Merge`, `engine.Evaluate`, `audit.Write` / `audit.DefaultPath`.
- Produces:
  - `func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int` — `args[0]` is the plane. Only `"claude"` is implemented; anything else → stderr "unsupported plane" + exit 2.
  - Flow: parse payload (parse error → stderr + exit 2, fail closed); load Base; `FindOverlayPath(tc.CWD)` → if found `LoadOverlay` (load error → stderr + exit 2); `Merge(base, ov, version)`; print each warning to stderr; `engine.Evaluate`; build + `audit.Write` a `Record` (path = `audit.DefaultPath(merged.Slots.AuditLog)`; write error → stderr note, continue); `EmitClaude`.
  - `run` dispatch gains `case "hook": return cmdHook(args[1:], stdin, stdout, stderr)`.

- [ ] **Step 1: Write the failing test**

`cmd/guardrail/hook_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func runHook(t *testing.T, fixture string) (int, string, string) {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "test", "fixtures", "claude", fixture))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// isolate the audit log
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "") // base-only
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, f, &out, &errb)
	return code, out.String(), errb.String()
}

func TestHookClaudeDeny(t *testing.T) {
	code, _, errb := runHook(t, "bash-rm-rf.json")
	if code != 2 {
		t.Fatalf("rm -rf: exit %d, want 2; stderr=%q", code, errb)
	}
}

func TestHookClaudeAllow(t *testing.T) {
	code, out, errb := runHook(t, "bash-ls.json")
	if code != 0 || out != "" {
		t.Fatalf("ls: exit %d out %q err %q", code, out, errb)
	}
}

func TestHookClaudeSecretDeny(t *testing.T) {
	code, _, _ := runHook(t, "read-env.json")
	if code != 2 {
		t.Fatalf("read .env: exit %d, want 2", code)
	}
}

func TestHookClaudeGitCommitAllowedForNow(t *testing.T) {
	// P2 (git-safety) lands in a later plan; until then git commit is not gated.
	code, _, _ := runHook(t, "bash-git-commit.json")
	if code != 0 {
		t.Fatalf("git commit: exit %d, want 0 (P2 not yet implemented)", code)
	}
}

func TestHookUnparseablePayloadFailsClosed(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, bytes.NewReader([]byte("not json")), &out, &errb)
	if code != 2 {
		t.Fatalf("bad payload: exit %d, want 2", code)
	}
}

func TestHookAuditLogWritten(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("GUARDRAIL_CONFIG", "")
	f, _ := os.Open(filepath.Join("..", "..", "test", "fixtures", "claude", "bash-rm-rf.json"))
	defer f.Close()
	var out, errb bytes.Buffer
	run([]string{"hook", "claude"}, f, &out, &errb)
	if _, err := os.Stat(filepath.Join(state, "guardrail", "audit.jsonl")); err != nil {
		t.Fatalf("audit log not written: %v", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -run TestHook -v`
Expected: FAIL — `hook` case / `cmdHook` missing.

- [ ] **Step 3: Add the dispatch case**

In `cmd/guardrail/run.go`, add to the `switch args[0]`:

```go
	case "hook":
		return cmdHook(args[1:], stdin, stdout, stderr)
```

- [ ] **Step 4: Write minimal implementation**

`cmd/guardrail/hook.go`:

```go
package main

import (
	"fmt"
	"io"

	"github.com/CtrlCarlitos/agent-guardrails/internal/adapter"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: hook needs a plane (claude)")
		return 2
	}
	if args[0] != "claude" {
		fmt.Fprintf(stderr, "guardrail: unsupported plane %q\n", args[0])
		return 2
	}

	tc, err := adapter.ParseClaude(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: unparseable hook payload (%v); failing closed\n", err)
		return 2
	}

	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot load base policy (%v); failing closed\n", err)
		return 2
	}

	var ov *policy.Overlay
	if pth, ok := policy.FindOverlayPath(tc.CWD); ok {
		ov, err = policy.LoadOverlay(pth)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: cannot load overlay (%v); failing closed\n", err)
			return 2
		}
	}

	merged, warnings, err := policy.Merge(base, ov, version)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: invalid overlay (%v); failing closed\n", err)
		return 2
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, w)
	}

	v := engine.Evaluate(tc, merged)

	rec := audit.Record{
		SessionID: tc.SessionID,
		Plane:     "claude",
		Tool:      tc.Tool,
		Event:     tc.Event,
		Command:   tc.Command,
		Paths:     tc.Paths,
		Decision:  string(v.Decision),
		RuleID:    v.RuleID,
		Reason:    v.Reason,
		Waivers:   waivedList(merged),
	}
	if err := audit.Write(rec, audit.DefaultPath(merged.Slots.AuditLog)); err != nil {
		fmt.Fprintf(stderr, "guardrail: audit write failed (%v)\n", err)
	}

	return adapter.EmitClaude(v, tc.Event, stdout, stderr)
}

func waivedList(p *policy.Policy) []string {
	var out []string
	for k, v := range p.Waived {
		if v {
			out = append(out, k)
		}
	}
	return out
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `/usr/local/go/bin/go test ./cmd/guardrail/ -v`
Expected: PASS (Task 1 + Task 18).

- [ ] **Step 6: Full build + manual smoke**

Run:
```bash
make build
echo '{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | ./guardrail hook claude; echo "exit=$?"
echo '{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}' | ./guardrail hook claude; echo "exit=$?"
```
Expected: first prints `guardrail: recursive/forced rm ...` to stderr, `exit=2`; second `exit=0` with no output.

- [ ] **Step 7: Commit**

```bash
gofmt -w cmd/guardrail/
git add cmd/guardrail/
git commit -m "feat: wire guardrail hook claude — parse, merge policy, evaluate, audit, emit"
```

---

### Task 19: Contract-fixture harness, degradation test, docs, tag

**Files:**
- Create: `test/fixtures/claude/expected.json`
- Create: `test/contract_test.go`
- Modify: `README.md`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `run` (package `main` is not importable from `test/`, so the contract test shells the built binary).
- Produces:
  - `test/fixtures/claude/expected.json` — map of fixture filename → `{ "exit": N }`.
  - `test/contract_test.go` — builds the binary once (`go build -o`), then for each `claude/*.json` fixture pipes it through `./guardrail hook claude` and asserts the exit code matches `expected.json`. Also asserts a deliberately pathological command still exits 0 or 2 (never panics / never a non-{0,2} code).

- [ ] **Step 1: Write `expected.json`**

`test/fixtures/claude/expected.json`:

```json
{
  "bash-rm-rf.json":      {"exit": 2},
  "bash-ls.json":         {"exit": 0},
  "read-env.json":        {"exit": 2},
  "bash-git-commit.json": {"exit": 0}
}
```

- [ ] **Step 2: Write the failing test**

`test/contract_test.go`:

```go
package test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "guardrail")
	out, err := exec.Command("/usr/local/go/bin/go", "build", "-o", bin, "../cmd/guardrail").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func TestClaudeContractFixtures(t *testing.T) {
	bin := buildBinary(t)
	raw, err := os.ReadFile("fixtures/claude/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]struct {
		Exit int `json:"exit"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("fixtures", "claude", name))
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bin, "hook", "claude")
			cmd.Stdin = bytes.NewReader(payload)
			cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+t.TempDir(), "GUARDRAIL_CONFIG=")
			_ = cmd.Run()
			got := cmd.ProcessState.ExitCode()
			if got != want.Exit {
				t.Fatalf("%s: exit %d, want %d", name, got, want.Exit)
			}
		})
	}
}

func TestClaudeNeverPanics(t *testing.T) {
	bin := buildBinary(t)
	weird := []string{
		`{"cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"$(“”)|&;`+"`"+`"}}`,
		`{"cwd":"/tmp","tool_name":"Bash","tool_input":{"command":""}}`,
		`{}`,
	}
	for _, p := range weird {
		cmd := exec.Command(bin, "hook", "claude")
		cmd.Stdin = bytes.NewReader([]byte(p))
		cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+t.TempDir())
		_ = cmd.Run()
		code := cmd.ProcessState.ExitCode()
		if code != 0 && code != 2 {
			t.Fatalf("payload %q produced exit %d, want 0 or 2", p, code)
		}
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `/usr/local/go/bin/go test ./test/ -v`
Expected: FAIL initially only if `expected.json` disagrees with behavior; otherwise it may already pass. If it passes immediately, that's acceptable for an integration harness — proceed. If `TestClaudeNeverPanics` fails, fix the offending module with a `recover` or guard and re-run.

- [ ] **Step 4: Make it pass**

If any case fails, adjust the rule module (not the expectation, unless the expectation is wrong per `DESIGN.md`). Re-run until green:

Run: `/usr/local/go/bin/go test ./... `
Expected: PASS across every package.

- [ ] **Step 5: Update `README.md` Status + `Makefile`**

`README.md` — replace the "Status" section body with:

```markdown
## Status

Plan 1 (engine core + Claude adapter) implemented: `guardrail hook claude` enforces
P1 (destructive commands) and P4 (secret paths) with audit logging and per-repo
`guardrail.toml` overlays. Plans 2–6 (declarative-floor generation, installer,
remaining policies, opencode/antigravity adapters, recipes) are pending — see
`docs/superpowers/plans/`.
```

`Makefile` — add:

```make
CGO_ENABLED ?= 0
.PHONY: contract
contract:
	$(GO) test ./test/ -v
```

- [ ] **Step 6: Commit and tag**

```bash
gofmt -w ./...
git add -A
git commit -m "test: Claude contract-fixture harness + never-panics guard; docs"
git tag v0.1.0-dev
```

---

## Self-Review

**1. Spec coverage (against `DESIGN.md`):**

| Spec item | Task |
|---|---|
| Engine = Go static binary `guardrail` | 1 |
| `guardrail hook claude` subcommand, Claude response contract | 16, 17, 18 |
| P3 real shell tokenizer (`mvdan.cc/sh`), compound split, wrapper strip, runner unwrap, fail-closed on parse error | 4, 5, 14 |
| P1 destructive-command gate (`rm -rf`/`dd`/`mkfs`/`shred`; git push -f / clean; docker down/prune/substituted; chmod/chown/find/truncate/redirect/kill; sudo) | 6, 7, 8 |
| P4 secret-path denial (expanded globs, `.env.example` carve-out, shell readers) + symlink-escape | 9, 10, 11 |
| P9 audit log — JSONL 0600, XDG/`LOCALAPPDATA`, per-project path override, secret redaction | 15, 18 |
| Embedded Base policy | 11 |
| `guardrail.toml` discovery from git root + `GUARDRAIL_CONFIG` | 12 |
| Base ∪ Overlay merge; overlay adds/tightens; `waive` (logged); no silent `deny`→`allow`; `engine_min_version` warn-not-block | 13 |
| Verdict severity `deny` > `ask` > `allow` | 2, 6, 14 |
| Fail-closed on unparseable payload / command / panic | 14, 18, 19 |
| Audit write failure never changes the verdict | 18 |

Deferred to later plans, by design (not gaps): declarative-floor generation + installer (Plan 2); P2/P5/P6/P7/P10 (Plan 3); opencode adapter (Plan 4); antigravity adapter (Plan 5); recipes + `guardrail sync` (Plan 6). The lethal-trifecta gate (P7) and egress (P6) are Plan 3 — `EgressAllowlist` is carried in the types now so the slot is stable.

**2. Placeholder scan:** No `TBD`/`TODO`/"handle edge cases"/"similar to Task N". Every code step is literal. Test code is complete.

**3. Type consistency:**
- `policy.Verdict{Decision, RuleID, Reason}` — used identically in Tasks 2, 6–10, 14, 17, 18.
- `engine.ToolCall` field set (`Plane, Event, Tool, Command, Paths, SessionID, CWD, RepoRoot, Raw`) — defined Task 3, populated Task 16, read Tasks 6–14.
- `engine.Simple{Argv, Redirects}` — defined Task 4, extended semantics Task 5, read Tasks 6–9.
- `engine.Normalize(string) ([]Simple, error)` — defined Task 5, called Tasks 6, 9.
- `engine.Evaluate(ToolCall, *policy.Policy) policy.Verdict` — defined Task 14, called Task 18.
- `policy.LoadBase() (*Policy, error)` / `FindOverlayPath(string) (string, bool)` / `LoadOverlay(string) (*Overlay, error)` / `Merge(*Policy, *Overlay, string) (*Policy, []string, error)` — defined Tasks 11–13, called Task 18.
- `audit.Record` / `audit.Write(Record, string) error` / `audit.DefaultPath(string) string` — defined Task 15, called Task 18.
- `adapter.ParseClaude(io.Reader) (engine.ToolCall, error)` / `adapter.EmitClaude(policy.Verdict, string, io.Writer, io.Writer) int` — defined Tasks 16–17, called Task 18.
- `run([]string, io.Reader, io.Writer, io.Writer) int` / `cmdHook` — defined Tasks 1, 18.
- `version` (`package main`) passed as `binaryVersion` into `Merge` — Tasks 1, 18.

No naming drift found.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-09-03-engine-core-claude-adapter.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
