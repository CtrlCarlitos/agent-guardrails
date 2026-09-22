package test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func goCmd() string {
	if v := os.Getenv("GUARDRAIL_GO"); v != "" {
		return v
	}
	if _, err := exec.LookPath("go"); err == nil {
		return "go"
	}
	return "/usr/local/go/bin/go"
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), testenv.ExecutableName("guardrail"))
	out, err := exec.Command(goCmd(), "build", "-o", bin, "../cmd/guardrail").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func TestGoCmdResolves(t *testing.T) {
	got := goCmd()
	if got == "" {
		t.Fatal("goCmd returned empty")
	}
	// it must be runnable
	if err := exec.Command(got, "version").Run(); err != nil {
		t.Fatalf("goCmd() = %q is not runnable: %v", got, err)
	}
}

func TestClaudeContractFixtures(t *testing.T) {
	bin := buildBinary(t)
	raw, err := os.ReadFile("fixtures/claude/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	// decision/rule/paths are optional and checked against the audit record the
	// hook wrote, so a fixture can pin the verdict behind an exit code (ask and
	// allow both exit 0) and the exact paths the adapter projected.
	var expected map[string]struct {
		Exit     int      `json:"exit"`
		Decision string   `json:"decision"`
		Rule     string   `json:"rule"`
		Paths    []string `json:"paths"`
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
			if name == "serena-mcp-memory.json" || name == "write-claude-md.json" {
				payload = bytes.ReplaceAll(payload, []byte("/tmp"), []byte(filepath.ToSlash(t.TempDir())))
			}
			roots := testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}
			cmd := exec.Command(bin, "hook", "claude")
			cmd.Stdin = bytes.NewReader(payload)
			// Isolated config: a developer's night marker or operator grants must
			// not flip a fixture's verdict.
			cmd.Env = testenv.ChildProcessEnv(roots, "GUARDRAIL_CONFIG=")
			_ = cmd.Run()
			got := cmd.ProcessState.ExitCode()
			if got != want.Exit {
				t.Fatalf("%s: exit %d, want %d", name, got, want.Exit)
			}
			if want.Decision == "" && want.Rule == "" && want.Paths == nil {
				return
			}
			rec := lastAuditRecord(t, filepath.Join(roots.State, "guardrail", "audit.jsonl"))
			if want.Decision != "" && rec.Decision != want.Decision {
				t.Fatalf("%s: decision %q, want %q", name, rec.Decision, want.Decision)
			}
			if want.Rule != "" && rec.RuleID != want.Rule {
				t.Fatalf("%s: rule %q, want %q", name, rec.RuleID, want.Rule)
			}
			if want.Paths != nil && strings.Join(rec.Paths, "\n") != strings.Join(want.Paths, "\n") {
				t.Fatalf("%s: paths %q, want %q", name, rec.Paths, want.Paths)
			}
		})
	}
}

type auditRecord struct {
	Decision string   `json:"decision"`
	RuleID   string   `json:"rule_id"`
	Paths    []string `json:"paths"`
}

func lastAuditRecord(t *testing.T, path string) auditRecord {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var rec auditRecord
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
		t.Fatalf("audit record: %v", err)
	}
	return rec
}

func TestOpencodeContractFixtures(t *testing.T) {
	bin := buildBinary(t)
	raw, err := os.ReadFile("fixtures/opencode/expected.json")
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
			payload, err := os.ReadFile(filepath.Join("fixtures", "opencode", name))
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bin, "hook", "opencode")
			cmd.Stdin = bytes.NewReader(payload)
			roots := testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}
			cmd.Env = testenv.ChildProcessEnv(roots, "GUARDRAIL_CONFIG=")
			_ = cmd.Run()
			if got := cmd.ProcessState.ExitCode(); got != want.Exit {
				t.Fatalf("%s: exit %d, want %d", name, got, want.Exit)
			}
		})
	}
}

func TestAntigravityContractFixtures(t *testing.T) {
	bin := buildBinary(t)
	raw, err := os.ReadFile("fixtures/antigravity/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("fixtures", "antigravity", name))
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bin, "hook", "antigravity", "pre")
			cmd.Stdin = bytes.NewReader(payload)
			roots := testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}
			cmd.Env = testenv.ChildProcessEnv(roots, "GUARDRAIL_CONFIG=")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("%s: hook failed: %v", name, err)
			}
			var got struct {
				Decision string `json:"decision"`
			}
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("%s: invalid JSON %q: %v", name, out, err)
			}
			if got.Decision != want.Decision {
				t.Fatalf("%s: decision %q, want %q", name, got.Decision, want.Decision)
			}
		})
	}
}

func TestClaudeNeverPanics(t *testing.T) {
	bin := buildBinary(t)
	weird := []string{
		`{"cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"$(“”)|&;` + "`" + `"}}`,
		`{"cwd":"/tmp","tool_name":"Bash","tool_input":{"command":""}}`,
		`{}`,
	}
	for _, p := range weird {
		cmd := exec.Command(bin, "hook", "claude")
		cmd.Stdin = bytes.NewReader([]byte(p))
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.Env = testenv.ChildProcessEnv(testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()})
		_ = cmd.Run()
		code := cmd.ProcessState.ExitCode()
		if code != 0 && code != 2 {
			t.Fatalf("payload %q produced exit %d, want 0 or 2", p, code)
		}
		if out := stderr.String(); strings.Contains(out, "panic:") {
			t.Fatalf("payload %q panicked:\n%s", p, out)
		}
	}
}

func TestCodexContractFixtures(t *testing.T) {
	bin := buildBinary(t)
	raw, err := os.ReadFile("fixtures/codex/expected.json")
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
			payload, err := os.ReadFile(filepath.Join("fixtures", "codex", name))
			if err != nil {
				t.Fatal(err)
			}
			payload = bytes.ReplaceAll(payload, []byte("/repo"), []byte(filepath.ToSlash(t.TempDir())))
			roots := testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}
			cmd := exec.Command(bin, "hook", "codex")
			cmd.Stdin = bytes.NewReader(payload)
			cmd.Env = testenv.ChildProcessEnv(roots, "GUARDRAIL_CONFIG=")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			_ = cmd.Run()
			wantExit := want.Exit
			if runtime.GOOS == "windows" && name == "bash-ls.json" {
				// Codex does not expose the runtime shell on Windows. An allowed
				// command must therefore fail closed instead of receiving a POSIX
				// updatedInput rewrite (#152, #157).
				wantExit = 2
			}
			got := cmd.ProcessState.ExitCode()
			if got != wantExit {
				t.Fatalf("%s: exit %d, want %d; stderr=%q", name, got, wantExit, stderr.String())
			}
			if runtime.GOOS == "windows" && name == "bash-ls.json" &&
				!strings.Contains(stderr.String(), "cannot prove the Windows command shell") {
				t.Fatalf("%s: missing fail-closed shell diagnostic; stderr=%q", name, stderr.String())
			}
		})
	}
}

func TestCodexWindowsContractFixtures(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-shaped fixtures are evaluated on a windows host")
	}
	bin := buildBinary(t)
	raw, err := os.ReadFile(filepath.Join("fixtures", "codex", "windows", "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]struct {
		Exit     int      `json:"exit"`
		Decision string   `json:"decision"`
		Rule     string   `json:"rule"`
		Paths    []string `json:"paths"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("fixtures", "codex", "windows", name))
			if err != nil {
				t.Fatal(err)
			}
			roots := testenv.Roots{Home: `C:\Users\fixture-user`, Config: t.TempDir(), State: t.TempDir()}
			cmd := exec.Command(bin, "hook", "codex")
			cmd.Stdin = bytes.NewReader(payload)
			cmd.Env = testenv.ChildProcessEnv(roots, "GUARDRAIL_CONFIG=")
			_ = cmd.Run()
			if got := cmd.ProcessState.ExitCode(); got != want.Exit {
				t.Fatalf("%s: exit %d, want %d", name, got, want.Exit)
			}
			rec := lastAuditRecord(t, filepath.Join(roots.State, "guardrail", "audit.jsonl"))
			if want.Decision != "" && rec.Decision != want.Decision {
				t.Fatalf("%s: decision %q, want %q", name, rec.Decision, want.Decision)
			}
			if want.Rule != "" && rec.RuleID != want.Rule {
				t.Fatalf("%s: rule %q, want %q", name, rec.RuleID, want.Rule)
			}
			if want.Paths != nil && strings.Join(rec.Paths, "\n") != strings.Join(want.Paths, "\n") {
				t.Fatalf("%s: paths %q, want %q", name, rec.Paths, want.Paths)
			}
		})
	}
}

// Windows-shaped payloads (drive letters, backslashes) are only meaningful
// on a Windows host: the Engine normalises separators with filepath.ToSlash,
// a no-op on POSIX. CI's windows job runs this; everywhere else it skips.
func TestClaudeWindowsContractFixtures(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-shaped fixtures are evaluated on a windows host")
	}
	bin := buildBinary(t)
	raw, err := os.ReadFile(filepath.Join("fixtures", "claude", "windows", "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]struct {
		Exit     int      `json:"exit"`
		Decision string   `json:"decision"`
		Rule     string   `json:"rule"`
		Paths    []string `json:"paths"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("fixtures", "claude", "windows", name))
			if err != nil {
				t.Fatal(err)
			}
			roots := testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}
			cmd := exec.Command(bin, "hook", "claude")
			cmd.Stdin = bytes.NewReader(payload)
			cmd.Env = testenv.ChildProcessEnv(roots, "GUARDRAIL_CONFIG=")
			_ = cmd.Run()
			if got := cmd.ProcessState.ExitCode(); got != want.Exit {
				t.Fatalf("%s: exit %d, want %d", name, got, want.Exit)
			}
			rec := lastAuditRecord(t, filepath.Join(roots.State, "guardrail", "audit.jsonl"))
			if want.Decision != "" && rec.Decision != want.Decision {
				t.Fatalf("%s: decision %q, want %q", name, rec.Decision, want.Decision)
			}
			if want.Rule != "" && rec.RuleID != want.Rule {
				t.Fatalf("%s: rule %q, want %q", name, rec.RuleID, want.Rule)
			}
			if want.Paths != nil && strings.Join(rec.Paths, "\n") != strings.Join(want.Paths, "\n") {
				t.Fatalf("%s: paths %q, want %q", name, rec.Paths, want.Paths)
			}
		})
	}
}

func TestAntigravityWindowsContractFixtures(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-shaped fixtures are evaluated on a windows host")
	}
	bin := buildBinary(t)
	raw, err := os.ReadFile(filepath.Join("fixtures", "antigravity", "windows", "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]struct {
		Decision string   `json:"decision"`
		Rule     string   `json:"rule"`
		Paths    []string `json:"paths"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("fixtures", "antigravity", "windows", name))
			if err != nil {
				t.Fatal(err)
			}
			roots := testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}
			cmd := exec.Command(bin, "hook", "antigravity", "pre")
			cmd.Stdin = bytes.NewReader(payload)
			cmd.Env = testenv.ChildProcessEnv(roots,
				"GUARDRAIL_CONFIG=",
				"ANTIGRAVITY_APP_DATA_DIR=C:\\test-gemini\\antigravity-cli",
			)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("%s: hook failed: %v", name, err)
			}
			var got struct {
				Decision string `json:"decision"`
			}
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("%s: invalid JSON %q: %v", name, out, err)
			}
			if got.Decision != want.Decision {
				t.Fatalf("%s: decision %q, want %q", name, got.Decision, want.Decision)
			}
			if want.Rule != "" || want.Paths != nil {
				rec := lastAuditRecord(t, filepath.Join(roots.State, "guardrail", "audit.jsonl"))
				if want.Rule != "" && rec.RuleID != want.Rule {
					t.Fatalf("%s: rule %q, want %q", name, rec.RuleID, want.Rule)
				}
				if want.Paths != nil && strings.Join(rec.Paths, "\n") != strings.Join(want.Paths, "\n") {
					t.Fatalf("%s: paths %q, want %q", name, rec.Paths, want.Paths)
				}
			}
		})
	}
}
