package adversarial

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	// The hook runs as a subprocess, so bind Go's test cache to its internal dependencies.
	_ "github.com/CtrlCarlitos/agent-guardrails/internal/adapter"
	_ "github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	_ "github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	_ "github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	_ "github.com/CtrlCarlitos/agent-guardrails/internal/recipe"
	_ "github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

type entry struct {
	Name     string   `json:"name"`
	Tool     string   `json:"tool"`
	Command  string   `json:"command,omitempty"`
	Paths    []string `json:"paths,omitempty"`
	CWD      string   `json:"cwd"`
	RepoRoot string   `json:"repo_root"`
	Want     string   `json:"want"`
}

var (
	adversarialBuildOnce sync.Once
	adversarialBuildDir  string
	adversarialBinary    string
	adversarialBuildErr  error
	adversarialBuildLog  string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if adversarialBuildDir != "" {
		_ = os.RemoveAll(adversarialBuildDir)
	}
	os.Exit(code)
}

func buildAdversarialBinary(t *testing.T) string {
	t.Helper()
	trackCommandSources(t)
	adversarialBuildOnce.Do(func() {
		adversarialBuildDir, adversarialBuildErr = os.MkdirTemp("", "guardrail-adversarial-")
		if adversarialBuildErr != nil {
			return
		}
		adversarialBinary = filepath.Join(adversarialBuildDir, "guardrail")
		var attempts []string
		for _, goBinary := range []string{"go", "/usr/local/go/bin/go"} {
			out, err := exec.Command(goBinary, "build", "-o", adversarialBinary, "../../cmd/guardrail").CombinedOutput()
			if err == nil {
				adversarialBuildErr = nil
				return
			}
			attempts = append(attempts, fmt.Sprintf("%s: %v: %s", goBinary, err, out))
			adversarialBuildErr = err
		}
		adversarialBuildLog = strings.Join(attempts, " / ")
	})
	if adversarialBuildErr != nil {
		t.Fatalf("build adversarial binary: %v (%s)", adversarialBuildErr, adversarialBuildLog)
	}
	return adversarialBinary
}

func trackCommandSources(t *testing.T) {
	t.Helper()
	sources, err := filepath.Glob("../../cmd/guardrail/*.go")
	if err != nil || len(sources) == 0 {
		t.Fatalf("locate guardrail command sources: %v", err)
	}
	for _, source := range sources {
		if _, err := os.ReadFile(source); err != nil {
			t.Fatalf("track guardrail command source %s: %v", source, err)
		}
	}
}

func TestAdversarialCorpus(t *testing.T) {
	bin := buildAdversarialBinary(t)
	raw, err := os.ReadFile("corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("corpus is empty")
	}

	names := make(map[string]bool, len(entries))
	for i, e := range entries {
		if err := validateEntry(e, names); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		e := e
		t.Run(e.Name, func(t *testing.T) {
			cwd := materializeRepo(t, e)
			in := map[string]any{
				"session_id":      fmt.Sprintf("adv-%03d", i),
				"cwd":             cwd,
				"hook_event_name": "PreToolUse",
				"tool_name":       e.Tool,
			}
			ti := map[string]any{}
			if e.Command != "" {
				ti["command"] = e.Command
			} else {
				ti["file_path"] = e.Paths[0]
			}
			in["tool_input"] = ti
			payload, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}

			stateHome := t.TempDir()
			configHome := t.TempDir()
			config := filepath.Join(t.TempDir(), "guardrail.toml")
			if err := os.WriteFile(config, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bin, "hook", "claude")
			cmd.Stdin = bytes.NewReader(payload)
			cmd.Env = append(os.Environ(),
				"XDG_STATE_HOME="+stateHome,
				"XDG_CONFIG_HOME="+configHome,
				"GUARDRAIL_CONFIG="+config,
			)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			runErr := cmd.Run()
			code := 0
			if runErr != nil {
				var exitErr *exec.ExitError
				if !errors.As(runErr, &exitErr) {
					t.Fatalf("run hook: %v", runErr)
				}
				code = exitErr.ExitCode()
			}

			got, err := classifyClaudeResult(code, stdout.String(), stderr.String())
			if err != nil {
				t.Fatalf("invalid Claude hook result: %v (exit=%d stdout=%s stderr=%s)", err, code, stdout.String(), stderr.String())
			}
			if got != e.Want {
				t.Fatalf("got %s, want %s (exit=%d stdout=%s stderr=%s)", got, e.Want, code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestClassifyClaudeResult(t *testing.T) {
	tests := []struct {
		name   string
		code   int
		stdout string
		stderr string
		want   string
		fail   bool
	}{
		{name: "allow", code: 0, want: "allow"},
		{name: "ask", code: 0, stdout: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"confirm"}}` + "\n", want: "ask"},
		{name: "deny", code: 2, stderr: "guardrail: blocked by policy\n", want: "deny"},
		{name: "exit two without guardrail stderr", code: 2, stderr: "command failed\n", fail: true},
		{name: "exit two with panic", code: 2, stderr: "panic: runtime failure\n", fail: true},
		{name: "exit two with guardrail-prefixed fatal", code: 2, stderr: "guardrail: fatal error: concurrent map writes\n", fail: true},
		{name: "exit two with stdout", code: 2, stdout: `{"hookSpecificOutput":{"permissionDecision":"ask"}}`, stderr: "guardrail: blocked by policy\n", fail: true},
		{name: "unknown exit", code: 3, stderr: "guardrail: unexpected failure\n", fail: true},
		{name: "invalid success stdout", code: 0, stdout: "not-json\n", fail: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := classifyClaudeResult(test.code, test.stdout, test.stderr)
			if test.fail {
				if err == nil {
					t.Fatalf("classifyClaudeResult(%d, %q, %q) = %q, want error", test.code, test.stdout, test.stderr, got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("classifyClaudeResult(%d, %q, %q) = %q, %v; want %q, nil", test.code, test.stdout, test.stderr, got, err, test.want)
			}
		})
	}
}

func TestClassifyClaudeResultRejectsExitTwoCrashProcess(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestFakeClaudeCrashProcess$")
	cmd.Env = append(os.Environ(), "GO_WANT_FAKE_CLAUDE_CRASH=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("fake crash error = %v, want process exit error", err)
	}
	if code := exitErr.ExitCode(); code != 2 {
		t.Fatalf("fake crash exit = %d, want 2", code)
	}
	if got, err := classifyClaudeResult(exitErr.ExitCode(), stdout.String(), stderr.String()); err == nil {
		t.Fatalf("fake crash classified as %q; stderr=%q", got, stderr.String())
	}
}

func TestFakeClaudeCrashProcess(t *testing.T) {
	if os.Getenv("GO_WANT_FAKE_CLAUDE_CRASH") != "1" {
		return
	}
	fmt.Fprintln(os.Stderr, "panic: simulated Go runtime crash")
	os.Exit(2)
}

func classifyClaudeResult(code int, stdout, stderr string) (string, error) {
	combined := strings.ToLower(stdout + "\n" + stderr)
	for _, marker := range []string{"panic:", "fatal error:", "runtime:", "goroutine "} {
		if strings.Contains(combined, marker) {
			return "", fmt.Errorf("hook output contains Go crash marker %q", marker)
		}
	}

	switch code {
	case 2:
		if stdout != "" {
			return "", errors.New("deny exit included contradictory stdout")
		}
		if stderr == "" {
			return "", errors.New("deny exit had empty stderr")
		}
		for _, line := range strings.Split(strings.TrimSuffix(stderr, "\n"), "\n") {
			line = strings.TrimSuffix(line, "\r")
			if !strings.HasPrefix(line, "guardrail: ") {
				return "", fmt.Errorf("deny stderr line does not match guardrail contract: %q", line)
			}
		}
		return "deny", nil
	case 0:
		if stdout == "" {
			return "allow", nil
		}
		var response struct {
			HookSpecificOutput struct {
				HookEventName            string `json:"hookEventName"`
				PermissionDecision       string `json:"permissionDecision"`
				PermissionDecisionReason string `json:"permissionDecisionReason"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal([]byte(stdout), &response); err != nil {
			return "", fmt.Errorf("exit-zero stdout is not Claude hook JSON: %w", err)
		}
		hook := response.HookSpecificOutput
		if hook.PermissionDecision != "ask" || hook.PermissionDecisionReason == "" ||
			(hook.HookEventName != "PreToolUse" && hook.HookEventName != "PostToolUse") {
			return "", errors.New("exit-zero stdout does not match Claude ask contract")
		}
		return "ask", nil
	default:
		return "", fmt.Errorf("hook exited with nonstandard status %d", code)
	}
}

func validateEntry(e entry, names map[string]bool) error {
	if e.Name == "" || names[e.Name] {
		return fmt.Errorf("name %q is empty or duplicated", e.Name)
	}
	names[e.Name] = true
	if e.Tool == "" || e.CWD == "" || e.RepoRoot == "" {
		return fmt.Errorf("%q must set tool, cwd, and repo_root", e.Name)
	}
	if (e.Command == "") == (len(e.Paths) == 0) {
		return fmt.Errorf("%q must set exactly one of command or paths", e.Name)
	}
	if len(e.Paths) > 1 {
		return fmt.Errorf("%q has %d paths; Claude accepts one file_path", e.Name, len(e.Paths))
	}
	switch e.Want {
	case "allow", "ask", "deny":
		return nil
	default:
		return fmt.Errorf("%q has invalid want %q", e.Name, e.Want)
	}
}

func materializeRepo(t *testing.T, e entry) string {
	t.Helper()
	logicalRoot := filepath.Clean(filepath.FromSlash(e.RepoRoot))
	logicalCWD := filepath.Clean(filepath.FromSlash(e.CWD))
	rel, err := filepath.Rel(logicalRoot, logicalCWD)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("cwd %q must be inside repo_root %q", e.CWD, e.RepoRoot)
	}
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("initialize repo fixture: %v: %s", err, out)
	}
	cwd := filepath.Join(repo, rel)
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	return cwd
}
