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

			got := "allow"
			switch {
			case code == 2:
				got = "deny"
			case code != 0:
				t.Fatalf("hook exited %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			case strings.Contains(stdout.String(), `"permissionDecision":"ask"`):
				got = "ask"
			}
			if got != e.Want {
				t.Fatalf("got %s, want %s (exit=%d stdout=%s stderr=%s)", got, e.Want, code, stdout.String(), stderr.String())
			}
		})
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
