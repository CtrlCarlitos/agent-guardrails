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
	bin := filepath.Join(t.TempDir(), "guardrail")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
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
		`{"cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"$(“”)|&;` + "`" + `"}}`,
		`{"cwd":"/tmp","tool_name":"Bash","tool_input":{"command":""}}`,
		`{}`,
	}
	for _, p := range weird {
		cmd := exec.Command(bin, "hook", "claude")
		cmd.Stdin = bytes.NewReader([]byte(p))
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+t.TempDir())
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
