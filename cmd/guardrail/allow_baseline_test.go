package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/allowbaseline"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// `guardrail allow-baseline` tells the operator which Claude Code allow rules are
// safe to put in their own settings (#363). It advises and writes nothing.

func writeClaudeAllow(t *testing.T, rules ...string) string {
	t.Helper()
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, filepath.Join(home, ".config"))
	testenv.SetState(t, t.TempDir())
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"permissions": map[string]any{"allow": rules}, "model": "opus"})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAllowBaselineListsTheRulesAndSaysItWritesNothing(t *testing.T) {
	path := writeClaudeAllow(t, "Bash(graft:*)")
	before, _ := os.ReadFile(path)
	var out, errb strings.Builder
	if code := run([]string{"allow-baseline"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errb.String())
	}
	text := out.String()
	for _, want := range []string{"Bash(go test:*)", "Bash(pytest:*)", "Bash(graft ask:*)", "writes nothing", "settings"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("allow-baseline changed the settings file")
	}
}

func TestAllowBaselineJSONIsExactlyTheSnippet(t *testing.T) {
	writeClaudeAllow(t)
	var out, errb strings.Builder
	if code := run([]string{"allow-baseline", "--json"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errb.String())
	}
	if got, want := strings.TrimSpace(out.String()), strings.TrimSpace(allowbaseline.SnippetJSON()); got != want {
		t.Fatalf("--json output is not the snippet:\n%s", got)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out.String()), &doc); err != nil {
		t.Fatalf("--json is not valid JSON: %v", err)
	}
}

func TestAllowBaselineCheckNamesBroadEntriesAndWhatIsMissing(t *testing.T) {
	writeClaudeAllow(t, "Bash(graft:*)", "Bash(npx graft:*)", "Bash(node dist/cli.js:*)", "Bash(go test:*)")
	var out, errb strings.Builder
	if code := run([]string{"allow-baseline", "--check"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errb.String())
	}
	text := out.String()
	for _, want := range []string{"1 of ", "Bash(graft:*)", "graft init", "Bash(npx graft:*)", "missing"} {
		if !strings.Contains(text, want) {
			t.Errorf("--check output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Bash(node dist/cli.js:*) ") && strings.Contains(text, "broader") && strings.Index(text, "Bash(node dist/cli.js:*)") < strings.Index(text, "missing") {
		t.Errorf("a narrow entry was reported as broad:\n%s", text)
	}
}

func TestAllowBaselineCheckWithNoSettingsFileIsNotAnError(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, filepath.Join(home, ".config"))
	testenv.SetState(t, t.TempDir())
	var out, errb strings.Builder
	if code := run([]string{"allow-baseline", "--check"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "no Claude settings") {
		t.Fatalf("output does not say there is nothing to compare:\n%s", out.String())
	}
}

func TestAllowBaselineRejectsUnknownArguments(t *testing.T) {
	var out, errb strings.Builder
	if code := run([]string{"allow-baseline", "--apply"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("exit = %d, want 2 (there is deliberately no apply)", code)
	}
}

// doctor carries one line so an over-broad entry is noticed without anyone
// having to think of the command.
func TestDoctorReportsAnAllowListBroaderThanTheBaseline(t *testing.T) {
	writeClaudeAllow(t, "Bash(graft:*)", "Bash(node:*)")
	var out, errb strings.Builder
	cmdDoctor(nil, &out, &errb)
	var line string
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(l, "claude allow list:") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("doctor prints no allow-list line:\n%s", out.String())
	}
	for _, want := range []string{"2 broader than the baseline", "guardrail allow-baseline --check"} {
		if !strings.Contains(line, want) {
			t.Errorf("the line %q lacks %q", line, want)
		}
	}
}

func TestDoctorPrintsNoAllowListLineWithoutASettingsFile(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, filepath.Join(home, ".config"))
	testenv.SetState(t, t.TempDir())
	var out, errb strings.Builder
	cmdDoctor(nil, &out, &errb)
	if strings.Contains(out.String(), "claude allow list:") {
		t.Fatalf("doctor invented an allow-list line with no settings file:\n%s", out.String())
	}
}
