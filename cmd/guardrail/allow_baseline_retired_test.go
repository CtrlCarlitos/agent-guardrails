package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// The allow-baseline was retired by operator ruling (#531, ADR-0028 update of
// 2026-11-15): the hook enforces everything a permissions.allow list could
// mirror, so guardrail no longer advises on that list or reads it for doctor.

func writeClaudeAllowList(t *testing.T, rules ...string) {
	t.Helper()
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, filepath.Join(home, ".config"))
	testenv.SetState(t, t.TempDir())
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"permissions": map[string]any{"allow": rules}})
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAllowBaselineSubcommandIsRetired(t *testing.T) {
	for _, args := range [][]string{{"allow-baseline"}, {"allow-baseline", "--json"}, {"allow-baseline", "--check"}} {
		var out, errb strings.Builder
		if code := run(args, strings.NewReader(""), &out, &errb); code != 2 {
			t.Errorf("%v: exit = %d, want 2 (unknown subcommand)", args, code)
		}
		if !strings.Contains(errb.String(), "unknown subcommand") {
			t.Errorf("%v: stderr = %q, want an unknown-subcommand error", args, errb.String())
		}
	}
}

func TestHelpNoLongerListsAllowBaseline(t *testing.T) {
	var out, errb strings.Builder
	run([]string{"help"}, strings.NewReader(""), &out, &errb)
	if strings.Contains(out.String()+errb.String(), "allow-baseline") {
		t.Fatalf("help still lists allow-baseline:\n%s", out.String())
	}
}

func TestDoctorNoLongerSummarisesTheClaudeAllowList(t *testing.T) {
	writeClaudeAllowList(t, "Bash(graft:*)", "Bash(node:*)", "Bash(go test:*)")
	var out, errb strings.Builder
	cmdDoctor(nil, &out, &errb)
	for _, gone := range []string{"claude allow list:", "baseline"} {
		if strings.Contains(out.String(), gone) {
			t.Errorf("doctor still prints %q:\n%s", gone, out.String())
		}
	}
}
