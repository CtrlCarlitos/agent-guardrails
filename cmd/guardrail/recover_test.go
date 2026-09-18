package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
)

func TestExecuteRecoverApprovalRepairsUnparseableClaudeSettings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	broken := `{"hooks":{"PreToolUse": TRUNCATED`
	if err := os.WriteFile(settings, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}

	r := approval.Request{ID: "recover-1", Plane: "operator", SessionID: "terminal", RepoRoot: home, Scope: approval.GlobalScope, Action: "recover", Parameters: map[string]string{"repair": "claude-settings"}}
	if err := executeRecoverApproval(r); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "guardrail-claude-pre") {
		t.Fatalf("settings not re-registered after reset: %s", raw)
	}
	backup, err := filepath.Glob(filepath.Join(home, ".claude", "settings.json.guardrail-recover-*"))
	if err != nil || len(backup) != 1 {
		t.Fatalf("backup = %v err=%v", backup, err)
	}
	saved, _ := os.ReadFile(backup[0])
	if string(saved) != broken {
		t.Fatalf("backup does not preserve the original bytes: %q", saved)
	}
}

func TestExecuteRecoverApprovalAbsorbsParseableDriftWithUserConfigIntact(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{"model":"user-model","hooks":{"PreToolUse":[{"matcher":"Task","hooks":[{"type":"command","command":"my-own-hook"}]},{"matcher":"Bash","hooks":[{"type":"command","command":"guardrail hook claude"}]}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	r := approval.Request{ID: "recover-2", Plane: "operator", SessionID: "terminal", RepoRoot: home, Scope: approval.GlobalScope, Action: "recover", Parameters: map[string]string{"repair": "claude-settings"}}
	if err := executeRecoverApproval(r); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(settings)
	got := string(raw)
	if !strings.Contains(got, "guardrail-claude-pre") || !strings.Contains(got, "my-own-hook") || !strings.Contains(got, "user-model") {
		t.Fatalf("repair lost user config or missed registration: %s", got)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if n := genconfig.CountUnmarkedGuardrailGroups(doc); n != 0 {
		t.Fatalf("%d unmarked entries remain after recover", n)
	}
	if err := executeRecoverApproval(r); err != nil {
		t.Fatalf("replay: %v", err)
	}
}

func TestExecuteRecoverApprovalRejectsUnknownRepair(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	r := approval.Request{Action: "recover", Parameters: map[string]string{"repair": "rm-rf"}}
	if err := executeRecoverApproval(r); err == nil {
		t.Fatal("unknown repair accepted")
	}
}

func TestRecoverCommandRequiresTerminalAndKnownRepair(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var out, errb strings.Builder
	if code := run([]string{"recover", "rm-rf"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), "known repair") {
		t.Fatalf("unknown repair exit = %d stderr %q", code, errb.String())
	}
	if code := run([]string{"recover", "claude-settings"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), "interactive") {
		t.Fatalf("non-terminal exit = %d stderr %q", code, errb.String())
	}
}

func TestRecoverClaudeSettingsHappyPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{broken`), 0o644); err != nil {
		t.Fatal(err)
	}

	var submitted []approval.Request
	var current approval.Request
	origSubmit, origQuery := submitPlaneRequest, queryPlaneStatus
	submitPlaneRequest = func(request approval.Request) (approval.Request, error) {
		current = request
		submitted = append(submitted, request)
		return approval.Request{ID: "stub-request", Status: "pending", ApprovalURL: "http://localhost:39169/approve"}, nil
	}
	queryPlaneStatus = func(socket, id string) (approval.Request, error) {
		if err := executeRecoverApproval(current); err != nil {
			return approval.Request{Status: "denied"}, nil
		}
		return approval.Request{Status: "approved"}, nil
	}
	defer func() { submitPlaneRequest, queryPlaneStatus = origSubmit, origQuery }()

	var out, errb strings.Builder
	if code := cmdRecoverTerminal([]string{"recover", "claude-settings"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d stderr %q", code, errb.String())
	}
	if len(submitted) != 1 || submitted[0].Action != "recover" {
		t.Fatalf("submissions = %+v", submitted)
	}
	if !strings.Contains(out.String(), "claude-settings recovered") {
		t.Fatalf("stdout = %q", out.String())
	}
	raw, _ := os.ReadFile(settings)
	if !strings.Contains(string(raw), "guardrail-claude-pre") {
		t.Fatalf("settings not repaired: %s", raw)
	}
}

// cmdRecoverTerminal invokes cmdRecover with the operator-terminal signal on.
func cmdRecoverTerminal(args []string, stdout, stderr io.Writer) int {
	return cmdRecover(args[1:], true, stdout, stderr)
}
