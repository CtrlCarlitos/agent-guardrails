package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
)

func TestCodexLifecycleRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("operator actions are unavailable on Windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, "custom-codex"))
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	path, err := planeConfigPath("codex")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(home, "custom-codex", "hooks.json") {
		t.Fatal(path)
	}
	writePlaneSettings(t, path, `{"description":"keep","hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"user-hook"}]}]}}`)
	r := approval.Request{ID: "codex-enable", Plane: "operator", SessionID: "terminal", RepoRoot: home, Scope: approval.GlobalScope, Action: "plane-enable", Parameters: map[string]string{"planes": "codex"}}
	if err := executePlaneApproval(r); err != nil {
		t.Fatal(err)
	}
	if !planeIntegrationRegistered("codex") {
		t.Fatal("enable did not register")
	}
	if !strings.Contains(planeStatusState("codex"), "verify trust") {
		t.Fatal(planeStatusState("codex"))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "rules", "guardrail.rules")); err != nil {
		t.Fatal(err)
	}
	r.ID = "codex-disable"
	r.Action = "plane-disable"
	if err := executePlaneApproval(r); err != nil {
		t.Fatal(err)
	}
	if planeIntegrationRegistered("codex") {
		t.Fatal("disable did not remove")
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "user-hook") || !strings.Contains(string(raw), "keep") {
		t.Fatal(string(raw))
	}
}

func TestCodexWindowsStatusReportsRegisteredUnenforced(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows runtime dispatch boundary")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex"))
	path, err := planeConfigPath("codex")
	if err != nil {
		t.Fatal(err)
	}
	if err := genconfig.MergePlaneInto(path, "codex", genconfig.CodexConfig("guardrail")); err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(filepath.Dir(path), "rules", "guardrail.rules")
	if err := os.MkdirAll(filepath.Dir(rulesPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, genconfig.CodexRules(), 0o600); err != nil {
		t.Fatal(err)
	}

	status := planeStatusState("codex")
	if !strings.Contains(status, "registered, unenforced") || !strings.Contains(status, "#24453") {
		t.Fatal(status)
	}
	if strings.Contains(status, "coverage confirmed") || strings.Contains(status, "enforced") && !strings.Contains(status, "unenforced") {
		t.Fatalf("status overclaims coverage: %s", status)
	}
}

func TestCodexHookBlocksAskAndMalformedAndDelegation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	cwd := t.TempDir()
	for _, tt := range []struct {
		tool   string
		input  any
		reason string
	}{
		{"Bash", map[string]any{"command": "chmod 777 file.txt"}, "cannot request approval"},
		{"spawn_agent", map[string]any{"message": "work"}, "perform the work yourself"},
		{"collaboration.spawn_agent", map[string]any{"message": "work"}, "perform the work yourself"},
		{"future_tool", map[string]any{}, "unclassified"},
		{"Bash", map[string]any{"command": 3}, "failing closed"},
	} {
		t.Run(tt.tool, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "fixture", "cwd": cwd, "tool_name": tt.tool, "tool_input": tt.input})
			var out, errb bytes.Buffer
			if code := run([]string{"hook", "codex"}, bytes.NewReader(raw), &out, &errb); code != 2 || !strings.Contains(errb.String(), tt.reason) {
				t.Fatalf("code %d: %s %s", code, out.String(), errb.String())
			}
		})
	}
}

func TestCodexSyncAndGenConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := run([]string{"sync", "--dir", dir, "--planes", "codex", "--binary", "/opt/guardrail"}, nil, &out, &errb); code != 0 {
		t.Fatalf("%d %s", code, errb.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".codex", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if !genconfig.CodexHooksRegistered(doc) {
		t.Fatal(string(raw))
	}
	out.Reset()
	errb.Reset()
	if code := run([]string{"gen-config", "codex", "--floor"}, nil, &out, &errb); code != 0 || !strings.Contains(out.String(), "forbidden") {
		t.Fatalf("%d: %s %s", code, out.String(), errb.String())
	}
}
