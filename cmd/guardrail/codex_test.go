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
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestCodexLifecycleRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("operator actions are unavailable on Windows")
	}
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("CODEX_HOME", filepath.Join(home, "custom-codex"))
	testenv.SetState(t, t.TempDir())
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
	testenv.SetHome(t, home)
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

func TestWindowsCodexHookBlocksAskAndMalformedAndDelegation(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	cwd := t.TempDir()
	for _, tt := range []struct {
		tool       string
		input      any
		reason     string
		class      string
		normalized string
		matched    string
	}{
		{"Bash", map[string]any{"command": "chmod 777 file.txt"}, "cannot request approval", "policy denial", "Bash", "Bash"},
		{"spawn_agent", map[string]any{"message": "work"}, "perform the work yourself", "policy denial", "spawn_agent", "spawn_agent"},
		{"future_tool", map[string]any{}, "unclassified", "policy denial", "future_tool", ""},
		{"Bash", map[string]any{"command": 3}, "failing closed", "handler failure", "Bash", "Bash"},
	} {
		t.Run(tt.tool, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "fixture", "cwd": cwd, "tool_name": tt.tool, "tool_input": tt.input})
			var out, errb bytes.Buffer
			const handlerHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			args := []string{"hook", "codex", "--handler-id", "guardrail-codex-PreToolUse", "--handler-hash", handlerHash}
			if code := run(args, bytes.NewReader(raw), &out, &errb); code != 2 || !strings.Contains(errb.String(), tt.reason) || !strings.Contains(errb.String(), "guardrail: "+tt.class+":") {
				t.Fatalf("code %d: %s %s", code, out.String(), errb.String())
			}
			diagnostic := parseCodexHookDiagnostic(t, errb.String())
			for key, want := range map[string]any{
				"class":                     strings.TrimSuffix(strings.TrimSuffix(tt.class, " denial"), " failure"),
				"declared_tool":             tt.tool,
				"normalized_identity":       tt.normalized,
				"matched_contract_identity": tt.matched,
				"handler_id":                "guardrail-codex-PreToolUse",
				"handler_hash":              handlerHash,
				"trust_hash":                "doctor-reconciliation-required",
				"session":                   "fixture",
				"exit_code":                 float64(2),
			} {
				if got := diagnostic[key]; got != want {
					t.Fatalf("diagnostic[%s] = %#v, want %#v; full=%#v", key, got, want, diagnostic)
				}
			}
			if got, _ := diagnostic["stderr"].(string); !strings.Contains(got, tt.reason) || strings.ContainsAny(got, "\r\n\t") {
				t.Fatalf("diagnostic stderr = %q, want bounded single-line raw failure", got)
			}
		})
	}
}

func parseCodexHookDiagnostic(t *testing.T, stderr string) map[string]any {
	t.Helper()
	const prefix = "guardrail: hook diagnostic: "
	for _, line := range strings.Split(stderr, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, prefix)), &got); err != nil {
			t.Fatalf("invalid hook diagnostic JSON: %v; line=%q", err, line)
		}
		return got
	}
	t.Fatalf("missing structured hook diagnostic: %s", stderr)
	return nil
}

func TestWindowsCodexHookRejectsInvalidDiagnosticMetadata(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"hook", "codex", "--handler-id", "attacker", "--handler-hash", "sha256:nope"}, strings.NewReader("{}"), &out, &errb)
	if code != 2 || out.Len() != 0 || !strings.Contains(errb.String(), "invalid handler identity or hash") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	diagnostic := parseCodexHookDiagnostic(t, errb.String())
	if diagnostic["class"] != "handler" || diagnostic["handler_id"] != "unavailable" || diagnostic["handler_hash"] != "unavailable" {
		t.Fatalf("invalid metadata was retained as trusted diagnostic identity: %#v", diagnostic)
	}
}

func TestCodexSyncAndGenConfig(t *testing.T) {
	testenv.SetConfig(t, t.TempDir())
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
