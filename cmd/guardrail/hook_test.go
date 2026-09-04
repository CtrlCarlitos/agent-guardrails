package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestHookStaleGuardrailConfigDegrades(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "/no/such/guardrail.toml")

	// a destructive command still gets blocked by the base policy
	rm := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, bytes.NewReader([]byte(rm)), &out, &errb)
	if code != 2 {
		t.Fatalf("rm -rf with stale GUARDRAIL_CONFIG: exit %d, want 2 (base policy still applies)", code)
	}
	if !strings.Contains(errb.String(), "/no/such/guardrail.toml") {
		t.Errorf("expected a stale-config warning on stderr; got %q", errb.String())
	}

	// a benign command is allowed
	errb.Reset()
	out.Reset()
	ls := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	code = run([]string{"hook", "claude"}, bytes.NewReader([]byte(ls)), &out, &errb)
	if code != 0 {
		t.Fatalf("ls with stale GUARDRAIL_CONFIG: exit %d, want 0", code)
	}
}

func TestTrifectaEscalatesAcrossTwoCalls(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := filepath.Join(t.TempDir(), "guardrail.toml")
	os.WriteFile(cfg, []byte("waive = [\"P4.secret-path\"]\n"), 0o644)
	t.Setenv("GUARDRAIL_CONFIG", cfg)

	sid := "trifecta-sess-1"
	readPayload := `{"session_id":"` + sid + `","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/.env"}}`
	var out1, err1 bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(readPayload), &out1, &err1); code != 0 {
		t.Fatalf("first call (waived secret read): exit %d, want 0; stderr=%s", code, err1.String())
	}

	curlPayload := `{"session_id":"` + sid + `","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl http://localhost:9999/x"}}`
	var out2, err2 bytes.Buffer
	code2 := run([]string{"hook", "claude"}, strings.NewReader(curlPayload), &out2, &err2)
	if code2 != 0 {
		t.Fatalf("second call: exit %d, want 0 (ask, not deny); stderr=%s", code2, err2.String())
	}
	if !strings.Contains(out2.String(), "trifecta") {
		t.Fatalf("second call should ask citing the trifecta pattern, got stdout=%s", out2.String())
	}
}

func TestTrifectaWaivedIsSilent(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := filepath.Join(t.TempDir(), "guardrail.toml")
	os.WriteFile(cfg, []byte("waive = [\"P4.secret-path\", \"P7.trifecta\"]\n"), 0o644)
	t.Setenv("GUARDRAIL_CONFIG", cfg)

	sid := "waived-trifecta-sess"
	readPayload := `{"session_id":"` + sid + `","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/.env"}}`
	var out1, err1 bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(readPayload), &out1, &err1); code != 0 {
		t.Fatalf("first call: exit %d, want 0; stderr=%s", code, err1.String())
	}
	curlPayload := `{"session_id":"` + sid + `","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl http://localhost:9999/x"}}`
	var out2, err2 bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(curlPayload), &out2, &err2); code != 0 || strings.Contains(out2.String(), "trifecta") {
		t.Fatalf("waived trifecta must stay silent: code=%d out=%s", code, out2.String())
	}
}

func TestTrifectaSilentWithoutPriorSignal(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"lone-sess","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl http://localhost:9999/x"}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb)
	if code != 0 || strings.Contains(out.String(), "trifecta") {
		t.Fatalf("a lone network call should not trigger trifecta: code=%d out=%s", code, out.String())
	}
}

func TestHookRecipeDeniesOnPostEditLintFailure(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/does-not-exist.go"}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb)
	if code != 2 {
		t.Fatalf("exit=%d, want 2 (recipe lint failure denies); stderr=%s", code, errb.String())
	}
}

func TestHookRecipeSilentOnBenignEdit(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"/tmp/README.md"}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d, want 0 (no recipe for .md)", code)
	}
}

func TestHookOpencodeDeny(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"s1","event":"pre","tool":"bash","command":"rm -rf /","cwd":"/tmp"}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "opencode"}, strings.NewReader(payload), &out, &errb)
	if code != 2 {
		t.Fatalf("exit=%d, want 2; stdout=%s stderr=%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), `"decision":"deny"`) {
		t.Fatalf("stdout = %s, want a deny decision", out.String())
	}
}

func TestHookOpencodeAllow(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"s1","event":"pre","tool":"bash","command":"ls -la","cwd":"/tmp"}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "opencode"}, strings.NewReader(payload), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
}

func TestHookOpencodeAuditRecordsCorrectPlane(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"s1","event":"pre","tool":"bash","command":"rm -rf /","cwd":"/tmp"}`
	var out, errb bytes.Buffer
	run([]string{"hook", "opencode"}, strings.NewReader(payload), &out, &errb)
	raw, err := os.ReadFile(filepath.Join(state, "guardrail", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"plane":"opencode"`) {
		t.Fatalf("audit record should say plane opencode, got: %s", raw)
	}
}

func TestHookAntigravityDeny(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /","Cwd":"/tmp"}}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "antigravity", "pre"}, strings.NewReader(payload), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d, want 0 (antigravity never uses exit code); stderr=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"decision":"deny"`) {
		t.Fatalf("stdout = %s, want a deny decision", out.String())
	}
}

func TestHookAntigravityAllow(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"ls -la","Cwd":"/tmp"}}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "antigravity", "pre"}, strings.NewReader(payload), &out, &errb)
	if code != 0 || !strings.Contains(out.String(), `"decision":"allow"`) {
		t.Fatalf("code=%d stdout=%s", code, out.String())
	}
}

func TestHookAntigravityPostAlwaysEmptyObject(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"conversationId":"c1","toolCall":{"name":"replace_file_content","args":{"TargetFile":"/tmp/.env"}}}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "antigravity", "post"}, strings.NewReader(payload), &out, &errb)
	if code != 0 || out.String() != "{}\n" {
		t.Fatalf("post phase: code=%d out=%q, want 0/{}", code, out.String())
	}
}

func TestHookAntigravityMissingPhase(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"hook", "antigravity"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (missing phase)", code)
	}
}

func TestHookAntigravityUnparseableIsDenyJSON(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	var out, errb bytes.Buffer
	code := run([]string{"hook", "antigravity", "pre"}, strings.NewReader("not json"), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d, want 0 (antigravity protocol is stdout-JSON-only); stderr=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"decision":"deny"`) {
		t.Fatalf("stdout = %s, want a deny decision", out.String())
	}
}

func TestHookSessionStart(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := filepath.Join(t.TempDir(), "guardrail.toml")
	os.WriteFile(cfg, []byte("waive = [\"P6\"]\n"), 0o644)
	t.Setenv("GUARDRAIL_CONFIG", cfg)

	payload := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"SessionStart"}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "autonomously") {
		t.Fatalf("missing posture text: %s", out.String())
	}
	if !strings.Contains(out.String(), "P6") {
		t.Fatalf("missing waiver banner: %s", out.String())
	}
}
