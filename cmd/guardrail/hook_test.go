package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

func overlayWithWaivers(count int) string {
	waivers := make([]string, count)
	for i := range waivers {
		waivers[i] = fmt.Sprintf("%q", fmt.Sprintf("warning-%02d", i+1))
	}
	return "waive = [" + strings.Join(waivers, ", ") + "]\n"
}

func authorizeOperatorWaivers(t *testing.T, repo string, ids ...string) {
	t.Helper()
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	dir := filepath.Join(configHome, "guardrail")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = fmt.Sprintf("%q", id)
	}
	body := fmt.Sprintf("[%q]\nwaive = [%s]\n", repo, strings.Join(quoted, ", "))
	if err := os.WriteFile(filepath.Join(dir, "waivers.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func repoWithAuthorizedWaiver(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	gitInitSync(t, root)
	sub := filepath.Join(root, "nested", "work")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "guardrail.toml"), []byte("waive = [\"P6.egress\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	authorizeOperatorWaivers(t, root, "P6.egress")
	t.Setenv("GUARDRAIL_CONFIG", "")
	return root, sub
}

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

func TestHookSanitizesOverlayDiscoveryWarning(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	missing := filepath.Join(t.TempDir(), "missing\nforged\tconfig\x7f.toml")
	t.Setenv("GUARDRAIL_CONFIG", missing)

	payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	lines := strings.Split(strings.TrimSuffix(errb.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("overlay discovery warning wrote %d lines, want 1: %q", len(lines), errb.String())
	}
	if strings.ContainsAny(lines[0], "\r\t\x00\x7f") || !strings.Contains(lines[0], "missing forged config .toml") {
		t.Fatalf("overlay discovery warning was not sanitized: %q", lines[0])
	}
}

func TestHookSanitizesOverlayControlledWarnings(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	overlayPath := filepath.Join(t.TempDir(), "guardrail.toml")
	overlay := `waive = ["P9.forged\nwarning\tclaim\u007f"]
[slots]
safe_roots = ["/definitely-outside\nforged\troot\u007f"]
`
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)

	payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	lines := strings.Split(strings.TrimSuffix(errb.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("overlay warnings wrote %d lines, want 2: %q", len(lines), errb.String())
	}
	for _, line := range lines {
		if strings.ContainsAny(line, "\r\t\x00\x7f") {
			t.Fatalf("overlay warning retained controls: %q", line)
		}
	}
	if !strings.Contains(lines[0], "safe_root /definitely-outside forged root") ||
		!strings.Contains(lines[1], "waiver of P9.forged warning claim") {
		t.Fatalf("overlay warnings were not normalized: %q", errb.String())
	}
}

func TestHookEmitsOnlyFirstTwentyMergeWarnings(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	overlayPath := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(overlayPath, []byte(overlayWithWaivers(21)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)

	payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	if strings.Count(errb.String(), "repo requested waiver of") != 20 {
		t.Fatalf("merge warning count = %d, want 20: %q", strings.Count(errb.String(), "repo requested waiver of"), errb.String())
	}
	if strings.Contains(errb.String(), "warning-21") {
		t.Fatalf("warning 21 reached stderr: %q", errb.String())
	}
}

func TestHookCumulativeWarningCapPreservesSessionStartOperatorWarning(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	configDir := filepath.Join(configHome, "guardrail")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "waivers.toml"), []byte(`malformed = [`), 0o600); err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(overlayPath, []byte(overlayWithWaivers(21)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)

	payload := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"SessionStart"}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	lines := strings.Split(strings.TrimSuffix(errb.String(), "\n"), "\n")
	if len(lines) != 20 {
		t.Fatalf("stderr wrote %d warning lines, want 20: %q", len(lines), errb.String())
	}
	const generic = "guardrail: operator configuration could not be loaded; operator-authorized policy changes remain disabled"
	if !strings.HasPrefix(lines[0], "guardrail: operator config unreadable") {
		t.Fatalf("detailed operator diagnostic was not first: %q", errb.String())
	}
	if strings.Contains(errb.String(), generic) {
		t.Fatalf("stderr duplicated generic and detailed operator warnings: %q", errb.String())
	}
	if !strings.Contains(errb.String(), "warning-19") || strings.Contains(errb.String(), "warning-20") {
		t.Fatalf("stderr did not truncate lower-priority Merge warnings: %q", errb.String())
	}
	if !strings.Contains(out.String(), generic) {
		t.Fatalf("SessionStart posture omitted generic operator warning: %s", out.String())
	}
	if genericAt, mergeAt := strings.Index(out.String(), generic), strings.Index(out.String(), "warning-01"); genericAt < 0 || mergeAt < 0 || genericAt > mergeAt {
		t.Fatalf("SessionStart posture did not prioritize generic operator warning: %s", out.String())
	}
	if !strings.Contains(out.String(), "warning-19") || strings.Contains(out.String(), "warning-20") {
		t.Fatalf("SessionStart posture did not truncate lower-priority Merge warnings: %s", out.String())
	}
}

func TestHookLateSessionWarningCannotExceedCumulativeCap(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	overlayPath := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(overlayPath, []byte(overlayWithWaivers(20)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)

	payload := `{"session_id":"../unsafe","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	lines := strings.Split(strings.TrimSuffix(errb.String(), "\n"), "\n")
	if len(lines) != 20 {
		t.Fatalf("stderr wrote %d warning lines, want 20: %q", len(lines), errb.String())
	}
	if !strings.Contains(lines[0], "unsafe session id") || strings.ContainsAny(lines[0], "\r\t\x00\x7f") {
		t.Fatalf("unsafe-session warning was not first and sanitized: %q", lines[0])
	}
	if !strings.Contains(errb.String(), "warning-19") || strings.Contains(errb.String(), "warning-20") {
		t.Fatalf("stderr did not truncate lower-priority Merge warnings: %q", errb.String())
	}
}

func TestHookLateAuditWarningCannotExceedCumulativeCap(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	configDir := filepath.Join(configHome, "guardrail")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "waivers.toml"), []byte("[\"/tmp\"]\naudit_log = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(t.TempDir(), "not-a-directory\nforged\tpath\x7f")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(blocker, "audit.jsonl")
	overlayPath := filepath.Join(t.TempDir(), "guardrail.toml")
	overlay := fmt.Sprintf("audit_log = %q\n", auditPath) + overlayWithWaivers(20)
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)

	payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	lines := strings.Split(strings.TrimSuffix(errb.String(), "\n"), "\n")
	if len(lines) != 20 {
		t.Fatalf("stderr wrote %d warning lines, want 20: %q", len(lines), errb.String())
	}
	if !strings.Contains(lines[0], "audit write failed") || strings.ContainsAny(lines[0], "\r\t\x00\x7f") ||
		!strings.Contains(lines[0], "not-a-directory forged path") {
		t.Fatalf("audit warning was not first and sanitized: %q", lines[0])
	}
	if !strings.Contains(errb.String(), "warning-19") || strings.Contains(errb.String(), "warning-20") {
		t.Fatalf("stderr did not truncate lower-priority Merge warnings: %q", errb.String())
	}
}

func TestTrifectaEscalatesAcrossTwoCalls(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	authorizeOperatorWaivers(t, "/tmp", "P4.secret-path")
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
	authorizeOperatorWaivers(t, "/tmp", "P4.secret-path", "P7.trifecta")
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

func TestHookRejectsUnsafeSessionID(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	authorizeOperatorWaivers(t, "/tmp", "P4.secret-path")
	cfg := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(cfg, []byte("waive = [\"P4.secret-path\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", cfg)

	sid := "../unsafe"
	readPayload := `{"session_id":"` + sid + `","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/.env"}}`
	var out1, err1 bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(readPayload), &out1, &err1); code != 0 {
		t.Fatalf("first call: exit %d, want 0; stderr=%s", code, err1.String())
	}
	if !strings.Contains(err1.String(), "unsafe session id") {
		t.Errorf("first call missing unsafe-session warning: %q", err1.String())
	}

	curlPayload := `{"session_id":"` + sid + `","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl http://localhost:9999/x"}}`
	var out2, err2 bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(curlPayload), &out2, &err2); code != 0 {
		t.Fatalf("second call: exit %d, want 0; stderr=%s", code, err2.String())
	}
	if strings.Contains(out2.String(), "trifecta") {
		t.Errorf("unsafe session id carried heuristic state between calls: %s", out2.String())
	}
	if !strings.Contains(err2.String(), "unsafe session id") {
		t.Errorf("second call missing unsafe-session warning: %q", err2.String())
	}
	if _, err := os.Stat(filepath.Join(state, "guardrail", "unsafe.json")); !os.IsNotExist(err) {
		t.Errorf("unsafe session id wrote outside the sessions dir: %v", err)
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

func TestHookAuditRetainsRawVerdictReason(t *testing.T) {
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	overlayPath := filepath.Join(t.TempDir(), "guardrail.toml")
	overlay := `[[rules]]
id = "project.raw-reason"
tool = "Bash"
pattern = "raw-reason-command"
decision = "deny"
reason = "raw\nreason\tclaim\u007f"
`
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)

	payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"raw-reason-command"}}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 2 {
		t.Fatalf("exit=%d, want 2; stderr=%q", code, errb.String())
	}
	if errb.String() != "guardrail: raw reason claim\n" {
		t.Fatalf("model-facing reason was not sanitized: %q", errb.String())
	}
	raw, err := os.ReadFile(filepath.Join(state, "guardrail", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.Reason != "raw\nreason\tclaim\x7f" {
		t.Fatalf("audit reason = %q, want raw Verdict reason", record.Reason)
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

func TestHookAntigravityParseErrorUsesSanitizedDenyProtocol(t *testing.T) {
	parseErr := errors.New("bad\nforged\t" + strings.Repeat("界", 300) + "\x7f")
	for _, phase := range []string{"pre", "post"} {
		t.Run(phase, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run([]string{"hook", "antigravity", phase}, failingReader{err: parseErr}, &out, &errb)
			if code != 0 || errb.Len() != 0 {
				t.Fatalf("code=%d, stderr=%q; want exit 0 and no stderr", code, errb.String())
			}
			var got map[string]string
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["decision"] != "deny" {
				t.Fatalf("decision = %q, want deny", got["decision"])
			}
			reason := got["reason"]
			if strings.ContainsAny(reason, "\n\r\t\x00\x7f") {
				t.Fatalf("parse error reason retained controls: %q", reason)
			}
			if len([]rune(reason)) != 201 || !strings.HasSuffix(reason, "…") {
				t.Fatalf("parse error reason was not truncated at 200 runes plus ellipsis: %q", reason)
			}
		})
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

func TestHookUsesTopLevelRepoGrantFromSubdirectory(t *testing.T) {
	_, sub := repoWithAuthorizedWaiver(t)
	payload := fmt.Sprintf(`{"session_id":"s1","cwd":%q,"hook_event_name":"SessionStart"}`, sub)
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "Active policy waivers in this repo (these rules are OFF): P6.egress") {
		t.Fatalf("top-level operator grant was not applied from subdirectory: %s", out.String())
	}
}

func TestHookSessionStartSanitizesOperatorConfigLoadError(t *testing.T) {
	configHome := filepath.Join(t.TempDir(), "config\nforged\tpath\x7f")
	t.Setenv("XDG_CONFIG_HOME", configHome)
	configDir := filepath.Join(configHome, "guardrail")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "waivers.toml")
	if err := os.WriteFile(configPath, []byte(`malformed = [`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", "")

	payload := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"SessionStart"}`
	var out, errb bytes.Buffer
	code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	const generic = "guardrail: operator configuration could not be loaded; operator-authorized policy changes remain disabled"
	if !strings.Contains(out.String(), generic) {
		t.Fatalf("SessionStart omitted generic operator warning: %s", out.String())
	}
	if strings.Contains(out.String(), configPath) || strings.Contains(out.String(), "parsing operator config") {
		t.Fatalf("SessionStart exposed detailed operator error: %s", out.String())
	}
	lines := strings.Split(strings.TrimSuffix(errb.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("operator load warnings wrote %d lines, want 1: %q", len(lines), errb.String())
	}
	for _, line := range lines {
		if strings.ContainsAny(line, "\r\t\x00\x7f") {
			t.Fatalf("operator load warning retained controls: %q", line)
		}
	}
	if !strings.Contains(lines[0], "parsing operator config") || !strings.Contains(lines[0], "config forged path /guardrail/waivers.toml") {
		t.Fatalf("stderr omitted sanitized operator diagnostics: %q", errb.String())
	}
	if strings.Contains(errb.String(), generic) {
		t.Fatalf("stderr duplicated the generic posture warning: %q", errb.String())
	}
}
