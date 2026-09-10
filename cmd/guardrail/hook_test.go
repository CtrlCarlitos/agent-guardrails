package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/night"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

func hookFailureInput(t *testing.T, plane, failure string) io.Reader {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")

	var payload string
	switch plane {
	case "claude":
		payload = `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	case "opencode":
		payload = `{"event":"pre","tool":"bash","command":"ls","cwd":"/tmp"}`
	case "antigravity":
		payload = `{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"ls","Cwd":"/tmp"}}}`
	default:
		t.Fatalf("unsupported test plane %q", plane)
	}

	if failure == "malformed_payload" {
		return strings.NewReader("{")
	}

	overlayPath := filepath.Join(t.TempDir(), "guardrail\nforged\t\x7f.toml")
	var overlay string
	switch failure {
	case "malformed_overlay":
		overlay = `malformed = [`
	case "oversized_overlay":
		overlay = strings.Repeat("#", (1<<20)+1)
	case "merge_error":
		overlay = `[[rules]]
id = "project.allow"
tool = "Bash"
pattern = "ls"
decision = "allow"
reason = "project allow rules must be rejected"
`
	default:
		t.Fatalf("unsupported hook failure %q", failure)
	}
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)
	return strings.NewReader(payload)
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

func configureTrackingPolicy(t *testing.T, waivers ...string) {
	t.Helper()
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	dir := filepath.Join(configHome, "guardrail")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	quoted := make([]string, len(waivers))
	for i, waiver := range waivers {
		quoted[i] = fmt.Sprintf("%q", waiver)
	}
	operator := fmt.Sprintf("[\"/tmp\"]\nwaive = [%s]\negress_allowlist = [\"api.example.com\"]\n", strings.Join(quoted, ", "))
	if err := os.WriteFile(filepath.Join(dir, "waivers.toml"), []byte(operator), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := fmt.Sprintf("waive = [%s]\n[slots]\negress_allowlist = [\"api.example.com\"]\n", strings.Join(quoted, ", "))
	overlayPath := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)
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

func enableNightForHook(t *testing.T) string {
	t.Helper()
	path, err := night.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := night.Write(path, night.Marker{Until: time.Now().Add(time.Hour), SetBy: "test:1"}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHookNightModeAllowsAsksAcrossPlanesWithAuditProvenance(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		payload string
		wantOut string
	}{
		{
			name:    "claude",
			args:    []string{"hook", "claude"},
			payload: `{"session_id":"night-claude","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}`,
			wantOut: "",
		},
		{
			name:    "opencode",
			args:    []string{"hook", "opencode"},
			payload: `{"session_id":"night-opencode","event":"pre","tool":"bash","command":"git push origin main","cwd":"/tmp","arguments":{"command":"git push origin main"}}`,
			wantOut: `"decision":"allow"`,
		},
		{
			name:    "antigravity",
			args:    []string{"hook", "antigravity", "pre"},
			payload: `{"conversationId":"night-antigravity","toolCall":{"name":"run_command","args":{"CommandLine":"git push origin main","Cwd":"/tmp"}}}`,
			wantOut: `"decision":"allow"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateHome := t.TempDir()
			t.Setenv("XDG_STATE_HOME", stateHome)
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("GUARDRAIL_CONFIG", "")
			enableNightForHook(t)

			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(tt.payload), &stdout, &stderr)
			if code != 0 || stderr.String() != "" || (tt.wantOut == "" && stdout.String() != "") || (tt.wantOut != "" && !strings.Contains(stdout.String(), tt.wantOut)) {
				t.Fatalf("night hook = code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
			}
			if tt.name != "claude" && !strings.Contains(stdout.String(), "NIGHT MODE until ") {
				t.Fatalf("first %s response omitted night banner: %s", tt.name, stdout.String())
			}

			records := readApprovalAudit(t, stateHome)
			if len(records) != 1 || records[0].Decision != "allow" || records[0].RuleID != "ask-allowed-by-night-mode" || records[0].OriginRuleID != "P2.git-push-protected" {
				t.Fatalf("night audit = %+v, want allow with night and origin rule IDs", records)
			}
		})
	}
}

func TestHookNightModeNeverWeakensDeny(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		payload string
	}{
		{name: "claude", args: []string{"hook", "claude"}, payload: `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`},
		{name: "opencode", args: []string{"hook", "opencode"}, payload: `{"event":"pre","tool":"bash","command":"rm -rf /","cwd":"/tmp"}`},
		{name: "antigravity", args: []string{"hook", "antigravity", "pre"}, payload: `{"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /","Cwd":"/tmp"}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("GUARDRAIL_CONFIG", "")
			enableNightForHook(t)
			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(tt.payload), &stdout, &stderr)
			if code != 2 && tt.name != "antigravity" {
				t.Fatalf("night deny exit = %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
			}
			if tt.name == "claude" && !strings.Contains(stderr.String(), "guardrail:") {
				t.Fatalf("night weakened Claude deny: stdout %q, stderr %q", stdout.String(), stderr.String())
			}
			if tt.name != "claude" && !strings.Contains(stdout.String(), `"decision":"deny"`) {
				t.Fatalf("night weakened %s deny: stdout %q, stderr %q", tt.name, stdout.String(), stderr.String())
			}
		})
	}
}

func TestHookNightModeIsReadForEveryCall(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := `{"session_id":"night-live","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}`
	call := func() string {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &stdout, &stderr); code != 0 || stderr.String() != "" {
			t.Fatalf("hook exit = %d, stderr %q", code, stderr.String())
		}
		return stdout.String()
	}
	if out := call(); !strings.Contains(out, `"permissionDecision":"ask"`) {
		t.Fatalf("inactive call = %q, want Ask", out)
	}
	path := enableNightForHook(t)
	if out := call(); out != "" {
		t.Fatalf("active call = %q, want Allow", out)
	}
	if err := night.Remove(path); err != nil {
		t.Fatal(err)
	}
	if out := call(); !strings.Contains(out, `"permissionDecision":"ask"`) {
		t.Fatalf("post-off call = %q, want Ask", out)
	}
}

func TestHookMalformedNightMarkerKeepsNormalPostureAndWarns(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	path, err := night.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("until = ["), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}`
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"ask"`) || !strings.Contains(stderr.String(), "night marker") {
		t.Fatalf("malformed marker = stdout %q, stderr %q; want normal Ask and warning", stdout.String(), stderr.String())
	}
}

func TestHookNightModeFallsBackToAskWhenAuditFails(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	configDir := filepath.Join(configHome, "guardrail")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(blocker, "audit.jsonl")
	if err := os.WriteFile(filepath.Join(configDir, "waivers.toml"), []byte("[\"/tmp\"]\naudit_log = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(overlayPath, []byte(fmt.Sprintf("audit_log = %q\n", auditPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)
	enableNightForHook(t)

	payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}`
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"ask"`) || !strings.Contains(stderr.String(), "audit write failed") {
		t.Fatalf("audit failure = stdout %q, stderr %q; want normal Ask plus warning", stdout.String(), stderr.String())
	}
}

func TestHookNightModeFallsBackToAskForNonRegularAuditDestination(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	configDir := filepath.Join(configHome, "guardrail")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "waivers.toml"), []byte("[\"/tmp\"]\naudit_log = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(overlayPath, []byte(fmt.Sprintf("audit_log = %q\n", os.DevNull)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)
	enableNightForHook(t)

	payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}`
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"ask"`) || !strings.Contains(stderr.String(), "audit write failed") {
		t.Fatalf("non-regular audit = stdout %q, stderr %q; want normal Ask plus warning", stdout.String(), stderr.String())
	}
}

func TestHookNightModeDoesNotCreateOpenCodeApprovalMemory(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	enableNightForHook(t)
	const sessionID = "night-no-approval"
	payload := `{"session_id":"` + sessionID + `","event":"pre","tool":"bash","command":"git push origin main","cwd":"/tmp","arguments":{"command":"git push origin main"}}`
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hook", "opencode"}, strings.NewReader(payload), &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	state, _ := readApprovalState(t, sessionID)
	if len(state.PendingApprovals) != 0 {
		t.Fatalf("night mode created approval memory: %+v", state.PendingApprovals)
	}
}

func TestHookNightBannerAppearsOncePerNonClaudeSession(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		payload string
	}{
		{name: "opencode", args: []string{"hook", "opencode"}, payload: `{"session_id":"night-banner-opencode","event":"pre","tool":"bash","command":"git push origin main","cwd":"/tmp"}`},
		{name: "antigravity", args: []string{"hook", "antigravity", "pre"}, payload: `{"conversationId":"night-banner-antigravity","toolCall":{"name":"run_command","args":{"CommandLine":"git push origin main","Cwd":"/tmp"}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("GUARDRAIL_CONFIG", "")
			enableNightForHook(t)
			for call := 1; call <= 2; call++ {
				var stdout, stderr bytes.Buffer
				if code := run(tt.args, strings.NewReader(tt.payload), &stdout, &stderr); code != 0 {
					t.Fatalf("call %d exit = %d, stderr %q", call, code, stderr.String())
				}
				hasBanner := strings.Contains(stdout.String(), "NIGHT MODE until ")
				if hasBanner != (call == 1) {
					t.Fatalf("call %d banner=%v, stdout %q", call, hasBanner, stdout.String())
				}
			}
		})
	}
}

func TestHookNightBannerAppearsWhenSessionTransactionFails(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	enableNightForHook(t)
	realTransaction := sessionTransaction
	sessionTransaction = func(string, func(*session.State) error) error {
		return errors.New("injected pre-commit failure")
	}
	t.Cleanup(func() { sessionTransaction = realTransaction })

	payload := `{"session_id":"night-banner-failed-transaction","event":"pre","tool":"bash","command":"git push origin main","cwd":"/tmp"}`
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hook", "opencode"}, strings.NewReader(payload), &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "NIGHT MODE until ") || !strings.Contains(stderr.String(), "session transaction failed") {
		t.Fatalf("transaction failure = stdout %q, stderr %q; want banner and warning", stdout.String(), stderr.String())
	}
}

func TestHookNightBannerTracksExactExpiryPerPlane(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	path, err := night.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	firstUntil := time.Now().Add(time.Hour).Truncate(time.Second).Add(100 * time.Millisecond)
	if err := night.Write(path, night.Marker{Until: firstUntil, SetBy: "test:1"}); err != nil {
		t.Fatal(err)
	}
	const sessionID = "night-exact-announcement"
	opencodePayload := `{"session_id":"` + sessionID + `","event":"pre","tool":"bash","command":"git push origin main","cwd":"/tmp"}`
	antigravityPayload := `{"conversationId":"` + sessionID + `","toolCall":{"name":"run_command","args":{"CommandLine":"git push origin main","Cwd":"/tmp"}}}`
	call := func(args []string, payload string) string {
		var stdout, stderr bytes.Buffer
		if code := run(args, strings.NewReader(payload), &stdout, &stderr); code != 0 {
			t.Fatalf("exit = %d, stderr %q", code, stderr.String())
		}
		return stdout.String()
	}
	if out := call([]string{"hook", "opencode"}, opencodePayload); !strings.Contains(out, "NIGHT MODE until ") {
		t.Fatalf("first OpenCode response omitted banner: %q", out)
	}
	if out := call([]string{"hook", "antigravity", "pre"}, antigravityPayload); !strings.Contains(out, "NIGHT MODE until ") {
		t.Fatalf("same session ID suppressed Antigravity banner: %q", out)
	}
	if err := night.Write(path, night.Marker{Until: firstUntil.Add(time.Nanosecond), SetBy: "test:2"}); err != nil {
		t.Fatal(err)
	}
	if out := call([]string{"hook", "opencode"}, opencodePayload); !strings.Contains(out, "NIGHT MODE until ") {
		t.Fatalf("new subsecond expiry suppressed OpenCode banner: %q", out)
	}
}

func TestHookClaudeSessionStartPrintsNightBannerFirst(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	enableNightForHook(t)
	payload := `{"session_id":"night-session-start","cwd":"/tmp","hook_event_name":"SessionStart"}`
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, stderr.String())
	}
	var response struct {
		HookSpecificOutput struct {
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(response.HookSpecificOutput.AdditionalContext, "NIGHT MODE until ") {
		t.Fatalf("SessionStart posture = %q, want night banner first", response.HookSpecificOutput.AdditionalContext)
	}
}

func TestHookNightControlIsP5DenyAcrossPlanes(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		payload string
	}{
		{name: "claude", args: []string{"hook", "claude"}, payload: `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"guardrail night off"}}`},
		{name: "opencode", args: []string{"hook", "opencode"}, payload: `{"event":"pre","tool":"bash","command":"guardrail night off","cwd":"/tmp"}`},
		{name: "antigravity", args: []string{"hook", "antigravity", "pre"}, payload: `{"toolCall":{"name":"run_command","args":{"CommandLine":"guardrail night off","Cwd":"/tmp"}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateHome := t.TempDir()
			t.Setenv("XDG_STATE_HOME", stateHome)
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("GUARDRAIL_CONFIG", "")
			enableNightForHook(t)
			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(tt.payload), &stdout, &stderr)
			if code != 2 && tt.name != "antigravity" {
				t.Fatalf("exit = %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
			}
			records := readApprovalAudit(t, stateHome)
			if len(records) != 1 || records[0].Decision != "deny" || records[0].RuleID != "P5.self-config" {
				t.Fatalf("audit = %+v, want deny/P5.self-config", records)
			}
		})
	}
}

func TestHookNightControlInInterpreterHeredocIsP5Deny(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	enableNightForHook(t)
	command := "python3 <<'PY'\nimport os\nos.system(\"guardrail night off\")\nPY"
	payload, err := json.Marshal(map[string]any{
		"cwd":             "/tmp",
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]string{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"hook", "claude"}, bytes.NewReader(payload), &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	records := readApprovalAudit(t, stateHome)
	if len(records) != 1 || records[0].Decision != "deny" || records[0].RuleID != "P5.self-config" {
		t.Fatalf("audit = %+v, want deny/P5.self-config", records)
	}
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
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	guardrailDir := filepath.Join(stateHome, "guardrail")
	if err := os.Mkdir(guardrailDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(guardrailDir, "sessions"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	overlayPath := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(overlayPath, []byte(overlayWithWaivers(20)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)

	payload := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	lines := strings.Split(strings.TrimSuffix(errb.String(), "\n"), "\n")
	if len(lines) != 20 {
		t.Fatalf("stderr wrote %d warning lines, want 20: %q", len(lines), errb.String())
	}
	if !strings.Contains(lines[0], "session transaction failed") || strings.ContainsAny(lines[0], "\r\t\x00\x7f") {
		t.Fatalf("session-transaction warning was not first and sanitized: %q", lines[0])
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

func TestTrackingUnavailableAsksForMissingSessionSignal(t *testing.T) {
	tests := []struct {
		name     string
		waivers  []string
		tool     string
		toolJSON string
	}{
		{"network", nil, "Bash", `{"command":"curl https://api.example.com/x"}`},
		{"private data", []string{"P4.secret-path"}, "Read", `{"file_path":"/tmp/.env"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateHome := t.TempDir()
			t.Setenv("XDG_STATE_HOME", stateHome)
			configureTrackingPolicy(t, test.waivers...)
			payload := fmt.Sprintf(`{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":%q,"tool_input":%s}`, test.tool, test.toolJSON)
			var out, errb bytes.Buffer
			if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
				t.Fatalf("signal without session ID: exit %d, want Ask exit 0; stderr=%s", code, errb.String())
			}
			if !strings.Contains(out.String(), `"permissionDecision":"ask"`) || !strings.Contains(out.String(), "session tracking") {
				t.Fatalf("signal without session ID was not a model-visible tracking Ask: %s", out.String())
			}
			auditLog, err := os.ReadFile(filepath.Join(stateHome, "guardrail", "audit.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(auditLog), `"rule_id":"P7.tracking-unavailable"`) {
				t.Fatalf("tracking Ask audit lacks P7 rule ID: %s", auditLog)
			}
		})
	}
}

func TestTrackingUnavailableAsksWhenTransactionFails(t *testing.T) {
	tests := []struct {
		name     string
		waivers  []string
		tool     string
		toolJSON string
	}{
		{"network", nil, "Bash", `{"command":"curl https://api.example.com/x"}`},
		{"private data", []string{"P4.secret-path"}, "Read", `{"file_path":"/tmp/.env"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configureTrackingPolicy(t, test.waivers...)
			blocker := filepath.Join(t.TempDir(), "state-is-a-file")
			if err := os.WriteFile(blocker, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("XDG_STATE_HOME", blocker)
			payload := fmt.Sprintf(`{"session_id":"s1","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":%q,"tool_input":%s}`, test.tool, test.toolJSON)
			var out, errb bytes.Buffer
			if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
				t.Fatalf("signal with failed transaction: exit %d, want Ask exit 0; stderr=%s", code, errb.String())
			}
			if !strings.Contains(out.String(), `"permissionDecision":"ask"`) || !strings.Contains(out.String(), "session tracking") {
				t.Fatalf("failed transaction was not a model-visible tracking Ask: %s", out.String())
			}
		})
	}
}

func TestTrackingUnavailablePreservesUnderlyingVerdicts(t *testing.T) {
	t.Run("Ask", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		configureTrackingPolicy(t)
		payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/cert.pem"}}`
		var out, errb bytes.Buffer
		if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
			t.Fatalf("underlying Ask exit %d; stderr=%s", code, errb.String())
		}
		if !strings.Contains(out.String(), "credential/secret path") || strings.Contains(out.String(), "session tracking") {
			t.Fatalf("underlying Ask changed: %s", out.String())
		}
	})

	t.Run("Deny", func(t *testing.T) {
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		configureTrackingPolicy(t)
		payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/.ssh/id_rsa"}}`
		var out, errb bytes.Buffer
		if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 2 {
			t.Fatalf("underlying Deny exit %d, want 2; stdout=%s stderr=%s", code, out.String(), errb.String())
		}
		if out.Len() != 0 || !strings.Contains(errb.String(), "credential/secret path") {
			t.Fatalf("underlying Deny changed: stdout=%s stderr=%s", out.String(), errb.String())
		}
	})
}

func TestTrackingUnavailableDoesNotInterruptRoutineCall(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	configureTrackingPolicy(t)
	payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 || out.Len() != 0 {
		t.Fatalf("routine call without session ID changed: code=%d stdout=%s stderr=%s", code, out.String(), errb.String())
	}
}

func TestTrackingUnavailableWaiverPreservesAllow(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	configureTrackingPolicy(t, "P7.trifecta")
	payload := `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl https://api.example.com/x"}}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 || out.Len() != 0 {
		t.Fatalf("waived tracking changed underlying Allow: code=%d stdout=%s stderr=%s", code, out.String(), errb.String())
	}
}

func TestTrifectaWaiverSkipsSessionTransaction(t *testing.T) {
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	configureTrackingPolicy(t, "P7.trifecta")
	store := filepath.Join(stateHome, "guardrail", "sessions")
	if err := os.MkdirAll(filepath.Dir(store), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}

	payload := `{"session_id":"waived-session","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl https://api.example.com/x"}}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 || out.Len() != 0 {
		t.Fatalf("waived tracking changed underlying Allow: code=%d stdout=%s stderr=%s", code, out.String(), errb.String())
	}
	if strings.Contains(errb.String(), "session transaction failed") {
		t.Fatalf("waived tracking attempted a session transaction: %s", errb.String())
	}
	if raw, err := os.ReadFile(store); err != nil || string(raw) != "blocked" {
		t.Fatalf("waived tracking changed session store: raw=%q err=%v", raw, err)
	}
}

func TestHookHashesNativeSessionID(t *testing.T) {
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
	if strings.Contains(err1.String(), "unsafe session id") {
		t.Errorf("native session ID was rejected: %q", err1.String())
	}

	curlPayload := `{"session_id":"` + sid + `","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl http://localhost:9999/x"}}`
	var out2, err2 bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(curlPayload), &out2, &err2); code != 0 {
		t.Fatalf("second call: exit %d, want 0; stderr=%s", code, err2.String())
	}
	if !strings.Contains(out2.String(), "trifecta") {
		t.Errorf("hashed native session ID did not carry heuristic state: %s", out2.String())
	}
	if strings.Contains(err2.String(), "unsafe session id") {
		t.Errorf("native session ID was rejected: %q", err2.String())
	}
	if _, err := os.Stat(filepath.Join(state, "guardrail", "unsafe.json")); !os.IsNotExist(err) {
		t.Errorf("raw native session ID wrote outside the sessions dir: %v", err)
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

type openCodeApprovalResult struct {
	Code     int
	Decision string
	Stdout   string
	Stderr   string
}

type approvalAuditRecord struct {
	Decision     string `json:"decision"`
	RuleID       string `json:"rule_id"`
	OriginRuleID string `json:"origin_rule_id"`
}

func TestOpenCodeApprovalHelperProcess(t *testing.T) {
	if os.Getenv("GUARDRAIL_TEST_OPENCODE_APPROVAL_HELPER") != "1" {
		return
	}
	if gate := os.Getenv("GUARDRAIL_TEST_OPENCODE_APPROVAL_GATE"); gate != "" {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(gate); err == nil {
				break
			} else if !os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(3)
			}
			if time.Now().After(deadline) {
				fmt.Fprintln(os.Stderr, "approval test gate timed out")
				os.Exit(3)
			}
			time.Sleep(time.Millisecond)
		}
	}
	code := run(
		[]string{"hook", "opencode"},
		strings.NewReader(os.Getenv("GUARDRAIL_TEST_OPENCODE_APPROVAL_PAYLOAD")),
		os.Stdout,
		os.Stderr,
	)
	os.Exit(code)
}

func openCodeApprovalCommand(payload, gate string, stdout, stderr io.Writer) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestOpenCodeApprovalHelperProcess$")
	cmd.Env = append(os.Environ(),
		"GUARDRAIL_TEST_OPENCODE_APPROVAL_HELPER=1",
		"GUARDRAIL_TEST_OPENCODE_APPROVAL_PAYLOAD="+payload,
		"GUARDRAIL_TEST_OPENCODE_APPROVAL_GATE="+gate,
	)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd
}

func runOpenCodeApprovalProcess(t *testing.T, payload string) openCodeApprovalResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := openCodeApprovalCommand(payload, "", &stdout, &stderr)
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run OpenCode approval helper: %v", err)
		}
		code = exitErr.ExitCode()
	}
	var response struct {
		Decision string `json:"decision"`
	}
	if decodeErr := json.Unmarshal(stdout.Bytes(), &response); decodeErr != nil {
		t.Fatalf("decode OpenCode approval helper output: %v; code=%d stdout=%q stderr=%q", decodeErr, code, stdout.String(), stderr.String())
	}
	return openCodeApprovalResult{Code: code, Decision: response.Decision, Stdout: stdout.String(), Stderr: stderr.String()}
}

func runOpenCodeApprovalHook(t *testing.T, payload string) openCodeApprovalResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run([]string{"hook", "opencode"}, strings.NewReader(payload), &stdout, &stderr)
	var response struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("decode OpenCode hook output: %v; code=%d stdout=%q stderr=%q", err, code, stdout.String(), stderr.String())
	}
	return openCodeApprovalResult{Code: code, Decision: response.Decision, Stdout: stdout.String(), Stderr: stderr.String()}
}

func openCodeApprovalPayload(sessionID, event, tool, command, cwd, arguments string) string {
	return fmt.Sprintf(
		`{"session_id":%q,"event":%q,"tool":%q,"command":%q,"cwd":%q,"arguments":%s}`,
		sessionID, event, tool, command, cwd, arguments,
	)
}

func configureApprovalTest(t *testing.T, overlay string) (string, string) {
	t.Helper()
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	overlayPath := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)
	return stateHome, overlayPath
}

func approvalAskOverlay(extra string) string {
	return extra + `[[rules]]
id = "project.approval-ask"
pattern = "approval-test"
decision = "ask"
reason = "approval test requires confirmation"
`
}

func readApprovalState(t *testing.T, sessionID string) (session.State, []byte) {
	t.Helper()
	raw, err := os.ReadFile(session.Path(sessionID))
	if err != nil {
		t.Fatal(err)
	}
	var state session.State
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	return state, raw
}

func readApprovalAudit(t *testing.T, stateHome string) []approvalAuditRecord {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stateHome, "guardrail", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	records := make([]approvalAuditRecord, len(lines))
	for i, line := range lines {
		if err := json.Unmarshal([]byte(line), &records[i]); err != nil {
			t.Fatalf("decode audit line %d: %v", i+1, err)
		}
	}
	return records
}

func assertApprovalDecision(t *testing.T, got openCodeApprovalResult, decision string) {
	t.Helper()
	if got.Decision != decision {
		t.Fatalf("decision=%q, want %q; code=%d stdout=%q stderr=%q", got.Decision, decision, got.Code, got.Stdout, got.Stderr)
	}
}

func TestOpenCodeApprovalMemoryPersistsOneShotAcrossProcesses(t *testing.T) {
	stateHome, _ := configureApprovalTest(t, "")
	const sessionID = "approval-one-shot"
	payload := openCodeApprovalPayload(sessionID, "pre", "bash", "git checkout .", "/tmp", `{"command":"git checkout ."}`)

	first := runOpenCodeApprovalProcess(t, payload)
	second := runOpenCodeApprovalProcess(t, payload)
	third := runOpenCodeApprovalProcess(t, payload)
	assertApprovalDecision(t, first, "ask")
	assertApprovalDecision(t, second, "allow")
	assertApprovalDecision(t, third, "ask")

	records := readApprovalAudit(t, stateHome)
	if len(records) != 3 {
		t.Fatalf("audit records=%d, want 3", len(records))
	}
	if records[0].RuleID != "P2.git-checkout-restore" || records[1].RuleID != "ask-approved-by-retry" || records[2].RuleID != "P2.git-checkout-restore" {
		t.Fatalf("audit Rule IDs=%q, %q, %q", records[0].RuleID, records[1].RuleID, records[2].RuleID)
	}
	if records[0].OriginRuleID != "" || records[1].OriginRuleID != "P2.git-checkout-restore" || records[2].OriginRuleID != "" {
		t.Fatalf("audit origin Rule IDs=%q, %q, %q", records[0].OriginRuleID, records[1].OriginRuleID, records[2].OriginRuleID)
	}
	auditRaw, err := os.ReadFile(filepath.Join(stateHome, "guardrail", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(auditRaw, []byte(`"arguments"`)) {
		t.Fatalf("audit exposed native arguments: %s", auditRaw)
	}
	state, raw := readApprovalState(t, sessionID)
	if len(state.PendingApprovals) != 1 {
		t.Fatalf("pending approvals=%d, want one fresh entry: %s", len(state.PendingApprovals), raw)
	}
	for digest, pending := range state.PendingApprovals {
		if len(digest) != 64 || pending.OriginRuleID != "P2.git-checkout-restore" || pending.ExpiresAt.IsZero() {
			t.Fatalf("persisted approval entry is not digest/rule/expiry only: %q %+v", digest, pending)
		}
	}
	if strings.Contains(string(raw), sessionID) || strings.Contains(string(raw), "git checkout") {
		t.Fatalf("session state exposed native identity or arguments: %s", raw)
	}
	base := filepath.Base(session.Path(sessionID))
	if digest, err := hex.DecodeString(strings.TrimSuffix(base, ".json")); err != nil || len(digest) != 32 || !strings.HasSuffix(base, ".json") {
		t.Fatalf("session filename %q is not an M-7 v2 digest", base)
	}
}

func TestOpenCodeApprovalMemoryRequiresExactIdentity(t *testing.T) {
	tests := []struct {
		name            string
		changedSession  string
		changedCWD      string
		changedTool     string
		changedArgument string
	}{
		{name: "session", changedSession: "approval-other-session"},
		{name: "CWD bytes", changedCWD: "/tmp/"},
		{name: "normalized tool", changedTool: "read"},
		{name: "arguments", changedArgument: `{"value":"changed"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _ = configureApprovalTest(t, approvalAskOverlay(""))
			const sessionID = "approval-exact-identity"
			original := openCodeApprovalPayload(sessionID, "pre", "bash", "approval-test", "/tmp", `{"value":"original"}`)
			assertApprovalDecision(t, runOpenCodeApprovalHook(t, original), "ask")

			changedSession, changedCWD, changedTool, changedArguments := sessionID, "/tmp", "bash", `{"value":"original"}`
			if test.changedSession != "" {
				changedSession = test.changedSession
			}
			if test.changedCWD != "" {
				changedCWD = test.changedCWD
			}
			if test.changedTool != "" {
				changedTool = test.changedTool
			}
			if test.changedArgument != "" {
				changedArguments = test.changedArgument
			}
			changed := openCodeApprovalPayload(changedSession, "pre", changedTool, "approval-test", changedCWD, changedArguments)
			assertApprovalDecision(t, runOpenCodeApprovalHook(t, changed), "ask")
			assertApprovalDecision(t, runOpenCodeApprovalHook(t, original), "allow")
		})
	}
}

func TestOpenCodeApprovalMemoryCanonicalizesObjectKeyOrder(t *testing.T) {
	_, _ = configureApprovalTest(t, approvalAskOverlay(""))
	first := openCodeApprovalPayload("approval-object-order", "pre", "bash", "approval-test", "/tmp", `{"outer":{"z":2,"a":1},"first":true}`)
	reordered := openCodeApprovalPayload("approval-object-order", "pre", "bash", "approval-test", "/tmp", `{"first":true,"outer":{"a":1,"z":2}}`)
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, first), "ask")
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, reordered), "allow")
}

func TestOpenCodeApprovalMemoryRejectsIncompleteIdentity(t *testing.T) {
	tests := []struct {
		name      string
		sessionID string
		payload   string
	}{
		{name: "session", payload: `{"event":"pre","tool":"bash","command":"approval-test","cwd":"/tmp","arguments":{"value":1}}`},
		{name: "CWD", sessionID: "missing-cwd", payload: `{"session_id":"missing-cwd","event":"pre","tool":"bash","command":"approval-test","arguments":{"value":1}}`},
		{name: "tool", sessionID: "missing-tool", payload: `{"session_id":"missing-tool","event":"pre","command":"approval-test","cwd":"/tmp","arguments":{"value":1}}`},
		{name: "arguments", sessionID: "missing-arguments", payload: `{"session_id":"missing-arguments","event":"pre","tool":"bash","command":"approval-test","cwd":"/tmp"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateHome, _ := configureApprovalTest(t, approvalAskOverlay(""))
			assertApprovalDecision(t, runOpenCodeApprovalHook(t, test.payload), "ask")
			if test.sessionID != "" {
				state, _ := readApprovalState(t, test.sessionID)
				if len(state.PendingApprovals) != 0 {
					t.Fatalf("incomplete identity wrote pending approval: %+v", state.PendingApprovals)
				}
				return
			}
			matches, err := filepath.Glob(filepath.Join(stateHome, "guardrail", "sessions", "v2", "*.json"))
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) != 0 {
				t.Fatalf("missing session identity wrote session files: %v", matches)
			}
		})
	}
}

func TestOpenCodeApprovalMemoryTransactionFailurePreservesAsk(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "state\nforged\twarning\x7f")
	if err := os.WriteFile(stateRoot, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", stateRoot)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	payload := openCodeApprovalPayload("approval-failed-transaction", "pre", "bash", "git checkout .", "/tmp", `{"command":"git checkout ."}`)
	result := runOpenCodeApprovalHook(t, payload)
	assertApprovalDecision(t, result, "ask")
	if !strings.Contains(result.Stderr, "session transaction failed") || strings.ContainsAny(result.Stderr, "\r\t\x00\x7f") {
		t.Fatalf("transaction warning missing or unsanitized: %q", result.Stderr)
	}
}

func injectPostCommitReleaseFailure(t *testing.T, message string) {
	t.Helper()
	realTransaction := sessionTransaction
	sessionTransaction = func(sessionID string, update func(*session.State) error) error {
		if err := realTransaction(sessionID, update); err != nil {
			return err
		}
		return fmt.Errorf("release session transaction lock: %s: %w", message, session.ErrTransactionCommitted)
	}
	t.Cleanup(func() { sessionTransaction = realTransaction })
}

func assertSanitizedCommittedReleaseWarning(t *testing.T, stderr string) {
	t.Helper()
	if !strings.Contains(stderr, "session transaction committed but lock release failed") ||
		!strings.Contains(stderr, "injected release forged claim") {
		t.Fatalf("committed release warning missing context: %q", stderr)
	}
	if strings.ContainsAny(stderr, "\r\t\x00\x7f") || strings.Count(stderr, "\n") != 1 {
		t.Fatalf("committed release warning was not one sanitized line: %q", stderr)
	}
}

func TestOpenCodeApprovalMemoryPostCommitReleaseFailurePreservesFirstAsk(t *testing.T) {
	stateHome, _ := configureApprovalTest(t, approvalAskOverlay(""))
	const sessionID = "approval-committed-first-ask"
	payload := openCodeApprovalPayload(sessionID, "pre", "bash", "approval-test", "/tmp", `{"value":1}`)
	injectPostCommitReleaseFailure(t, "injected release\nforged\tclaim\x7f")

	result := runOpenCodeApprovalHook(t, payload)
	assertApprovalDecision(t, result, "ask")
	assertSanitizedCommittedReleaseWarning(t, result.Stderr)
	state, _ := readApprovalState(t, sessionID)
	if len(state.PendingApprovals) != 1 {
		t.Fatalf("committed first Ask did not preserve pending state: %+v", state.PendingApprovals)
	}
	records := readApprovalAudit(t, stateHome)
	if len(records) != 1 || records[0].Decision != "ask" || records[0].RuleID != "project.approval-ask" || records[0].OriginRuleID != "" {
		t.Fatalf("committed first Ask audit changed: %+v", records)
	}
}

func TestOpenCodeApprovalMemoryPostCommitReleaseFailurePreservesConsumedAllow(t *testing.T) {
	stateHome, _ := configureApprovalTest(t, approvalAskOverlay(""))
	const sessionID = "approval-committed-consume"
	payload := openCodeApprovalPayload(sessionID, "pre", "bash", "approval-test", "/tmp", `{"value":1}`)
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "ask")
	injectPostCommitReleaseFailure(t, "injected release\nforged\tclaim\x7f")

	result := runOpenCodeApprovalHook(t, payload)
	assertApprovalDecision(t, result, "allow")
	assertSanitizedCommittedReleaseWarning(t, result.Stderr)
	state, _ := readApprovalState(t, sessionID)
	if len(state.PendingApprovals) != 0 {
		t.Fatalf("committed retry did not preserve consumed state: %+v", state.PendingApprovals)
	}
	records := readApprovalAudit(t, stateHome)
	if len(records) != 2 || records[1].Decision != "allow" || records[1].RuleID != "ask-approved-by-retry" || records[1].OriginRuleID != "project.approval-ask" {
		t.Fatalf("committed retry lost synthetic attribution: %+v", records)
	}
}

func TestOpenCodeApprovalMemoryPreCommitFailureStillFallsBack(t *testing.T) {
	_, _ = configureApprovalTest(t, approvalAskOverlay(""))
	const sessionID = "approval-pre-commit-control"
	payload := openCodeApprovalPayload(sessionID, "pre", "bash", "approval-test", "/tmp", `{"value":1}`)
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "ask")
	seeded, _ := readApprovalState(t, sessionID)
	if len(seeded.PendingApprovals) != 1 {
		t.Fatalf("seeded pending approvals=%d, want 1", len(seeded.PendingApprovals))
	}

	realTransaction := sessionTransaction
	sessionTransaction = func(string, func(*session.State) error) error {
		return errors.New("injected pre-commit failure")
	}
	t.Cleanup(func() { sessionTransaction = realTransaction })
	result := runOpenCodeApprovalHook(t, payload)
	assertApprovalDecision(t, result, "ask")
	if !strings.Contains(result.Stderr, "session transaction failed") {
		t.Fatalf("pre-commit failure warning missing: %q", result.Stderr)
	}
	remaining, _ := readApprovalState(t, sessionID)
	if len(remaining.PendingApprovals) != 1 {
		t.Fatalf("pre-commit fallback recorded or consumed approval: %+v", remaining.PendingApprovals)
	}
}

func TestOpenCodeApprovalMemoryWorksWithP7Waiver(t *testing.T) {
	repo := t.TempDir()
	gitInitSync(t, repo)
	_, overlayPath := configureApprovalTest(t, approvalAskOverlay(`waive = ["P7.trifecta"]
`))
	configHome := os.Getenv("XDG_CONFIG_HOME")
	operatorDir := filepath.Join(configHome, "guardrail")
	if err := os.MkdirAll(operatorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	operator := fmt.Sprintf("[%q]\nwaive = [\"P7.trifecta\"]\n", repo)
	if err := os.WriteFile(filepath.Join(operatorDir, "waivers.toml"), []byte(operator), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)
	payload := openCodeApprovalPayload("approval-p7-waived", "pre", "bash", "approval-test", repo, `{"value":1}`)
	first := runOpenCodeApprovalHook(t, payload)
	assertApprovalDecision(t, first, "ask")
	if !strings.Contains(first.Stderr, "P7.trifecta is WAIVED") {
		t.Fatalf("test did not activate the P7 waiver: %q", first.Stderr)
	}
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "allow")
}

func TestOpenCodeApprovalMemoryIncludesP7GeneratedAsk(t *testing.T) {
	repo := t.TempDir()
	gitInitSync(t, repo)
	_, overlayPath := configureApprovalTest(t, `waive = ["P4.secret-path"]
[slots]
egress_allowlist = ["api.example.com"]
`)
	configHome := os.Getenv("XDG_CONFIG_HOME")
	operatorDir := filepath.Join(configHome, "guardrail")
	if err := os.MkdirAll(operatorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	operator := fmt.Sprintf("[%q]\nwaive = [\"P4.secret-path\"]\negress_allowlist = [\"api.example.com\"]\n", repo)
	if err := os.WriteFile(filepath.Join(operatorDir, "waivers.toml"), []byte(operator), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)
	const sessionID = "approval-p7-generated"
	private := openCodeApprovalPayload(sessionID, "pre", "read", "", repo, fmt.Sprintf(`{"filePath":%q}`, filepath.Join(repo, ".env")))
	private = strings.Replace(private, `"command":""`, fmt.Sprintf(`"command":"","paths":[%q]`, filepath.Join(repo, ".env")), 1)
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, private), "allow")
	network := openCodeApprovalPayload(sessionID, "pre", "bash", "curl https://api.example.com/x", repo, `{"command":"curl https://api.example.com/x"}`)
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, network), "ask")
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, network), "allow")
}

func TestApprovalMemoryDoesNotCrossPlaneOrPostBoundary(t *testing.T) {
	t.Run("Claude", func(t *testing.T) {
		_, _ = configureApprovalTest(t, "")
		payload := `{"session_id":"approval-claude","cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git checkout ."}}`
		for i := 0; i < 2; i++ {
			var stdout, stderr bytes.Buffer
			if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"permissionDecision":"ask"`) {
				t.Fatalf("Claude call %d did not remain Ask: code=%d stdout=%q stderr=%q", i+1, code, stdout.String(), stderr.String())
			}
		}
		state, _ := readApprovalState(t, "approval-claude")
		if len(state.PendingApprovals) != 0 {
			t.Fatalf("Claude wrote approval memory: %+v", state.PendingApprovals)
		}
	})

	t.Run("OpenCode post", func(t *testing.T) {
		stateHome, _ := configureApprovalTest(t, "")
		payload := openCodeApprovalPayload("approval-post", "post", "bash", "git checkout .", "/tmp", `{"command":"git checkout ."}`)
		assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "ask")
		assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "ask")
		matches, err := filepath.Glob(filepath.Join(stateHome, "guardrail", "sessions", "v2", "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("OpenCode post wrote session approval state: %v", matches)
		}
	})
}

func TestOpenCodeApprovalMemoryCurrentDenyConsumesPending(t *testing.T) {
	stateHome, overlayPath := configureApprovalTest(t, "")
	const sessionID = "approval-current-deny"
	payload := openCodeApprovalPayload(sessionID, "pre", "bash", "git checkout .", "/tmp", `{"command":"git checkout ."}`)
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "ask")
	denyOverlay := `[[rules]]
id = "project.tightened-deny"
tool = "Bash"
pattern = "git checkout ."
decision = "deny"
reason = "policy was tightened"
`
	if err := os.WriteFile(overlayPath, []byte(denyOverlay), 0o600); err != nil {
		t.Fatal(err)
	}
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "deny")
	if err := os.WriteFile(overlayPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "ask")
	state, _ := readApprovalState(t, sessionID)
	if len(state.PendingApprovals) != 1 {
		t.Fatalf("Deny did not consume stale approval before later Ask: %+v", state.PendingApprovals)
	}
	records := readApprovalAudit(t, stateHome)
	if len(records) != 3 || records[1].Decision != "deny" || records[1].RuleID != "project.tightened-deny" || records[1].OriginRuleID != "" {
		t.Fatalf("current Deny audit was downgraded or attributed as approval: %+v", records)
	}
}

func TestOpenCodeApprovalMemoryCurrentAllowConsumesPending(t *testing.T) {
	stateHome, overlayPath := configureApprovalTest(t, approvalAskOverlay(""))
	const sessionID = "approval-current-allow"
	payload := openCodeApprovalPayload(sessionID, "pre", "bash", "approval-test", "/tmp", `{"value":1}`)
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "ask")
	seeded, _ := readApprovalState(t, sessionID)
	if len(seeded.PendingApprovals) != 1 {
		t.Fatalf("seeded pending approvals=%d, want 1", len(seeded.PendingApprovals))
	}
	if err := os.WriteFile(overlayPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "allow")
	consumed, _ := readApprovalState(t, sessionID)
	if len(consumed.PendingApprovals) != 0 {
		t.Fatalf("current Allow did not consume pending approval: %+v", consumed.PendingApprovals)
	}
	if err := os.WriteFile(overlayPath, []byte(approvalAskOverlay("")), 0o600); err != nil {
		t.Fatal(err)
	}
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "ask")
	records := readApprovalAudit(t, stateHome)
	if len(records) != 3 || records[1].Decision != "allow" || records[1].RuleID != "" || records[1].OriginRuleID != "" {
		t.Fatalf("current Allow audit changed during consume: %+v", records)
	}
}

func TestOpenCodeApprovalMemoryConcurrentRetriesHaveOneConsumer(t *testing.T) {
	_, _ = configureApprovalTest(t, approvalAskOverlay(""))
	const sessionID = "approval-concurrent"
	payload := openCodeApprovalPayload(sessionID, "pre", "bash", "approval-test", "/tmp", `{"value":1}`)
	assertApprovalDecision(t, runOpenCodeApprovalHook(t, payload), "ask")
	seeded, _ := readApprovalState(t, sessionID)
	if len(seeded.PendingApprovals) != 1 {
		t.Fatalf("seeded pending approvals=%d, want 1", len(seeded.PendingApprovals))
	}
	var seededDigest string
	var seededExpiry time.Time
	for digest := range seeded.PendingApprovals {
		seededDigest = digest
		seededExpiry = seeded.PendingApprovals[digest].ExpiresAt
	}

	gate := filepath.Join(t.TempDir(), "start")
	var stdout1, stderr1, stdout2, stderr2 bytes.Buffer
	cmd1 := openCodeApprovalCommand(payload, gate, &stdout1, &stderr1)
	cmd2 := openCodeApprovalCommand(payload, gate, &stdout2, &stderr2)
	if err := cmd1.Start(); err != nil {
		t.Fatal(err)
	}
	if err := cmd2.Start(); err != nil {
		_ = cmd1.Process.Kill()
		_ = cmd1.Wait()
		t.Fatal(err)
	}
	if err := os.WriteFile(gate, []byte("start"), 0o600); err != nil {
		t.Fatal(err)
	}
	err1 := cmd1.Wait()
	err2 := cmd2.Wait()
	if err1 != nil || err2 != nil {
		t.Fatalf("concurrent retries failed: err1=%v stdout1=%q stderr1=%q err2=%v stdout2=%q stderr2=%q", err1, stdout1.String(), stderr1.String(), err2, stdout2.String(), stderr2.String())
	}
	decisions := map[string]int{}
	for i, raw := range [][]byte{stdout1.Bytes(), stdout2.Bytes()} {
		var response struct {
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal(raw, &response); err != nil {
			t.Fatalf("decode concurrent response %d: %v; output=%q", i+1, err, raw)
		}
		decisions[response.Decision]++
	}
	if decisions["allow"] != 1 || decisions["ask"] != 1 {
		t.Fatalf("concurrent decisions=%v, want one synthetic Allow and one Ask", decisions)
	}
	final, _ := readApprovalState(t, sessionID)
	if len(final.PendingApprovals) != 1 {
		t.Fatalf("final pending approvals=%d, want one fresh entry: %+v", len(final.PendingApprovals), final.PendingApprovals)
	}
	if _, ok := final.PendingApprovals[seededDigest]; !ok {
		t.Fatalf("fresh pending entry digest changed: seeded=%q final=%+v", seededDigest, final.PendingApprovals)
	}
	if !final.PendingApprovals[seededDigest].ExpiresAt.After(seededExpiry) {
		t.Fatalf("concurrent Ask did not replace the consumed approval with a fresh expiry: seeded=%s final=%s", seededExpiry, final.PendingApprovals[seededDigest].ExpiresAt)
	}
	records := readApprovalAudit(t, os.Getenv("XDG_STATE_HOME"))
	var syntheticAllows, originalAsks int
	for _, record := range records {
		if record.Decision == "allow" && record.RuleID == "ask-approved-by-retry" {
			syntheticAllows++
		}
		if record.Decision == "ask" && record.RuleID == "project.approval-ask" {
			originalAsks++
		}
	}
	if len(records) != 3 || syntheticAllows != 1 || originalAsks != 2 {
		t.Fatalf("concurrent audit records=%+v, want seed Ask plus one synthetic Allow and one fresh Ask", records)
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

func TestHookAntigravityFailuresUsePhaseContract(t *testing.T) {
	failures := []string{"malformed_payload", "malformed_overlay", "oversized_overlay", "merge_error"}
	for _, failure := range failures {
		for _, phase := range []string{"pre", "post"} {
			t.Run(failure+"/"+phase, func(t *testing.T) {
				var out, errb bytes.Buffer
				code := run([]string{"hook", "antigravity", phase}, hookFailureInput(t, "antigravity", failure), &out, &errb)
				if code != 0 || errb.Len() != 0 {
					t.Fatalf("code=%d, stderr=%q; want exit 0 and no stderr", code, errb.String())
				}
				if phase == "post" {
					if out.String() != "{}\n" {
						t.Fatalf("post failure stdout = %q, want exactly %q", out.String(), "{}\n")
					}
					return
				}

				var got map[string]string
				if err := json.Unmarshal(out.Bytes(), &got); err != nil {
					t.Fatalf("pre failure stdout is not JSON: %v; stdout=%q", err, out.String())
				}
				if got["decision"] != "deny" {
					t.Fatalf("decision = %q, want deny", got["decision"])
				}
				if reason := got["reason"]; reason == "" || strings.ContainsAny(reason, "\n\r\t\x00\x7f") {
					t.Fatalf("reason must be nonempty and sanitized: %q", reason)
				}
			})
		}
	}
}

func TestHookCommandPlaneFailuresRetainExitTwo(t *testing.T) {
	failures := []string{"malformed_payload", "malformed_overlay", "oversized_overlay", "merge_error"}
	for _, plane := range []string{"claude", "opencode"} {
		for _, failure := range failures {
			t.Run(plane+"/"+failure, func(t *testing.T) {
				var out, errb bytes.Buffer
				code := run([]string{"hook", plane}, hookFailureInput(t, plane, failure), &out, &errb)
				if code != 2 || out.Len() != 0 {
					t.Fatalf("code=%d, stdout=%q; want exit 2 and no stdout", code, out.String())
				}
				if warning := errb.String(); warning == "" || strings.ContainsAny(warning, "\r\t\x00\x7f") || strings.Count(warning, "\n") != 1 {
					t.Fatalf("stderr must contain one sanitized warning: %q", warning)
				}
			})
		}
	}
}

func TestHookAntigravityFailureReasonIsSanitized(t *testing.T) {
	parseErr := errors.New("bad\nforged\t" + strings.Repeat("界", 300) + "\x7f")
	var out, errb bytes.Buffer
	code := run([]string{"hook", "antigravity", "pre"}, failingReader{err: parseErr}, &out, &errb)
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

func TestHookSessionStartSurfacesSanitizedUnauthorizedWaiverWarning(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg := filepath.Join(t.TempDir(), "guardrail.toml")
	if err := os.WriteFile(cfg, []byte(`waive = ["P6.egress\nforged\twarning\u007fclaim"]`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", cfg)

	payload := `{"session_id":"s1","cwd":"/tmp","hook_event_name":"SessionStart"}`
	var out, errb bytes.Buffer
	if code := run([]string{"hook", "claude"}, strings.NewReader(payload), &out, &errb); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	var got struct {
		HookSpecificOutput struct {
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	const warning = "guardrail: repo requested waiver of P6.egress forged warning claim, which is NOT authorized"
	if strings.Count(got.HookSpecificOutput.AdditionalContext, warning) != 1 {
		t.Fatalf("SessionStart must contain one sanitized unauthorized-waiver warning: %q", got.HookSpecificOutput.AdditionalContext)
	}
	if strings.ContainsAny(got.HookSpecificOutput.AdditionalContext, "\r\t\x00\x7f") {
		t.Fatalf("SessionStart posture retained injected controls: %q", got.HookSpecificOutput.AdditionalContext)
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
