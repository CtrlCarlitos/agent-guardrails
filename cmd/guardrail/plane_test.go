package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

// runPlaneTerminal invokes cmdPlane with the operator-terminal signal forced on.
func runPlaneTerminal(args []string, stdout, stderr io.Writer) int {
	return cmdPlane(args[1:], true, stdout, stderr)
}

func writePlaneSettings(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readPlaneJSON(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestPlaneConfigPathUsesGlobalPlaneLocations(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", cfg)

	cases := map[string]string{
		"claude":      filepath.Join(home, ".claude", "settings.json"),
		"opencode":    filepath.Join(cfg, "opencode", "opencode.json"),
		"antigravity": filepath.Join(home, ".gemini", "config", "hooks.json"),
	}
	for plane, want := range cases {
		got, err := planeConfigPath(plane)
		if err != nil {
			t.Fatalf("planeConfigPath(%s): %v", plane, err)
		}
		if got != want {
			t.Errorf("planeConfigPath(%s) = %q, want %q", plane, got, want)
		}
	}
}

func TestPlaneConfigHomeFallbackWithoutXDGConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	got, err := planeConfigPath("opencode")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".config", "opencode", "opencode.json")
	if got != want {
		t.Fatalf("planeConfigPath(opencode) = %q, want %q", got, want)
	}
}

func TestExecutePlaneApprovalDisablesClaude(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	settings := filepath.Join(home, ".claude", "settings.json")
	writePlaneSettings(t, settings, `{"hooks":{"PreToolUse":[{"matcher":"Task","hooks":[{"type":"command","command":"my-own-hook"}]},{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[{"type":"command","command":"guardrail hook claude"}]}]}}`)

	r := approval.Request{ID: "plane-disable-1", Plane: "operator", SessionID: "terminal", RepoRoot: home, Scope: approval.GlobalScope, Action: "plane-disable", Parameters: map[string]string{"planes": "claude"}}
	if err := executePlaneApproval(r); err != nil {
		t.Fatal(err)
	}

	got := readPlaneJSON(t, settings)
	if strings.Contains(got, "guardrail-claude-pre") {
		t.Fatalf("owned hook remains after disable: %s", got)
	}
	if !strings.Contains(got, "my-own-hook") {
		t.Fatalf("user hook removed by disable: %s", got)
	}

	// A replayed approved request is idempotent, not an error.
	if err := executePlaneApproval(r); err != nil {
		t.Fatalf("replay: %v", err)
	}
}

func TestExecutePlaneApprovalDisablesOpenCodeAndAntigravity(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	opencode := filepath.Join(cfg, "opencode", "opencode.json")
	antigravity := filepath.Join(home, ".gemini", "config", "hooks.json")
	writePlaneSettings(t, opencode, `{"permission":{"bash":{"*":"allow"}},"plugin":["/x/guardrail.js"],"model":"keep"}`)
	writePlaneSettings(t, antigravity, `{"guardrail":{"enabled":true},"user":{"hook":"keep"}}`)

	base := approval.Request{Plane: "operator", SessionID: "terminal", RepoRoot: home, Scope: approval.GlobalScope, Action: "plane-disable"}
	for i, plane := range []string{"opencode", "antigravity"} {
		r := base
		r.ID = "plane-disable-multi-" + plane
		r.Parameters = map[string]string{"planes": plane}
		if err := executePlaneApproval(r); err != nil {
			t.Fatalf("plane %s: %v", plane, err)
		}
		_ = i
	}

	if got := readPlaneJSON(t, opencode); strings.Contains(got, "permission") || strings.Contains(got, "guardrail.js") || !strings.Contains(got, "keep") {
		t.Fatalf("opencode disable wrong: %s", got)
	}
	if got := readPlaneJSON(t, antigravity); strings.Contains(got, "guardrail") || !strings.Contains(got, "keep") {
		t.Fatalf("antigravity disable wrong: %s", got)
	}
}

func TestExecutePlaneApprovalRejectsInvalidRequests(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cases := []approval.Request{
		{Action: "plane-enable", Parameters: map[string]string{"planes": "codex"}},
		{Action: "plane-disable", Parameters: map[string]string{"planes": "codex"}},
		{Action: "plane-disable", Parameters: map[string]string{"planes": ""}},
		{Action: "night-on", Parameters: map[string]string{"planes": "claude"}},
		{Action: "web-host-grant", Parameters: map[string]string{"planes": "claude"}},
	}
	for _, r := range cases {
		if err := executePlaneApproval(r); err == nil {
			t.Errorf("request %+v accepted", r)
		}
	}
}

func TestPlaneCommandArgumentValidation(t *testing.T) {
	restore := stubPlaneTransport([]string{"approved"})
	defer restore()

	var out, errb strings.Builder
	if code := run([]string{"plane"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("no subcommand exit = %d", code)
	}
	if code := run([]string{"plane", "disable"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("missing plane exit = %d", code)
	}
	if code := run([]string{"plane", "disable", "codex"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), "unsupported") {
		t.Fatalf("codex exit = %d, stderr %q", code, errb.String())
	}
	if code := run([]string{"plane", "disable", "emacs"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("unknown plane exit = %d", code)
	}
	if code := run([]string{"plane", "disable", "claude", "opencode"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("multiple planes exit = %d", code)
	}
	if code := run([]string{"plane", "enable", "codex"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), "unsupported") {
		t.Fatalf("enable codex exit = %d, stderr %q", code, errb.String())
	}
	if code := run([]string{"plane", "enable", "claude"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), "interactive") {
		t.Fatalf("enable non-terminal exit = %d, stderr %q", code, errb.String())
	}
	if code := run([]string{"plane", "warp"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("unknown subcommand exit = %d", code)
	}
}

func TestPlaneDisableRequiresInteractiveTerminal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	restore := stubPlaneTransport([]string{"approved"})
	defer restore()

	var out, errb strings.Builder
	// run() derives terminal from *os.File stdin; a strings.Reader is not one.
	if code := run([]string{"plane", "disable", "claude"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), "interactive") {
		t.Fatalf("non-terminal exit = %d, stderr %q", code, errb.String())
	}
}

func TestPlaneDisableClaudeHappyPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[]}]}}`)
	restore := stubPlaneTransport([]string{"pending", "approved"})
	defer restore()
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal([]string{"plane", "disable", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "claude disabled") || !strings.Contains(out.String(), "http://localhost:39169/approve") {
		t.Fatalf("stdout missing outcome/URL: %q", out.String())
	}
}

func TestPlaneDisableAllSkipsMissingAndReportsCodexUnsupported(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[]}]}}`)
	writePlaneSettings(t, filepath.Join(home, ".gemini", "config", "hooks.json"), `{"guardrail":{"enabled":true}}`)
	restore := stubPlaneTransport([]string{"approved"})
	defer restore()
	origInstalled := planeInstalled
	installed := map[string]bool{"claude": true, "opencode": false, "antigravity": true}
	planeInstalled = func(plane string) bool { return installed[plane] }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal([]string{"plane", "disable", "--all"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "claude disabled") || !strings.Contains(got, "antigravity disabled") {
		t.Fatalf("stdout missing enabled-plane outcomes: %q", got)
	}
	if !strings.Contains(got, "opencode: not detected") {
		t.Fatalf("stdout missing undetected report: %q", got)
	}
	if !strings.Contains(got, "codex: unsupported") {
		t.Fatalf("stdout missing codex report: %q", got)
	}
}

func TestPlaneDisableDeniedApprovalFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[]}]}}`)
	restore := stubPlaneTransport([]string{"denied"})
	defer restore()
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal([]string{"plane", "disable", "claude"}, &out, &errb); code != 1 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
}

// stubPlaneTransport replaces daemon submission and status polling so command
// tests never touch a real approval daemon. Like the real daemon, an approved
// status executes the registered plane action handler locally.
func stubPlaneTransport(statuses []string) func() {
	origSubmit := submitPlaneRequest
	origQuery := queryPlaneStatus
	var current approval.Request
	submitPlaneRequest = func(request approval.Request) (approval.Request, error) {
		current = request
		return approval.Request{ID: "stub-request", Status: "pending", ApprovalURL: "http://localhost:39169/approve", ExpiresAt: request.ExpiresAt}, nil
	}
	queryPlaneStatus = func(socket, id string) (approval.Request, error) {
		if len(statuses) == 0 {
			return approval.Request{Status: "expired"}, nil
		}
		status := statuses[0]
		statuses = statuses[1:]
		if status == "approved" {
			if err := executePlaneApproval(current); err != nil {
				return approval.Request{Status: "denied"}, nil
			}
		}
		return approval.Request{Status: status}, nil
	}
	return func() {
		submitPlaneRequest = origSubmit
		queryPlaneStatus = origQuery
	}
}

func TestExecutePlaneApprovalEnablesClaude(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	settings := filepath.Join(home, ".claude", "settings.json")
	writePlaneSettings(t, settings, `{"hooks":{"PreToolUse":[{"matcher":"Task","hooks":[{"type":"command","command":"my-own-hook"}]}]}}`)

	r := approval.Request{ID: "plane-enable-1", Plane: "operator", SessionID: "terminal", RepoRoot: home, Scope: approval.GlobalScope, Action: "plane-enable", Parameters: map[string]string{"planes": "claude"}}
	if err := executePlaneApproval(r); err != nil {
		t.Fatal(err)
	}

	got := readPlaneJSON(t, settings)
	if !strings.Contains(got, "guardrail-claude-pre") {
		t.Fatalf("owned hook missing after enable: %s", got)
	}
	if !strings.Contains(got, "my-own-hook") {
		t.Fatalf("user hook removed by enable: %s", got)
	}
	if err := executePlaneApproval(r); err != nil {
		t.Fatalf("replay: %v", err)
	}
}

func TestExecutePlaneApprovalEnablesOpenCode(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	settings := filepath.Join(cfg, "opencode", "opencode.json")
	writePlaneSettings(t, settings, `{"model":"keep"}`)

	r := approval.Request{ID: "plane-enable-oc", Plane: "operator", SessionID: "terminal", RepoRoot: home, Scope: approval.GlobalScope, Action: "plane-enable", Parameters: map[string]string{"planes": "opencode"}}
	if err := executePlaneApproval(r); err != nil {
		t.Fatal(err)
	}

	got := readPlaneJSON(t, settings)
	if !strings.Contains(got, "permission") || !strings.Contains(got, "guardrail.js") || !strings.Contains(got, "keep") {
		t.Fatalf("opencode enable wrong: %s", got)
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		dataHome = filepath.Join(home, ".local", "share")
	}
	if raw, err := os.ReadFile(filepath.Join(dataHome, "guardrail", "guardrail.js")); err != nil || len(raw) == 0 {
		t.Fatalf("plugin file missing under XDG data home: %v", err)
	}
}

func TestExecutePlaneApprovalEnablesAntigravity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	hooks := filepath.Join(home, ".gemini", "config", "hooks.json")
	writePlaneSettings(t, hooks, `{"user":{"hook":"keep"}}`)

	r := approval.Request{ID: "plane-enable-agy", Plane: "operator", SessionID: "terminal", RepoRoot: home, Scope: approval.GlobalScope, Action: "plane-enable", Parameters: map[string]string{"planes": "antigravity"}}
	if err := executePlaneApproval(r); err != nil {
		t.Fatal(err)
	}

	got := readPlaneJSON(t, hooks)
	if !strings.Contains(got, "guardrail") || !strings.Contains(got, "guardrail-antigravity-pre") || !strings.Contains(got, "keep") {
		t.Fatalf("antigravity enable wrong: %s", got)
	}
}

func TestExecutePlaneApprovalRejectsEnableForUnknownPlane(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	r := approval.Request{Action: "plane-enable", Parameters: map[string]string{"planes": "codex"}}
	if err := executePlaneApproval(r); err == nil {
		t.Fatal("codex enable accepted")
	}
}

func TestPlaneEnableClaudeHappyPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	restore := stubPlaneTransport([]string{"approved"})
	defer restore()
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal([]string{"plane", "enable", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "claude enabled") {
		t.Fatalf("stdout missing outcome: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Fatalf("settings not written: %v", err)
	}
}

func TestPlaneEnableAllSkipsMissingAndReportsCodexUnsupported(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	restore := stubPlaneTransport([]string{"approved", "approved", "approved"})
	defer restore()
	origInstalled := planeInstalled
	installed := map[string]bool{"claude": true, "opencode": false, "antigravity": true}
	planeInstalled = func(plane string) bool { return installed[plane] }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal([]string{"plane", "enable", "--all"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "claude enabled") || !strings.Contains(got, "antigravity enabled") {
		t.Fatalf("stdout missing enabled outcomes: %q", got)
	}
	if !strings.Contains(got, "opencode: not detected") || !strings.Contains(got, "codex: unsupported") {
		t.Fatalf("stdout missing reports: %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Fatalf("claude settings not written: %q %v", out.String(), err)
	}
}

func TestPlaneStatusReportsLifecycleStateWithoutTerminal(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[]}]}}`)
	writePlaneSettings(t, filepath.Join(cfg, "opencode", "opencode.json"), `{"model":"keep"}`)

	var out, errb strings.Builder
	if code := run([]string{"plane", "status"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "claude: guardrail hook registered") {
		t.Fatalf("claude state missing: %q", got)
	}
	if !strings.Contains(got, "opencode: present, integration NOT registered") {
		t.Fatalf("opencode state missing: %q", got)
	}
	if !strings.Contains(got, "antigravity: no hooks.json") {
		t.Fatalf("antigravity state missing: %q", got)
	}
	if !strings.Contains(got, "codex: unsupported") {
		t.Fatalf("codex line missing: %q", got)
	}
}

func TestExecutePlaneApprovalAppliesBatch(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[]}]}}`)
	writePlaneSettings(t, filepath.Join(home, ".gemini", "config", "hooks.json"), `{"guardrail":{"enabled":true}}`)

	r := approval.Request{ID: "plane-batch-1", Plane: "operator", SessionID: "terminal", RepoRoot: home, Scope: approval.GlobalScope, Action: "plane-disable", Parameters: map[string]string{"planes": "claude,antigravity"}}
	if err := executePlaneApproval(r); err != nil {
		t.Fatal(err)
	}
	if got := readPlaneJSON(t, filepath.Join(home, ".claude", "settings.json")); strings.Contains(got, "guardrail-claude-pre") {
		t.Fatalf("claude not disabled: %s", got)
	}
	if got := readPlaneJSON(t, filepath.Join(home, ".gemini", "config", "hooks.json")); strings.Contains(got, "guardrail") {
		t.Fatalf("antigravity not disabled: %s", got)
	}
}

func TestPlaneEnableAllBatchesOneApprovalAndSkipsSatisfied(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	// claude already enabled; antigravity needs enabling; opencode not detected.
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[]}]}}`)
	origInstalled := planeInstalled
	planeInstalled = func(plane string) bool { return plane != "opencode" }
	defer func() { planeInstalled = origInstalled }()

	var submitted []approval.Request
	origSubmit, origQuery := submitPlaneRequest, queryPlaneStatus
	submitPlaneRequest = func(request approval.Request) (approval.Request, error) {
		submitted = append(submitted, request)
		return approval.Request{ID: "stub-request", Status: "pending", ApprovalURL: "http://localhost:39169/approve"}, nil
	}
	queryPlaneStatus = func(socket, id string) (approval.Request, error) {
		return approval.Request{Status: "approved"}, nil
	}
	defer func() { submitPlaneRequest, queryPlaneStatus = origSubmit, origQuery }()

	var out, errb strings.Builder
	if code := runPlaneTerminal([]string{"plane", "enable", "--all"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if len(submitted) != 1 {
		t.Fatalf("submitted %d requests, want 1 batched: %+v", len(submitted), submitted)
	}
	if got := submitted[0].Parameters["planes"]; got != "antigravity" {
		t.Fatalf("batch planes = %q, want only antigravity", got)
	}
	got := out.String()
	if !strings.Contains(got, "claude: already enabled") || !strings.Contains(got, "opencode: not detected") {
		t.Fatalf("stdout missing skip reports: %q", got)
	}
}

func TestPlaneEnableAllSteadyStatePromptsNobody(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[]}]}}`)
	writePlaneSettings(t, filepath.Join(cfg, "opencode", "opencode.json"), `{"plugin":["/x/guardrail.js"]}`)
	writePlaneSettings(t, filepath.Join(home, ".gemini", "config", "hooks.json"), `{"guardrail":{"enabled":true}}`)
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	origSubmit := submitPlaneRequest
	submitPlaneRequest = func(request approval.Request) (approval.Request, error) {
		t.Fatalf("steady-state enable must not submit: %+v", request)
		return approval.Request{}, nil
	}
	defer func() { submitPlaneRequest = origSubmit }()

	var out, errb strings.Builder
	if code := runPlaneTerminal([]string{"plane", "enable", "--all"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	for _, want := range []string{"claude: already enabled", "opencode: already enabled", "antigravity: already enabled"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stdout missing %q: %q", want, out.String())
		}
	}
}

func TestPlaneEnableObservesCompletedStatus(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"stale","matcher":"Task","hooks":[]}]}}`)
	restore := stubPlaneTransport([]string{"executing", "completed"})
	defer restore()
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal([]string{"plane", "enable", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "claude enabled") {
		t.Fatalf("stdout missing outcome: %q", out.String())
	}
}
