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
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// guardTestHome fails the test unless HOME is sandboxed under the system temp
// root, so lifecycle tests can never mutate the operator's real settings.
func guardTestHome(t *testing.T) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(home, os.TempDir()) {
		t.Fatalf("test would mutate real HOME %q; sandbox it with testenv.SetHome", home)
	}
}

// runPlaneTerminal invokes cmdPlane with the operator-terminal signal forced on.
func runPlaneTerminal(t *testing.T, args []string, stdout, stderr io.Writer) int {
	t.Helper()
	guardTestHome(t)
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
	testenv.SetHome(t, home)
	testenv.SetConfig(t, cfg)

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
	testenv.SetHome(t, home)
	testenv.SetConfig(t, "")

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
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	testenv.SetState(t, t.TempDir())
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
	testenv.SetHome(t, home)
	testenv.SetConfig(t, cfg)
	testenv.SetState(t, t.TempDir())
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
	testenv.SetState(t, t.TempDir())
	cases := []approval.Request{
		{Action: "plane-enable", Parameters: map[string]string{"planes": "unsupported-plane"}},
		{Action: "plane-disable", Parameters: map[string]string{"planes": "unsupported-plane"}},
		{Action: "plane-disable", Parameters: map[string]string{"planes": ""}},
		{Action: "plane-enable", Parameters: map[string]string{"planes": "claude", "reconcile_ownership": "codex"}},
		{Action: "plane-disable", Parameters: map[string]string{"planes": "claude", "reconcile_ownership": "claude"}},
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
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	restore := stubPlaneTransport(t, []string{"approved"})
	defer restore()

	var out, errb strings.Builder
	if code := run([]string{"plane"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("no subcommand exit = %d", code)
	}
	if code := run([]string{"plane", "disable"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("missing plane exit = %d", code)
	}
	if code := run([]string{"plane", "disable", "codex"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), "interactive") {
		t.Fatalf("codex exit = %d, stderr %q", code, errb.String())
	}
	if code := run([]string{"plane", "disable", "emacs"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("unknown plane exit = %d", code)
	}
	if code := run([]string{"plane", "disable", "claude", "opencode"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("multiple planes exit = %d", code)
	}
	if code := run([]string{"plane", "enable", "codex"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), "interactive") {
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
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	restore := stubPlaneTransport(t, []string{"approved"})
	defer restore()

	var out, errb strings.Builder
	// run() derives terminal from *os.File stdin; a strings.Reader is not one.
	if code := run([]string{"plane", "disable", "claude"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), "interactive") {
		t.Fatalf("non-terminal exit = %d, stderr %q", code, errb.String())
	}
}

func TestPlaneDisableClaudeHappyPath(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[]}]}}`)
	restore := stubPlaneTransport(t, []string{"pending", "approved"})
	defer restore()
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "disable", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "claude disabled") || !strings.Contains(out.String(), "http://localhost:39169/approve") {
		t.Fatalf("stdout missing outcome/URL: %q", out.String())
	}
}

func TestPlaneDisableAllSkipsMissingAndReportsUndetectedPlanes(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[]}]}}`)
	writePlaneSettings(t, filepath.Join(home, ".gemini", "config", "hooks.json"), `{"guardrail":{"enabled":true}}`)
	restore := stubPlaneTransport(t, []string{"approved"})
	defer restore()
	origInstalled := planeInstalled
	installed := map[string]bool{"claude": true, "opencode": false, "antigravity": true}
	planeInstalled = func(plane string) bool { return installed[plane] }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "disable", "--all"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "claude disabled") || !strings.Contains(got, "antigravity disabled") {
		t.Fatalf("stdout missing enabled-plane outcomes: %q", got)
	}
	if !strings.Contains(got, "opencode: not detected") {
		t.Fatalf("stdout missing undetected report: %q", got)
	}
	if !strings.Contains(got, "codex: not detected") {
		t.Fatalf("stdout missing codex report: %q", got)
	}
}

func TestPlaneDisableDeniedApprovalFails(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[]}]}}`)
	restore := stubPlaneTransport(t, []string{"denied"})
	defer restore()
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "disable", "claude"}, &out, &errb); code != 1 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
}

// stubPlaneTransport replaces daemon submission and status polling so command
// tests never touch a real approval daemon. Like the real daemon, an approved
// status executes the registered plane action handler locally.
func stubPlaneTransport(t *testing.T, statuses []string) func() {
	t.Helper()
	guardTestHome(t)
	origSubmit := submitPlaneRequest
	origQuery := queryPlaneStatus
	origShutdown := setupShutdownDaemon
	setupShutdownDaemon = func(string) error { return nil }
	// The stubbed daemon stands in for an enrolled operator; the preflight
	// must see one too, or the command stops before the transport (#326).
	stubOperatorEnrolled(t, true)
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
		setupShutdownDaemon = origShutdown
	}
}

func TestExecutePlaneApprovalEnablesClaude(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	testenv.SetState(t, t.TempDir())
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
	testenv.SetHome(t, home)
	testenv.SetConfig(t, cfg)
	testenv.SetState(t, t.TempDir())
	settings := filepath.Join(cfg, "opencode", "opencode.json")
	writePlaneSettings(t, settings, `{"model":"keep"}`)

	r := approval.Request{ID: "plane-enable-oc", Plane: "operator", SessionID: "terminal", RepoRoot: home, Scope: approval.GlobalScope, Action: "plane-enable", Parameters: map[string]string{"planes": "opencode"}}
	if err := executePlaneApproval(r); err != nil {
		t.Fatal(err)
	}

	got := readPlaneJSON(t, settings)
	if strings.Contains(got, "permission") || !strings.Contains(got, "guardrail.js") || !strings.Contains(got, "keep") {
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
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	testenv.SetState(t, t.TempDir())
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
	testenv.SetState(t, t.TempDir())
	r := approval.Request{Action: "plane-enable", Parameters: map[string]string{"planes": "unsupported-plane"}}
	if err := executePlaneApproval(r); err == nil {
		t.Fatal("codex enable accepted")
	}
}

func TestPlaneEnableClaudeHappyPath(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	restore := stubPlaneTransport(t, []string{"approved"})
	defer restore()
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "enable", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "claude enabled") {
		t.Fatalf("stdout missing outcome: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Fatalf("settings not written: %v", err)
	}
}

func TestPlaneEnableAllSkipsMissingAndReportsUndetectedPlanes(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	restore := stubPlaneTransport(t, []string{"approved", "approved", "approved"})
	defer restore()
	origInstalled := planeInstalled
	installed := map[string]bool{"claude": true, "opencode": false, "antigravity": true}
	planeInstalled = func(plane string) bool { return installed[plane] }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "enable", "--all"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	got := out.String()
	if !strings.Contains(got, "claude enabled") || !strings.Contains(got, "antigravity enabled") {
		t.Fatalf("stdout missing enabled outcomes: %q", got)
	}
	if !strings.Contains(got, "opencode: not detected") || !strings.Contains(got, "codex: not detected") {
		t.Fatalf("stdout missing reports: %q", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Fatalf("claude settings not written: %q %v", out.String(), err)
	}
}

func TestPlaneStatusReportsLifecycleStateWithoutTerminal(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, cfg)
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
	if !strings.Contains(got, "codex: no hooks.json") {
		t.Fatalf("codex line missing: %q", got)
	}
}

func TestExecutePlaneApprovalAppliesBatch(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	testenv.SetState(t, t.TempDir())
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
	testenv.SetHome(t, home)
	testenv.SetConfig(t, cfg)
	testenv.SetState(t, t.TempDir())
	// claude already enabled (hooks + current floor); antigravity needs enabling; opencode not detected.
	reconcilePlanes(t, home, "claude")
	origInstalled := planeInstalled
	planeInstalled = func(plane string) bool { return plane != "opencode" }
	defer func() { planeInstalled = origInstalled }()

	var submitted []approval.Request
	origSubmit, origQuery := submitPlaneRequest, queryPlaneStatus
	stubOperatorEnrolled(t, true)
	submitPlaneRequest = func(request approval.Request) (approval.Request, error) {
		submitted = append(submitted, request)
		return approval.Request{ID: "stub-request", Status: "pending", ApprovalURL: "http://localhost:39169/approve"}, nil
	}
	queryPlaneStatus = func(socket, id string) (approval.Request, error) {
		return approval.Request{Status: "approved"}, nil
	}
	defer func() { submitPlaneRequest, queryPlaneStatus = origSubmit, origQuery }()

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "enable", "--all"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if len(submitted) != 1 {
		t.Fatalf("submitted %d requests, want 1 batched: %+v", len(submitted), submitted)
	}
	if got := submitted[0].Parameters["planes"]; got != "antigravity,codex" {
		t.Fatalf("batch planes = %q, want antigravity,codex", got)
	}
	got := out.String()
	if !strings.Contains(got, "claude: already enabled") || !strings.Contains(got, "opencode: not detected") {
		t.Fatalf("stdout missing skip reports: %q", got)
	}
}

func TestPlaneEnableAllSteadyStatePromptsNobody(t *testing.T) {
	home := t.TempDir()
	cfg := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, cfg)
	testenv.SetState(t, t.TempDir())
	reconcilePlanes(t, home, supportedPlanes...)
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
	if code := runPlaneTerminal(t, []string{"plane", "enable", "--all"}, &out, &errb); code != 0 {
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
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	testenv.SetState(t, t.TempDir())
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"stale","matcher":"Task","hooks":[]}]}}`)
	restore := stubPlaneTransport(t, []string{"executing", "completed"})
	defer restore()
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "enable", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "claude enabled") {
		t.Fatalf("stdout missing outcome: %q", out.String())
	}
}

func TestPlaneEnableAllHealsUnmarkedLegacyClaudeEntries(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	testenv.SetState(t, t.TempDir())
	settings := filepath.Join(home, ".claude", "settings.json")
	writePlaneSettings(t, settings, `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[{"type":"command","command":"guardrail hook claude"}]},{"matcher":"Bash","hooks":[{"type":"command","command":"guardrail hook claude"}]}]}}`)

	var submitted []approval.Request
	var current approval.Request
	origSubmit, origQuery := submitPlaneRequest, queryPlaneStatus
	stubOperatorEnrolled(t, true)
	submitPlaneRequest = func(request approval.Request) (approval.Request, error) {
		current = request
		submitted = append(submitted, request)
		return approval.Request{ID: "stub-request", Status: "pending", ApprovalURL: "http://localhost:39169/approve"}, nil
	}
	queryPlaneStatus = func(socket, id string) (approval.Request, error) {
		if err := executePlaneApproval(current); err != nil {
			return approval.Request{Status: "denied"}, nil
		}
		return approval.Request{Status: "approved"}, nil
	}
	defer func() { submitPlaneRequest, queryPlaneStatus = origSubmit, origQuery }()
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "enable", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if len(submitted) != 1 || submitted[0].Parameters["planes"] != "claude" {
		t.Fatalf("claude was skipped despite unmarked entries: %+v", submitted)
	}
	got := readPlaneJSON(t, settings)
	if !strings.Contains(got, "guardrail-claude-pre") {
		t.Fatalf("marked entry missing: %s", got)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatal(err)
	}
	if n := genconfig.CountUnmarkedGuardrailGroups(doc); n != 0 {
		t.Fatalf("%d unmarked entries remain after enable", n)
	}
}

func TestPlaneStatusAntigravityDriftStates(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	testenv.SetState(t, t.TempDir())
	hooksPath := filepath.Join(home, ".gemini", "config", "hooks.json")

	// 1. Missing
	if got := planeStatusState("antigravity"); got != "no hooks.json" {
		t.Fatalf("missing hooks.json: got %q, want 'no hooks.json'", got)
	}

	// 2. Corrupted / unparseable
	writePlaneSettings(t, hooksPath, `{"guardrail": {broken json`)
	if got := planeStatusState("antigravity"); !strings.HasPrefix(got, "unparseable (") {
		t.Fatalf("corrupted hooks.json: got %q, want 'unparseable (...)'", got)
	}

	// 3. Disabled
	writePlaneSettings(t, hooksPath, `{"guardrail":{"enabled":false,"PreToolUse":[]}}`)
	if got := planeStatusState("antigravity"); got != "present, disabled" {
		t.Fatalf("disabled hooks.json: got %q, want 'present, disabled'", got)
	}

	// 4. Unmarked legacy hooks
	writePlaneSettings(t, hooksPath, `{"guardrail":{"enabled":true,"PreToolUse":[{"matcher":"*","hooks":[{"command":"guardrail hook antigravity pre","type":"command"}]}]}}`)
	if got := planeStatusState("antigravity"); got != "present, integration NOT registered" {
		t.Fatalf("unmarked legacy hooks.json: got %q, want 'present, integration NOT registered'", got)
	}

	// 5. Valid registered
	writePlaneSettings(t, hooksPath, `{"guardrail":{"enabled":true,"PreToolUse":[{"id":"guardrail-antigravity-pre","matcher":"*","hooks":[{"command":"guardrail hook antigravity pre","type":"command"}]}]}}`)
	if got := planeStatusState("antigravity"); got != "guardrail integration registered" {
		t.Fatalf("valid registered hooks.json: got %q, want 'guardrail integration registered'", got)
	}
}

func TestPlaneEnableHealsAntigravityUnmarkedAndDisabled(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	testenv.SetState(t, t.TempDir())
	hooksPath := filepath.Join(home, ".gemini", "config", "hooks.json")

	// Start with unmarked legacy entry + disabled
	writePlaneSettings(t, hooksPath, `{"guardrail":{"enabled":false,"PreToolUse":[{"matcher":"*","hooks":[{"command":"guardrail hook antigravity pre","type":"command"}]}]}}`)

	var submitted []approval.Request
	var current approval.Request
	origSubmit, origQuery := submitPlaneRequest, queryPlaneStatus
	stubOperatorEnrolled(t, true)
	submitPlaneRequest = func(request approval.Request) (approval.Request, error) {
		current = request
		submitted = append(submitted, request)
		return approval.Request{ID: "stub-antigravity-request", Status: "pending", ApprovalURL: "http://localhost:39169/approve"}, nil
	}
	queryPlaneStatus = func(socket, id string) (approval.Request, error) {
		if err := executePlaneApproval(current); err != nil {
			return approval.Request{Status: "denied"}, nil
		}
		return approval.Request{Status: "approved"}, nil
	}
	defer func() { submitPlaneRequest, queryPlaneStatus = origSubmit, origQuery }()
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "enable", "antigravity"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if len(submitted) != 1 || submitted[0].Parameters["planes"] != "antigravity" {
		t.Fatalf("antigravity enable skipped: %+v", submitted)
	}
	got := readPlaneJSON(t, hooksPath)
	if !strings.Contains(got, "guardrail-antigravity-pre") {
		t.Fatalf("marked entry missing: %s", got)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatal(err)
	}
	if n := genconfig.CountUnmarkedAntigravityGroups(doc); n != 0 {
		t.Fatalf("%d unmarked entries remain after enable", n)
	}
	guardrail, _ := doc["guardrail"].(map[string]any)
	if enabled, _ := guardrail["enabled"].(bool); !enabled {
		t.Fatalf("guardrail was not enabled after enable: %v", guardrail)
	}
}

// reconcilePlanes puts each plane in the fully reconciled state for a
// sandboxed binary path: exactly what enable writes (owned hook groups that
// match this binary, the current permissions floor, wrapper and plugin), so
// the one reconcile rule (setupEnableReason) reports nothing to do. The data
// root is pinned under home so the opencode plugin never lands outside it.
func reconcilePlanes(t *testing.T, home string, planes ...string) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	t.Setenv("CODEX_HOME", "")
	useInstalledExecutable(t, filepath.Join(home, "bin", "guardrail"))
	for _, plane := range planes {
		enableForDrift(t, plane)
	}
}

// A registered hook with a stale permissions floor is drift, not "already
// enabled": a released floor change (a new allow, deny, or ask entry) must
// land on the next plane enable, and the merge is idempotent.
func TestPlaneEnableClaudeReMergesWhenFloorDrifted(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	writePlaneSettings(t, filepath.Join(home, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[]}]},"permissions":{"deny":["Bash(rm -rf /)"]}}`)
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()

	var submitted []approval.Request
	origSubmit, origQuery := submitPlaneRequest, queryPlaneStatus
	stubOperatorEnrolled(t, true)
	submitPlaneRequest = func(request approval.Request) (approval.Request, error) {
		submitted = append(submitted, request)
		return approval.Request{ID: "stub-request", Status: "pending", ApprovalURL: "http://localhost:39169/approve"}, nil
	}
	queryPlaneStatus = func(socket, id string) (approval.Request, error) {
		return approval.Request{Status: "approved"}, nil
	}
	defer func() { submitPlaneRequest, queryPlaneStatus = origSubmit, origQuery }()

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "enable", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr %q", code, errb.String())
	}
	if len(submitted) != 1 || submitted[0].Parameters["planes"] != "claude" {
		t.Fatalf("submitted = %+v, want one claude enable", submitted)
	}
	if strings.Contains(out.String(), "already enabled") || !strings.Contains(out.String(), "claude: permissions floor drifted") {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestPlaneEnableClaudeSkipsWhenHooksAndFloorAreCurrent(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	reconcilePlanes(t, home, "claude")
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()
	origSubmit := submitPlaneRequest
	submitPlaneRequest = func(request approval.Request) (approval.Request, error) {
		t.Fatalf("unexpected request: %+v", request)
		return approval.Request{}, nil
	}
	defer func() { submitPlaneRequest = origSubmit }()

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "enable", "claude"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "claude: already enabled") {
		t.Fatalf("exit = %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
}

func TestClaudeSteadyStateSurvivesIdStripping(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, home+"/.config")
	testenv.SetState(t, t.TempDir())
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	// Claude Code rewrote settings.json and stripped all id fields.
	// The hooks are still functionally present by command pattern.
	idStripped := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"guardrail hook claude","timeout":10}]}],"PostToolUse":[{"matcher":"Write|Edit|MultiEdit","hooks":[{"type":"command","command":"guardrail hook claude"}]}],"SessionStart":[{"matcher":"startup|clear|compact","hooks":[{"type":"command","command":"guardrail hook claude"}]}]}}`
	if err := os.WriteFile(settings, []byte(idStripped), 0o644); err != nil {
		t.Fatal(err)
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("claude with id-stripped hooks counts as not registered; steady state broken")
	}

	// True duplicates (marked + unmarked in the same event) still drift.
	duplicate := `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"*","hooks":[{"type":"command","command":"guardrail hook claude","timeout":10}]},{"matcher":"*","hooks":[{"type":"command","command":"guardrail hook claude","timeout":10}]}]}}`
	if err := os.WriteFile(settings, []byte(duplicate), 0o644); err != nil {
		t.Fatal(err)
	}
	if planeIntegrationRegistered("claude") {
		t.Fatal("claude with a true unmarked duplicate counts as registered; drift missed")
	}
}

// plane enable and setup share one reconcile rule: a registered plane whose
// handlers were written for another binary re-enables instead of reporting
// "already enabled".
func TestPlaneEnableReenablesOnHandlerDrift(t *testing.T) {
	_, b := driftSandbox(t)
	enableForDrift(t, "claude")
	useInstalledExecutable(t, b)
	origInstalled := planeInstalled
	planeInstalled = func(string) bool { return true }
	defer func() { planeInstalled = origInstalled }()
	useTransport(t, []string{"approved"})
	seen := countSubmits(t)

	var out, errb strings.Builder
	if code := runPlaneTerminal(t, []string{"plane", "enable", "claude"}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "claude: registered handlers differ from this binary; re-enabling\n") {
		t.Fatalf("stdout missing handler-drift line: %q", out.String())
	}
	if len(*seen) != 1 || (*seen)[0].Parameters["planes"] != "claude" {
		t.Fatalf("submitted = %+v, want one claude enable", *seen)
	}
	assertDrift(t, "claude", false)
}
