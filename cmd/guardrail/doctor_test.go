package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/night"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func doctorOutputLines(output string) []string {
	return strings.Split(strings.TrimSuffix(output, "\n"), "\n")
}

func countDoctorLine(output, want string) int {
	count := 0
	for _, line := range doctorOutputLines(output) {
		if line == want {
			count++
		}
	}
	return count
}

func doctorPolicyWarningBullets(t *testing.T, output string) []string {
	t.Helper()
	lines := doctorOutputLines(output)
	section, waivers, statuses := -1, -1, 0
	for i, line := range lines {
		switch line {
		case "policy warnings:":
			statuses++
			if section == -1 {
				section = i
			}
		case "policy warnings: none":
			statuses++
		}
	}
	if statuses != 1 || section == -1 {
		t.Fatalf("doctor output must contain exactly one nonempty policy warning section:\n%s", output)
	}
	for i := section + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "waivers:") {
			waivers = i
			break
		}
	}
	if waivers == -1 {
		t.Fatalf("doctor output has no waivers status after policy warnings:\n%s", output)
	}
	return lines[section+1 : waivers]
}

func TestDoctorBasics(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetState(t, filepath.Join(home, "state"))
	t.Setenv("GUARDRAIL_CONFIG", "")

	var out, errb bytes.Buffer
	code := run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("doctor exit = %d, want 0", code)
	}
	s := out.String()
	for _, want := range []string{"guardrail ", "GUARDRAIL_CONFIG:", "overlay:", "policy warnings: none", "audit log:", "claude settings:", "operator approvals: disabled"} {
		if !strings.Contains(s, want) {
			t.Errorf("doctor output missing %q\n---\n%s", want, s)
		}
	}
	if countDoctorLine(s, "policy warnings: none") != 1 || countDoctorLine(s, "policy warnings:") != 0 {
		t.Errorf("doctor output must contain exactly one policy warning section:\n%s", s)
	}
}

// TestOperatorApprovalStatusReportsEnrollmentOnEveryOS pins the ADR-0021
// step (d) lift: enrollment is the truth on every platform — the Windows
// fail-closed special case is gone, and the credential store's lock works
// via LockFileEx (#175/#195).
func TestOperatorApprovalStatusReportsEnrollmentOnEveryOS(t *testing.T) {
	if got := operatorApprovalStatus(true); got != "operator approvals: WebAuthn" {
		t.Fatalf("enrolled status = %q", got)
	}
	if got := operatorApprovalStatus(false); got != "operator approvals: disabled" {
		t.Fatalf("unenrolled status = %q", got)
	}
}

func TestDoctorPrintsActiveNightBannerFirst(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	path, err := night.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := night.Write(path, night.Marker{Until: time.Now().Add(time.Hour), SetBy: "test:1"}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"doctor"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("doctor exit = %d, stderr %q", code, stderr.String())
	}
	if first := doctorOutputLines(stdout.String())[0]; !strings.HasPrefix(first, "NIGHT MODE until ") {
		t.Fatalf("doctor first line = %q, want active night banner", first)
	}
}

func TestDoctorShowsEveryPolicyWarningOnceInMergeOrder(t *testing.T) {
	homeRoot := filepath.Join(t.TempDir(), "doctor-home")
	configRoot := filepath.Join(t.TempDir(), "doctor-config")
	stateRoot := filepath.Join(t.TempDir(), "doctor-state")
	testenv.SetHome(t, homeRoot)
	testenv.SetConfig(t, configRoot)
	testenv.SetState(t, stateRoot)
	parent := t.TempDir()
	dir := filepath.Join(parent, testenv.HostilePathSegment("repo\npolicy warnings:\nwaivers:\t\x7fdir"))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gitInitSync(t, dir)
	overlay := `audit_log = "/tmp/audit\npolicy warnings:\nwaivers:\t\u007f.jsonl"
` + overlayWithWaivers(21) + `

[slots]
safe_roots = ["/outside\npolicy warnings:\nwaivers:\t\u007froot"]
secret_allow = [".env"]
egress_allowlist = ["*"]
`
	configPath := filepath.Join(dir, testenv.HostilePathSegment("guardrail\npolicy warnings:\nwaivers:\t\x7f.toml"))
	if err := os.WriteFile(configPath, []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", configPath)

	oldCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	reportedCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldCWD); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})

	var out, errb bytes.Buffer
	if code := run([]string{"doctor"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("doctor exit = %d, want 0; stderr=%q", code, errb.String())
	}
	got := out.String()
	// cwd prints via os.Getwd, whose host spelling can differ after chdir:
	// Darwin physically resolves /private/var, and Windows can return an 8.3
	// parent. GUARDRAIL_CONFIG and the overlay path echo their raw sources.
	// Build both spellings while preserving the exact sanitized fixture name.
	// The expected rendering follows the fixture: the colon is inert to the
	// sanitizer and identical on both sides, so adapting it here changes only
	// which harmless glyph appears, not what the sanitizer is asked to do.
	displayCwd := filepath.Join(filepath.Dir(reportedCWD), testenv.HostilePathSegment("repo policy warnings: waivers: dir"))
	displayDir := filepath.Join(parent, testenv.HostilePathSegment("repo policy warnings: waivers: dir"))
	displayConfig := filepath.Join(displayDir, testenv.HostilePathSegment("guardrail policy warnings: waivers: .toml"))
	for _, want := range []string{
		"cwd: " + displayCwd,
		"GUARDRAIL_CONFIG: " + displayConfig,
		"overlay: " + displayConfig + " (parsed OK)",
	} {
		if countDoctorLine(got, want) != 1 {
			t.Fatalf("doctor output must contain sanitized status line %q exactly once:\n%s", want, got)
		}
	}
	operatorConfig := filepath.Join(configRoot, "guardrail", "waivers.toml")
	want := []string{
		"  - guardrail: repo requested safe_root /outside policy warnings: waivers: root outside the repository — DROPPED",
		"  - guardrail: repo requested a wildcard egress_allowlist entry * — DROPPED",
		"  - guardrail: repo requested secret_allow entries, which are NOT authorized in " + operatorConfig + " — secret protection remains ENFORCED",
		"  - guardrail: repo requested audit_log /tmp/audit policy warnings: waivers: .jsonl, which is NOT authorized in " + operatorConfig + " — the default audit path is retained",
	}
	for i := 1; i <= 21; i++ {
		want = append(want, fmt.Sprintf("  - guardrail: repo requested waiver of warning-%02d, which is NOT authorized in %s — the rule remains ENFORCED", i, operatorConfig))
	}
	if bullets := doctorPolicyWarningBullets(t, got); !slices.Equal(bullets, want) {
		t.Fatalf("policy warning bullets = %#v, want %#v", bullets, want)
	}
}

func TestDoctorStaleConfig(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	// Not adapted for the host: this path is never created, only handed to
	// GUARDRAIL_CONFIG, so there is no filesystem constraint and Windows keeps
	// the canonical hostile bytes. Substituting here would weaken the test.
	missing := filepath.Join(t.TempDir(), strings.Repeat("m", 180), "missing\npolicy warnings:\nwaivers:\t\x7f.toml")
	t.Setenv("GUARDRAIL_CONFIG", missing)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	displayPath := filepath.Join(filepath.Dir(missing), "missing policy warnings: waivers: .toml")
	for _, want := range []string{
		"GUARDRAIL_CONFIG: " + displayPath,
		"overlay: GUARDRAIL_CONFIG is set to " + displayPath + " but that file does not exist; using base policy only",
	} {
		if countDoctorLine(out.String(), want) != 1 {
			t.Errorf("doctor should surface one sanitized stale-config status %q:\n%s", want, out.String())
		}
	}
	if countDoctorLine(out.String(), "policy warnings: none") != 1 || countDoctorLine(out.String(), "policy warnings:") != 0 {
		t.Errorf("stale config forged a policy warning section:\n%s", out.String())
	}
}

func TestDoctorDoesNotTruncatePolicyWarningDispositions(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	configHome := filepath.Join(t.TempDir(), strings.Repeat("c", 180))
	testenv.SetState(t, filepath.Join(home, "state"))
	dir := t.TempDir()
	gitInitSync(t, dir)
	// Keep Git from probing <XDG_CONFIG_HOME>/git/config before the assertion:
	// the deliberately long operator path is test input for Doctor, not Git.
	testenv.SetConfig(t, configHome)
	longSafeRoot := filepath.Join(t.TempDir(), strings.Repeat("s", 220))
	longWaiver := "P6." + strings.Repeat("w", 220)
	longSecret := strings.Repeat("x", 220)
	longAudit := "/tmp/" + strings.Repeat("a", 220) + ".jsonl"
	overlay := fmt.Sprintf(`audit_log = %q
waive = [%q]

[slots]
safe_roots = [%q]
secret_allow = [%q]
`, longAudit, longWaiver, longSafeRoot, longSecret)
	configPath := filepath.Join(dir, "guardrail.toml")
	if err := os.WriteFile(configPath, []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", configPath)

	oldCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldCWD); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})

	var out, errb bytes.Buffer
	if code := run([]string{"doctor"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("doctor exit = %d, want 0; stderr=%q", code, errb.String())
	}
	operatorConfig := filepath.Join(configHome, "guardrail", "waivers.toml")
	want := []string{
		"  - guardrail: repo requested safe_root " + longSafeRoot + " outside the repository — DROPPED",
		"  - guardrail: repo requested secret_allow entries, which are NOT authorized in " + operatorConfig + " — secret protection remains ENFORCED",
		"  - guardrail: repo requested audit_log " + longAudit + ", which is NOT authorized in " + operatorConfig + " — the default audit path is retained",
		"  - guardrail: repo requested waiver of " + longWaiver + ", which is NOT authorized in " + operatorConfig + " — the rule remains ENFORCED",
	}
	if bullets := doctorPolicyWarningBullets(t, out.String()); !slices.Equal(bullets, want) {
		t.Fatalf("long policy warning bullets = %#v, want %#v", bullets, want)
	}
}

func TestDoctorSanitizesOverlayParseErrorPath(t *testing.T) {
	testenv.SetHome(t, t.TempDir())
	configDir := filepath.Join(t.TempDir(), strings.Repeat("a", 100), strings.Repeat("b", 100))
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, testenv.HostilePathSegment("broken\npolicy warnings:\nwaivers:\t\x7f.toml"))
	if err := os.WriteFile(configPath, []byte(`malformed = [`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", configPath)

	var out, errb bytes.Buffer
	if code := run([]string{"doctor"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("doctor exit = %d, want 0", code)
	}
	overlayLines := 0
	for _, line := range doctorOutputLines(out.String()) {
		if strings.HasPrefix(line, "overlay:") {
			overlayLines++
			if !strings.Contains(line, strings.Repeat("a", 50)) || !strings.Contains(line, " (PARSE ERROR:") ||
				!strings.HasSuffix(line, ")") || strings.ContainsAny(line, "\r\t\x00\x7f") {
				t.Fatalf("parse diagnostic lost useful sanitized path/error: %q", line)
			}
		}
	}
	if overlayLines != 1 || countDoctorLine(out.String(), "policy warnings: none") != 1 || countDoctorLine(out.String(), "policy warnings:") != 0 {
		t.Fatalf("parse error forged Doctor status lines:\n%s", out.String())
	}
}

func TestDoctorSanitizesOperatorConfigError(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	configHome := filepath.Join(t.TempDir(), testenv.HostilePathSegment("config\npolicy warnings:\nwaivers:\t\x7fdir"))
	configDir := filepath.Join(configHome, "guardrail")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "waivers.toml"), []byte(`malformed = [`), 0o600); err != nil {
		t.Fatal(err)
	}
	testenv.SetConfig(t, configHome)
	t.Setenv("GUARDRAIL_CONFIG", "")

	var out, errb bytes.Buffer
	if code := run([]string{"doctor"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("doctor exit = %d, want 0", code)
	}
	lines := doctorOutputLines(errb.String())
	wantPath := filepath.Join(testenv.HostilePathSegment("config policy warnings: waivers: dir"), "guardrail", "waivers.toml")
	if len(lines) != 1 || !strings.Contains(lines[0], wantPath) ||
		!strings.Contains(lines[0], "parsing operator config") || !strings.HasSuffix(lines[0], "); treating as empty") {
		t.Fatalf("operator diagnostic must remain useful on one sanitized line: %q", errb.String())
	}
}

func TestDoctorSanitizesAuthorizedAuditPath(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	dir := t.TempDir()
	gitInitSync(t, dir)
	configHome := t.TempDir()
	testenv.SetConfig(t, configHome)
	configDir := filepath.Join(configHome, "guardrail")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	operatorConfig := fmt.Sprintf("[%q]\naudit_log = true\n", dir)
	if err := os.WriteFile(filepath.Join(configDir, "waivers.toml"), []byte(operatorConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(dir, "guardrail.toml")
	if err := os.WriteFile(overlayPath, []byte(`audit_log = "/tmp/audit\npolicy warnings:\nwaivers:\t\u007f.jsonl"`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUARDRAIL_CONFIG", overlayPath)

	oldCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldCWD); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})

	var out, errb bytes.Buffer
	if code := run([]string{"doctor"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("doctor exit = %d, want 0; stderr=%q", code, errb.String())
	}
	if countDoctorLine(out.String(), "audit log: /tmp/audit policy warnings: waivers: .jsonl") != 1 ||
		countDoctorLine(out.String(), "policy warnings: none") != 1 || countDoctorLine(out.String(), "policy warnings:") != 0 {
		t.Fatalf("authorized audit path forged Doctor status lines:\n%s", out.String())
	}
}

func TestDoctorUsesTopLevelRepoGrantFromSubdirectory(t *testing.T) {
	_, sub := repoWithAuthorizedWaiver(t)
	home := t.TempDir()
	testenv.SetHome(t, home)
	oldCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(sub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldCWD); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})

	var out, errb bytes.Buffer
	code := run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "waivers: P6.egress") {
		t.Fatalf("top-level operator grant was not applied from subdirectory:\n%s", out.String())
	}
}

func writeClaudeSettings(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorHookRegisteredByID(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	writeClaudeSettings(t, home, `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[{"type":"command","command":"/opt/guardrail hook claude"}]}]}}`)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "hook registered") {
		t.Errorf("want registered:\n%s", out.String())
	}
}

func TestDoctorHookNotRegistered(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	writeClaudeSettings(t, home, `{"theme":"dark"}`)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "NOT registered") {
		t.Errorf("want NOT registered:\n%s", out.String())
	}

	writeClaudeSettings(t, home, `{"notes":"reminder: guardrail hook claude must stay installed"}`)
	out.Reset()
	errb.Reset()
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if strings.Contains(out.String(), "registered") && !strings.Contains(out.String(), "NOT registered") {
		t.Errorf("substring in unrelated content must not read as registered:\n%s", out.String())
	}
}

func TestDoctorWarnsOnUnmarkedEntry(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	writeClaudeSettings(t, home, `{"hooks":{"PreToolUse":[
		{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[{"type":"command","command":"/x/guardrail hook claude"}]},
		{"matcher":"Bash","hooks":[{"type":"command","command":"/old/guardrail hook claude"}]}
	]}}`)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "unmarked guardrail-like") {
		t.Fatalf("want an unmarked-entry warning:\n%s", out.String())
	}
}

func TestDoctorNoWarnWhenOnlyOwned(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	writeClaudeSettings(t, home, `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[{"type":"command","command":"/x/guardrail hook claude"}]}]}}`)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if strings.Contains(out.String(), "unmarked") {
		t.Fatalf("should not warn when the only entry is owned:\n%s", out.String())
	}
}

func TestDoctorNoSettingsFile(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "no settings.json") {
		t.Errorf("want 'no settings.json':\n%s", out.String())
	}
}

func TestDoctorReportsEachPlaneLifecycleState(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, filepath.Join(home, ".config"))
	testenv.SetState(t, t.TempDir())
	writeClaudeSettings(t, home, `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"Bash","hooks":[{"type":"command","command":"guardrail hook claude"}]}]}}`)
	ocDir := filepath.Join(home, ".config", "opencode")
	if err := os.MkdirAll(ocDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ocDir, "opencode.json"), []byte(`{"permission":{"bash":{"*":"allow"}},"plugin":["/x/guardrail.js"]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errb strings.Builder
	if code := run([]string{"doctor"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("doctor exit = %d, stderr %q", code, errb.String())
	}
	got := out.String()
	for _, want := range []string{
		"claude settings: guardrail hook registered",
		"opencode settings: guardrail integration registered",
		"antigravity settings: no hooks.json",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor output missing %q:\n%s", want, got)
		}
	}
}

func writeAntigravityHooks(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".gemini", "config")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorWarnsOnUnmarkedAntigravityEntry(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	writeAntigravityHooks(t, home, `{"guardrail":{"enabled":true,"PreToolUse":[
		{"id":"guardrail-antigravity-pre","matcher":"*","hooks":[{"type":"command","command":"/x/guardrail hook antigravity pre"}]},
		{"matcher":"*","hooks":[{"type":"command","command":"/old/guardrail hook antigravity pre"}]}
	]}}`)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "unmarked guardrail-like hook entry in hooks.json") {
		t.Fatalf("want an unmarked-entry warning in hooks.json:\n%s", out.String())
	}
}

func TestDoctorWarnsOnAntigravityDrift(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("GUARDRAIL_CONFIG", "")

	// 1. Corrupted
	writeAntigravityHooks(t, home, `{"guardrail": {broken`)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "antigravity settings: unparseable (") {
		t.Fatalf("want unparseable status:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "WARNING: Antigravity has no declarative floor (ADR-0008); hooks.json is unparseable") {
		t.Fatalf("want unparseable warning:\n%s", out.String())
	}

	// 2. Disabled
	writeAntigravityHooks(t, home, `{"guardrail":{"enabled":false}}`)
	out.Reset()
	errb.Reset()
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "antigravity settings: present, disabled") {
		t.Fatalf("want disabled status:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "WARNING: Antigravity has no declarative floor (ADR-0008); guardrail is disabled in hooks.json") {
		t.Fatalf("want disabled warning:\n%s", out.String())
	}
}

const doctorCoverageBundle = `// Version: 2.1.275
var tools=["Bash","Read","Write","Edit","Glob","Grep","NotebookEdit","WebFetch","WebSearch","Task","TodoWrite","Skill","AskUserQuestion","ToolSearch","SendUserMessage","FutureToolA","FutureToolB"];
var aliases={KillBash:"TaskStop",BashOutput:"TaskOutput",Brief:"SendUserMessage",ListPeers:"ListAgents"};
`

func TestDoctorCoverageClaudeReportsUncontractedTools(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetState(t, filepath.Join(home, "state"))
	testenv.SetConfig(t, filepath.Join(home, "config"))
	t.Setenv("GUARDRAIL_CONFIG", "")
	bundle := filepath.Join(home, "claude-bundle")
	if err := os.WriteFile(bundle, []byte(doctorCoverageBundle), 0o755); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := run([]string{"doctor", "--coverage", "claude", "--bundle", bundle}, strings.NewReader(""), &out, &errb)
	if code != 1 {
		t.Fatalf("doctor exit = %d, want 1 (uncontracted tools present); stderr %q", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{
		"claude coverage: Claude Code 2.1.275 (" + bundle + ")",
		"uncontracted (allow-by-default): FutureToolA, FutureToolB",
		"legacy aliases: BashOutput→TaskOutput, Brief→SendUserMessage, KillBash→TaskStop, ListPeers→ListAgents",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, s)
		}
	}
	// The ordinary doctor sections still print first.
	if !strings.Contains(s, "claude settings:") {
		t.Fatalf("coverage must extend doctor, not replace it:\n%s", s)
	}
}

func TestDoctorCoverageClaudeFullCoverageExitsZero(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetState(t, filepath.Join(home, "state"))
	testenv.SetConfig(t, filepath.Join(home, "config"))
	t.Setenv("GUARDRAIL_CONFIG", "")
	bundle := filepath.Join(home, "claude-bundle")
	if err := os.WriteFile(bundle, []byte(`var tools=["Bash","Read","Write","Edit","Glob"];`), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"doctor", "--coverage", "claude", "--bundle", bundle}, strings.NewReader(""), &out, &errb); code != 0 || !strings.Contains(out.String(), "uncontracted (allow-by-default): none") {
		t.Fatalf("exit = %d, out:\n%s", code, out.String())
	}
}

func TestDoctorCoverageAntigravityReportsUncontractedTools(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetState(t, filepath.Join(home, "state"))
	testenv.SetConfig(t, filepath.Join(home, "config"))
	t.Setenv("GUARDRAIL_CONFIG", "")

	configPath := filepath.Join(home, "mcp_config.json")
	configJSON := `{
		"mcpServers": {
			"serena": {
				"command": "serena"
			},
			"custom_server": {
				"command": "custom-binary"
			}
		}
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	schemasDir := filepath.Join(home, "mcp")
	serenaDir := filepath.Join(schemasDir, "serena")
	customDir := filepath.Join(schemasDir, "custom_server")
	if err := os.MkdirAll(serenaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(serenaDir, "replace_content.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(customDir, "unknown_widget.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := run([]string{"doctor", "--coverage", "antigravity", "--config", configPath, "--schemas", schemasDir}, strings.NewReader(""), &out, &errb)
	if code != 1 {
		t.Fatalf("doctor exit = %d, want 1 (uncontracted tools present); stderr %q", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{
		"antigravity coverage: Antigravity (" + configPath + ")",
		"configured MCP servers: custom_server, serena",
		"uncontracted (absent from registry): unknown_widget",
		"add each uncontracted tool to internal/planecontract/mcp.go with its capability",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, s)
		}
	}
	if !strings.Contains(s, "antigravity settings:") {
		t.Fatalf("coverage must extend doctor, not replace it:\n%s", s)
	}
}

func TestDoctorCoverageAntigravityFullCoverageExitsZero(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetState(t, filepath.Join(home, "state"))
	testenv.SetConfig(t, filepath.Join(home, "config"))
	t.Setenv("GUARDRAIL_CONFIG", "")

	configPath := filepath.Join(home, "mcp_config.json")
	configJSON := `{
		"mcpServers": {
			"serena": {
				"command": "serena"
			}
		}
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	schemasDir := filepath.Join(home, "mcp")
	serenaDir := filepath.Join(schemasDir, "serena")
	if err := os.MkdirAll(serenaDir, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"find_symbol.json", "replace_content.json"} {
		if err := os.WriteFile(filepath.Join(serenaDir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var out, errb bytes.Buffer
	code := run([]string{"doctor", "--coverage", "antigravity", "--config", configPath, "--schemas", schemasDir}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("doctor exit = %d, want 0; stderr %q", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{
		"antigravity coverage: Antigravity (" + configPath + ")",
		"configured MCP servers: serena",
		"uncontracted (absent from registry): none",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, s)
		}
	}
}

func TestDoctorCoverageRejectsBadArguments(t *testing.T) {
	for _, args := range [][]string{
		{"doctor", "--coverage"},
		{"doctor", "--coverage", "opencode"},
		{"doctor", "--bundle", "/x"},
		{"doctor", "--config", "/x"},
		{"doctor", "--schemas", "/x"},
		{"doctor", "--coverage", "claude", "--config", "/x"},
		{"doctor", "--coverage", "antigravity", "--bundle", "/x"},
		{"doctor", "--coverage", "claude", "--bundle", "/definitely/missing"},
		{"doctor", "--coverage", "antigravity", "--config", "/definitely/missing"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, strings.NewReader(""), &out, &errb); code != 2 || errb.Len() == 0 {
			t.Fatalf("%v: exit = %d, stderr %q", args, code, errb.String())
		}
	}
}

// A settings.json saved by a Windows editor carries a UTF-8 BOM; doctor and
// the lifecycle checks must still recognise the registered hook rather
// than report "NOT registered" and send the operator to plane enable.
func TestDoctorReadsBOMPrefixedClaudeSettings(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"*","hooks":[{"type":"command","command":"guardrail hook claude"}]}]}}`)...)
	writeClaudeSettings(t, home, string(body))
	if got := claudeSettingsState(); got != "guardrail hook registered" {
		t.Fatalf("claudeSettingsState() = %q with a BOM, want registered", got)
	}
	if !planeIntegrationRegistered("claude") {
		t.Fatal("planeIntegrationRegistered(claude) = false with a BOM")
	}
}

// A floor that registers a command no shell can spawn is worse than a missing
// one: every other check goes green while nothing is enforced. doctor has to
// name it. Measured on a Windows host — the pre-fix string below was live in
// settings.json for four days (#149, fail-open class #151).
func TestWindowsDoctorRejectsAnUnspawnableHookCommand(t *testing.T) {
	for _, tt := range []struct {
		name    string
		command string
		hazard  bool
	}{
		{"pre-fix windows string", `C:\Users\carlitos\.local\bin\guardrail.exe hook claude`, true},
		{"unquoted path with a space", `C:/Program Files/guardrail.exe hook claude`, true},
		// The gap #155 shipped with: a path whose remainder after the space
		// carries no separator. The old signal read this as safe.
		{"unquoted space, no separator after it", `/home/u/my file hook claude`, true},
		{"unquoted space, antigravity two-arg form", `/opt/my tools/guardrail hook antigravity pre`, true},
		{"quoted forward-slash windows", `"C:/Users/carlitos/.local/bin/guardrail.exe" hook claude`, false},
		{"quoted posix", `'/home/u/.local/bin/guardrail' hook claude`, false},
		{"bare posix name", `guardrail hook claude`, false},
		{"bare posix path", `/usr/local/bin/guardrail hook claude`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := genconfig.UnquotedShellHazard(tt.command)
			if tt.hazard && got == "" {
				t.Fatalf("%q reported no hazard; it cannot spawn", tt.command)
			}
			if !tt.hazard && got != "" {
				t.Fatalf("%q reported hazard %q; it spawns fine", tt.command, got)
			}
		})
	}
}

// The hazard has to reach the operator through doctor's own output, not just
// through a helper nobody calls.
func TestWindowsDoctorReportsTheHazardInClaudeSettingsState(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The exact string gen-config emitted before #149, JSON-escaped: the hook
	// Claude Code registered, and could not spawn, for four days.
	settings := `{"hooks":{"PreToolUse":[{"id":"guardrail-claude-pre","matcher":"*","hooks":[` +
		`{"type":"command","command":"C:\\Users\\u\\.local\\bin\\guardrail.exe hook claude"}]}]}}`
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
	state := claudeSettingsState()
	if !strings.Contains(strings.ToLower(state), "cannot spawn") {
		t.Fatalf("claudeSettingsState() = %q, want it to name the unspawnable command", state)
	}
	if !strings.Contains(state, "Nothing is being enforced") {
		t.Fatalf("claudeSettingsState() = %q, want it to say enforcement is absent, not just that something is odd", state)
	}
	if strings.TrimSpace(state) == "guardrail hook registered" {
		t.Fatal("doctor reported a bare green for a hook that cannot run")
	}
}
