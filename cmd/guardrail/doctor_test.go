package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorBasics(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	t.Setenv("GUARDRAIL_CONFIG", "")

	var out, errb bytes.Buffer
	code := run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("doctor exit = %d, want 0", code)
	}
	s := out.String()
	for _, want := range []string{"guardrail ", "GUARDRAIL_CONFIG:", "overlay:", "policy warnings: none", "audit log:", "claude settings:"} {
		if !strings.Contains(s, want) {
			t.Errorf("doctor output missing %q\n---\n%s", want, s)
		}
	}
	if strings.Count(s, "policy warnings:") != 1 {
		t.Errorf("doctor output must contain exactly one policy warning section:\n%s", s)
	}
}

func TestDoctorShowsEveryPolicyWarningOnceInMergeOrder(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	dir := t.TempDir()
	gitInitSync(t, dir)
	overlay := `audit_log = "/tmp/repo-audit.jsonl"
waive = ["P1.rm-rf"]

[slots]
safe_roots = ["/outside-repo"]
secret_allow = [".env"]
egress_allowlist = ["*"]
`
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
	got := out.String()
	if strings.Count(got, "policy warnings:") != 1 {
		t.Fatalf("doctor output must contain exactly one policy warning section:\n%s", got)
	}
	warnings := []string{
		"safe_root /outside-repo outside the repository",
		"wildcard egress_allowlist entry *",
		"secret_allow entries, which are NOT authorized",
		"audit_log /tmp/repo-audit.jsonl, which is NOT authorized",
		"waiver of P1.rm-rf, which is NOT authorized",
	}
	previous := strings.Index(got, "policy warnings:")
	for _, warning := range warnings {
		if strings.Count(got, warning) != 1 {
			t.Fatalf("doctor output must show warning %q exactly once:\n%s", warning, got)
		}
		at := strings.Index(got, warning)
		if at < previous || !strings.Contains(got[previous:at], "  - ") {
			t.Fatalf("doctor output must show every warning as an ordered bullet:\n%s", got)
		}
		previous = at
	}
}

func TestDoctorStaleConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "/no/such/file.toml")
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "/no/such/file.toml") {
		t.Errorf("doctor should surface the stale GUARDRAIL_CONFIG path:\n%s", out.String())
	}
}

func TestDoctorUsesTopLevelRepoGrantFromSubdirectory(t *testing.T) {
	_, sub := repoWithAuthorizedWaiver(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
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
	t.Setenv("HOME", home)
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
	t.Setenv("HOME", home)
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
	t.Setenv("HOME", home)
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
	t.Setenv("HOME", home)
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
	t.Setenv("HOME", home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "no settings.json") {
		t.Errorf("want 'no settings.json':\n%s", out.String())
	}
}
