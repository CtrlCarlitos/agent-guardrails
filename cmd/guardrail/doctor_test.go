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
	for _, want := range []string{"guardrail ", "GUARDRAIL_CONFIG:", "overlay:", "audit log:", "claude settings:"} {
		if !strings.Contains(s, want) {
			t.Errorf("doctor output missing %q\n---\n%s", want, s)
		}
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

func TestDoctorSeesRegisteredHook(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GUARDRAIL_CONFIG", "")
	cdir := filepath.Join(home, ".claude")
	os.MkdirAll(cdir, 0o755)
	os.WriteFile(filepath.Join(cdir, "settings.json"),
		[]byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"guardrail hook claude"}]}]}}`), 0o644)
	var out, errb bytes.Buffer
	run([]string{"doctor"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(out.String(), "hook registered") {
		t.Errorf("doctor should detect the registered hook:\n%s", out.String())
	}
}
