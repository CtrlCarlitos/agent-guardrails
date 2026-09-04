package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"version"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), "guardrail") {
		t.Fatalf("stdout = %q, want it to contain %q", out.String(), "guardrail")
	}
}

func TestRunUnknownSubcommand(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"frobnicate"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "unknown subcommand") {
		t.Fatalf("stderr = %q, want it to mention %q", errb.String(), "unknown subcommand")
	}
}

func TestRunHelp(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"help"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("help exit = %d, want 0", code)
	}
	for _, want := range []string{"hook", "gen-config", "doctor", "version"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage missing %q", want)
		}
	}
}

func TestRunNoArgs(t *testing.T) {
	var out, errb bytes.Buffer
	code := run(nil, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}
