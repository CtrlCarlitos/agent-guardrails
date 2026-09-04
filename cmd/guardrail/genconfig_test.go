package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenConfigNoPlane(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "plane") {
		t.Fatalf("stderr = %q, want it to mention a plane", errb.String())
	}
}

func TestGenConfigUnsupportedPlane(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "emacs"}, strings.NewReader(""), &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "emacs") {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
}

func TestGenConfigBadFlag(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude", "--nope"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}
