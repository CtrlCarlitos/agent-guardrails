package main

import (
	"bytes"
	"encoding/json"
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

func TestGenConfigClaudePrint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"gen-config", "claude", "--print"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	var frag map[string]any
	if err := json.Unmarshal(out.Bytes(), &frag); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
	if _, ok := frag["hooks"]; !ok {
		t.Error("no hooks key")
	}
	if _, ok := frag["permissions"]; !ok {
		t.Error("no permissions key")
	}
}
