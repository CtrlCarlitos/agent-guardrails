package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

func TestApprovalsRefusesNonTerminal(t *testing.T) {
	if code := cmdApprovals([]string{"--request", "x"}, false, io.Discard, io.Discard); code == 0 {
		t.Fatal("accepted piped approval command")
	}
}

func TestApprovalsDoesNotBypassUnavailableDaemon(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	r, err := approval.New().Create(approval.Request{
		Plane: "claude", SessionID: "test-session", RepoRoot: t.TempDir(),
		Scope: approval.Allow, Reason: "test approval",
	})
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := cmdApprovalsInput([]string{"--request", r.ID}, true, strings.NewReader("y\n"), io.Discard, &stderr); code == 0 {
		t.Fatal("TTY approval bypassed unavailable daemon")
	}
	if !strings.Contains(stderr.String(), "approval daemon unavailable") {
		t.Fatalf("stderr = %q, want unavailable daemon status", stderr.String())
	}
}
