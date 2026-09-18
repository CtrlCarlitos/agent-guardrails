package main

import (
	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"io"
	"strings"
	"testing"
)

func TestApprovalsRejectsTTYClientMode(t *testing.T) {
	if got := cmdApprovalsInput([]string{"--request", "known"}, true, strings.NewReader("y\n"), io.Discard, io.Discard); got != 2 {
		t.Fatalf("exit = %d, want 2", got)
	}
}

func TestApprovalsListShowsPendingRequests(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	daemon, err := approval.StartDaemon(approval.DefaultSocketPath(), approval.New(), nil, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer daemon.Close()
	var out, errb strings.Builder
	if code := run([]string{"approvals", "list"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "no pending") {
		t.Fatalf("empty list output = %q", out.String())
	}
	if code := run([]string{"approvals", "approve"}, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("approve without id exit = %d", code)
	}
	// Non-terminal approve is refused before any daemon contact.
	if code := run([]string{"approvals", "approve", "abc"}, strings.NewReader(""), &out, &errb); code != 2 || !strings.Contains(errb.String(), "interactive") {
		t.Fatalf("non-terminal approve exit = %d stderr %q", code, errb.String())
	}
}
