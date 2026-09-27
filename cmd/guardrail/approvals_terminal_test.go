package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// #416: run() passed operatorTerminal=false and no input to cmdApprovals from
// the first commit, so `approvals grant` refused even in the operator's own
// console. The grant tests called cmdApprovalsInput directly and never saw it.
func TestApprovalsGrantThroughRunHonoursAnOperatorTerminal(t *testing.T) {
	repo := grantEnv(t)
	saved := operatorTerminal
	t.Cleanup(func() { operatorTerminal = saved })
	operatorTerminal = func(io.Reader) bool { return true }

	var stdout, stderr bytes.Buffer
	code := run([]string{"approvals", "grant", "--repo", repo, "--rule", "P2.git-push-protected",
		"--command", "git push origin main"}, strings.NewReader("yes\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("grant from a terminal -> %d, stderr=%q", code, stderr.String())
	}
	if grants := loadGrants(t, repo); len(grants) != 1 {
		t.Fatalf("recorded %d grants, want 1", len(grants))
	}
}

func TestApprovalsGrantThroughRunRefusesWithoutATerminal(t *testing.T) {
	repo := grantEnv(t)
	var stdout, stderr bytes.Buffer
	// A strings.Reader is never a terminal.
	code := run([]string{"approvals", "grant", "--repo", repo, "--rule", "P2.git-push-protected",
		"--command", "git push origin main"}, strings.NewReader("yes\n"), &stdout, &stderr)
	if code == 0 {
		t.Fatal("a non-terminal caller issued a grant")
	}
	if grants := loadGrants(t, repo); len(grants) != 0 {
		t.Errorf("recorded %v, want nothing", grants)
	}
}
