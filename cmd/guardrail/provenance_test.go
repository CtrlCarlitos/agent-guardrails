package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func seedWorktreeCreation(t *testing.T, session, command, decision string, age time.Duration) {
	t.Helper()
	rec := audit.Record{
		TS:        time.Now().UTC().Add(-age).Format(time.RFC3339Nano),
		SessionID: session, Plane: "claude", Tool: "Bash", Event: "pre",
		Command: command, Decision: decision,
	}
	if err := audit.Write(rec, audit.DefaultPath("")); err != nil {
		t.Fatal(err)
	}
}

// ADR-0039 (#630): a session may remove the exact worktree it created —
// the creation record is same-session audit evidence, the match is the
// exact path, and everything else keeps today's ask.
func TestWindowsAndPOSIXSessionCreatedWorktreeRemoval(t *testing.T) {
	dir := t.TempDir()
	sandbox := func(t *testing.T) {
		testenv.SetState(t, t.TempDir())
		testenv.SetConfig(t, t.TempDir())
		t.Setenv("GUARDRAIL_CONFIG", "")
	}
	remove := func(session, command string) (int, string, string) {
		t.Helper()
		code, payload, _ := claudeHook(t, session, dir, command)
		decision, reason := claudeDecision(payload)
		return code, decision, reason
	}

	t.Run("created this session, exact path", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat -b feat", "allow", time.Minute)
		// Claude allows are silent: exit 0, no permissionDecision payload.
		code, decision, _ := remove("s1", "git worktree remove .worktrees/feat")
		if code != 0 || decision != "" {
			t.Fatalf("code=%d decision=%q; want the silent provenance allow", code, decision)
		}
	})

	t.Run("with --force", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat", "allow", time.Minute)
		code, decision, _ := remove("s1", "git worktree remove --force .worktrees/feat")
		if code != 0 || decision != "" {
			t.Fatalf("code=%d decision=%q; want allow", code, decision)
		}
	})

	t.Run("absolute creation, relative removal", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", "git worktree add "+dir+"/.worktrees/feat", "allow", time.Minute)
		code, decision, _ := remove("s1", "git worktree remove .worktrees/feat")
		if code != 0 || decision != "" {
			t.Fatalf("code=%d decision=%q; want allow", code, decision)
		}
	})

	t.Run("no creation record", func(t *testing.T) {
		sandbox(t)
		_, decision, reason := remove("s1", "git worktree remove .worktrees/feat")
		if decision != "ask" || !strings.Contains(reason, "worktree") {
			t.Fatalf("decision=%q reason=%q; want the ordinary ask", decision, reason)
		}
	})

	t.Run("another session created it", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s2", "git worktree add .worktrees/feat", "allow", time.Minute)
		_, decision, _ := remove("s1", "git worktree remove .worktrees/feat")
		if decision != "ask" {
			t.Fatalf("decision=%q; cross-session provenance must not count", decision)
		}
	})

	t.Run("different path", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat", "allow", time.Minute)
		_, decision, _ := remove("s1", "git worktree remove .worktrees/other")
		if decision != "ask" {
			t.Fatalf("decision=%q; a different path must not inherit provenance", decision)
		}
	})

	t.Run("creation was denied", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat", "deny", time.Minute)
		_, decision, _ := remove("s1", "git worktree remove .worktrees/feat")
		if decision != "ask" {
			t.Fatalf("decision=%q; a denied creation is not evidence", decision)
		}
	})

	t.Run("creation evidence expired", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat", "allow", 25*time.Hour)
		_, decision, _ := remove("s1", "git worktree remove .worktrees/feat")
		if decision != "ask" {
			t.Fatalf("decision=%q; stale provenance must not count", decision)
		}
	})
}

// The allowance must be auditable: the allow record carries the rule and
// the provenance reason.
func TestWindowsAndPOSIXWorktreeProvenanceAllowIsAudited(t *testing.T) {
	dir := t.TempDir()
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat", "allow", time.Minute)
	if _, payload, _ := claudeHook(t, "s1", dir, "git worktree remove .worktrees/feat"); true {
		_ = payload
	}
	raw, err := os.ReadFile(audit.DefaultPath(""))
	if err != nil {
		t.Fatal(err)
	}
	allowSeen := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec audit.Record
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.Decision == "allow" && strings.Contains(rec.Command, "git worktree remove") {
			allowSeen = strings.Contains(rec.Reason, "created by this session")
		}
	}
	if !allowSeen {
		t.Fatalf("no audited provenance allow in %s", raw)
	}
}
