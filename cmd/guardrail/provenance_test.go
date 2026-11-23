package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func createProvenanceWorktree(t *testing.T, dir, wt string) {
	t.Helper()
	provenanceGit(t, dir, "init", "-q")
	provenanceGit(t, dir, "commit", "--allow-empty", "-qm", "base")
	provenanceGit(t, dir, "update-ref", "refs/remotes/origin/main", "HEAD")
	provenanceGit(t, dir, "worktree", "add", "--detach", wt)
}

func provenanceGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgSign=false", "-c", "core.hooksPath="}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

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
// sandboxWorktreeProvenance isolates state, config and the audit log a
// provenance test reads and writes.
func sandboxWorktreeProvenance(t *testing.T) {
	t.Helper()
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
}

func TestWindowsAndPOSIXSessionCreatedWorktreeRemoval(t *testing.T) {
	dir := t.TempDir()
	createProvenanceWorktree(t, dir, ".worktrees/feat")
	sandbox := sandboxWorktreeProvenance
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
		code, decision, reason := remove("s1", "git worktree remove .worktrees/feat")
		if code != 0 || decision != "" {
			t.Fatalf("code=%d decision=%q reason=%q; want the silent provenance allow", code, decision, reason)
		}
	})

	t.Run("local commits and files still require approval", func(t *testing.T) {
		sandbox(t)
		wt := filepath.Join(dir, ".worktrees", "local")
		provenanceGit(t, dir, "worktree", "add", "--detach", wt)
		seedWorktreeCreation(t, "s1", "git worktree add --detach .worktrees/local", "allow", time.Minute)
		provenanceGit(t, wt, "commit", "--allow-empty", "-qm", "unpublished")
		_, decision, _ := remove("s1", "git worktree remove .worktrees/local")
		if decision != "ask" {
			t.Errorf("unpublished commit: decision=%q; want ask", decision)
		}
		provenanceGit(t, wt, "update-ref", "refs/remotes/origin/main", "HEAD")
		file := filepath.Join(wt, "draft.txt")
		if err := os.WriteFile(file, []byte("draft"), 0600); err != nil {
			t.Fatal(err)
		}
		_, decision, _ = remove("s1", "git worktree remove .worktrees/local")
		if decision != "ask" {
			t.Fatalf("untracked draft: decision=%q; want ask", decision)
		}
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("forced removal still asks even with creation provenance", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat", "allow", time.Minute)
		for _, flag := range []string{"--force", "-f", "-ff"} {
			_, decision, _ := remove("s1", "git worktree remove "+flag+" .worktrees/feat")
			if decision != "ask" {
				t.Errorf("%s: decision=%q; want ask", flag, decision)
			}
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

	// #151 delta sweep: provenance must NEVER relax compound commands,
	// non-literal expansions, redirections/env overrides, or -C directory shifts.
	t.Run("compound command smuggling second worktree remove", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat", "allow", time.Minute)
		_, decision, _ := remove("s1", "git worktree remove .worktrees/feat && git worktree remove .worktrees/other")
		if decision != "ask" {
			t.Fatalf("decision=%q; compound worktree remove must not inherit provenance allow", decision)
		}
	})

	t.Run("compound command smuggling another ask", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat", "allow", time.Minute)
		_, decision, _ := remove("s1", "git worktree remove .worktrees/feat && git branch -D main")
		if decision != "ask" {
			t.Fatalf("decision=%q; compound command with git branch -D must not inherit provenance allow", decision)
		}
	})

	t.Run("variable suffix expansion must not match literal prefix", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat", "allow", time.Minute)
		_, decision, _ := remove("s1", "git worktree remove .worktrees/feat$EXTRA")
		if decision != "ask" {
			t.Fatalf("decision=%q; dynamic variable suffix must not inherit provenance allow", decision)
		}
	})

	t.Run("git -C into another repo must not match cwd creation", func(t *testing.T) {
		sandbox(t)
		otherRepo := t.TempDir()
		seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat", "allow", time.Minute)
		_, decision, _ := remove("s1", "git -C "+otherRepo+" worktree remove .worktrees/feat")
		if decision != "ask" {
			t.Fatalf("decision=%q; git -C into a different repo must not match cwd provenance", decision)
		}
	})

	t.Run("redirection or env override on remove must not inherit provenance", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", "git worktree add .worktrees/feat", "allow", time.Minute)
		for _, cmd := range []string{
			"git worktree remove .worktrees/feat > out.txt",
			"GIT_DIR=/other git worktree remove .worktrees/feat",
		} {
			_, decision, _ := remove("s1", cmd)
			if decision != "ask" {
				t.Fatalf("%q: decision=%q; want ask", cmd, decision)
			}
		}
	})

	t.Run("quoted literal path still matches", func(t *testing.T) {
		sandbox(t)
		seedWorktreeCreation(t, "s1", `git worktree add ".worktrees/feat"`, "allow", time.Minute)
		code, decision, _ := remove("s1", `git worktree remove '.worktrees/feat'`)
		if code != 0 || decision != "" {
			t.Fatalf("code=%d decision=%q; static quoted literal path should match provenance", code, decision)
		}
	})

	t.Run("matching git -C add and remove allows", func(t *testing.T) {
		sandbox(t)
		otherRepo := t.TempDir()
		createProvenanceWorktree(t, otherRepo, ".worktrees/feat")
		seedWorktreeCreation(t, "s1", "git -C "+otherRepo+" worktree add .worktrees/feat", "allow", time.Minute)
		code, decision, _ := remove("s1", "git -C "+otherRepo+" worktree remove .worktrees/feat")
		if code != 0 || decision != "" {
			t.Fatalf("code=%d decision=%q; matching git -C add/remove should match provenance", code, decision)
		}
	})
}

// #691 field report, Windows rows: the exact command shapes a Git Bash
// session used — forward-slash absolute Windows paths, `--detach` with a
// trailing commit-ish, and Claude Code's auto/bypass permission mode, where
// the remove arrives as a host-auto-escalated deny. Any regression in the
// path canonicalization, the `--detach` parse, or the escalation hook of
// applyWorktreeProvenance makes this fail. (The reporting machine ran
// v0.23.45-dev, which predates #638 entirely: the allowance was never
// installed there. Current builds must keep matching these shapes.) The
// drive-letter `C:/…` spelling materializes on Windows, where the report
// came from; on POSIX the same absolute-path shapes run with their native
// root, so both platforms pin the behavior class.
func TestSessionCreatedWorktreeRemovalMatchesFieldReportWindowsShapes(t *testing.T) {
	dir := t.TempDir()
	wt := filepath.ToSlash(filepath.Join(dir, ".worktrees", "council",
		"2026-11-22-claude-quoting-check", "claude-haiku"))
	createProvenanceWorktree(t, dir, wt)
	add := "git worktree add --detach " + wt + " cf265624a517e0b5591b1d6ad467efab5661492d"
	remove := "git worktree remove " + wt
	removeEnvelope := func(t *testing.T, mode string) string {
		t.Helper()
		envelope := map[string]any{
			"session_id": "s1", "hook_event_name": "PreToolUse",
			"cwd": filepath.ToSlash(dir), "tool_name": "Bash",
			"tool_input": map[string]any{"command": remove},
		}
		if mode != "default" {
			envelope["permission_mode"] = mode
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}

	for _, mode := range []string{"default", "auto", "bypassPermissions"} {
		t.Run("permission mode "+mode, func(t *testing.T) {
			sandboxWorktreeProvenance(t)
			seedWorktreeCreation(t, "s1", add, "allow", time.Minute)
			var out, errb bytes.Buffer
			code := run([]string{"hook", "claude"}, strings.NewReader(removeEnvelope(t, mode)), &out, &errb)
			var decoded map[string]any
			_ = json.Unmarshal(out.Bytes(), &decoded)
			// Claude allows are silent: exit 0, no permissionDecision —
			// including under auto/bypass, where without the creation
			// record the same call is a host-auto deny.
			if decision, reason := claudeDecision(decoded); code != 0 || decision != "" {
				t.Fatalf("mode=%s code=%d decision=%q reason=%q; want the silent provenance allow", mode, code, decision, reason)
			}
		})
	}

	// Counterfactual (review of #691): the same shapes without a creation
	// record keep the ordinary outcomes, so the loop above cannot pass
	// vacuously through an over-allowing escalation path — under auto and
	// bypass the remove stays the host-auto deny.
	for _, mode := range []string{"auto", "bypassPermissions"} {
		t.Run("no creation record, permission mode "+mode, func(t *testing.T) {
			sandboxWorktreeProvenance(t)
			var out, errb bytes.Buffer
			code := run([]string{"hook", "claude"}, strings.NewReader(removeEnvelope(t, mode)), &out, &errb)
			if code != 2 || !strings.Contains(errb.String(), "auto/bypass permission mode") {
				t.Fatalf("mode=%s code=%d stderr=%q; want the host-auto deny", mode, code, errb.String())
			}
		})
	}
}

// The allowance must be auditable: the allow record carries the rule and
// the provenance reason.
func TestWindowsAndPOSIXWorktreeProvenanceAllowIsAudited(t *testing.T) {
	dir := t.TempDir()
	createProvenanceWorktree(t, dir, ".worktrees/feat")
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
