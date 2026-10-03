package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/actiongrant"
	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestWindowsAndPOSIXRecordGrantRequiresTerminalShowsPatchAndDecline(t *testing.T) {
	home := t.TempDir()
	t.Setenv("APPDATA", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	s, err := actiongrant.Default()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	patch := "*** Begin Patch\n*** Add File: .github/workflows/ci.yml\n+name: approved\n*** End Patch"
	a := actiongrant.Action{Plane: "codex", Session: "s", Repo: repo, CWD: repo, Tool: "apply_patch", Kind: "patch", Rule: "P5.ci-infra-lockfile", Text: patch, Paths: []string{filepath.Join(repo, ".github", "workflows", "ci.yml")}}
	r, err := s.Create(a, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := cmdApprovalsGrant([]string{"--record", r.ID}, false, strings.NewReader("yes\n"), &out, &errs); code != 2 {
		t.Fatalf("non-terminal: %d %s", code, errs.String())
	}
	useApprovalMode(t, policy.ApprovalPrompt)
	out.Reset()
	errs.Reset()
	if code := cmdApprovalsGrant([]string{"--record", r.ID}, true, strings.NewReader("no\n"), &out, &errs); code != 1 {
		t.Fatalf("decline: %d %s", code, errs.String())
	}
	if !strings.Contains(out.String(), patch) || !strings.Contains(out.String(), repo) {
		t.Fatalf("ceremony lost exact action: %s", out.String())
	}
	if _, ok, err := s.Consume(a, time.Now()); err != nil || ok {
		t.Fatalf("declined grant consumed: %v %v", ok, err)
	}
	out.Reset()
	errs.Reset()
	if code := cmdApprovalsGrant([]string{"--record", r.ID}, true, strings.NewReader("yes\n"), &out, &errs); code != 0 {
		t.Fatalf("approval: %d %s", code, errs.String())
	}
	if _, ok, err := s.Consume(a, time.Now()); err != nil || !ok {
		t.Fatalf("approved action not consumed: %v %v", ok, err)
	}
}

func TestWindowsAndPOSIXExactActionPasskeyRequiresEnrollmentAndBrokerAttribution(t *testing.T) {
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	useApprovalMode(t, policy.ApprovalPasskey)
	s, err := actiongrant.Default()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	a := actiongrant.Action{Plane: "codex", Session: "s", Repo: repo, CWD: repo, Tool: "Bash", Kind: "command", Rule: "P6.package-install", Text: "npm install fixture"}
	r, err := s.Create(a, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := cmdRecordGrant([]string{"--record", r.ID}, true, strings.NewReader("yes\n"), &out, &errs); code != 3 || !strings.Contains(errs.String(), "enrolled") {
		t.Fatalf("unenrolled passkey bypass: %d %s", code, errs.String())
	}
	for _, req := range []approval.Request{
		{RepoRoot: repo, Parameters: map[string]string{"record": r.ID, "digest": r.Digest}},
		{RepoRoot: repo, Parameters: map[string]string{"record": r.ID, "digest": r.Digest}, Transport: "terminal-prompt", CredentialFingerprint: "fixture"},
		{RepoRoot: repo, Parameters: map[string]string{"record": r.ID, "digest": r.Digest}, Transport: "webauthn"},
	} {
		if err := executeExactActionGrant(req); err == nil {
			t.Fatal("unattributed broker call authorized")
		}
	}
	if _, spent, err := s.Consume(a, time.Now()); err != nil || spent {
		t.Fatalf("unauthenticated grant: %v %v", spent, err)
	}
}

func TestWindowsAndPOSIXExactActionAuditFailureKeepsRetryBlockedAndSpent(t *testing.T) {
	repo := t.TempDir()
	gitInitSync(t, repo)
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	useApprovalMode(t, policy.ApprovalPrompt)
	patch := "*** Begin Patch\n*** Add File: .github/workflows/ci.yml\n+name: ci\n*** End Patch"
	raw, _ := json.Marshal(map[string]any{"session_id": "audit-session", "cwd": repo, "hook_event_name": "PreToolUse", "tool_name": "apply_patch", "tool_input": map[string]string{"command": patch}})
	var out, errs bytes.Buffer
	run([]string{"hook", "codex"}, bytes.NewReader(raw), &out, &errs)
	records := auditRecordsFor(t, audit.DefaultPath(""))
	id := records[len(records)-1].RequestID
	if id == "" {
		t.Fatal("missing exact request")
	}
	if code := cmdRecordGrant([]string{"--record", id}, true, strings.NewReader("yes\n"), &out, &errs); code != 0 {
		t.Fatalf("grant: %d %s", code, errs.String())
	}
	if err := os.Remove(audit.DefaultPath("")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(audit.DefaultPath(""), 0o700); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errs.Reset()
	if code := run([]string{"hook", "codex"}, bytes.NewReader(raw), &out, &errs); code != 2 || !strings.Contains(errs.String(), "use was consumed") {
		t.Fatalf("failed audit allowed: %d %s %s", code, out.String(), errs.String())
	}
	s, err := actiongrant.Default()
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Read(id, time.Now())
	if err != nil || r.Status != "consumed" {
		t.Fatalf("failed audit refunded use: %+v %v", r, err)
	}
}

func TestWindowsAndPOSIXCodexPatchAskRecordsOneExactApprovalRequest(t *testing.T) {
	repo := t.TempDir()
	gitInitSync(t, repo)
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	useApprovalMode(t, policy.ApprovalPrompt)
	patch := "*** Begin Patch\n*** Add File: .github/workflows/ci.yml\n+name: ci\n*** End Patch"
	call := func(text, event string) audit.Record {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"session_id": "exact-session", "cwd": repo, "hook_event_name": event, "tool_name": "apply_patch", "tool_input": map[string]string{"command": text}})
		var out, errs bytes.Buffer
		run([]string{"hook", "codex"}, bytes.NewReader(raw), &out, &errs)
		records := auditRecordsFor(t, audit.DefaultPath(""))
		rec := records[len(records)-1]
		if rec.Decision == "ask" && event == "PreToolUse" && !strings.Contains(errs.String(), "--record "+rec.RequestID) {
			t.Fatalf("missing actionable guidance: %s", errs.String())
		}
		return rec
	}
	first := call(patch, "PreToolUse")
	if first.Decision != "ask" || first.RequestID == "" {
		t.Fatalf("no durable request: %+v", first)
	}
	retry := call(patch, "PreToolUse")
	if retry.RequestID != first.RequestID {
		t.Fatal("identical pending retry created another request")
	}
	var out, errs bytes.Buffer
	if code := cmdApprovalsGrant([]string{"--record", first.RequestID}, true, strings.NewReader("yes\n"), &out, &errs); code != 0 {
		t.Fatalf("grant: %d %s", code, errs.String())
	}
	changed := call(strings.ReplaceAll(patch, "name: ci", "name: changed"), "PreToolUse")
	if changed.Decision != "ask" {
		t.Fatalf("changed patch allowed: %+v", changed)
	}
	allowed := call(patch, "PreToolUse")
	if allowed.Decision != "allow" || allowed.RuleID != "ask-allowed-by-operator-grant" || allowed.OriginRuleID != first.RuleID {
		t.Fatalf("grant not applied: %+v", allowed)
	}
	spent := call(patch, "PreToolUse")
	if spent.Decision != "ask" {
		t.Fatalf("spent grant allowed: %+v", spent)
	}
	post := call(patch, "PostToolUse")
	if post.RequestID != "" {
		t.Fatal("post edit created an approval request")
	}
}
