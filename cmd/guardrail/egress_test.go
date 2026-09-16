package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestApprovedWebHostGrantAndRevokeMutateOnlyRequestedScope(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	if err := executeWebHostApproval(approval.Request{RepoRoot: repo, Host: "api.example.test", Scope: approval.RepoScope, Action: "web-host-grant"}); err != nil {
		t.Fatal(err)
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !op.AllowsWebHost(repo, "api.example.test") {
		t.Fatal("repository authorization was not written")
	}
	ov, err := policy.LoadOverlay(filepath.Join(repo, "guardrail.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ov.WebHosts) != 1 || ov.WebHosts[0] != "api.example.test" {
		t.Fatalf("overlay web hosts = %v", ov.WebHosts)
	}
	if err := executeWebHostApproval(approval.Request{RepoRoot: repo, Host: "api.example.test", Scope: approval.RepoScope, Action: "web-host-revoke"}); err != nil {
		t.Fatal(err)
	}
	op, err = policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if op.AllowsWebHost(repo, "api.example.test") {
		t.Fatal("repository authorization was not revoked")
	}
	ov, err = policy.LoadOverlay(filepath.Join(repo, "guardrail.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ov.WebHosts) != 0 {
		t.Fatalf("overlay web hosts = %v, want none", ov.WebHosts)
	}
}

func TestApprovedGlobalWebHostGrantDoesNotModifyOverlay(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	if err := executeWebHostApproval(approval.Request{RepoRoot: repo, Host: "global.example.test", Scope: approval.GlobalScope, Action: "web-host-grant"}); err != nil {
		t.Fatal(err)
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !op.AllowsGlobalWebHost("global.example.test") {
		t.Fatal("global authorization was not written")
	}
	if _, err := policy.LoadOverlay(filepath.Join(repo, "guardrail.toml")); err == nil {
		t.Fatal("global grant created a repository overlay")
	}
}

func TestRejectedOverlayLeavesOperatorGrantUnchanged(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	if err := executeWebHostApproval(approval.Request{RepoRoot: repo, Host: "existing.example.test", Scope: approval.RepoScope, Action: "web-host-grant"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "guardrail.toml"), []byte("[slots\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := executeWebHostApproval(approval.Request{RepoRoot: repo, Host: "new.example.test", Scope: approval.RepoScope, Action: "web-host-grant"}); err == nil {
		t.Fatal("invalid overlay was accepted")
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if op.AllowsWebHost(repo, "new.example.test") {
		t.Fatal("operator grant was committed despite rejected overlay")
	}
}

func TestCompletedWebHostMutationWritesAuditRecord(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	if err := executeWebHostApproval(approval.Request{ID: "web-host-request", Plane: "opencode", RepoRoot: repo, Host: "api.example.test", Scope: approval.RepoScope, Action: "web-host-grant"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(audit.DefaultPath(""))
	if err != nil {
		t.Fatal(err)
	}
	var rec audit.Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.OperatorAction != "web-host-grant" || rec.Decision != "completed" || rec.RequestID != "web-host-request" {
		t.Fatalf("audit record = %+v, want completed web-host mutation", rec)
	}
}
