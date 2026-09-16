package main

import (
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
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
