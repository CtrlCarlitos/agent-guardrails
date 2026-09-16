package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
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

func TestConcurrentRepositoryGrantsRetainEveryHost(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	hosts := []string{"one.example.test", "two.example.test", "three.example.test", "four.example.test"}
	start := make(chan struct{})
	errs := make(chan error, len(hosts))
	var wg sync.WaitGroup
	for _, host := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- executeWebHostApproval(approval.Request{RepoRoot: repo, Host: host, Scope: approval.RepoScope, Action: "web-host-grant"})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	ov, err := policy.LoadOverlay(filepath.Join(repo, "guardrail.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range hosts {
		if !op.AllowsWebHost(repo, host) {
			t.Fatalf("operator config lost concurrent host %q", host)
		}
		found := false
		for _, existing := range ov.WebHosts {
			found = found || existing == host
		}
		if !found {
			t.Fatalf("overlay lost concurrent host %q", host)
		}
	}
}

func TestAllowanceJournalRecoversAfterOverlayWriteBeforeOperatorWrite(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	host := "crash-window.example.test"
	overlayPath := filepath.Join(repo, "guardrail.toml")
	overlay, mode, _, _, err := overlayWebHostContent(overlayPath, host, true)
	if err != nil {
		t.Fatal(err)
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	op.Repos[repo] = policy.RepoGrant{WebHosts: []string{host}}
	operator, err := operatorConfigContent(op)
	if err != nil {
		t.Fatal(err)
	}
	journalPath, err := allowanceJournalPath(repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(journalPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAllowanceJournal(journalPath, allowanceJournal{OverlayPath: overlayPath, OverlayAfter: overlay, OverlayMode: uint32(mode), OperatorPath: policy.OperatorConfigPath(), OperatorAfter: operator}); err != nil {
		t.Fatal(err)
	}
	// Model a process crash after the first durable document replacement.
	if err := writePrivateFile(overlayPath, overlay, mode); err != nil {
		t.Fatal(err)
	}
	if err := recoverAllowanceJournal(journalPath); err != nil {
		t.Fatal(err)
	}
	op, err = policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !op.AllowsWebHost(repo, host) {
		t.Fatal("recovery did not complete operator grant")
	}
	ov, err := policy.LoadOverlay(overlayPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(ov.WebHosts) != 1 || ov.WebHosts[0] != host {
		t.Fatalf("recovered overlay web hosts = %v", ov.WebHosts)
	}
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Fatalf("journal remained after recovery: %v", err)
	}
}

func TestForgedAllowanceJournalCannotGrantHost(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	journalPath, err := allowanceJournalPath(repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(journalPath), 0o700); err != nil {
		t.Fatal(err)
	}
	forged := allowanceJournal{OverlayPath: filepath.Join(repo, "guardrail.toml"), OverlayAfter: []byte("[slots]\nweb_hosts = [\"forged.example.test\"]\n"), OverlayMode: 0o644, OperatorPath: policy.OperatorConfigPath(), OperatorAfter: []byte("[web_hosts]\nglobal = [\"forged.example.test\"]\n")}
	if err := writePrivateFile(journalPath, mustJSON(t, forged), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverAllowanceJournal(journalPath); err == nil {
		t.Fatal("forged journal was accepted")
	}
	if _, err := os.Stat(policy.OperatorConfigPath()); !os.IsNotExist(err) {
		t.Fatalf("forged journal wrote operator config: %v", err)
	}
}

func TestUnsafeAllowanceJournalDirectoryIsRejected(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	journalPath, err := allowanceJournalPath(repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(journalPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := executeWebHostApproval(approval.Request{RepoRoot: repo, Host: "unsafe.example.test", Scope: approval.RepoScope, Action: "web-host-grant"}); err == nil {
		t.Fatal("grant accepted an unsafe journal directory")
	}
}

func TestConcurrentRepositoryGrantsAcrossReposRetainEveryHost(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	repos := []string{filepath.Join(t.TempDir(), "one"), filepath.Join(t.TempDir(), "two")}
	start := make(chan struct{})
	errs := make(chan error, len(repos))
	var wg sync.WaitGroup
	for i, repo := range repos {
		host := []string{"one.example.test", "two.example.test"}[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- executeWebHostApproval(approval.Request{RepoRoot: repo, Host: host, Scope: approval.RepoScope, Action: "web-host-grant"})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	for i, repo := range repos {
		if !op.AllowsWebHost(repo, []string{"one.example.test", "two.example.test"}[i]) {
			t.Fatalf("operator config lost concurrent repository grant for %q", repo)
		}
	}
}

func TestConcurrentGlobalAndRepositoryGrantsRetainEveryHost(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	requests := []approval.Request{
		{RepoRoot: repo, Host: "global.example.test", Scope: approval.GlobalScope, Action: "web-host-grant"},
		{RepoRoot: repo, Host: "repo.example.test", Scope: approval.RepoScope, Action: "web-host-grant"},
	}
	start := make(chan struct{})
	errs := make(chan error, len(requests))
	var wg sync.WaitGroup
	for _, request := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- executeWebHostApproval(request)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !op.AllowsGlobalWebHost("global.example.test") || !op.AllowsWebHost(repo, "repo.example.test") {
		t.Fatalf("operator config lost mixed grant: %+v", op)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
