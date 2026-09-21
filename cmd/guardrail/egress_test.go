package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestApprovedWebHostGrantAndRevokeMutateOnlyRequestedScope(t *testing.T) {
	testenv.SetConfig(t, t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	if err := executeWebHostApproval(approval.Request{RepoRoot: repo, Parameters: map[string]string{"hosts": "api.example.test"}, Scope: approval.RepoScope, Action: "web-host-grant"}); err != nil {
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
	if err := executeWebHostApproval(approval.Request{RepoRoot: repo, Parameters: map[string]string{"hosts": "api.example.test"}, Scope: approval.RepoScope, Action: "web-host-revoke"}); err != nil {
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
	testenv.SetConfig(t, t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	if err := executeWebHostApproval(approval.Request{RepoRoot: repo, Parameters: map[string]string{"hosts": "global.example.test"}, Scope: approval.GlobalScope, Action: "web-host-grant"}); err != nil {
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
	testenv.SetConfig(t, t.TempDir())
	repo := filepath.Join(t.TempDir(), "repo")
	if err := executeWebHostApproval(approval.Request{RepoRoot: repo, Parameters: map[string]string{"hosts": "existing.example.test"}, Scope: approval.RepoScope, Action: "web-host-grant"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "guardrail.toml"), []byte("[slots\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := executeWebHostApproval(approval.Request{RepoRoot: repo, Parameters: map[string]string{"hosts": "new.example.test"}, Scope: approval.RepoScope, Action: "web-host-grant"}); err == nil {
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
	setOperatorEnv(t)
	repo := filepath.Join(t.TempDir(), "repo")
	if err := executeWebHostApproval(approval.Request{ID: "web-host-request", Plane: "opencode", RepoRoot: repo, Parameters: map[string]string{"hosts": "api.example.test"}, Scope: approval.RepoScope, Action: "web-host-grant", CredentialFingerprint: "a1b2c3d4e5f60708", Transport: "webauthn"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(audit.DefaultPath(""))
	if err != nil {
		t.Fatal(err)
	}
	var rec audit.Record
	if err := json.Unmarshal([]byte(strings.Split(strings.TrimSpace(string(raw)), "\n")[1]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.OperatorAction != "web-host-grant" || rec.Decision != "completed" || rec.RequestID != "web-host-request" || rec.CredentialFingerprint != "a1b2c3d4e5f60708" || rec.Transport != "webauthn" {
		t.Fatalf("audit record = %+v, want completed web-host mutation", rec)
	}
}

func TestWebHostDoesNotMutateWhenAuditIntentFails(t *testing.T) {
	setOperatorEnv(t)
	repo := filepath.Join(t.TempDir(), "repo")
	previous := writeActionAudit
	writeActionAudit = func(audit.Record, string) error { return os.ErrPermission }
	t.Cleanup(func() { writeActionAudit = previous })
	err := executeWebHostApproval(approval.Request{ID: "web-host-audit-intent", Plane: "opencode", RepoRoot: repo, Parameters: map[string]string{"hosts": "api.example.test"}, Scope: approval.RepoScope, Action: "web-host-grant"})
	if err == nil {
		t.Fatal("web-host action succeeded despite an unwritable audit intent")
	}
	if _, err := os.Stat(filepath.Join(repo, "guardrail.toml")); !os.IsNotExist(err) {
		t.Fatalf("overlay exists after intent failure: %v", err)
	}
}

func TestWebHostCompletionAuditFailureKeepsCompletedActionRecoverable(t *testing.T) {
	setOperatorEnv(t)
	repo := filepath.Join(t.TempDir(), "repo")
	previous := writeActionAudit
	calls := 0
	writeActionAudit = func(rec audit.Record, path string) error {
		calls++
		if rec.Decision == "completed" && calls == 2 {
			return os.ErrPermission
		}
		return audit.Write(rec, path)
	}
	t.Cleanup(func() { writeActionAudit = previous })
	if err := executeWebHostApproval(approval.Request{ID: "web-host-audit-completion", Plane: "opencode", RepoRoot: repo, Parameters: map[string]string{"hosts": "api.example.test"}, Scope: approval.RepoScope, Action: "web-host-grant"}); err != nil {
		t.Fatalf("mutated action was reported denied: %v", err)
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil || !op.AllowsWebHost(repo, "api.example.test") {
		t.Fatalf("web-host mutation missing after completion audit failure: %v", err)
	}
	writeActionAudit = audit.Write
	if err := recoverActionAudits(); err != nil {
		t.Fatalf("recover completion audit: %v", err)
	}
}

func TestWebHostRecoveryReplayIsStateIdempotent(t *testing.T) {
	for _, action := range []string{"web-host-grant", "web-host-revoke"} {
		t.Run(action, func(t *testing.T) {
			setOperatorEnv(t)
			repo := filepath.Join(t.TempDir(), "repo")
			host := "replay.example.test"
			if err := os.MkdirAll(repo, 0o755); err != nil {
				t.Fatal(err)
			}
			if action == "web-host-revoke" {
				if err := applyRepoWebHost(repo, host, true); err != nil {
					t.Fatal(err)
				}
			}
			r := approval.Request{ID: action + "-crash-window", Plane: "opencode", RepoRoot: repo, Scope: approval.RepoScope, Action: action, Parameters: map[string]string{"hosts": host}}
			if alreadyCompleted, err := startActionAudit(r); err != nil || alreadyCompleted {
				t.Fatalf("start action audit = completed %t, error %v", alreadyCompleted, err)
			}
			if err := applyRepoWebHost(repo, host, action == "web-host-grant"); err != nil {
				t.Fatal(err)
			}
			if err := executeWebHostApproval(r); err != nil {
				t.Fatal(err)
			}
			op, err := policy.LoadOperatorConfig()
			if err != nil {
				t.Fatal(err)
			}
			if got, want := op.AllowsWebHost(repo, host), action == "web-host-grant"; got != want {
				t.Fatalf("host grant after replay = %t, want %t", got, want)
			}
			raw, err := os.ReadFile(audit.DefaultPath(""))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(string(raw), `"request_id":"`+r.ID+`"`); got != 2 {
				t.Fatalf("logical action audit records = %d, want requested and completed once", got)
			}
		})
	}
}

func TestConcurrentRepositoryGrantsRetainEveryHost(t *testing.T) {
	setOperatorEnv(t)
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
			errs <- executeWebHostApproval(approval.Request{ID: "concurrent-" + host, RepoRoot: repo, Scope: approval.RepoScope, Action: "web-host-grant", Parameters: map[string]string{"hosts": host}})
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
	setOperatorEnv(t)
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
	setOperatorEnv(t)
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
	setOperatorEnv(t)
	repo := filepath.Join(t.TempDir(), "repo")
	journalPath, err := allowanceJournalPath(repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(journalPath), 0o755); err != nil {
		t.Fatal(err)
	}
	// On Windows the 0o755 mode conveys nothing: an unsafe directory is one
	// whose ACL grants a broad group, so widen it explicitly.
	if err := widenArtifactForTest(filepath.Dir(journalPath)); err != nil {
		t.Fatal(err)
	}
	// The invariant is repair-or-reject, never a violating grant: before the
	// action-audit gate lifted, this flow died at that gate and the test
	// passed for the wrong reason. With the gates lifted, ensureAllowanceDir
	// must either stamp the widened directory owner-only before any journal
	// is written, or reject the grant. Either way, no artifact inside may
	// carry a broad-group ACE afterward.
	grantErr := executeWebHostApproval(approval.Request{RepoRoot: repo, Parameters: map[string]string{"hosts": "unsafe.example.test"}, Scope: approval.RepoScope, Action: "web-host-grant"})
	if grantErr != nil {
		return // rejected: fail-closed honored
	}
	assertJournalDirPrivate(t, filepath.Dir(journalPath))
}

func TestConcurrentRepositoryGrantsAcrossReposRetainEveryHost(t *testing.T) {
	setOperatorEnv(t)
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
			errs <- executeWebHostApproval(approval.Request{ID: "concurrent-" + host, RepoRoot: repo, Scope: approval.RepoScope, Action: "web-host-grant", Parameters: map[string]string{"hosts": host}})
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
	setOperatorEnv(t)
	repo := filepath.Join(t.TempDir(), "repo")
	// Distinct logical actions require distinct idempotency-journal identities.
	requests := []approval.Request{
		{ID: "concurrent-global", RepoRoot: repo, Parameters: map[string]string{"hosts": "global.example.test"}, Scope: approval.GlobalScope, Action: "web-host-grant"},
		{ID: "concurrent-repo", RepoRoot: repo, Scope: approval.RepoScope, Action: "web-host-grant", Parameters: map[string]string{"hosts": "repo.example.test"}},
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

func TestExecuteWebHostApprovalGrantsHostBatchAtomically(t *testing.T) {
	repo := t.TempDir()
	setOperatorEnv(t)
	r := approval.Request{ID: "web-host-batch-1", Plane: "opencode", RepoRoot: repo, Scope: approval.RepoScope, Action: "web-host-grant", Parameters: map[string]string{"scope": "repo", "hosts": "api.example.com,cdn.example.com"}}
	if err := executeWebHostApproval(r); err != nil {
		t.Fatal(err)
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !op.AllowsWebHost(repo, "api.example.com") || !op.AllowsWebHost(repo, "cdn.example.com") {
		t.Fatal("batch host not granted")
	}
	if err := executeWebHostApproval(r); err != nil {
		t.Fatalf("replay: %v", err)
	}
}

func TestApplyWebHostBatchRollsBackAppliedHosts(t *testing.T) {
	var calls []string
	failOn := "cdn.example.com"
	apply := func(host string, grant bool) error {
		if host == failOn && grant {
			return fmt.Errorf("simulated failure")
		}
		calls = append(calls, fmt.Sprintf("%s=%v", host, grant))
		return nil
	}
	err := applyWebHostBatch([]string{"api.example.com", "cdn.example.com", "extra.example.com"}, true, apply)
	if err == nil {
		t.Fatal("batch error swallowed")
	}
	want := []string{"api.example.com=true", "api.example.com=false"}
	if !slices.Equal(calls, want) {
		t.Fatalf("calls = %v, want apply then rollback of exactly the applied host: %v", calls, want)
	}
}
