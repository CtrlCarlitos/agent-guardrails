package approval_test

import (
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/actiongrant"
	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestWindowsAndPOSIXExactActionBrokerKeepsBodyPrivateAndRejectsChangedBindings(t *testing.T) {
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	s, err := actiongrant.Default()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	patch := "*** Begin Patch\n*** Add File: .github/workflows/ci.yml\n+name: body-must-stay-private\n*** End Patch"
	a := actiongrant.Action{Plane: "codex", Session: "s", Repo: repo, CWD: repo, Tool: "apply_patch", Kind: "patch", Rule: "P5.ci-infra-lockfile", Text: patch, Paths: []string{filepath.Join(repo, ".github/workflows/ci.yml")}}
	r, err := s.Create(a, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	base := approval.Request{Plane: "operator", SessionID: "terminal", RepoRoot: repo, Scope: approval.OnceScope, Reason: "review exact action", Action: "exact-action-grant", Parameters: map[string]string{"record": r.ID, "digest": r.Digest}, ExpiresAt: r.Expires}
	b := approval.New()
	created, err := b.Create(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(created.Summary(), patch) {
		t.Fatal("ceremony did not retrieve complete private patch")
	}
	raw, err := os.ReadFile(approval.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "body-must-stay-private") {
		t.Fatal("broker persisted raw action body")
	}
	browser, pageURL, err := approval.StartBrowser(b, browserStore(t), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close()
	for _, change := range []func(*approval.Request){
		func(r *approval.Request) { r.Plane = "codex" },
		func(r *approval.Request) { r.Scope = approval.GlobalScope },
		func(r *approval.Request) { r.Host = "example.test" },
		func(r *approval.Request) { r.RepoRoot = filepath.Dir(repo) },
		func(r *approval.Request) { r.Parameters["digest"] = "changed" },
		func(r *approval.Request) { r.Parameters["raw"] = patch },
		func(r *approval.Request) { r.ExpiresAt = r.ExpiresAt.Add(time.Second) },
	} {
		bad := base
		bad.Parameters = maps.Clone(base.Parameters)
		change(&bad)
		if _, err := b.Create(bad); err == nil {
			t.Fatalf("changed request accepted: %+v", bad)
		}
	}
	if err := s.Revoke(r.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	response, err := http.Get(pageURL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("browser advertised an unavailable exact action: %d", response.StatusCode)
	}
	if reopened, _, err := approval.StartBrowser(b, browserStore(t), created.ID); err == nil {
		reopened.Close()
		t.Fatal("browser issued a ceremony without a reviewable pending action")
	}
	if _, err := b.Create(base); err == nil {
		t.Fatal("revoked action request accepted")
	}
}
