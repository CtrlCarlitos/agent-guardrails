package actiongrant

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWindowsAndPOSIXActionGrantAuditFailureCannotAuthorize(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "actions")}
	a := testAction(t)
	now := time.Now().UTC()
	r, err := s.Create(a, now)
	if err != nil {
		t.Fatal(err)
	}
	auditFailure := errors.New("audit unavailable")
	err = s.AuthorizeWithAudit(r.ID, r.Digest, "terminal-prompt", now, func(Request) error { return auditFailure })
	if !errors.Is(err, auditFailure) {
		t.Fatalf("authorization error: %v", err)
	}
	if _, spent, err := s.Consume(a, now); err != nil || spent {
		t.Fatalf("failed audit authorized: %v %v", spent, err)
	}
	if err := s.AuthorizeWithAudit(r.ID, r.Digest, "terminal-prompt", now, func(got Request) error {
		if got.ID != r.ID || got.Digest != r.Digest {
			t.Fatal("audit action mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, spent, err := s.Consume(a, now); err != nil || !spent {
		t.Fatalf("successful audit: %v %v", spent, err)
	}
}

func testAction(t *testing.T) Action {
	t.Helper()
	repo := t.TempDir()
	return Action{Plane: "codex", Session: "session", Repo: repo, CWD: repo, Tool: "apply_patch", Rule: "P5.ci-infra-lockfile", Kind: "patch", Text: "*** Begin Patch\n*** Add File: .github/workflows/check.yml\n+name: check\n*** End Patch", Paths: []string{filepath.Join(repo, ".github", "workflows", "check.yml")}}
}

func authorizeFixture(s Store, id, digest, transport string, now time.Time) error {
	return s.AuthorizeWithAudit(id, digest, transport, now, func(Request) error { return nil })
}

func TestWindowsAndPOSIXActionGrantRejectsLossyJSONText(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "actions")}
	a := testAction(t)
	a.Text = "invalid byte: \xff"
	if _, err := s.Create(a, time.Now()); err == nil {
		t.Fatal("JSON would replace invalid UTF-8 and lose exact text")
	}
}

func TestWindowsAndPOSIXActionGrantTamperedRecordFailsClosed(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "actions")}
	a := testAction(t)
	now := time.Now()
	r, err := s.Create(a, now)
	if err != nil {
		t.Fatal(err)
	}
	r.Action.Text += "changed"
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, r.ID+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := authorizeFixture(s, r.ID, r.Digest, "terminal-prompt", now); err == nil {
		t.Fatal("tampered record approved")
	}
	if _, spent, err := s.Consume(a, now); err == nil || spent {
		t.Fatalf("tampered store allowed: %v %v", spent, err)
	}
}

func TestWindowsAndPOSIXActionGrantStoreBoundsLiveRequestsAndPrunesExpired(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "actions")}
	a := testAction(t)
	a.Tool, a.Kind, a.Rule, a.Paths = "Bash", "command", "P6.package-install", nil
	now := time.Now()
	for i := 0; i < maxRecords; i++ {
		a.Text = fmt.Sprintf("npm install fixture-%d", i)
		if _, err := s.Create(a, now); err != nil {
			t.Fatal(err)
		}
	}
	a.Text = "npm install one-too-many"
	if _, err := s.Create(a, now); err == nil {
		t.Fatal("live request bound was not enforced")
	}
	if _, err := s.Create(a, now.Add(TTL+time.Second)); err != nil {
		t.Fatalf("expired requests did not release capacity: %v", err)
	}
}

func TestWindowsAndPOSIXActionGrantMatchesExactlyAndOnlyOnce(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "actions")}
	a := testAction(t)
	now := time.Now().UTC()
	r, err := s.Create(a, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizeFixture(s, r.ID, r.Digest, "terminal-prompt", now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Action){
		func(a *Action) { a.Text += "\n" },
		func(a *Action) { a.Rule = "P5.out-of-repo" },
		func(a *Action) { a.Session = "other" },
		func(a *Action) { a.CWD = filepath.Dir(a.CWD) },
		func(a *Action) { a.Repo = filepath.Dir(a.Repo) },
		func(a *Action) { a.Tool = "Bash" },
		func(a *Action) { a.Paths = []string{filepath.Join(a.Repo, "other")} },
	} {
		other := a
		change(&other)
		if _, ok, err := s.Consume(other, now); err != nil || ok {
			t.Fatalf("mismatch consumed: %v %v", ok, err)
		}
	}
	if _, ok, err := s.Consume(a, now); err != nil || !ok {
		t.Fatalf("exact retry: %v %v", ok, err)
	}
	if _, ok, err := s.Consume(a, now); err != nil || ok {
		t.Fatalf("second retry: %v %v", ok, err)
	}
}

func TestWindowsAndPOSIXActionGrantConcurrentConsumption(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "actions")}
	a := testAction(t)
	now := time.Now().UTC()
	r, err := s.Create(a, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizeFixture(s, r.ID, r.Digest, "terminal-prompt", now); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := s.Consume(a, now)
			if err != nil {
				t.Error(err)
			}
			results <- ok
		}()
	}
	wg.Wait()
	close(results)
	n := 0
	for ok := range results {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d consumers allowed", n)
	}
}

func TestWindowsAndPOSIXActionGrantExpiryRevocationAndExclusions(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "actions")}
	a := testAction(t)
	now := time.Now().UTC()
	r, err := s.Create(a, now)
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.Create(a, now.Add(time.Minute))
	if err != nil || same.ID != r.ID || !same.Expires.Equal(r.Expires) {
		t.Fatalf("retry extended request: %+v %v", same, err)
	}
	if err := authorizeFixture(s, r.ID, r.Digest, "terminal-prompt", now.Add(16*time.Minute)); err == nil {
		t.Fatal("expired approval accepted")
	}
	if err := authorizeFixture(s, r.ID, "changed", "terminal-prompt", now); err == nil {
		t.Fatal("changed digest accepted")
	}
	if err := s.Revoke(r.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := authorizeFixture(s, r.ID, r.Digest, "terminal-prompt", now); err == nil {
		t.Fatal("revoked request approved")
	}
	for _, rule := range []string{"P3.unresolved", "tokenize-failed", "capability-external", "P1.power"} {
		a.Rule = rule
		if _, err := s.Create(a, now); err == nil {
			t.Fatalf("created excluded %s", rule)
		}
	}
	if _, err := s.Read("../other", now); err == nil {
		t.Fatal("accepted path traversal ID")
	}
}
