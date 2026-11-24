package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/actiongrant"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestWindowsAndPOSIXListPendingActionRecords(t *testing.T) {
	testenv.SetConfig(t, t.TempDir())
	store, err := actiongrant.Default()
	if err != nil {
		t.Fatal(err)
	}
	list := func(terminal bool) (int, string, string) {
		t.Helper()
		var out, errs bytes.Buffer
		code := cmdApprovalsInput([]string{"list", "--records"}, terminal, nil, &out, &errs)
		return code, out.String(), errs.String()
	}
	if code, out, errs := list(true); code != 0 || !strings.Contains(out, "No pending exact-action requests") {
		t.Fatalf("empty queue: %d, %q, %q", code, out, errs)
	}
	if _, err := os.Stat(store.Dir); !os.IsNotExist(err) {
		t.Fatalf("listing created the store or stat failed: %v", err)
	}

	now := time.Now().UTC()
	repo := t.TempDir()
	create := func(text string, at time.Time) actiongrant.Request {
		t.Helper()
		r, err := store.Create(actiongrant.Action{
			Plane: "codex", Session: "fixture", Repo: repo, CWD: repo,
			Tool: "Bash", Rule: "P6.package-install", Kind: "command", Text: text,
		}, at)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	older := create("npm install older", now.Add(-time.Minute))
	newer := create("npm install newer\x1b[2J", now)
	approved := create("npm install approved", now)
	consumed := create("npm install consumed", now)
	for _, r := range []actiongrant.Request{approved, consumed} {
		if err := store.AuthorizeWithAudit(r.ID, r.Digest, "terminal-prompt", now, func(actiongrant.Request) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if _, spent, err := store.Consume(consumed.Action, now); err != nil || !spent {
		t.Fatalf("consume: %v, %v", spent, err)
	}
	revoked := create("npm install revoked", now)
	if err := store.Revoke(revoked.ID, now); err != nil {
		t.Fatal(err)
	}
	expired := create("npm install expired", now.Add(-actiongrant.TTL-time.Minute))

	if code, out, errs := list(false); code != 2 || out != "" || !strings.Contains(errs, "interactive local terminal") {
		t.Fatalf("non-terminal queue: %d, %q, %q", code, out, errs)
	}
	code, out, errs := list(true)
	if code != 0 {
		t.Fatalf("list: %d, %s", code, errs)
	}
	for _, want := range []string{
		"guardrail approvals grant --record " + older.ID,
		"guardrail approvals grant --record " + newer.ID,
		"P6.package-install", "npm install older", `npm install newer\x1b[2J`,
		newer.Expires.Format(time.RFC3339),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("queue lacks %q: %s", want, out)
		}
	}
	if strings.Index(out, newer.ID) > strings.Index(out, older.ID) {
		t.Errorf("newest request should be first: %s", out)
	}
	if strings.ContainsRune(out, '\x1b') {
		t.Errorf("unescaped terminal control in queue: %q", out)
	}
	for _, r := range []actiongrant.Request{approved, consumed, revoked, expired} {
		if strings.Contains(out, r.ID) {
			t.Errorf("listed non-pending request %s", r.ID)
		}
	}
	if _, err := os.Stat(filepath.Join(store.Dir, expired.ID+".json")); err != nil {
		t.Fatalf("listing changed the expired record: %v", err)
	}
}
