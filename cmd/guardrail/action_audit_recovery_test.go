package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

// #441: recovery reads every other transaction's journal to finish ones a
// crash left behind. Under concurrent grants it met journals that live
// transactions were replacing or removing, returned that as an error, and the
// live grant failed (TestConcurrentRepositoryGrantsRetainEveryHost, Windows,
// full suite). A journal that has vanished or is held open belongs to a live
// transaction; recovery skips it.
func TestActionAuditRecoverySkipsJournalsOfLiveTransactions(t *testing.T) {
	setOperatorEnv(t)
	own, err := actionAuditPath("own")
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := actionAuditPath("sibling")
	if err != nil {
		t.Fatal(err)
	}
	journal := actionAuditJournal{Record: actionAuditRecord(approval.Request{ID: "sibling", Action: "web-host-grant"}, "completed")}
	if err := writeActionAuditJournal(sibling, journal); err != nil {
		t.Fatal(err)
	}
	saved := readActionAuditJournal
	t.Cleanup(func() { readActionAuditJournal = saved })

	// Removed between ReadDir and the read.
	readActionAuditJournal = func(path string) (actionAuditJournal, error) {
		if filepath.Clean(path) == filepath.Clean(sibling) {
			return actionAuditJournal{}, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
		}
		return saved(path)
	}
	if err := recoverActionAuditsExcept(own); err != nil {
		t.Fatalf("a vanished sibling journal failed recovery: %v", err)
	}

	// A journal that is genuinely broken still fails recovery: skipping is
	// only for the live-transaction cases.
	readActionAuditJournal = func(path string) (actionAuditJournal, error) {
		return actionAuditJournal{}, os.ErrPermission
	}
	if err := recoverActionAuditsExcept(own); err == nil {
		t.Fatal("an unreadable journal was skipped; only vanished or in-use ones may be")
	}
}
