package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
)

// The error #441 measured: another process holds the sibling journal open.
func TestWindowsActionAuditRecoverySkipsAJournalInUse(t *testing.T) {
	setOperatorEnv(t)
	own, _ := actionAuditPath("own")
	sibling, _ := actionAuditPath("sibling")
	journal := actionAuditJournal{Record: actionAuditRecord(approval.Request{ID: "sibling", Action: "web-host-grant"}, "completed")}
	if err := writeActionAuditJournal(sibling, journal); err != nil {
		t.Fatal(err)
	}
	saved := readActionAuditJournal
	t.Cleanup(func() { readActionAuditJournal = saved })
	for name, errno := range map[string]syscall.Errno{"sharing": 32, "lock": 33} {
		readActionAuditJournal = func(path string) (actionAuditJournal, error) {
			if filepath.Clean(path) == filepath.Clean(sibling) {
				return actionAuditJournal{}, &os.PathError{Op: "open", Path: path, Err: errno}
			}
			return saved(path)
		}
		if err := recoverActionAuditsExcept(own); err != nil {
			t.Errorf("%s violation on a sibling journal failed recovery: %v", name, err)
		}
	}
}
