package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
)

var writeActionAudit = audit.Write

type actionAuditJournal struct {
	Record  audit.Record `json:"record"`
	Mutated bool         `json:"mutated"`
}

func actionAuditDir() (string, error) {
	var base string
	if runtime.GOOS == "windows" {
		base = os.Getenv("LOCALAPPDATA")
		if base == "" || !filepath.IsAbs(base) {
			return "", errors.New("LOCALAPPDATA must be an absolute path")
		}
	} else {
		base = os.Getenv("XDG_STATE_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".local", "state")
		}
	}
	dir := filepath.Join(base, "guardrail", "action-audit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func actionAuditPath(id string) (string, error) {
	dir, err := actionAuditDir()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(id))
	return filepath.Join(dir, hex.EncodeToString(digest[:])+".json"), nil
}

func actionAuditRecord(r approval.Request, decision string) audit.Record {
	return audit.Record{Plane: r.Plane, Tool: "guardrail", Event: "operator-action", Decision: decision, OperatorAction: r.Action, RequestID: r.ID, Transport: r.Transport, CredentialFingerprint: r.CredentialFingerprint}
}

// writeBootstrapAudit records a first-install registration made without an
// approval (ADR-0030): an operator action with transport "bootstrap", no
// request and no credential, so it is distinguishable from an approved one.
// No journal: the merge is idempotent and the next setup re-checks it.
func writeBootstrapAudit(planes []string) error {
	rec := audit.Record{
		Plane:          "operator",
		Tool:           "guardrail",
		Event:          "operator-action",
		Decision:       "completed",
		OperatorAction: "plane-enable",
		Transport:      "bootstrap",
		Reason:         "bootstrap: no operator enrolled; planes " + strings.Join(planes, ","),
	}
	return writeActionAudit(rec, audit.DefaultPath(""))
}

// startActionAudit records durable audit intent before a persistent action mutates.
// A recovered mutation is completed without applying its idempotent state change again.
func startActionAudit(r approval.Request) (bool, error) {
	path, err := actionAuditPath(r.ID)
	if err != nil {
		return false, err
	}
	if err := recoverActionAuditsExcept(path); err != nil {
		return false, err
	}
	if journal, err := loadActionAudit(path); err == nil {
		if journal.Mutated {
			_ = finishActionAudit(path, journal)
			return true, nil
		}
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := writeActionAudit(actionAuditRecord(r, "requested"), audit.DefaultPath("")); err != nil {
		return false, err
	}
	journal := actionAuditJournal{Record: actionAuditRecord(r, "completed")}
	if err := writeActionAuditJournal(path, journal); err != nil {
		return false, err
	}
	return false, nil
}

func completeActionAudit(r approval.Request) error {
	path, err := actionAuditPath(r.ID)
	if err != nil {
		return err
	}
	journal, err := loadActionAudit(path)
	if err != nil {
		return err
	}
	journal.Mutated = true
	if err := writeActionAuditJournal(path, journal); err != nil {
		return err
	}
	return finishActionAudit(path, journal)
}

func finishActionAudit(path string, journal actionAuditJournal) error {
	if err := writeActionAudit(journal.Record, audit.DefaultPath("")); err != nil {
		return err
	}
	// Concurrent grants can race journal cleanup; a journal another
	// transaction already removed is successfully finished, not an error.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func recoverActionAudits() error {
	return recoverActionAuditsExcept("")
}

func recoverActionAuditsExcept(skip string) error {
	dir, err := actionAuditDir()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		// Another action may be atomically replacing its journal while we scan.
		if strings.HasPrefix(entry.Name(), ".guardrail-") && strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		if entry.IsDir() || !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".json" {
			return fmt.Errorf("unsafe action audit journal entry")
		}
		path := filepath.Join(dir, entry.Name())
		if path == skip {
			continue
		}
		journal, err := loadActionAudit(path)
		if err != nil {
			return err
		}
		if journal.Mutated {
			if err := finishActionAudit(path, journal); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadActionAudit(path string) (actionAuditJournal, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return actionAuditJournal{}, err
	}
	var journal actionAuditJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		return actionAuditJournal{}, fmt.Errorf("decode action audit journal: %w", err)
	}
	if journal.Record.OperatorAction == "" || journal.Record.Decision != "completed" {
		return actionAuditJournal{}, errors.New("invalid action audit journal")
	}
	return journal, nil
}

func writeActionAuditJournal(path string, journal actionAuditJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return writeSyncedPrivateFile(path, raw, 0o600)
}
