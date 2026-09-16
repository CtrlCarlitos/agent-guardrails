package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/gofrs/flock"
)

type allowanceJournal struct {
	OverlayPath   string `json:"overlay_path"`
	OverlayAfter  []byte `json:"overlay_after"`
	OverlayMode   uint32 `json:"overlay_mode"`
	OperatorPath  string `json:"operator_path"`
	OperatorAfter []byte `json:"operator_after"`
}

func applyRepoWebHost(repo, host string, grant bool) error {
	journalPath, err := allowanceJournalPath(repo)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(journalPath), 0o700); err != nil {
		return err
	}
	lock := flock.New(journalPath+".lock", flock.SetPermissions(0o600))
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	if err := recoverAllowanceJournal(journalPath); err != nil {
		return err
	}

	op, err := policy.LoadOperatorConfig()
	if err != nil {
		return err
	}
	overlayPath := filepath.Join(repo, "guardrail.toml")
	overlay, mode, _, _, err := overlayWebHostContent(overlayPath, host, grant)
	if err != nil {
		return err
	}
	if op.Repos == nil {
		op.Repos = map[string]policy.RepoGrant{}
	}
	repoGrant := op.Repos[repo]
	repoGrant.WebHosts = updateHost(repoGrant.WebHosts, host, grant)
	op.Repos[repo] = repoGrant
	operator, err := operatorConfigContent(op)
	if err != nil {
		return err
	}
	operatorPath := policy.OperatorConfigPath()
	if err := os.MkdirAll(filepath.Dir(operatorPath), 0o700); err != nil {
		return err
	}
	journal := allowanceJournal{OverlayPath: overlayPath, OverlayAfter: overlay, OverlayMode: uint32(mode), OperatorPath: operatorPath, OperatorAfter: operator}
	if err := writeAllowanceJournal(journalPath, journal); err != nil {
		return err
	}
	return recoverAllowanceJournal(journalPath)
}

func allowanceJournalPath(repo string) (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	digest := sha256.Sum256([]byte(filepath.Clean(repo)))
	return filepath.Join(base, "guardrail", "allowances", fmt.Sprintf("%x.json", digest[:])), nil
}

func writeAllowanceJournal(path string, journal allowanceJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return writePrivateFile(path, raw, 0o600)
}

func recoverAllowanceJournal(path string) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal allowanceJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		return fmt.Errorf("decode allowance transaction journal: %w", err)
	}
	if !filepath.IsAbs(journal.OverlayPath) || journal.OperatorPath != policy.OperatorConfigPath() {
		return fmt.Errorf("invalid allowance transaction journal")
	}
	if err := writePrivateFile(journal.OverlayPath, journal.OverlayAfter, os.FileMode(journal.OverlayMode)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(journal.OperatorPath), 0o700); err != nil {
		return err
	}
	if err := writePrivateFile(journal.OperatorPath, journal.OperatorAfter, 0o600); err != nil {
		return err
	}
	return os.Remove(path)
}
