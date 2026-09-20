package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/gofrs/flock"
)

type allowanceJournal struct {
	OverlayPath   string `json:"overlay_path"`
	OverlayAfter  []byte `json:"overlay_after"`
	OverlayMode   uint32 `json:"overlay_mode"`
	OperatorPath  string `json:"operator_path"`
	OperatorAfter []byte `json:"operator_after"`
	MAC           []byte `json:"mac"`
}

func applyGlobalWebHost(host string, grant bool) error {
	dir, err := allowanceJournalDir()
	if err != nil {
		return err
	}
	if err := ensureAllowanceDir(dir); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(dir, "operator.lock"), flock.SetPermissions(0o600))
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	if err := recoverAllowanceJournals(dir); err != nil {
		return err
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil {
		return err
	}
	op.GlobalWebHosts = updateHost(op.GlobalWebHosts, host, grant)
	raw, err := operatorConfigContent(op)
	if err != nil {
		return err
	}
	path := policy.OperatorConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := securePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return writeSyncedPrivateFile(path, raw, 0o600)
}

func applyRepoWebHost(repo, host string, grant bool) error {
	dir, err := allowanceJournalDir()
	if err != nil {
		return err
	}
	if err := ensureAllowanceDir(dir); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(dir, "operator.lock"), flock.SetPermissions(0o600))
	if err := lock.Lock(); err != nil {
		return err
	}
	defer lock.Unlock()
	if err := recoverAllowanceJournals(dir); err != nil {
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
	if err := securePrivateDir(filepath.Dir(operatorPath)); err != nil {
		return err
	}
	journalPath := filepath.Join(dir, filepath.Base(mustAllowanceJournalPath(repo)))
	journal := allowanceJournal{OverlayPath: overlayPath, OverlayAfter: overlay, OverlayMode: uint32(mode), OperatorPath: operatorPath, OperatorAfter: operator}
	if err := writeAllowanceJournal(journalPath, journal); err != nil {
		return err
	}
	return recoverAllowanceJournal(journalPath)
}

func allowanceJournalPath(repo string) (string, error) {
	dir, err := allowanceJournalDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(mustAllowanceJournalPath(repo))), nil
}

func allowanceJournalDir() (string, error) {
	if runtime.GOOS == "windows" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" || !filepath.IsAbs(base) {
			return "", fmt.Errorf("LOCALAPPDATA must be an absolute path")
		}
		return filepath.Join(base, "guardrail", "allowances"), nil
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "guardrail", "allowances"), nil
}

func mustAllowanceJournalPath(repo string) string {
	digest := sha256.Sum256([]byte(filepath.Clean(repo)))
	return fmt.Sprintf("%x.json", digest[:])
}

func writeAllowanceJournal(path string, journal allowanceJournal) error {
	key, err := allowanceKey(filepath.Dir(path))
	if err != nil {
		return err
	}
	journal.MAC = nil
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	journal.MAC = mac.Sum(nil)
	raw, err = json.Marshal(journal)
	if err != nil {
		return err
	}
	return writeSyncedPrivateFile(path, raw, 0o600)
}

func recoverAllowanceJournal(path string) error {
	if err := ensureAllowanceDir(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && validatePrivateFile(path, info) != nil {
		return fmt.Errorf("unsafe allowance journal")
	}
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
	key, err := allowanceKey(filepath.Dir(path))
	if err != nil {
		return err
	}
	provided := journal.MAC
	journal.MAC = nil
	unsigned, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(unsigned)
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return fmt.Errorf("invalid allowance transaction journal authentication")
	}
	if !filepath.IsAbs(journal.OverlayPath) || journal.OperatorPath != policy.OperatorConfigPath() {
		return fmt.Errorf("invalid allowance transaction journal")
	}
	if err := writeSyncedPrivateFile(journal.OverlayPath, journal.OverlayAfter, os.FileMode(journal.OverlayMode)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(journal.OperatorPath), 0o700); err != nil {
		return err
	}
	if err := securePrivateDir(filepath.Dir(journal.OperatorPath)); err != nil {
		return err
	}
	if err := writeSyncedPrivateFile(journal.OperatorPath, journal.OperatorAfter, 0o600); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncParent(filepath.Dir(path))
}

func recoverAllowanceJournals(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			if err := recoverAllowanceJournal(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureAllowanceDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := securePrivateDir(dir); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || validatePrivateDir(dir, info) != nil {
		return fmt.Errorf("allowance journal directory is not private")
	}
	return nil
}

func allowanceKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "auth.key")
	if info, err := os.Lstat(path); err == nil {
		if validatePrivateFile(path, info) != nil {
			return nil, fmt.Errorf("unsafe allowance journal key")
		}
		return os.ReadFile(path)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := writeSyncedPrivateFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func writeSyncedPrivateFile(path string, content []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".guardrail-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncParent(filepath.Dir(path))
}

func syncParent(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
