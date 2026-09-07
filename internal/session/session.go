// Package session tracks per-session signals consumed by policy heuristics.
package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

const (
	lockWait       = 2 * time.Second
	lockRetryDelay = time.Millisecond
)

var errEmptySessionID = errors.New("session ID is empty")

type State struct {
	SawPrivateRead bool   `json:"saw_private_read"`
	SawNetworkCall bool   `json:"saw_network_call"`
	UpdatedAt      string `json:"updated_at"`
}

func dir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "guardrail", "sessions")
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "guardrail", "sessions")
}

func Path(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(sessionID))
	return filepath.Join(dir(), hex.EncodeToString(digest[:])+".json")
}

// Transaction exclusively loads, updates, and atomically persists one session.
// Its store-wide OS lock is released automatically if the process exits.
func Transaction(sessionID string, update func(*State) error) (err error) {
	path := Path(sessionID)
	if path == "" {
		return errEmptySessionID
	}
	if update == nil {
		return errors.New("session transaction callback is nil")
	}
	d := dir()
	if err := os.MkdirAll(d, 0o700); err != nil {
		return fmt.Errorf("create session store: %w", err)
	}

	lock := flock.New(filepath.Join(d, ".lock"), flock.SetPermissions(0o600))
	ctx, cancel := context.WithTimeout(context.Background(), lockWait)
	defer cancel()
	locked, lockErr := lock.TryLockContext(ctx, lockRetryDelay)
	if lockErr != nil {
		return fmt.Errorf("acquire session transaction lock: %w", lockErr)
	}
	if !locked {
		return fmt.Errorf("acquire session transaction lock: %w", ctx.Err())
	}
	defer func() {
		if unlockErr := lock.Unlock(); err == nil && unlockErr != nil {
			err = fmt.Errorf("release session transaction lock: %w", unlockErr)
		}
	}()

	var state State
	raw, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return fmt.Errorf("read session state: %w", readErr)
	}
	if readErr == nil {
		if err := json.Unmarshal(raw, &state); err != nil {
			return fmt.Errorf("decode session state: %w", err)
		}
	}
	if err := update(&state); err != nil {
		return err
	}
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err = json.Marshal(&state)
	if err != nil {
		return fmt.Errorf("encode session state: %w", err)
	}
	if err := atomicWrite(path, raw); err != nil {
		return fmt.Errorf("persist session state: %w", err)
	}

	prune(d)
	return nil
}

func atomicWrite(path string, raw []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".session-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// prune removes session files whose mtime is older than 24h. Best-effort:
// any error here is silently swallowed, never returned to the caller.
func prune(d string) {
	entries, err := os.ReadDir(d)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		os.Remove(filepath.Join(d, e.Name()))
	}
}
