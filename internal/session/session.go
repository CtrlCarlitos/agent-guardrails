// Package session tracks a small set of per-session signals — has this
// Claude session touched a private-data path, has it attempted network
// egress — consumed by the P7 lethal-trifecta heuristic in internal/engine.
// State is best-effort: a read/write failure never blocks a verdict, it just
// means the heuristic silently sees no signal yet.
package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

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
	return filepath.Join(dir(), sessionID+".json")
}

func Load(sessionID string) (*State, error) {
	if sessionID == "" {
		return &State{}, nil
	}
	raw, err := os.ReadFile(Path(sessionID))
	if err != nil {
		if os.IsNotExist(err) {
			return &State{}, nil
		}
		return &State{}, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return &State{}, err
	}
	return &s, nil
}

func Save(sessionID string, s *State) error {
	if sessionID == "" {
		return nil
	}
	s.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	d := dir()
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.WriteFile(Path(sessionID), raw, 0o600); err != nil {
		return err
	}
	prune(d)
	return nil
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
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		os.Remove(filepath.Join(d, e.Name()))
	}
}
