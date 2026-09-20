package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
)

const maxCodexRolloutFiles = 10_000

type codexKnownSession struct {
	ID      string
	Started time.Time
	Path    string
}

func defaultCodexSessionsRoot() (string, error) {
	if home := strings.TrimSpace(os.Getenv("CODEX_HOME")); home != "" {
		return filepath.Join(home, "sessions"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".codex", "sessions"), nil
}

func readCodexKnownSessions(root string) ([]codexKnownSession, error) {
	byID := map[string]codexKnownSession{}
	files := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) && path == root {
				return fs.SkipAll
			}
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "rollout-") || filepath.Ext(entry.Name()) != ".jsonl" {
			return nil
		}
		files++
		if files > maxCodexRolloutFiles {
			return fmt.Errorf("Codex session inventory exceeds %d rollout files", maxCodexRolloutFiles)
		}
		session, err := readCodexSessionMeta(path)
		if err != nil {
			return err
		}
		if audit.IsSyntheticCodexSession(session.ID) {
			return nil
		}
		if prior, ok := byID[session.ID]; !ok || session.Started.After(prior.Started) {
			byID[session.ID] = session
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sessions := make([]codexKnownSession, 0, len(byID))
	for _, session := range byID {
		sessions = append(sessions, session)
	}
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].Started.Equal(sessions[j].Started) {
			return sessions[i].ID < sessions[j].ID
		}
		return sessions[i].Started.After(sessions[j].Started)
	})
	return sessions, nil
}

func readCodexSessionMeta(path string) (codexKnownSession, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return codexKnownSession{}, err
	}
	if !info.Mode().IsRegular() {
		return codexKnownSession{}, fmt.Errorf("Codex rollout is not a regular file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return codexKnownSession{}, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var meta struct {
			Timestamp string `json:"timestamp"`
			Type      string `json:"type"`
			Payload   struct {
				SessionID string `json:"session_id"`
				ID        string `json:"id"`
				Timestamp string `json:"timestamp"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(line, &meta); err != nil {
			return codexKnownSession{}, fmt.Errorf("Codex rollout metadata %q: %w", path, err)
		}
		if meta.Type != "session_meta" {
			return codexKnownSession{}, fmt.Errorf("Codex rollout %q does not start with session_meta", path)
		}
		id := strings.TrimSpace(meta.Payload.SessionID)
		if id == "" {
			id = strings.TrimSpace(meta.Payload.ID)
		}
		timestamp := meta.Payload.Timestamp
		if timestamp == "" {
			timestamp = meta.Timestamp
		}
		started, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil || id == "" {
			return codexKnownSession{}, fmt.Errorf("Codex rollout %q has invalid session identity or timestamp", path)
		}
		return codexKnownSession{ID: id, Started: started, Path: path}, nil
	}
	if err := scanner.Err(); err != nil {
		return codexKnownSession{}, fmt.Errorf("Codex rollout metadata %q: %w", path, err)
	}
	return codexKnownSession{}, fmt.Errorf("Codex rollout %q is empty", path)
}
