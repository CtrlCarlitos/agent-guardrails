// Package audit appends one JSONL record per guardrail decision.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

type Record struct {
	TS           string   `json:"ts"`
	SessionID    string   `json:"session_id,omitempty"`
	Plane        string   `json:"plane"`
	Tool         string   `json:"tool"`
	Event        string   `json:"event,omitempty"`
	Command      string   `json:"command,omitempty"`
	Paths        []string `json:"paths,omitempty"`
	Decision     string   `json:"decision"`
	RuleID       string   `json:"rule_id,omitempty"`
	OriginRuleID string   `json:"origin_rule_id,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	Waivers      []string `json:"waivers,omitempty"`
}

func DefaultPath(override string) string {
	if override != "" {
		return override
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "guardrail", "audit.jsonl")
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "guardrail", "audit.jsonl")
}

var redactors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(pass(word)?|secret|token|api[_-]?key|authorization|bearer)(["']?\s*[:=]\s*["']?|\s+)(?:(?:bearer|basic)\s+)?[^\s"']+`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]+`),
	regexp.MustCompile(`-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----`),
}

func redact(s string) string {
	for _, re := range redactors {
		s = re.ReplaceAllString(s, "«redacted»")
	}
	return s
}

func Write(rec Record, path string) (err error) {
	if rec.TS == "" {
		rec.TS = time.Now().UTC().Format(time.RFC3339)
	}
	rec.Command = redact(rec.Command)
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return appendLine(path, append(line, '\n'), nil)
}

func appendLine(path string, line []byte, afterAppend func() error) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := openRegularAppend(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	if _, err = f.Write(line); err != nil {
		return err
	}
	if afterAppend != nil {
		if err := afterAppend(); err != nil {
			return err
		}
	}
	return validateRegularDestination(path, f, nil)
}

func openRegularAppend(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil && !before.Mode().IsRegular() {
		return nil, errors.New("audit destination is not a regular file")
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := validateRegularDestination(path, f, before); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			return nil, fmt.Errorf("audit destination changed or is not a regular file; closing: %w", closeErr)
		}
		return nil, err
	}
	return f, nil
}

func validateRegularDestination(path string, f *os.File, before os.FileInfo) error {
	opened, statErr := f.Stat()
	current, lstatErr := os.Lstat(path)
	changed := statErr != nil || lstatErr != nil || !opened.Mode().IsRegular() ||
		!current.Mode().IsRegular() || !os.SameFile(opened, current) ||
		before != nil && !os.SameFile(before, opened)
	if changed {
		return errors.New("audit destination changed or is not a regular file")
	}
	return nil
}
