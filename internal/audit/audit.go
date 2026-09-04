// Package audit appends one JSONL record per guardrail decision.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

type Record struct {
	TS        string   `json:"ts"`
	SessionID string   `json:"session_id,omitempty"`
	Plane     string   `json:"plane"`
	Tool      string   `json:"tool"`
	Event     string   `json:"event,omitempty"`
	Command   string   `json:"command,omitempty"`
	Paths     []string `json:"paths,omitempty"`
	Decision  string   `json:"decision"`
	RuleID    string   `json:"rule_id,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Waivers   []string `json:"waivers,omitempty"`
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

func Write(rec Record, path string) error {
	if rec.TS == "" {
		rec.TS = time.Now().UTC().Format(time.RFC3339)
	}
	rec.Command = redact(rec.Command)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return err
}
