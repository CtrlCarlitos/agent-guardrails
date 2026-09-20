// Package audit appends one JSONL record per guardrail decision.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"
)

type Record struct {
	TS                    string   `json:"ts"`
	SessionID             string   `json:"session_id,omitempty"`
	Plane                 string   `json:"plane"`
	Tool                  string   `json:"tool"`
	NativeTool            string   `json:"native_tool,omitempty"`
	Capability            string   `json:"capability,omitempty"`
	InputShape            string   `json:"input_shape,omitempty"`
	AuditKind             string   `json:"audit_kind,omitempty"`
	Event                 string   `json:"event,omitempty"`
	Command               string   `json:"command,omitempty"`
	Paths                 []string `json:"paths,omitempty"`
	Decision              string   `json:"decision"`
	RuleID                string   `json:"rule_id,omitempty"`
	OriginRuleID          string   `json:"origin_rule_id,omitempty"`
	Reason                string   `json:"reason,omitempty"`
	Waivers               []string `json:"waivers,omitempty"`
	OperatorAction        string   `json:"operator_action,omitempty"`
	RequestID             string   `json:"request_id,omitempty"`
	Transport             string   `json:"transport,omitempty"`
	CredentialFingerprint string   `json:"credential_fingerprint,omitempty"`
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

var (
	assignmentSecretRE = regexp.MustCompile(`(?i)(?:--|-)?(pass(?:word)?|secret|token|api[_-]?key|authorization|bearer)["']?\s*[:=]\s*["']?(?:(?:bearer|basic)\s+)?[^\s"']+["']?`)
	bearerAuthRE       = regexp.MustCompile(`(?i)(?:authorization\s+)?bearer\s+[^\s"']+`)
	unassignedSecretRE = regexp.MustCompile(`(?i)(?:--|-)?(pass(?:word)?|secret|token|api[_-]?key)\s+([^\s"']+)`)
)

var redactors = []*regexp.Regexp{
	assignmentSecretRE,
	bearerAuthRE,
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]+`),
	regexp.MustCompile(`-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----`),
}

func isHighEntropy(s string) bool {
	s = strings.Trim(s, `"'`)
	if len(s) < 16 {
		return false
	}
	freq := make(map[rune]float64)
	hasDigit := false
	hasLetter := false
	for _, r := range s {
		freq[r]++
		if unicode.IsDigit(r) {
			hasDigit = true
		} else if unicode.IsLetter(r) {
			hasLetter = true
		}
	}
	total := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return (entropy >= 3.0 && hasDigit && hasLetter) || entropy >= 3.8
}

func redact(s string) string {
	for _, re := range redactors {
		s = re.ReplaceAllString(s, "«redacted»")
	}
	s = unassignedSecretRE.ReplaceAllStringFunc(s, func(match string) string {
		sub := unassignedSecretRE.FindStringSubmatch(match)
		if len(sub) >= 3 && isHighEntropy(sub[2]) {
			return "«redacted»"
		}
		return match
	})
	return s
}

// auditRotateBytes is the per-segment size limit; on crossing it the current
// segment rotates to audit-<utc>.jsonl and audit.jsonl starts fresh. The
// audit log is telemetry: unbounded growth is a slow-burn problem, and
// rotation keeps `guardrail audit` fast without losing history.
var auditRotateBytes int64 = 20 << 20

const auditRotatedKeep = 3

func Write(rec Record, path string) (err error) {
	if rec.TS == "" {
		rec.TS = time.Now().UTC().Format(time.RFC3339)
	}
	rec.Command = redact(rec.Command)
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := appendLine(path, append(line, '\n'), nil); err != nil {
		return err
	}
	return rotateIfOverLimit(path)
}

func rotateIfOverLimit(path string) error {
	info, err := os.Stat(path)
	if err != nil || info.Size() <= auditRotateBytes {
		return err
	}
	segment := fmt.Sprintf("%s-%s.jsonl", path[:len(path)-len(".jsonl")], time.Now().UTC().Format("20060102-150405.000000000"))
	if err := os.Rename(path, segment); err != nil {
		return err
	}
	rotated, err := filepath.Glob(path[:len(path)-len(".jsonl")] + "-*.jsonl")
	if err != nil {
		return err
	}
	sort.Strings(rotated)
	for excess := 0; len(rotated)-auditRotatedKeep-excess > 0; excess++ {
		if err := os.Remove(rotated[excess]); err != nil {
			return err
		}
	}
	return nil
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

// Segments returns the current audit path plus its rotated siblings, oldest
// first, for whole-history summarization.
func Segments(path string) ([]string, error) {
	_, statErr := os.Stat(path)
	if statErr != nil && !os.IsNotExist(statErr) {
		return nil, statErr
	}
	base := strings.TrimSuffix(path, ".jsonl")
	rotated, err := filepath.Glob(base + "-*.jsonl")
	if err != nil {
		return nil, err
	}
	sort.Strings(rotated)
	if statErr == nil {
		rotated = append(rotated, path)
	}
	return rotated, nil
}

// Summarize aggregates every record across segments: totals, decisions,
// planes, non-allow rules, and unclassified tool names.
func Summarize(segments []string) (total int, byDecision, byPlane, byRule map[string]int, unknownTools []string) {
	byDecision = map[string]int{}
	byPlane = map[string]int{}
	byRule = map[string]int{}
	unknown := map[string]bool{}
	for _, segment := range segments {
		raw, err := os.ReadFile(segment)
		if err != nil {
			continue
		}
		for _, line := range splitLines(raw) {
			var rec Record
			if json.Unmarshal(line, &rec) != nil {
				continue
			}
			total++
			byDecision[rec.Decision]++
			byPlane[rec.Plane]++
			if rec.Decision != "allow" && rec.RuleID != "" {
				byRule[rec.RuleID]++
			}
			if rec.RuleID == "unknown-native-tool" && rec.NativeTool != "" {
				unknown[rec.NativeTool] = true
			}
		}
	}
	unknownTools = make([]string, 0, len(unknown))
	for name := range unknown {
		unknownTools = append(unknownTools, name)
	}
	sort.Strings(unknownTools)
	return total, byDecision, byPlane, byRule, unknownTools
}

func splitLines(raw []byte) [][]byte {
	var lines [][]byte
	for len(raw) > 0 {
		i := 0
		for i < len(raw) && raw[i] != '\n' {
			i++
		}
		if i > 0 {
			lines = append(lines, raw[:i])
		}
		raw = raw[min(i+1, len(raw)):]
	}
	return lines
}
