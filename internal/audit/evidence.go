package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// CodexEvidence is an audit heuristic, not authentication of runtime dispatch.
// Counts describe the retained log segments, not the lifetime of the install.
type CodexEvidence struct {
	Records, Codex, Synthetic, Stale, Rejected, Duplicates, Eligible, Sessions, QualifiedSessions, Malformed int
}

// Observed requires two distinct eligible pre-hook records in one session.
func (e CodexEvidence) Observed() bool { return e.QualifiedSessions > 0 && e.Malformed == 0 }

// syntheticCodexSession is deliberately an explicit prefix list (ADR-0020).
// A prefix matches only the whole ID or a hyphen-delimited suffix.
func syntheticCodexSession(id string) bool {
	for _, prefix := range []string{"selftest", "codex-fixture", "fixture"} {
		if id == prefix || strings.HasPrefix(id, prefix+"-") {
			return true
		}
	}
	return false
}

// ReadCodexEvidence scans retained segments after the running binary's mtime.
// Only pre-hook verdicts count, so pre/post for one call cannot open the gate.
// Canonical record hashes deduplicate copies even with reordered JSON keys.
// Callers must treat read errors as an incomplete scan and keep the gate shut.
func ReadCodexEvidence(segments []string, cutoff, now time.Time) (CodexEvidence, error) {
	var result CodexEvidence
	seen := map[[32]byte]bool{}
	sessions := map[string]int{}
	for _, path := range segments {
		err := func() error {
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Size() > 128<<20 {
				return fmt.Errorf("audit segment is not a regular file of at most 128 MiB")
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			if err := validateRegularDestination(path, f, info); err != nil {
				return err
			}
			limited := &io.LimitedReader{R: f, N: (128 << 20) + 1}
			scanner := bufio.NewScanner(limited)
			scanner.Buffer(make([]byte, 64<<10), (128<<20)+1)
			for scanner.Scan() {
				line := bytes.TrimSpace(scanner.Bytes())
				if len(line) == 0 {
					continue
				}
				result.Records++
				var rec Record
				if err := json.Unmarshal(line, &rec); err != nil {
					result.Malformed++
					continue
				}
				if rec.Plane != "codex" {
					continue
				}
				result.Codex++
				if syntheticCodexSession(rec.SessionID) {
					result.Synthetic++
					continue
				}
				ts, err := time.Parse(time.RFC3339Nano, rec.TS)
				if err != nil || ts.After(now) || strings.TrimSpace(rec.SessionID) == "" || rec.Event != "pre" || rec.Tool == "" || (rec.Decision != "allow" && rec.Decision != "ask" && rec.Decision != "deny") {
					result.Rejected++
					continue
				}
				if !ts.After(cutoff) {
					result.Stale++
					continue
				}
				canonical, _ := json.Marshal(rec)
				key := sha256.Sum256(canonical)
				if seen[key] {
					result.Duplicates++
					continue
				}
				seen[key] = true
				result.Eligible++
				sessions[rec.SessionID]++
				if sessions[rec.SessionID] == 1 {
					result.Sessions++
				}
				if sessions[rec.SessionID] == 2 {
					result.QualifiedSessions++
				}
			}
			if limited.N == 0 {
				return fmt.Errorf("audit segment exceeds 128 MiB")
			}
			return scanner.Err()
		}()
		if err != nil {
			return result, fmt.Errorf("reading audit segment %q: %w", path, err)
		}
	}
	return result, nil
}
