package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// CodexEvidence is an audit heuristic, not authentication of runtime dispatch.
// Counts describe the retained log segments, not the lifetime of the install.
// The shape is shared by every plane's gate; Codex counts records for whichever
// plane was scanned.
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
// Within a session, only timestamp, tool, or decision differences add evidence.
// JSON formatting and changes to other fields do not create evidence points.
// Callers must treat read errors as an incomplete scan and keep the gate shut.
func ReadCodexEvidence(segments []string, cutoff, now time.Time) (CodexEvidence, error) {
	return readPlaneEvidence(segments, "codex", syntheticCodexSession, cutoff, now)
}

// ReadClaudeEvidence answers the same question for the claude plane: did the
// registered hook actually run? Registration alone read as green for four days
// on a Windows host while an unspawnable command enforced nothing (#149).
//
// The one difference from codex is which sessions count as real. codex uses an
// explicit prefix denylist (ADR-0020). claude cannot: every claude record in
// this repo's own audit log came from an ad-hoc fixture or probe id —
// night-claude, trifecta-sess-1, ../unsafe, c1, manual-probe-1 — and a
// denylist that misses one opens the gate falsely, which is the failure class
// the gate exists to catch. A real Claude Code session id is a UUID, so the
// shape is required positively: forging one is deliberate, forgetting to
// denylist a prefix is an accident. If Claude Code ever changes that format
// the gate closes, which is the safe direction.
func ReadClaudeEvidence(segments []string, cutoff, now time.Time) (CodexEvidence, error) {
	return readPlaneEvidence(segments, "claude", nonRealClaudeSession, cutoff, now)
}

// nonRealClaudeSession reports whether a session id is anything other than a
// live Claude Code session: the synthetic prefixes, and anything that is not
// UUID-shaped.
func nonRealClaudeSession(id string) bool {
	return syntheticCodexSession(id) || !uuidShaped(id)
}

// uuidShaped matches 8-4-4-4-12 lowercase-or-uppercase hex, the shape Claude
// Code's session_id carries.
func uuidShaped(id string) bool {
	groups := strings.Split(id, "-")
	if len(groups) != 5 {
		return false
	}
	for i, want := range []int{8, 4, 4, 4, 12} {
		if len(groups[i]) != want {
			return false
		}
		for _, r := range groups[i] {
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
				return false
			}
		}
	}
	return true
}

func readPlaneEvidence(segments []string, plane string, synthetic func(string) bool, cutoff, now time.Time) (CodexEvidence, error) {
	var result CodexEvidence
	seen := map[[4]string]bool{}
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
				if rec.Plane != plane {
					continue
				}
				result.Codex++
				if synthetic(rec.SessionID) {
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
				key := [4]string{rec.SessionID, ts.UTC().Format(time.RFC3339Nano), rec.Tool, rec.Decision}
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
