package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// CodexEvidence is an audit heuristic, not authentication of runtime dispatch.
// Counts describe the retained log segments, not the lifetime of the install.
type CodexEvidence struct {
	Records, Codex, Synthetic, Stale, Rejected, Duplicates, Eligible, Sessions, QualifiedSessions, Malformed, OtherSessions int
	ObservedTools, MissingExpectedTools, Capabilities                                                                       []string
}

// Observed requires two distinct eligible pre-hook records in one session.
func (e CodexEvidence) Observed() bool {
	return e.QualifiedSessions > 0 && e.Malformed == 0 && len(e.MissingExpectedTools) == 0
}

// syntheticCodexSession is deliberately an explicit prefix list (ADR-0020).
// A prefix matches only the whole ID or a hyphen-delimited suffix.
func syntheticCodexSession(id string) bool {
	return IsSyntheticCodexSession(id)
}

// IsSyntheticCodexSession reports the documented ADR-0020 fixture prefixes.
func IsSyntheticCodexSession(id string) bool {
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
	return ReadCodexEvidenceFiltered(segments, cutoff, now, "", nil)
}

// ReadCodexEvidenceFiltered applies an optional exact session selection and
// expected-tool assertions. Expected tools match either normalized tool or
// native tool names from eligible records.
func ReadCodexEvidenceFiltered(segments []string, cutoff, now time.Time, sessionID string, expectedTools []string) (CodexEvidence, error) {
	return readPlaneEvidence(segments, "codex", syntheticCodexSession, cutoff, now, sessionID, expectedTools)
}

// ReadClaudeEvidence answers for claude the question ADR-0020 asks for codex:
// did the registered hook actually run? Registration alone read as green for
// four days on a Windows host while an unspawnable command enforced nothing
// (#149).
//
// The one difference from codex is which sessions count as real. codex uses an
// explicit prefix denylist (ADR-0020). claude cannot: every claude record in
// this repo's own audit log came from an ad-hoc fixture or probe id —
// night-claude, trifecta-sess-1, ../unsafe, c1, manual-probe-1 — and a denylist
// that misses one opens the gate falsely, which is the failure class the gate
// exists to catch. A real Claude Code session id is a UUID, so the shape is
// required positively: forging one is deliberate, forgetting to denylist a
// prefix is an accident. If Claude Code ever changes that format the gate
// closes, which is the safe direction.
func ReadClaudeEvidence(segments []string, cutoff, now time.Time) (CodexEvidence, error) {
	return readPlaneEvidence(segments, "claude", nonRealClaudeSession, cutoff, now, "", nil)
}

// nonRealClaudeSession reports whether a session id is anything other than a
// live Claude Code session: the synthetic prefixes, and anything not
// UUID-shaped.
func nonRealClaudeSession(id string) bool {
	return IsSyntheticCodexSession(id) || !uuidShaped(id)
}

// uuidShaped matches 8-4-4-4-12 hex, the shape Claude Code's session_id carries.
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

// readPlaneEvidence is the shared scanner. Every count, the exact-session
// filter and the expected-tool assertions behave identically for each plane;
// only the plane name and the definition of a synthetic session differ.
func readPlaneEvidence(segments []string, plane string, synthetic func(string) bool, cutoff, now time.Time, sessionID string, expectedTools []string) (CodexEvidence, error) {
	var result CodexEvidence
	seen := map[[4]string]bool{}
	sessions := map[string]int{}
	observedTools := map[string]bool{}
	capabilities := map[string]bool{}
	expected := map[string]bool{}
	for _, tool := range expectedTools {
		tool = strings.TrimSpace(tool)
		if tool != "" {
			expected[tool] = true
		}
	}
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
				if sessionID != "" && rec.SessionID != sessionID {
					result.OtherSessions++
					continue
				}
				key := [4]string{rec.SessionID, ts.UTC().Format(time.RFC3339Nano), rec.Tool, rec.Decision}
				if seen[key] {
					result.Duplicates++
					continue
				}
				seen[key] = true
				result.Eligible++
				observedTools[rec.Tool] = true
				if rec.NativeTool != "" {
					observedTools[rec.NativeTool] = true
				}
				if rec.Capability != "" {
					capabilities[rec.Capability] = true
				}
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
	for tool := range observedTools {
		result.ObservedTools = append(result.ObservedTools, tool)
	}
	sort.Strings(result.ObservedTools)
	for tool := range expected {
		if !observedTools[tool] {
			result.MissingExpectedTools = append(result.MissingExpectedTools, tool)
		}
	}
	sort.Strings(result.MissingExpectedTools)
	for capability := range capabilities {
		result.Capabilities = append(result.Capabilities, capability)
	}
	sort.Strings(result.Capabilities)
	return result, nil
}
