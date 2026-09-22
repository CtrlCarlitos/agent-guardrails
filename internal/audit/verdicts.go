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

// VerdictProfile answers a different question from the evidence gate.
//
// The gate answers "is the guard present": it counts records and looks for two
// pre-hook records in one real session, which shows the hook ran. It cannot
// show what the hook *decided*, so a guard that runs and allows everything
// reads identically to one that is working.
//
// This is the view over decision, rule_id and session_id, which the audit log
// already carries. It is deliberately descriptive rather than judgmental: it
// reports what fired and how concentrated it was, and leaves "is that right"
// to the operator, who knows what the session was trying to do.
type VerdictProfile struct {
	Allow, Ask, Deny int
	Records          int // records for this plane inside the window
	Stale            int // records for this plane before the window
	Malformed        int
	Sessions         int // distinct sessions inside the window
	Rules            []RuleProfile
}

// RuleProfile is one rule's activity inside the window.
//
// Sessions and RepeatSessions are the ask-pressure signal. guardrail never
// learns how a human answered an Ask — the prompt is answered inside the
// plane and no record comes back — so the answered-yes-without-reading ratio
// is not computable from this log. What is computable is how hard a rule
// leans on a single session, and a rule asked four times in one session is
// eroding trust whether or not the answers are visible.
type RuleProfile struct {
	RuleID           string
	Allow, Ask, Deny int
	Sessions         int // distinct sessions this rule fired in
	RepeatSessions   int // sessions where it fired more than once
	MaxPerSession    int // the worst single session
	repeatCounts     map[string]int
}

// Total is every decision this rule issued inside the window.
func (r RuleProfile) Total() int { return r.Allow + r.Ask + r.Deny }

// ReadVerdictProfile aggregates one plane's decisions over the audit segments,
// counting only records after cutoff — the deployed binary's mtime, the same
// window the evidence gate uses, because the question is whether *this* build
// is deciding.
func ReadVerdictProfile(segments []string, plane string, cutoff, now time.Time) (VerdictProfile, error) {
	var profile VerdictProfile
	sessions := map[string]bool{}
	rules := map[string]*RuleProfile{}

	for _, path := range segments {
		if err := scanVerdictSegment(path, plane, cutoff, now, &profile, sessions, rules); err != nil {
			return VerdictProfile{}, err
		}
	}

	profile.Sessions = len(sessions)
	for _, rule := range rules {
		for _, count := range rule.repeatCounts {
			if count > 1 {
				rule.RepeatSessions++
			}
			if count > rule.MaxPerSession {
				rule.MaxPerSession = count
			}
		}
		rule.Sessions = len(rule.repeatCounts)
		rule.repeatCounts = nil
		profile.Rules = append(profile.Rules, *rule)
	}
	// Worst first, so the pressure reads without sorting; ties by name so the
	// output is stable between runs on the same data.
	sort.Slice(profile.Rules, func(i, j int) bool {
		if profile.Rules[i].Total() != profile.Rules[j].Total() {
			return profile.Rules[i].Total() > profile.Rules[j].Total()
		}
		return profile.Rules[i].RuleID < profile.Rules[j].RuleID
	})
	return profile, nil
}

func scanVerdictSegment(path, plane string, cutoff, now time.Time, profile *VerdictProfile, sessions map[string]bool, rules map[string]*RuleProfile) error {
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
		var rec Record
		if json.Unmarshal(line, &rec) != nil {
			profile.Malformed++
			continue
		}
		if rec.Plane != plane {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, rec.TS)
		if err != nil || ts.After(now) {
			continue
		}
		if !ts.After(cutoff) {
			profile.Stale++
			continue
		}
		countVerdict(rec, profile, sessions, rules)
	}
	return scanner.Err()
}

func countVerdict(rec Record, profile *VerdictProfile, sessions map[string]bool, rules map[string]*RuleProfile) {
	switch rec.Decision {
	case "allow":
		profile.Allow++
	case "ask":
		profile.Ask++
	case "deny":
		profile.Deny++
	default:
		// complete, or anything the Engine grows later: counted as a record
		// but not attributed to a decision tier it does not belong to.
	}
	profile.Records++
	if id := strings.TrimSpace(rec.SessionID); id != "" {
		sessions[id] = true
	}

	ruleID := strings.TrimSpace(rec.RuleID)
	if ruleID == "" {
		// An allow usually carries no rule: nothing matched. Attributing it to
		// a rule would invent precision the record does not have.
		return
	}
	rule := rules[ruleID]
	if rule == nil {
		rule = &RuleProfile{RuleID: ruleID, repeatCounts: map[string]int{}}
		rules[ruleID] = rule
	}
	switch rec.Decision {
	case "allow":
		rule.Allow++
	case "ask":
		rule.Ask++
	case "deny":
		rule.Deny++
	}
	if id := strings.TrimSpace(rec.SessionID); id != "" {
		rule.repeatCounts[id]++
	}
}
