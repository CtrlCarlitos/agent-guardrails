package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
	"github.com/CtrlCarlitos/agent-guardrails/internal/selftestfixtures"
)

// selftestProbesOverride lets unit tests tamper with the loaded probe slice
// without mutating the embedded fixture tree. Production code leaves it nil.
var selftestProbesOverride []selftestfixtures.Probe

func loadSelftestProbes() ([]selftestfixtures.Probe, error) {
	if selftestProbesOverride != nil {
		return selftestProbesOverride, nil
	}
	return selftestfixtures.Load(runtime.GOOS)
}

// cmdSelftest runs the embedded probe matrix through the installed binary's
// hook path. It verifies enforcement behavior — not just registration, which
// doctor already covers. Direct hook invocation only: it cannot prove a plane
// runtime invokes its hooks (codex's hosted-tool gap); audit records remain
// the live-mediation evidence.
func cmdSelftest(args []string, stdout, stderr io.Writer) int {
	if len(args) >= 2 && args[0] == "--evidence" {
		switch args[1] {
		case "codex":
			opts, ok := parseCodexEvidenceOptions(args[2:], time.Now(), stderr)
			if !ok {
				return 2
			}
			return cmdCodexEvidence(opts, stdout, stderr)
		case "claude":
			// The claude gate answers one question and takes no options: the
			// codex selectors exist to pin a specific live session, and the
			// claude question is whether any real session was mediated at all.
			if len(args) != 2 {
				fmt.Fprintln(stderr, "guardrail: selftest --evidence claude takes no further arguments")
				return 2
			}
			return cmdClaudeEvidence(stdout, stderr)
		}
	}
	if len(args) != 0 {
		fmt.Fprintln(stderr, "guardrail: selftest accepts only [--evidence claude] or [--evidence codex [--session <id>] [--since <RFC3339|duration>] [--expect-tool <name>]]")
		return 2
	}
	probes, err := loadSelftestProbes()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: selftest could not load embedded fixtures: %v\n", err)
		return 1
	}
	// A unique session suffix per invocation keeps selftest idempotent: a
	// repeated ask probe must never consume a prior run's approval-memory
	// entry and report allow (the double-run lesson from codex).
	sessionSuffix := fmt.Sprintf("selftest-%d", time.Now().UnixNano())
	passed := map[string]int{}
	failed := map[string]int{}
	planeOrder := []string{"claude", "opencode", "antigravity", "codex"}
	seenPlane := map[string]bool{"claude": true, "opencode": true, "antigravity": true, "codex": true}
	for _, probe := range probes {
		if !seenPlane[probe.Plane] {
			seenPlane[probe.Plane] = true
			planeOrder = append(planeOrder, probe.Plane)
		}
		payload := strings.ReplaceAll(probe.Payload, "selftest", sessionSuffix)
		var out, errb strings.Builder
		code := run(append([]string{"hook"}, probe.Args...), strings.NewReader(payload), &out, &errb)
		decision, ruleID := parseSelftestVerdict(code, out.String(), errb.String())
		if ruleID == "" && probe.WantRuleID != "" {
			// Planes whose native response carries no rule (Claude: deny is
			// guidance text, allow is silence) expose it through the audit
			// record the hook wrote for this probe's synthetic session.
			ruleID = selftestRuleFromAudit(sessionSuffix)
		}
		if decision == probe.WantDecision && (probe.WantRuleID == "" || ruleID == probe.WantRuleID) {
			passed[probe.Plane]++
			continue
		}
		failed[probe.Plane]++
		fmt.Fprintf(stdout, "  FAILED %s: %s — got %s/%s (exit %d), want %s/%s\n",
			probe.Plane, probe.Name, decision, ruleID, code, probe.WantDecision, probe.WantRuleID)
	}
	totalPassed := 0
	totalFailed := 0
	for _, plane := range planeOrder {
		totalPassed += passed[plane]
		if failed[plane] > 0 {
			fmt.Fprintf(stdout, "%s: %d/%d probes failed\n", plane, failed[plane], passed[plane]+failed[plane])
			totalFailed += failed[plane]
			continue
		}
		fmt.Fprintf(stdout, "%s: probes pass (%d)\n", plane, passed[plane])
	}
	fmt.Fprintln(stdout, "note: codex probes invoke the hook directly; live runtime mediation is evidenced by audit records")
	if totalFailed > 0 {
		fmt.Fprintf(stdout, "selftest: %d probes failed\n", totalFailed)
		return 1
	}
	fmt.Fprintf(stdout, "selftest: all probes passed — runs every recorded fixture (%d)\n", totalPassed)
	if err := recordSelftestPass(version); err != nil {
		fmt.Fprintf(stdout, "note: could not record the pass (%s); the SessionStart posture will keep asking\n", safetext.SingleLine(err.Error()))
	}
	return 0
}

// selftestRuleFromAudit returns the rule of the newest audit record written
// for the synthetic session, or "" when none can be read: the probe then
// fails on its rule expectation, which is the honest outcome.
func selftestRuleFromAudit(sessionID string) string {
	raw, err := os.ReadFile(audit.DefaultPath(""))
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var rec struct {
			SessionID string `json:"session_id"`
			RuleID    string `json:"rule_id"`
		}
		if json.Unmarshal([]byte(lines[i]), &rec) == nil && rec.SessionID == sessionID {
			return rec.RuleID
		}
	}
	return ""
}

// parseSelftestVerdict extracts the decision from whichever stream the
// plane's adapter emits: claude/agy print deny reasons to stderr, opencode
// and codex print JSON to stdout. Exit 2 accompanies deny, 0 allow/ask.
func parseSelftestVerdict(code int, stdout, stderr string) (decision, ruleID string) {
	var payload struct {
		Decision string `json:"decision"`
		RuleID   string `json:"rule_id"`
		Hook     *struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &payload); err == nil {
		if payload.Decision != "" {
			if payload.Decision == "force_ask" {
				payload.Decision = "ask"
			}
			return payload.Decision, payload.RuleID
		}
		if payload.Hook != nil && payload.Hook.PermissionDecision != "" {
			decision := payload.Hook.PermissionDecision
			if decision == "force_ask" {
				decision = "ask"
			}
			return decision, ""
		}
	}
	if strings.Contains(stderr, "Guardrail denied this action") {
		return "deny", ""
	}
	if strings.Contains(stderr, "Operator authorization required") {
		return "ask", ""
	}
	if code == 0 {
		return "allow", ""
	}
	return fmt.Sprintf("exit-%d", code), ""
}
