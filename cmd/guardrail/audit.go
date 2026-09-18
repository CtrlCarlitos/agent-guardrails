package main

import (
	"fmt"
	"io"
	"sort"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
)

// cmdAudit summarizes the audit log: the coverage audits were born from
// mining it with ad-hoc scripts; this makes the instrument first-class.
func cmdAudit(args []string, stdout, stderr io.Writer) int {
	path := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--path" && i+1 < len(args) {
			i++
			path = args[i]
			continue
		}
		fmt.Fprintln(stderr, "guardrail: audit accepts only [--path <file>]")
		return 2
	}
	if path == "" {
		path = audit.DefaultPath("")
	}
	segments, err := audit.Segments(path)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: audit log unavailable: %v\n", err)
		return 1
	}
	total, byDecision, byPlane, byRule, unknownTools := audit.Summarize(segments)
	fmt.Fprintf(stdout, "audit log: %s (%d segment(s))\n", path, len(segments))
	fmt.Fprintf(stdout, "records: %d\n", total)
	fmt.Fprintf(stdout, "by decision: allow=%d ask=%d deny=%d complete=%d\n",
		byDecision["allow"], byDecision["ask"], byDecision["deny"], byDecision["complete"])
	fmt.Fprintf(stdout, "by plane: claude=%d opencode=%d antigravity=%d codex=%d operator=%d\n",
		byPlane["claude"], byPlane["opencode"], byPlane["antigravity"], byPlane["codex"], byPlane["operator"])
	top := topRules(byRule, 5)
	if len(top) > 0 {
		fmt.Fprintln(stdout, "top non-allow rules:")
		for _, r := range top {
			fmt.Fprintf(stdout, "  %4d  %s\n", r.count, r.rule)
		}
	}
	if len(unknownTools) > 0 {
		fmt.Fprintln(stdout, "unclassified tools observed (ask/deny posture):")
		for _, tool := range unknownTools {
			fmt.Fprintf(stdout, "  %s\n", tool)
		}
	}
	return 0
}

func topRules(byRule map[string]int, n int) []struct {
	rule  string
	count int
} {
	rules := make([]struct {
		rule  string
		count int
	}, 0, len(byRule))
	for rule, count := range byRule {
		if rule == "" || rule == "operator-action" {
			continue
		}
		rules = append(rules, struct {
			rule  string
			count int
		}{rule, count})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].count != rules[j].count {
			return rules[i].count > rules[j].count
		}
		return rules[i].rule < rules[j].rule
	})
	if len(rules) > n {
		rules = rules[:n]
	}
	return rules
}
