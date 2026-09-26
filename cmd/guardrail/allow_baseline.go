package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/allowbaseline"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
)

// `guardrail allow-baseline` prints the Claude Code allow rules that are safe
// for an operator to put in their own settings, and compares their list with
// them (#363). It is advice about a file the operator owns (ADR-0028): there is
// deliberately no apply, guardrail writes nothing, and the Engine still blocks
// and never approves. See docs/allow-baseline.md.
func cmdAllowBaseline(args []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 0:
		printAllowBaseline(stdout)
		return 0
	case len(args) == 1 && args[0] == "--json":
		fmt.Fprintln(stdout, allowbaseline.SnippetJSON())
		return 0
	case len(args) == 1 && args[0] == "--check":
		return checkAllowBaseline(stdout, stderr)
	}
	fmt.Fprintln(stderr, "guardrail: allow-baseline takes no argument, --json or --check (there is no apply: the settings file is yours)")
	return 2
}

func printAllowBaseline(stdout io.Writer) {
	fmt.Fprintln(stdout, "allow baseline for Claude Code")
	fmt.Fprintln(stdout, "Rules safe to put in permissions.allow of your own settings file (~/.claude/settings.json).")
	fmt.Fprintln(stdout, "guardrail writes nothing: this is a list for you to review and paste. The Engine still")
	fmt.Fprintln(stdout, "blocks what it blocks; these only stop Claude Code's own prompt for commands that cannot")
	fmt.Fprintln(stdout, "install, fetch or run arbitrary code. `guardrail allow-baseline --json` prints them as a block.")
	group := ""
	for _, e := range allowbaseline.Baseline() {
		if e.Group != group {
			group = e.Group
			fmt.Fprintf(stdout, "\n[%s]\n", group)
		}
		fmt.Fprintf(stdout, "  %-38s %s\n", e.Rule, e.Why)
	}
}

// claudeAllowRules reads permissions.allow from the operator's Claude settings.
// found is false when there is no settings file, which is not an error.
func claudeAllowRules() (rules []string, found bool, err error) {
	path, err := planeConfigPath("claude")
	if err != nil {
		return nil, false, err
	}
	doc, err := genconfig.ReadJSONObject(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	permissions, _ := doc["permissions"].(map[string]any)
	list, _ := permissions["allow"].([]any)
	for _, entry := range list {
		if s, ok := entry.(string); ok {
			rules = append(rules, s)
		}
	}
	return rules, true, nil
}

func checkAllowBaseline(stdout, stderr io.Writer) int {
	rules, found, err := claudeAllowRules()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: allow-baseline: cannot read the Claude settings: %v\n", err)
		return 1
	}
	if !found {
		fmt.Fprintln(stdout, "no Claude settings file; nothing to compare with the baseline")
		return 0
	}
	c := allowbaseline.Compare(rules)
	fmt.Fprintf(stdout, "your allow list has %d rules; %d of %d baseline rules are present, %d missing\n", len(rules), c.Present, c.Total, len(c.Missing))
	if len(c.Broad) > 0 {
		fmt.Fprintf(stdout, "\n%d of your rules are broader than the baseline:\n", len(c.Broad))
		for _, f := range c.Broad {
			fmt.Fprintf(stdout, "  %s\n      %s\n", f.Rule, f.Why)
		}
	}
	if len(c.Missing) > 0 {
		fmt.Fprintln(stdout, "\nbaseline rules you do not have (add the ones you want; `guardrail allow-baseline` explains each):")
		group := ""
		missing := append([]allowbaseline.Entry(nil), c.Missing...)
		sort.SliceStable(missing, func(i, j int) bool { return missing[i].Group < missing[j].Group })
		for _, e := range missing {
			if e.Group != group {
				group = e.Group
				fmt.Fprintf(stdout, "  [%s]\n", group)
			}
			fmt.Fprintf(stdout, "    %s\n", e.Rule)
		}
	}
	return 0
}

// allowListLine is doctor's one-line summary, or "" when there is no Claude
// settings file to summarise.
func allowListLine() string {
	rules, found, err := claudeAllowRules()
	if err != nil || !found {
		return ""
	}
	c := allowbaseline.Compare(rules)
	parts := []string{fmt.Sprintf("%d of %d baseline rules present", c.Present, c.Total)}
	if n := len(c.Broad); n > 0 {
		parts = append(parts, fmt.Sprintf("%d broader than the baseline", n))
	}
	return "claude allow list: " + strings.Join(parts, "; ") + " (guardrail allow-baseline --check)"
}
