package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "guardrail %s\n", safetext.SingleLine(version))

	cwd, _ := os.Getwd()
	fmt.Fprintf(stdout, "cwd: %s\n", safetext.SingleLine(cwd))
	repoRoot := cwd
	if root, ok := policy.FindRepoRoot(cwd); ok {
		repoRoot = root
	}

	if v := os.Getenv("GUARDRAIL_CONFIG"); v != "" {
		fmt.Fprintf(stdout, "GUARDRAIL_CONFIG: %s\n", safetext.SingleLine(v))
	} else {
		fmt.Fprintln(stdout, "GUARDRAIL_CONFIG: (unset)")
	}

	base, baseErr := policy.LoadBase()
	if baseErr != nil {
		fmt.Fprintf(stdout, "base policy: ERROR %s\n", safetext.SingleLine(baseErr.Error()))
		return 0
	}

	pth, ok, warn := policy.FindOverlayPath(cwd)
	if warn != "" {
		fmt.Fprintf(stdout, "overlay: %s\n", safetext.SingleLine(strings.TrimPrefix(warn, "guardrail: ")))
	}
	var ov *policy.Overlay
	switch {
	case ok:
		o, err := policy.LoadOverlay(pth)
		if err != nil {
			fmt.Fprintf(stdout, "overlay: %s (PARSE ERROR: %s)\n",
				safetext.SingleLine(pth), safetext.SingleLine(err.Error()))
		} else {
			ov = o
			fmt.Fprintf(stdout, "overlay: %s (parsed OK)\n", safetext.SingleLine(pth))
		}
	case warn == "":
		fmt.Fprintln(stdout, "overlay: none")
	}

	op, opErr := policy.LoadOperatorConfig()
	if opErr != nil {
		fmt.Fprintf(stderr, "guardrail: operator config unreadable (%s); treating as empty\n",
			safetext.SingleLine(opErr.Error()))
	}
	merged, warnings, err := policy.Merge(base, ov, version, op, repoRoot)
	if err != nil {
		fmt.Fprintf(stdout, "merge: ERROR %s\n", safetext.SingleLine(err.Error()))
		return 0
	}
	if len(warnings) == 0 {
		fmt.Fprintln(stdout, "policy warnings: none")
	} else {
		fmt.Fprintln(stdout, "policy warnings:")
		for _, w := range warnings {
			fmt.Fprintf(stdout, "  - %s\n", safetext.SingleLine(w))
		}
	}

	waived := policy.SortedWaivers(merged)
	if len(waived) == 0 {
		fmt.Fprintln(stdout, "waivers: none")
	} else {
		fmt.Fprintf(stdout, "waivers: %s\n", safetext.SingleLine(strings.Join(waived, ", ")))
	}

	fmt.Fprintf(stdout, "audit log: %s\n", safetext.SingleLine(audit.DefaultPath(merged.Slots.AuditLog)))

	fmt.Fprintf(stdout, "claude settings: %s\n", safetext.SingleLine(claudeSettingsState()))
	if home, err := os.UserHomeDir(); err == nil {
		if raw, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json")); err == nil {
			var doc map[string]any
			if json.Unmarshal(raw, &doc) == nil {
				if n := unmarkedGuardrailGroups(doc); n > 0 {
					plural := "entry"
					if n > 1 {
						plural = "entries"
					}
					fmt.Fprintf(stdout, "  WARNING: %d unmarked guardrail-like hook %s in settings.json — invisible to doctor and will be forked by the next merge. Remove them by hand; re-running the installer will not (its merge adds its own marked entry alongside).\n", n, plural)
				}
			}
		}
	}
	return 0
}

func claudeSettingsState() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "unknown (no home dir)"
	}
	p := filepath.Join(home, ".claude", "settings.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "no settings.json"
		}
		return fmt.Sprintf("unreadable: %v", err)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) == nil {
		if hooksHaveOwnedGroup(doc) {
			return "guardrail hook registered"
		}
		return "present, hook NOT registered"
	}
	if strings.Contains(string(raw), "guardrail hook claude") {
		return "guardrail hook registered (unparsed match)"
	}
	return "present, hook NOT registered"
}

func hooksHaveOwnedGroup(doc map[string]any) bool {
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		return false
	}
	for _, ev := range hooks {
		groups, ok := ev.([]any)
		if !ok {
			continue
		}
		for _, g := range groups {
			m, ok := g.(map[string]any)
			if !ok {
				continue
			}
			if id, _ := m["id"].(string); strings.HasPrefix(id, "guardrail-") {
				return true
			}
		}
	}
	return false
}

func unmarkedGuardrailGroups(doc map[string]any) int {
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		return 0
	}
	n := 0
	for _, ev := range hooks {
		groups, ok := ev.([]any)
		if !ok {
			continue
		}
		for _, g := range groups {
			m, ok := g.(map[string]any)
			if !ok {
				continue
			}
			if id, _ := m["id"].(string); strings.HasPrefix(id, "guardrail-") {
				continue
			}
			if b, _ := json.Marshal(m); strings.Contains(string(b), "guardrail hook ") {
				n++
			}
		}
	}
	return n
}
