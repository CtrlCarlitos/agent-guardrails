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
)

func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "guardrail %s\n", version)

	cwd, _ := os.Getwd()
	fmt.Fprintf(stdout, "cwd: %s\n", cwd)

	if v := os.Getenv("GUARDRAIL_CONFIG"); v != "" {
		fmt.Fprintf(stdout, "GUARDRAIL_CONFIG: %s\n", v)
	} else {
		fmt.Fprintln(stdout, "GUARDRAIL_CONFIG: (unset)")
	}

	base, baseErr := policy.LoadBase()
	if baseErr != nil {
		fmt.Fprintf(stdout, "base policy: ERROR %v\n", baseErr)
		return 0
	}

	pth, ok, warn := policy.FindOverlayPath(cwd)
	if warn != "" {
		fmt.Fprintf(stdout, "overlay: %s\n", strings.TrimPrefix(warn, "guardrail: "))
	}
	var ov *policy.Overlay
	switch {
	case ok:
		o, err := policy.LoadOverlay(pth)
		if err != nil {
			fmt.Fprintf(stdout, "overlay: %s (PARSE ERROR: %v)\n", pth, err)
		} else {
			ov = o
			fmt.Fprintf(stdout, "overlay: %s (parsed OK)\n", pth)
		}
	case warn == "":
		fmt.Fprintln(stdout, "overlay: none")
	}

	merged, warnings, err := policy.Merge(base, ov, version)
	if err != nil {
		fmt.Fprintf(stdout, "merge: ERROR %v\n", err)
		return 0
	}
	for _, w := range warnings {
		fmt.Fprintf(stdout, "  %s\n", w)
	}

	waived := policy.SortedWaivers(merged)
	if len(waived) == 0 {
		fmt.Fprintln(stdout, "waivers: none")
	} else {
		fmt.Fprintf(stdout, "waivers: %s\n", strings.Join(waived, ", "))
	}

	fmt.Fprintf(stdout, "audit log: %s\n", audit.DefaultPath(merged.Slots.AuditLog))

	fmt.Fprintf(stdout, "claude settings: %s\n", claudeSettingsState())
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
