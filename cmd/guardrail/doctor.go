package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/coverage"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	opts, ok := parseDoctorArgs(args, stderr)
	if !ok {
		return 2
	}
	code := printDoctor(stdout, stderr)
	if opts.coverage == "" {
		return code
	}
	if covCode := printClaudeCoverage(opts.bundle, stdout, stderr); covCode != 0 {
		return covCode
	}
	return code
}

type doctorOptions struct {
	coverage string // plane to inventory; "" means none
	bundle   string // explicit bundle path; "" resolves the installed one
}

func parseDoctorArgs(args []string, stderr io.Writer) (doctorOptions, bool) {
	var opts doctorOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--coverage":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "guardrail: doctor --coverage needs a plane (claude)")
				return opts, false
			}
			i++
			opts.coverage = args[i]
		case "--bundle":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "guardrail: doctor --bundle needs a path")
				return opts, false
			}
			i++
			opts.bundle = args[i]
		default:
			fmt.Fprintf(stderr, "guardrail: doctor: unknown argument %q\n", safetext.SingleLine(args[i]))
			return opts, false
		}
	}
	if opts.bundle != "" && opts.coverage == "" {
		fmt.Fprintln(stderr, "guardrail: doctor --bundle only applies with --coverage claude")
		return opts, false
	}
	if opts.coverage != "" && opts.coverage != "claude" {
		fmt.Fprintf(stderr, "guardrail: doctor --coverage supports claude only (got %q)\n", safetext.SingleLine(opts.coverage))
		return opts, false
	}
	return opts, true
}

// claudeContracted is the coverage seam: the set of native names the Claude
// contract classifies. MCP tools are contracted by prefix and never appear
// as bare names in the bundle, so the check is the plane's static table.
func claudeContracted() (func(string) bool, []string) {
	names := []string{}
	set := map[string]bool{}
	for _, spec := range planecontract.RegisteredTools("claude") {
		set[spec.NativeTool] = true
		names = append(names, spec.NativeTool)
	}
	return func(name string) bool { return set[name] }, names
}

// printClaudeCoverage inventories the installed Claude Code bundle against
// the contract. Uncontracted tools are the finding: under the audit posture
// they allow by default. Exit 1 when any exist so scripts can gate on it.
func printClaudeCoverage(bundle string, stdout, stderr io.Writer) int {
	if bundle == "" {
		path, err := coverage.ClaudeBundlePath()
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: doctor --coverage claude: %s\n", safetext.SingleLine(err.Error()))
			return 2
		}
		bundle = path
	}
	f, err := os.Open(bundle)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: doctor --coverage claude: cannot open bundle: %s\n", safetext.SingleLine(err.Error()))
		return 2
	}
	defer f.Close()
	contracted, names := claudeContracted()
	inv, err := coverage.ScanClaudeBundle(f, contracted)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: doctor --coverage claude: %s\n", safetext.SingleLine(err.Error()))
		return 2
	}
	label := "Claude Code"
	if inv.Version != "" {
		label += " " + inv.Version
	}
	fmt.Fprintf(stdout, "claude coverage: %s (%s)\n", label, safetext.SingleLine(bundle))
	for _, line := range inv.Describe(names) {
		fmt.Fprintln(stdout, "  "+safetext.SingleLine(line))
	}
	if len(inv.Uncontracted) > 0 {
		fmt.Fprintln(stdout, "  add each uncontracted tool to internal/planecontract/claude.go with its capability; until then it runs under unknown_tool_posture")
		return 1
	}
	return 0
}

func printDoctor(stdout, stderr io.Writer) int {
	nightState, err := loadNightState(time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: night marker unreadable (%s); night mode remains inactive\n", safetext.SingleLine(err.Error()))
	} else if nightState.Active {
		fmt.Fprintln(stdout, nightState.Banner())
	}
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
	enrolled, _ := defaultOperatorAuthStore().Enrolled()
	fmt.Fprintln(stdout, operatorApprovalStatus(runtime.GOOS == "windows", enrolled))

	fmt.Fprintf(stdout, "claude settings: %s\n", safetext.SingleLine(claudeSettingsState()))
	fmt.Fprintf(stdout, "opencode settings: %s\n", safetext.SingleLine(planeStatusState("opencode")))
	fmt.Fprintf(stdout, "codex settings: %s\n", safetext.SingleLine(planeStatusState("codex")))
	fmt.Fprintf(stdout, "antigravity settings: %s\n", safetext.SingleLine(planeStatusState("antigravity")))
	if home, err := os.UserHomeDir(); err == nil {
		if raw, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json")); err == nil {
			var doc map[string]any
			if json.Unmarshal(raw, &doc) == nil {
				if n := unmarkedGuardrailGroups(doc); n > 0 {
					plural := "entry"
					if n > 1 {
						plural = "entries"
					}
					fmt.Fprintf(stdout, "  WARNING: %d unmarked guardrail-like hook %s in settings.json — legacy pre-marker entries. `guardrail plane enable claude` absorbs them; re-running the installer also will.\n", n, plural)
				}
			}
		}
		agPath := filepath.Join(home, ".gemini", "config", "hooks.json")
		if raw, err := os.ReadFile(agPath); err == nil {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				fmt.Fprintf(stdout, "  WARNING: Antigravity has no declarative floor (ADR-0008); hooks.json is unparseable so Antigravity runs completely unguarded. Run `guardrail plane enable antigravity`.\n")
			} else {
				if guardrail, ok := doc["guardrail"].(map[string]any); ok {
					if enabled, ok := guardrail["enabled"].(bool); ok && !enabled {
						fmt.Fprintf(stdout, "  WARNING: Antigravity has no declarative floor (ADR-0008); guardrail is disabled in hooks.json so Antigravity runs completely unguarded. Run `guardrail plane enable antigravity`.\n")
					}
				}
				if n := genconfig.CountUnmarkedAntigravityGroups(doc); n > 0 {
					plural := "entry"
					if n > 1 {
						plural = "entries"
					}
					fmt.Fprintf(stdout, "  WARNING: %d unmarked guardrail-like hook %s in hooks.json — legacy pre-marker entries. `guardrail plane enable antigravity` absorbs them; re-running the installer also will.\n", n, plural)
				}
			}
		} else if errors.Is(err, fs.ErrNotExist) && planeInstalled("antigravity") {
			fmt.Fprintf(stdout, "  WARNING: Antigravity has no declarative floor (ADR-0008); without hooks.json, Antigravity runs completely unguarded. Run `guardrail plane enable antigravity`.\n")
		}
	}
	return 0
}

func operatorApprovalStatus(windows, enrolled bool) string {
	if windows {
		return "operator approvals: disabled (Windows fail-closed)"
	}
	if enrolled {
		return "operator approvals: WebAuthn"
	}
	return "operator approvals: disabled"
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
	return genconfig.CountUnmarkedGuardrailGroups(doc)
}
