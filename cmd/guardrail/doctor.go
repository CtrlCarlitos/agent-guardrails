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
	if opts.codexHooks {
		path, err := planeConfigPath("codex")
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: Codex hooks path: %s\n", safetext.SingleLine(err.Error()))
			return 1
		}
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: Codex diagnostic cwd: %s\n", safetext.SingleLine(err.Error()))
			return 1
		}
		if diagnosticCode := printCodexHookDiagnostics(path, cwd, runtime.GOOS, stdout, stderr); diagnosticCode != 0 {
			return diagnosticCode
		}
		return code
	}
	if opts.coverage == "" {
		return code
	}
	switch opts.coverage {
	case "codex":
		if covCode := cmdDoctorCodexCoverage(args, stdout, stderr); covCode != 0 {
			return covCode
		}
	case "claude":
		if covCode := printClaudeCoverage(opts.bundle, stdout, stderr); covCode != 0 {
			return covCode
		}
	case "antigravity":
		if covCode := printAntigravityCoverage(opts.config, opts.schemas, stdout, stderr); covCode != 0 {
			return covCode
		}
	}
	return code
}

type doctorOptions struct {
	schema     string // captured Responses tool schema (codex)
	coverage   string // plane to inventory; "" means none
	bundle     string // explicit bundle path; "" resolves the installed one (claude)
	config     string // explicit mcp_config.json path; "" resolves default (antigravity)
	schemas    string // explicit mcp schemas dir; "" resolves default (antigravity)
	codexHooks bool   // inspect trust, direct execution, and observed Codex runtime evidence
}

func parseDoctorArgs(args []string, stderr io.Writer) (doctorOptions, bool) {
	var opts doctorOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--coverage":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "guardrail: doctor --coverage needs a plane (claude, antigravity, codex)")
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
		case "--config":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "guardrail: doctor --config needs a path")
				return opts, false
			}
			i++
			opts.config = args[i]
		case "--schema":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "guardrail: doctor --schema needs a path")
				return opts, false
			}
			i++
			opts.schema = args[i]
		case "--schemas":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "guardrail: doctor --schemas needs a path")
				return opts, false
			}
			i++
			opts.schemas = args[i]
		case "--codex-hooks":
			if opts.codexHooks {
				fmt.Fprintln(stderr, "guardrail: duplicate --codex-hooks")
				return opts, false
			}
			opts.codexHooks = true
		default:
			fmt.Fprintf(stderr, "guardrail: doctor: unknown argument %q\n", safetext.SingleLine(args[i]))
			return opts, false
		}
	}
	if opts.schema != "" && opts.coverage != "codex" {
		fmt.Fprintln(stderr, "guardrail: doctor --schema only applies with --coverage codex")
		return opts, false
	}
	if opts.coverage == "codex" && opts.schema == "" {
		fmt.Fprintln(stderr, "guardrail: doctor --coverage codex requires --schema <Responses-tools.json>")
		return opts, false
	}
	if opts.bundle != "" && opts.coverage != "claude" {
		fmt.Fprintln(stderr, "guardrail: doctor --bundle only applies with --coverage claude")
		return opts, false
	}
	if (opts.config != "" || opts.schemas != "") && opts.coverage != "antigravity" {
		fmt.Fprintln(stderr, "guardrail: doctor --config and --schemas only apply with --coverage antigravity")
		return opts, false
	}
	if opts.coverage != "" && opts.coverage != "claude" && opts.coverage != "antigravity" && opts.coverage != "codex" {
		fmt.Fprintf(stderr, "guardrail: doctor --coverage supports claude, antigravity, codex (got %q)\n", safetext.SingleLine(opts.coverage))
		return opts, false
	}
	if opts.codexHooks && (opts.coverage != "" || opts.bundle != "" || opts.config != "" || opts.schema != "" || opts.schemas != "") {
		fmt.Fprintln(stderr, "guardrail: doctor --codex-hooks cannot be combined with coverage options")
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

// printAntigravityCoverage inventories configured MCP servers and tool schemas
// against the registry. Uncontracted tools are the finding.
// Exit 1 when any exist so scripts can gate on it; 2 on missing/bad config.
func printAntigravityCoverage(configPath, schemasDir string, stdout, stderr io.Writer) int {
	if configPath == "" {
		p, err := coverage.AntigravityConfigPath()
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: doctor --coverage antigravity: %s\n", safetext.SingleLine(err.Error()))
			return 2
		}
		configPath = p
	}
	if schemasDir == "" {
		s, err := coverage.AntigravitySchemasDir()
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: doctor --coverage antigravity: %s\n", safetext.SingleLine(err.Error()))
			return 2
		}
		schemasDir = s
	}

	inv, err := coverage.ScanAntigravity(configPath, schemasDir, planecontract.MatchMCPTool)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: doctor --coverage antigravity: %s\n", safetext.SingleLine(err.Error()))
		return 2
	}

	fmt.Fprintf(stdout, "antigravity coverage: Antigravity (%s)\n", safetext.SingleLine(configPath))
	for _, line := range inv.Describe() {
		fmt.Fprintln(stdout, "  "+safetext.SingleLine(line))
	}
	if len(inv.Uncontracted) > 0 {
		fmt.Fprintln(stdout, "  add each uncontracted tool to internal/planecontract/mcp.go with its capability and path args; until then it runs under unknown_tool_posture")
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
	fmt.Fprintln(stdout, operatorApprovalStatus(enrolled))

	fmt.Fprintf(stdout, "claude settings: %s\n", safetext.SingleLine(claudeSettingsLine()))
	fmt.Fprintf(stdout, "opencode settings: %s\n", safetext.SingleLine(planeStatusState("opencode")))
	fmt.Fprintf(stdout, "codex settings: %s\n", safetext.SingleLine(planeStatusState("codex")))
	fmt.Fprintf(stdout, "antigravity settings: %s\n", safetext.SingleLine(planeStatusState("antigravity")))
	if home, err := os.UserHomeDir(); err == nil {
		if doc, err := genconfig.ReadJSONObject(filepath.Join(home, ".claude", "settings.json")); err == nil {
			{
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
	printSpawnProbe(stdout)
	// Posture, not policy: guardrail cannot narrow the operator's credential,
	// only notice that it is wider than the work needs (#236). Warns, never
	// fails, and reports nothing at all when it learned nothing -- silence
	// here means "not known", never "fine".
	printCredentialPosture(stdout)
	return 0
}

// operatorApprovalStatus reports the credential-store state. ADR-0021 step
// (d) lifted the Windows gate: the platform no longer forces the disabled
// string; enrollment is the truth on every OS.
func operatorApprovalStatus(enrolled bool) string {
	if enrolled {
		return "operator approvals: WebAuthn"
	}
	return "operator approvals: disabled"
}

// claudeRegisteredPrefix and claudeCannotSpawnMarker label the two states the
// composed doctor line has to tell apart. Shared so it can do so without
// matching prose.
const (
	claudeRegisteredPrefix  = "guardrail hook registered"
	claudeCannotSpawnMarker = "CANNOT SPAWN"
)

// claudeSettingsLine is doctor's claude line, composed from the two different
// questions doctor can answer about a hook.
//
// claudeSettingsState says whether it is registered, and — because that is a
// hard fault the lifecycle must act on — whether the command can spawn at all.
// claudeMediationCaveat says whether it has ever been seen to run, which is a
// soft caveat a fresh enrolment legitimately trips.
//
// A command that cannot spawn has necessarily never fired, so the two would
// otherwise print the cause and then its consequence. Naming the cause once is
// the more useful line.
func claudeSettingsLine() string {
	state := claudeSettingsState()
	if !strings.HasPrefix(state, claudeRegisteredPrefix) {
		// Nothing is registered, so "never observed firing" would be noise on
		// top of a more basic finding the operator has to fix first.
		return state
	}
	if strings.Contains(state, claudeCannotSpawnMarker) {
		return state
	}
	return state + claudeMediationCaveat()
}

func claudeSettingsState() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "unknown (no home dir)"
	}
	p := filepath.Join(home, ".claude", "settings.json")
	doc, err := genconfig.ReadJSONObject(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "no settings.json"
		}
		if _, statErr := os.Stat(p); statErr != nil {
			return fmt.Sprintf("unreadable: %v", statErr)
		}
	}
	if err == nil {
		if hooksHaveOwnedGroup(doc) {
			if hazard := guardrailHookSpawnHazard(doc); hazard != "" {
				return "guardrail hook registered but " + claudeCannotSpawnMarker + " — " + hazard +
					". Nothing is being enforced; re-run `guardrail plane enable claude` to rewrite the command"
			}
			return "guardrail hook registered"
		}
		return "present, hook NOT registered"
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "guardrail hook claude") {
		return "guardrail hook registered (unparsed match)"
	}
	return "present, hook NOT registered"
}

// guardrailHookSpawnHazard returns why one of our registered hook commands
// cannot be spawned by a shell, or "" when all of them can.
//
// Registration and execution are different claims, and doctor could only see
// the first. An unquoted Windows path registers perfectly and dies in a POSIX
// shell on the first backslash, so the floor looked installed and enforced
// nothing (#149). A green that cannot distinguish the two is worse than no
// check, because it is the thing an operator trusts.
func guardrailHookSpawnHazard(doc map[string]any) string {
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		return ""
	}
	for _, ev := range hooks {
		groups, ok := ev.([]any)
		if !ok {
			continue
		}
		for _, g := range groups {
			group, ok := g.(map[string]any)
			if !ok {
				continue
			}
			id, _ := group["id"].(string)
			if !strings.HasPrefix(id, "guardrail-") && !hasGuardrailHookCommand(group) {
				continue
			}
			handlers, ok := group["hooks"].([]any)
			if !ok {
				continue
			}
			for _, h := range handlers {
				handler, ok := h.(map[string]any)
				if !ok {
					continue
				}
				command, _ := handler["command"].(string)
				if hazard := genconfig.UnquotedShellHazard(command); hazard != "" {
					return hazard
				}
			}
		}
	}
	return ""
}

// claudeMediationCaveat qualifies a registered hook with what the audit log
// says about it actually running, or "" once it demonstrably has.
//
// Registration and execution are different claims and doctor only ever checked
// the first. On Windows the registered command could not spawn, so the claude
// line read a bare green for four days while nothing was enforced (#149). A
// green that cannot tell those apart is the most expensive kind, because it is
// the one an operator trusts.
//
// This is deliberately appended at doctor's print site rather than inside
// claudeSettingsState, and the distinction matters. That string is also the
// lifecycle's ownership test — planeIntegrationRegistered compares it for
// exact equality — and it reaches the model in the SessionStart line, which is
// meant to fall silent in steady state. A missing record is not drift and not
// something an agent can act on: a freshly enrolled plane has none yet and is
// not broken. So this is an operator-facing caveat only, and it disappears on
// its own the first time a real session is mediated.
func claudeMediationCaveat() string {
	segments, err := audit.Segments(audit.DefaultPath(""))
	if err != nil {
		return " (mediation unverified: audit log unreadable)"
	}
	cutoff := time.Time{}
	if binary, err := os.Executable(); err == nil {
		if info, err := os.Stat(binary); err == nil {
			cutoff = info.ModTime()
		}
	}
	evidence, err := audit.ReadClaudeEvidence(segments, cutoff, time.Now())
	if err != nil {
		return " (mediation unverified: audit scan incomplete)"
	}
	if evidence.Observed() {
		return ""
	}
	return " but NEVER OBSERVED FIRING — no audit record from a real session since this binary was built." +
		" Registration is not enforcement; confirm with `guardrail selftest --evidence claude`"
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
			// Claude Code's serializer strips undocumented fields (including
			// our `id` marker) when it rewrites settings.json during normal
			// sessions. The hook command is the durable ownership marker.
			if hasGuardrailHookCommand(m) {
				return true
			}
		}
	}
	return false
}

// hasGuardrailHookCommand reports whether a hook group's command list invokes
// the guardrail binary, regardless of whether the id marker survived Claude
// Code's settings serializer.
func hasGuardrailHookCommand(group map[string]any) bool {
	hooks, ok := group["hooks"].([]any)
	if !ok {
		return false
	}
	for _, h := range hooks {
		m, ok := h.(map[string]any)
		if !ok {
			continue
		}
		if cmd, _ := m["command"].(string); cmd != "" && strings.Contains(cmd, "guardrail") && strings.Contains(cmd, " hook claude") {
			return true
		}
	}
	return false
}

func unmarkedGuardrailGroups(doc map[string]any) int {
	// Doctor warns only on true duplicates — unmarked entries alongside
	// marked ones. Claude Code strips ids during normal sessions; those
	// id-stripped hooks are owned by command pattern, not drift.
	return genconfig.CountUnmarkedGuardrailDuplicates(doc)
}
