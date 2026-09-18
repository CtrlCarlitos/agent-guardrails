package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func init() {
	approval.RegisterAction("plane-disable", executePlaneApproval)
	approval.RegisterAction("plane-enable", executePlaneApproval)
}

// Daemon seams overridable in tests; production paths talk to the approval daemon.
var (
	submitPlaneRequest = approval.SubmitOnDemand
	queryPlaneStatus   = approval.QueryStatus
	planeInstalled     = func(plane string) bool {
		if path, err := planeConfigPath(plane); err == nil {
			if _, err := os.Stat(path); err == nil {
				return true
			}
		}
		binary := map[string]string{"claude": "claude", "opencode": "opencode", "antigravity": "agy", "codex": "codex"}[plane]
		if binary == "" {
			return false
		}
		_, err := exec.LookPath(binary)
		return err == nil
	}
)

// supportedPlanes are ordered for stable --all reporting.
var supportedPlanes = []string{"claude", "opencode", "antigravity", "codex"}

func planeConfigPath(plane string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch plane {
	case "codex":
		if dir := os.Getenv("CODEX_HOME"); dir != "" {
			return filepath.Join(dir, "hooks.json"), nil
		}
		return filepath.Join(home, ".codex", "hooks.json"), nil
	case "claude":
		return filepath.Join(home, ".claude", "settings.json"), nil
	case "opencode":
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			base = filepath.Join(home, ".config")
		}
		return filepath.Join(base, "opencode", "opencode.json"), nil
	case "antigravity":
		return filepath.Join(home, ".gemini", "config", "hooks.json"), nil
	default:
		return "", fmt.Errorf("unsupported plane %q", plane)
	}
}

// executePlaneApproval applies an approved plane lifecycle action for a batch
// of exact planes: disable removes only Guardrail-owned integration entries;
// enable regenerates and merges them.
func executePlaneApproval(r approval.Request) error {
	if r.Action != "plane-disable" && r.Action != "plane-enable" {
		return fmt.Errorf("invalid approved plane action")
	}
	var planes []string
	for _, plane := range strings.Split(r.Parameters["planes"], ",") {
		if !isSupportedPlane(plane) {
			return fmt.Errorf("invalid approved plane action")
		}
		planes = append(planes, plane)
	}
	if len(planes) == 0 {
		return fmt.Errorf("invalid approved plane action")
	}
	alreadyCompleted, err := startActionAudit(r)
	if err != nil {
		return err
	}
	if alreadyCompleted {
		return nil
	}
	if r.Action == "plane-enable" {
		for _, plane := range planes {
			if err := enablePlaneIntegration(plane); err != nil {
				return err
			}
		}
	} else {
		for _, plane := range planes {
			path, err := planeConfigPath(plane)
			if err != nil {
				return err
			}
			if err := genconfig.RemovePlaneFrom(path, plane); err != nil {
				return err
			}
		}
	}
	_ = completeActionAudit(r)
	return nil
}

func planePluginDir() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "guardrail"), nil
}

func enablePlaneIntegration(plane string) error {
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	if abs, err := filepath.Abs(binary); err == nil {
		binary = abs
	}
	path, err := planeConfigPath(plane)
	if err != nil {
		return err
	}
	switch plane {
	case "codex":
		if err := genconfig.WriteCodexRules(path); err != nil {
			return err
		}
		return genconfig.MergePlaneInto(path, plane, genconfig.CodexConfig(binary))
	case "claude":
		base, err := policy.LoadBase()
		if err != nil {
			return err
		}
		return genconfig.MergePlaneInto(path, plane, genconfig.ClaudeConfig(base, binary))
	case "opencode":
		base, err := policy.LoadBase()
		if err != nil {
			return err
		}
		dir, err := planePluginDir()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		pluginPath := filepath.Join(dir, "guardrail.js")
		if err := os.WriteFile(pluginPath, genconfig.OpencodePluginFor(binary), 0o644); err != nil {
			return err
		}
		if abs, err := filepath.Abs(pluginPath); err == nil {
			pluginPath = abs
		}
		return genconfig.MergePlaneInto(path, plane, genconfig.OpencodeConfig(base, pluginPath))
	case "antigravity":
		return genconfig.MergePlaneInto(path, plane, genconfig.AntigravityConfig(binary))
	default:
		return fmt.Errorf("unsupported plane %q", plane)
	}
}

func cmdPlane(args []string, terminal bool, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: plane requires a subcommand (status, enable, disable)")
		return 2
	}
	switch args[0] {
	case "disable":
		return cmdPlaneLifecycle(args[1:], "plane-disable", "disabled", terminal, stdout, stderr)
	case "enable":
		return cmdPlaneLifecycle(args[1:], "plane-enable", "enabled", terminal, stdout, stderr)
	case "status":
		return cmdPlaneStatus(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "guardrail: unknown plane subcommand %q\n", args[0])
		return 2
	}
}

func isSupportedPlane(name string) bool {
	return name == "claude" || name == "opencode" || name == "antigravity" || name == "codex"
}

// parsePlaneTargets resolves the argv of enable/disable into target planes.
func parsePlaneTargets(args []string, stdout, stderr io.Writer) (targets []string, all bool, ok bool) {
	switch {
	case len(args) == 1 && args[0] == "--all":
		for _, plane := range supportedPlanes {
			if planeInstalled(plane) {
				targets = append(targets, plane)
			}
		}
		return targets, true, true
	case len(args) == 1 && isSupportedPlane(args[0]):
		return []string{args[0]}, false, true
	default:
		fmt.Fprintln(stderr, "guardrail: plane lifecycle needs exactly one plane (claude, opencode, antigravity, codex) or --all")
		return nil, false, false
	}
}

func cmdPlaneLifecycle(args []string, action, outcome string, terminal bool, stdout, stderr io.Writer) int {
	verb := actionSuffix(action)
	targets, all, ok := parsePlaneTargets(args, stdout, stderr)
	if !ok {
		return 2
	}
	if runtime.GOOS == "windows" {
		fmt.Fprintln(stderr, "guardrail: plane commands are unavailable on Windows")
		return 2
	}
	if !terminal {
		fmt.Fprintf(stderr, "guardrail: plane %s requires an interactive local terminal\n", verb)
		return 2
	}

	// Reconciliation: a plane already in the desired state never prompts.
	var batch []string
	for _, plane := range targets {
		if planeIntegrationRegistered(plane) == (action == "plane-enable") {
			fmt.Fprintf(stdout, "%s: already %s\n", plane, outcome)
			continue
		}
		batch = append(batch, plane)
	}
	if all {
		for _, plane := range supportedPlanes {
			if !planeInstalled(plane) {
				fmt.Fprintf(stdout, "%s: not detected\n", plane)
			}
		}
	}
	if len(batch) == 0 {
		return 0
	}
	if !planesViaApproval(batch, action, outcome, stdout, stderr) {
		return 1
	}
	return 0
}

func actionSuffix(action string) string {
	if action == "plane-enable" {
		return "enable"
	}
	return "disable"
}

// planesViaApproval submits ONE broker request for the whole batch, so a
// single WebAuthn ceremony covers every plane.
func planesViaApproval(planes []string, action, outcome string, stdout, stderr io.Writer) bool {
	cwd, _ := os.Getwd()
	request := approval.Request{
		Plane:      "operator",
		SessionID:  "terminal",
		RepoRoot:   cwd,
		Scope:      approval.GlobalScope,
		Reason:     "operator terminal plane " + actionSuffix(action),
		Action:     action,
		Parameters: map[string]string{"planes": strings.Join(planes, ",")},
	}
	created, err := submitPlaneRequest(request)
	if err != nil {
		for _, plane := range planes {
			fmt.Fprintf(stderr, "guardrail: %s: approval request failed: %v\n", plane, err)
		}
		return false
	}
	fmt.Fprintf(stdout, "%s: approval required; open %s\n", strings.Join(planes, ", "), created.ApprovalURL)

	deadline := time.Now().Add(5 * time.Minute)
	if created.ExpiresAt.After(time.Now()) && created.ExpiresAt.Before(deadline) {
		deadline = created.ExpiresAt
	}
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		status, err := queryPlaneStatus(approval.DefaultSocketPath(), created.ID)
		if err != nil {
			for _, plane := range planes {
				fmt.Fprintf(stderr, "guardrail: %s: approval daemon unavailable\n", plane)
			}
			return false
		}
		switch status.Status {
		case "approved", "completed":
			// "completed" is the daemon's post-application terminal state;
			// "approved" is the pre-dispatch window for handler-less actions.
			for _, plane := range planes {
				fmt.Fprintf(stdout, "%s %s\n", plane, outcome)
			}
			return true
		case "denied", "expired":
			for _, plane := range planes {
				fmt.Fprintf(stderr, "guardrail: %s: %s %s\n", plane, actionSuffix(action), status.Status)
			}
			return false
		}
	}
	for _, plane := range planes {
		fmt.Fprintf(stderr, "guardrail: %s: %s approval expired\n", plane, actionSuffix(action))
	}
	return false
}

func cmdPlaneStatus(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "guardrail: plane status takes no arguments")
		return 2
	}
	for _, plane := range supportedPlanes {
		fmt.Fprintf(stdout, "%s: %s\n", plane, planeStatusState(plane))
	}
	return 0
}

// planeIntegrationRegistered reports whether Guardrail's integration is
// present in the plane's global config. It drives reconciliation skipping.
// Claude additionally requires zero unmarked legacy entries: their presence
// is drift the enable merge must absorb.
func planeIntegrationRegistered(plane string) bool {
	if plane == "claude" {
		if claudeSettingsState() != "guardrail hook registered" {
			return false
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		raw, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
		if err != nil {
			return false
		}
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil {
			return false
		}
		return genconfig.CountUnmarkedGuardrailGroups(doc) == 0
	}
	path, err := planeConfigPath(plane)
	if err != nil {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	if plane == "codex" {
		return genconfig.CodexHooksRegistered(doc) && genconfig.CodexRulesRegistered(path)
	}
	if plane == "opencode" {
		if plugins, ok := doc["plugin"].([]any); ok {
			for _, entry := range plugins {
				if s, ok := entry.(string); ok && filepath.Base(s) == "guardrail.js" {
					return true
				}
			}
		}
		return false
	}
	if plane == "antigravity" {
		guardrail, ok := doc["guardrail"].(map[string]any)
		if !ok {
			return false
		}
		enabled, ok := guardrail["enabled"].(bool)
		if !ok || !enabled {
			return false
		}
		if antigravityHasHookGroups(guardrail) && !antigravityHooksHaveOwnedGroup(guardrail) {
			return false
		}
		return genconfig.CountUnmarkedAntigravityGroups(doc) == 0
	}
	_, ok := doc["guardrail"]
	return ok
}

func antigravityHasHookGroups(guardrail map[string]any) bool {
	for _, ev := range guardrail {
		if groups, ok := ev.([]any); ok && len(groups) > 0 {
			return true
		}
	}
	return false
}

func antigravityHooksHaveOwnedGroup(guardrail map[string]any) bool {
	for _, ev := range guardrail {
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

// planeStatusState reports whether Guardrail's integration is registered in
// the plane's global config. It is read-only and never needs approval.
func planeStatusState(plane string) string {
	if plane == "claude" {
		return claudeSettingsState()
	}
	path, err := planeConfigPath(plane)
	if err != nil {
		return fmt.Sprintf("unknown (%v)", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if plane == "opencode" {
				return "no opencode.json"
			}
			return "no hooks.json"
		}
		return fmt.Sprintf("unreadable: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Sprintf("unparseable (%v)", err)
	}
	if plane == "antigravity" {
		if guardrail, ok := doc["guardrail"].(map[string]any); ok {
			if enabled, ok := guardrail["enabled"].(bool); ok && !enabled {
				return "present, disabled"
			}
		}
	}
	if planeIntegrationRegistered(plane) {
		if plane == "codex" {
			return "guardrail hooks registered; verify trust in /hooks; coverage limited (ADR-0014)"
		}
		return "guardrail integration registered"
	}
	return "present, integration NOT registered"
}
