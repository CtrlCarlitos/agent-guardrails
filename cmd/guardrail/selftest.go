package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// selftestProbe is one direct hook invocation with its expected verdict.
// Payloads exercise each plane's adapter through the installed binary's own
// evaluation path — no configuration is mutated and no tool executes; hooks
// are pre-execution evaluation only.
type selftestProbe struct {
	Plane        string
	Name         string
	Args         []string // hook subcommand args (plane [phase])
	Payload      string
	WantDecision string
	WantRuleID   string
}

var selftestProbes = []selftestProbe{
	// claude — allow, deny (bash), deny (secret read), night-preserved ask (MCP external).
	{Plane: "claude", Name: "benign edit allows", Args: []string{"claude"},
		Payload:      `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"/tmp/selftest/a.go","new_string":"x"}}`,
		WantDecision: "allow"},
	{Plane: "claude", Name: "rm -rf denies", Args: []string{"claude"},
		Payload:      `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`,
		WantDecision: "deny"},
	{Plane: "claude", Name: "secret read denies", Args: []string{"claude"},
		Payload:      `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/home/selftest/.ssh/id_ed25519"}}`,
		WantDecision: "deny"},
	{Plane: "claude", Name: "unknown MCP asks (night-preserved)", Args: []string{"claude"},
		Payload:      `{"cwd":"/tmp","hook_event_name":"PreToolUse","tool_name":"mcp__weather__forecast","tool_input":{"city":"denver"}}`,
		WantDecision: "ask"},

	// opencode — allow, deny, MCP registry projection, unknown asks.
	{Plane: "opencode", Name: "benign read allows", Args: []string{"opencode"},
		Payload:      `{"session_id":"selftest","event":"pre","tool":"read","paths":["/tmp/selftest/a.go"],"cwd":"/tmp"}`,
		WantDecision: "allow"},
	{Plane: "opencode", Name: "serena secret mutation denies", Args: []string{"opencode"},
		Payload:      `{"session_id":"selftest","event":"pre","tool":"serena_replace_content","cwd":"/tmp","arguments":{"relative_path":".env","content":"x"}}`,
		WantDecision: "deny"},
	{Plane: "opencode", Name: "unknown tool asks (night-preserved)", Args: []string{"opencode"},
		Payload:      `{"session_id":"selftest","event":"pre","tool":"brand_new_thing","cwd":"/tmp","arguments":{}}`,
		WantDecision: "ask"},

	// antigravity — run_command parity through the pre phase.
	{Plane: "antigravity", Name: "destructive run_command denies", Args: []string{"antigravity", "pre"},
		Payload:      `{"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /","Cwd":"/tmp"}}}`,
		WantDecision: "deny"},
	{Plane: "antigravity", Name: "secret view denies", Args: []string{"antigravity", "pre"},
		Payload:      `{"toolCall":{"name":"view_file","args":{"TargetFile":"/home/selftest/.ssh/id_ed25519"}}}`,
		WantDecision: "deny"},

	// codex — direct invocation proves the binary path and verdicts; live
	// runtime mediation is a separate question (see audit records).
	{Plane: "codex", Name: "benign command allows", Args: []string{"codex"},
		Payload:      `{"hook_event_name":"PreToolUse","session_id":"selftest","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}`,
		WantDecision: "allow"},
	{Plane: "codex", Name: "destructive denies", Args: []string{"codex"},
		Payload:      `{"hook_event_name":"PreToolUse","session_id":"selftest","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`,
		WantDecision: "deny"},
}

// cmdSelftest runs the embedded probe matrix through the installed binary's
// hook path. It verifies enforcement behavior — not just registration, which
// doctor already covers. Direct hook invocation only: it cannot prove a plane
// runtime invokes its hooks (codex's hosted-tool gap); audit records remain
// the live-mediation evidence.
func cmdSelftest(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "guardrail: selftest takes no arguments")
		return 2
	}
	// A unique session suffix per invocation keeps selftest idempotent: a
	// repeated ask probe must never consume a prior run's approval-memory
	// entry and report allow (the double-run lesson from codex).
	sessionSuffix := fmt.Sprintf("selftest-%d", time.Now().UnixNano())
	passed := map[string]int{}
	failed := map[string]int{}
	for _, probe := range selftestProbes {
		payload := strings.ReplaceAll(probe.Payload, "selftest", sessionSuffix)
		var out, errb strings.Builder
		code := run(append([]string{"hook"}, probe.Args...), strings.NewReader(payload), &out, &errb)
		decision, ruleID := parseSelftestVerdict(code, out.String(), errb.String())
		if decision == probe.WantDecision && (probe.WantRuleID == "" || ruleID == probe.WantRuleID) {
			passed[probe.Plane]++
			continue
		}
		failed[probe.Plane]++
		fmt.Fprintf(stdout, "  FAILED %s: %s — got %s/%s (exit %d), want %s/%s\n",
			probe.Plane, probe.Name, decision, ruleID, code, probe.WantDecision, probe.WantRuleID)
	}
	totalFailed := 0
	for _, plane := range []string{"claude", "opencode", "antigravity", "codex"} {
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
	fmt.Fprintln(stdout, "selftest: all probes passed")
	return 0
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
