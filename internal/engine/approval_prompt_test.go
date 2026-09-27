package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// ADR-0033: in prompt mode the hook asks for a closed set of canonical
// operator commands. The recogniser is a whitelist of whole commands; every
// other spelling stays under P5.self-config.
func TestOperatorActionRecognizesCanonicalLifecycleCommands(t *testing.T) {
	for _, tt := range []struct {
		command string
		name    string
		params  map[string]string
	}{
		{"guardrail setup", "setup", map[string]string{"state": "enabled"}},
		{"guardrail setup --state disabled", "setup", map[string]string{"state": "disabled"}},
		{"guardrail setup --state=enabled --planes=claude,codex", "setup", map[string]string{"state": "enabled", "planes": "claude,codex"}},
		{"guardrail setup --planes opencode --state disabled", "setup", map[string]string{"state": "disabled", "planes": "opencode"}},
		{"guardrail plane enable claude", "plane-enable", map[string]string{"target": "claude"}},
		{"guardrail plane disable --all", "plane-disable", map[string]string{"target": "--all"}},
		{"guardrail recover claude-settings", "recover", map[string]string{"repair": "claude-settings"}},
		{"guardrail web-research off", "web-research-set", map[string]string{"enforcement": "off"}},
		{"guardrail web-research on", "web-research-set", map[string]string{"enforcement": "on"}},
	} {
		action, ok := OperatorAction(ToolCall{Tool: "Bash", Command: tt.command})
		if !ok || action.Name != tt.name || action.Command != tt.command || action.Brokered() {
			t.Errorf("OperatorAction(%q) = (%+v, %v), want lifecycle %s with its canonical command", tt.command, action, ok, tt.name)
			continue
		}
		for key, want := range tt.params {
			if action.Parameters[key] != want {
				t.Errorf("OperatorAction(%q).Parameters[%s] = %q, want %q", tt.command, key, action.Parameters[key], want)
			}
		}
		if action.Summary() == "" {
			t.Errorf("OperatorAction(%q) has no summary for the ask", tt.command)
		}
	}
	for _, command := range []string{"guardrail night off", "guardrail egress grant --scope repo --host a.example.com"} {
		action, ok := OperatorAction(ToolCall{Tool: "Bash", Command: command})
		if !ok || !action.Brokered() || action.Command != command {
			t.Errorf("OperatorAction(%q) = (%+v, %v), want the brokered action it always was", command, action, ok)
		}
	}
}

func TestOperatorActionRejectsLifecycleNearMisses(t *testing.T) {
	for _, command := range []string{
		"guardrail setup --state paused",
		"guardrail setup --planes claude,nope",
		"guardrail setup --state disabled --state enabled",
		"guardrail setup  --state disabled",
		"guardrail setup --state",
		"guardrail setup extra",
		"guardrail setup; true",
		"guardrail setup && guardrail plane disable --all",
		"guardrail plane enable",
		"guardrail plane enable claude opencode",
		"guardrail plane enable Claude",
		"guardrail plane status",
		"guardrail plane enable claude > /tmp/x",
		"guardrail recover everything",
		"guardrail recover",
		"guardrail web-research status",
		"guardrail web-research off --now",
		"guardrail operator enroll",
		"guardrail operator recover-reset",
		"/usr/local/bin/guardrail setup",
		"guardrail.exe setup",
		"GUARDRAIL setup",
		"guardrail setup\n",
		"env guardrail setup",
		"script -qc 'guardrail setup' /dev/null",
		"guardrail hook claude",
	} {
		if action, ok := OperatorAction(ToolCall{Tool: "Bash", Command: command}); ok {
			t.Errorf("OperatorAction(%q) = %+v, want no canonical action", command, action)
		}
	}
}

// #413 relied on "an agent cannot fake a TTY through a pty wrapper". Measured
// on d274a8e only interpreters were denied; these wrappers were allowed.
func TestTerminalWrappersInvokingSelfControlAreDenied(t *testing.T) {
	for _, command := range []string{
		`script -qc "guardrail setup" /dev/null`,
		`script -q /dev/null guardrail setup`,
		`script -c 'guardrail plane enable claude'`,
		`script -qec "guardrail night off" /dev/null`,
		`python3 -c 'import pty; pty.spawn(["guardrail","setup"])'`,
		`python3 -c "import pty; pty.spawn('guardrail recover claude-settings')"`,
		`expect -c 'spawn guardrail setup; interact'`,
		`expect -c "spawn guardrail plane disable --all; expect eof"`,
		`unbuffer guardrail setup`,
		`unbuffer -p guardrail plane enable claude`,
		`winpty guardrail setup`,
		`winpty guardrail.exe plane enable claude`,
		`winpty -Xallow-non-tty guardrail operator enroll`,
		`tmux new-session -d 'guardrail setup'`,
		`screen -dm guardrail setup`,
		`socat - EXEC:'guardrail setup',pty`,
		`dtach -n /tmp/s guardrail setup`,
		`abduco -n s guardrail setup`,
		`empty -f guardrail setup`,
		`faketty guardrail setup`,
		`mintty -e guardrail setup`,
		`wt guardrail setup`,
		`conhost guardrail setup`,
		`unbuffer guardrail night off`,
		`script -qc "guardrail night on --until 07:00" /dev/null`,
		`winpty guardrail egress grant --scope repo --host a.example.com`,
		`script -qc "guardrail web-research off" /dev/null`,
	} {
		v := evalBash(t, command)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%q -> %+v, want deny/P5.self-config", command, v)
		}
	}
	// Wrappers stay usable for everything else.
	for _, command := range []string{
		`script -q /dev/null ls`,
		`unbuffer go test ./...`,
		`tmux new-session -d 'make build'`,
		`winpty guardrail doctor`,
	} {
		if v := evalBash(t, command); v != nil && v.RuleID == "P5.self-config" {
			t.Errorf("%q -> %+v, want no self-config verdict", command, v)
		}
	}
}

// A non-canonical egress spelling reached the CLI, which only its TTY gate
// stopped; `hook` lets a session forge its host's payload and mint a ticket.
func TestEgressAndHookInvocationsAreSelfConfig(t *testing.T) {
	for _, command := range []string{
		"guardrail egress grant --scope repo --host a.example.com; true",
		"guardrail egress grant --host a.example.com --scope repo --scope global",
		"guardrail egress revoke --scope global --host a.example.com && echo done",
		"guardrail hook claude",
		`echo '{"tool_name":"Bash"}' | guardrail hook claude`,
		"guardrail hook opencode < payload.json",
		`python3 -c "import subprocess; subprocess.run(['guardrail','hook','claude'])"`,
	} {
		v := evalBash(t, command)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%q -> %+v, want deny/P5.self-config", command, v)
		}
	}
}

// Tickets are honoured because of where they live: writing there is P5.
func TestApprovalTicketDirectoryIsProtected(t *testing.T) {
	for _, p := range []string{
		"/home/u/.local/state/guardrail/approval-tickets/0123-abcd.json",
		"/home/u/.local/state/guardrail/approval-tickets",
		"/tmp/state/guardrail/approval-tickets/x.json",
	} {
		read := ToolCall{Tool: "Read", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(read, pathPol()); v != nil {
			t.Errorf("Read %q -> %+v, want nil (a ticket holds no secret)", p, v)
		}
		write := ToolCall{Tool: "Write", Paths: []string{p}, RepoRoot: "/repo", CWD: "/repo"}
		if v := checkPaths(write, pathPol()); v == nil || v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("Write %q -> %+v, want deny/P5.self-config", p, v)
		}
	}
	for _, command := range []string{
		"printf '{}' > /home/u/.local/state/guardrail/approval-tickets/k.json",
		"cp forged.json /home/u/.local/state/guardrail/approval-tickets/k.json",
		`python3 -c "open('/home/u/.local/state/guardrail/approval-tickets/k.json','w').write('{}')"`,
		`python3 -c "open(r'C:\Users\u\AppData\Local\guardrail\approval-tickets\k.json','w')"`,
	} {
		tc := ToolCall{Tool: "Bash", Command: command, RepoRoot: "/repo", CWD: "/repo"}
		if v := Evaluate(tc, pathPol()); v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("Bash %q -> %+v, want deny/P5.self-config", command, v)
		}
	}
}
