package engine

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Action is the canonical operation a broker, not a guarded shell, may execute.
// Command is the exact canonical command text it was recognised from.
type Action struct {
	Name       string
	Parameters map[string]string
	Command    string
}

// Brokered reports whether the action is one the hook has always filed with
// the approval broker (night mode and web-host grants). The lifecycle actions
// are recognised only so prompt mode can ask for them (ADR-0033); in passkey
// mode they stay P5.self-config.
func (a Action) Brokered() bool {
	switch a.Name {
	case "night-on", "night-off", "web-host-grant", "web-host-revoke":
		return true
	}
	return false
}

// Summary is the operator-facing description of the action, used as the
// question a prompt-mode ask puts to the human.
func (a Action) Summary() string {
	p := a.Parameters
	switch a.Name {
	case "setup":
		planes := "every detected plane"
		if p["planes"] != "" {
			planes = "planes " + p["planes"]
		}
		if p["state"] == "disabled" {
			return "remove guardrail from " + planes + " (guardrail setup --state disabled)"
		}
		return "register guardrail on " + planes + " (guardrail setup)"
	case "plane-enable", "plane-disable":
		target := "the " + p["target"] + " plane"
		if p["target"] == "--all" {
			target = "every detected plane"
		}
		if a.Name == "plane-disable" {
			return "remove guardrail from " + target
		}
		return "register guardrail on " + target
	case "recover":
		return "repair " + p["repair"] + " (guardrail recovery: backup, then re-register)"
	case "web-research-set":
		if p["enforcement"] == "off" {
			return "turn native web-research enforcement off, machine-wide"
		}
		return "turn native web-research enforcement on (strict), machine-wide"
	case "night-on":
		return "turn night mode on until " + p["until"] + " (asks become allows)"
	case "night-off":
		return "turn night mode off"
	case "web-host-grant":
		return "let guardrail fetch reach " + p["hosts"] + " (" + p["scope"] + " scope)"
	case "web-host-revoke":
		return "withdraw guardrail fetch access to " + p["hosts"] + " (" + p["scope"] + " scope)"
	}
	return a.Name
}

var lifecyclePlanes = map[string]bool{"claude": true, "opencode": true, "antigravity": true, "codex": true}
var lifecycleRepairs = map[string]bool{"claude-settings": true, "opencode-config": true, "antigravity-hooks": true}

// canonicalCommandBytes is the whitelist every canonical operator command is
// written in: no quoting, substitution, chaining, redirection, tabs or
// newlines can be part of one.
func canonicalCommandBytes(command string) bool {
	for i := 0; i < len(command); i++ {
		c := command[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == ',' || c == '=' || c == '-' || c == ':' || c == ' ') {
			return false
		}
	}
	return true
}

// parseLifecycleCommand recognises the canonical lifecycle commands prompt
// mode can ask for (ADR-0033): setup, plane enable|disable, recover and
// web-research on|off, as whole commands with exactly the flags each takes.
func parseLifecycleCommand(command string) (Action, bool) {
	if !strings.HasPrefix(command, "guardrail ") || !canonicalCommandBytes(command) {
		return Action{}, false
	}
	tokens := strings.Split(command, " ")
	for _, token := range tokens {
		if token == "" {
			return Action{}, false
		}
	}
	switch tokens[1] {
	case "setup":
		values := map[string]string{}
		for i := 2; i < len(tokens); i++ {
			name, value, inline := strings.Cut(strings.TrimPrefix(tokens[i], "--"), "=")
			if !strings.HasPrefix(tokens[i], "--") || (name != "state" && name != "planes") {
				return Action{}, false
			}
			if !inline {
				i++
				if i >= len(tokens) || strings.HasPrefix(tokens[i], "-") {
					return Action{}, false
				}
				value = tokens[i]
			}
			if _, dup := values[name]; dup || value == "" {
				return Action{}, false
			}
			values[name] = value
		}
		state := values["state"]
		if state == "" {
			state = "enabled"
		}
		if state != "enabled" && state != "disabled" {
			return Action{}, false
		}
		params := map[string]string{"state": state}
		if list, ok := values["planes"]; ok {
			seen := map[string]bool{}
			for _, plane := range strings.Split(list, ",") {
				if !lifecyclePlanes[plane] || seen[plane] {
					return Action{}, false
				}
				seen[plane] = true
			}
			params["planes"] = list
		}
		return Action{Name: "setup", Parameters: params, Command: command}, true
	case "plane":
		if len(tokens) != 4 || (tokens[2] != "enable" && tokens[2] != "disable") || (!lifecyclePlanes[tokens[3]] && tokens[3] != "--all") {
			return Action{}, false
		}
		return Action{Name: "plane-" + tokens[2], Parameters: map[string]string{"target": tokens[3]}, Command: command}, true
	case "recover":
		if len(tokens) != 3 || !lifecycleRepairs[tokens[2]] {
			return Action{}, false
		}
		return Action{Name: "recover", Parameters: map[string]string{"repair": tokens[2]}, Command: command}, true
	case "web-research":
		if len(tokens) != 3 || (tokens[2] != "on" && tokens[2] != "off") {
			return Action{}, false
		}
		return Action{Name: "web-research-set", Parameters: map[string]string{"enforcement": tokens[2]}, Command: command}, true
	}
	return Action{}, false
}

var nightUntilCommand = regexp.MustCompile(`\Aguardrail night on --until ([0-2][0-9]:[0-5][0-9])\z`)
var hostList = `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+`
var webHostBatch = regexp.MustCompile(`\A` + hostList + `(?:,` + hostList + `)*\z`)

// parseWebHostCommand recognises `guardrail egress grant|revoke` with exactly one
// --scope and one --host, in either order and in either `--flag value` or
// `--flag=value` spelling (#126: argument parsers are order-agnostic, and a
// guard that is not sends the command down the unbrokered path, where the agent
// loses the passkey flow).
//
// It stays a whitelist, not a shell parser. Every byte of the command must be a
// lowercase letter, digit, '.', ',', '=', '-' or a single space, so quoting,
// substitution, chaining, pipes, redirects, tabs and newlines can never be part
// of a canonical action. Each flag must appear exactly once with a non-empty
// value, and any other flag, operand or extra space is rejected. The broker path
// files an approval request, so what counts as canonical must not widen.
func parseWebHostCommand(command string) (verb, scope, hosts string, ok bool) {
	const prefix = "guardrail egress "
	if !strings.HasPrefix(command, prefix) {
		return "", "", "", false
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == ',' || c == '=' || c == '-' || c == ' ') {
			return "", "", "", false
		}
	}
	tokens := strings.Split(command[len(prefix):], " ")
	if len(tokens) < 3 || (tokens[0] != "grant" && tokens[0] != "revoke") {
		return "", "", "", false
	}
	verb = tokens[0]
	values := map[string]string{}
	for i := 1; i < len(tokens); i++ {
		token := tokens[i]
		if token == "" || !strings.HasPrefix(token, "--") {
			return "", "", "", false
		}
		name, value, hasValue := strings.Cut(token[2:], "=")
		if !hasValue {
			i++
			if i >= len(tokens) || strings.HasPrefix(tokens[i], "-") {
				return "", "", "", false
			}
			value = tokens[i]
		}
		if (name != "scope" && name != "host") || value == "" || strings.Contains(value, "=") {
			return "", "", "", false
		}
		if _, dup := values[name]; dup {
			return "", "", "", false
		}
		values[name] = value
	}
	scope, hosts = values["scope"], values["host"]
	if len(values) != 2 || (scope != "repo" && scope != "global") || !webHostBatch.MatchString(hosts) {
		return "", "", "", false
	}
	for _, host := range strings.Split(hosts, ",") {
		if policy.ValidateWebHost(host) != nil {
			return "", "", "", false
		}
	}
	return verb, scope, hosts, true
}

// OperatorAction accepts only a complete canonical command with no shell syntax.
// Everything else remains subject to the unconditional self-configuration deny.
func OperatorAction(tc ToolCall) (Action, bool) {
	if !tc.IsBash() {
		return Action{}, false
	}
	if tc.Command == "guardrail night off" {
		return Action{Name: "night-off", Command: tc.Command}, true
	}
	matches := nightUntilCommand.FindStringSubmatch(tc.Command)
	if len(matches) == 2 {
		if _, err := time.Parse("15:04", matches[1]); err != nil {
			return Action{}, false
		}
		return Action{Name: "night-on", Parameters: map[string]string{"until": matches[1]}, Command: tc.Command}, true
	}
	if verb, scope, hosts, ok := parseWebHostCommand(tc.Command); ok {
		return Action{Name: "web-host-" + verb, Parameters: map[string]string{"scope": scope, "hosts": hosts}, Command: tc.Command}, true
	}
	return parseLifecycleCommand(tc.Command)
}

// OperatorActionSatisfied reports whether a web-host grant would change
// nothing: every requested host is already authorized at the requested
// scope. The broker applies an approved grant itself, so a model re-issuing
// the command after approval must be told the grant holds rather than have
// a duplicate request filed. Other actions are never short-circuited.
func OperatorActionSatisfied(a Action, pol *policy.Policy, op *policy.OperatorConfig) (string, bool) {
	if a.Name != "web-host-grant" || pol == nil {
		return "", false
	}
	var allowed []string
	switch a.Parameters["scope"] {
	case "repo":
		allowed = pol.Slots.WebHosts
	case "global":
		if op == nil {
			return "", false
		}
		allowed = op.GlobalWebHosts
	default:
		return "", false
	}
	hosts := strings.Split(a.Parameters["hosts"], ",")
	for _, host := range hosts {
		if !slices.Contains(allowed, host) {
			return "", false
		}
	}
	return "egress to " + strings.Join(hosts, ", ") + " is already authorized at " + a.Parameters["scope"] + " scope; no request filed", true
}
