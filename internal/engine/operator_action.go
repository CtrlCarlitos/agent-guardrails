package engine

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Action is the canonical operation a broker, not a guarded shell, may execute.
type Action struct {
	Name       string
	Parameters map[string]string
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
		return Action{Name: "night-off"}, true
	}
	matches := nightUntilCommand.FindStringSubmatch(tc.Command)
	if len(matches) == 2 {
		if _, err := time.Parse("15:04", matches[1]); err != nil {
			return Action{}, false
		}
		return Action{Name: "night-on", Parameters: map[string]string{"until": matches[1]}}, true
	}
	verb, scope, hosts, ok := parseWebHostCommand(tc.Command)
	if !ok {
		return Action{}, false
	}
	return Action{Name: "web-host-" + verb, Parameters: map[string]string{"scope": scope, "hosts": hosts}}, true
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
