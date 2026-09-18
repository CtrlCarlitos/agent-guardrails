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
var webHostCommand = regexp.MustCompile(`\Aguardrail egress (grant|revoke) --scope (repo|global) --host (` + hostList + `(?:,` + hostList + `)*)\z`)

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
	matches = webHostCommand.FindStringSubmatch(tc.Command)
	if len(matches) != 4 {
		return Action{}, false
	}
	for _, host := range strings.Split(matches[3], ",") {
		if policy.ValidateWebHost(host) != nil {
			return Action{}, false
		}
	}
	return Action{Name: "web-host-" + matches[1], Parameters: map[string]string{"scope": matches[2], "hosts": matches[3]}}, true
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
