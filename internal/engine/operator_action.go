package engine

import (
	"regexp"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Action is the canonical operation a broker, not a guarded shell, may execute.
type Action struct {
	Name       string
	Parameters map[string]string
}

var nightUntilCommand = regexp.MustCompile(`\Aguardrail night on --until ([0-2][0-9]:[0-5][0-9])\z`)
var webHostCommand = regexp.MustCompile(`\Aguardrail egress (grant|revoke) --scope (repo|global) --host ([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\z`)

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
	if len(matches) != 4 || policy.ValidateWebHost(matches[3]) != nil {
		return Action{}, false
	}
	return Action{Name: "web-host-" + matches[1], Parameters: map[string]string{"scope": matches[2], "host": matches[3]}}, true
}
