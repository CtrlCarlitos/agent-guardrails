package engine

import (
	"regexp"
	"time"
)

// Action is the canonical operation a broker, not a guarded shell, may execute.
type Action struct {
	Name       string
	Parameters map[string]string
}

var nightUntilCommand = regexp.MustCompile(`\Aguardrail night on --until ([0-2][0-9]:[0-5][0-9])\z`)

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
	if len(matches) != 2 {
		return Action{}, false
	}
	if _, err := time.Parse("15:04", matches[1]); err != nil {
		return Action{}, false
	}
	return Action{Name: "night-on", Parameters: map[string]string{"until": matches[1]}}, true
}
