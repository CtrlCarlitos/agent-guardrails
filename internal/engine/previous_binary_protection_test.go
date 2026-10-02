package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #94: the binary an update keeps for `guardrail rollback`, and the record
// that vouches for it, are guardrail machinery like the binary itself. The
// record's SHA-256 already makes a changed file detectable; protecting both
// keeps a session from breaking rollback by overwriting or deleting them.
func TestKeptPreviousBinaryAndRecordAreSelfConfig(t *testing.T) {
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	for _, cmd := range []string{
		`cp evil /home/u/.local/bin/guardrail.previous`,
		`cp evil.exe C:/Users/u/.local/bin/guardrail.previous.exe`,
		`rm /home/u/.local/bin/guardrail.previous`,
		`echo {} > /home/u/.local/state/guardrail/previous.json`,
	} {
		v := Evaluate(ToolCall{Plane: "claude", Event: "pre", Tool: "Bash", NativeTool: "Bash", Capability: policy.CapabilityCommand, InputShape: "command", Command: cmd, CWD: repo, RepoRoot: repo}, pol)
		if v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%s: %s %s; want deny P5.self-config", cmd, v.Decision, v.RuleID)
		}
	}
}
