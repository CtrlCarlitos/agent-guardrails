package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #512: `guardrail update <version>` from an agent session could replace the
// enforcement binary with an older release that enforces less (measured:
// `guardrail update v0.1.0-dev` allowed). Upgrading stays the sanctioned path
// the docs and the binary-protection guidance point agents to; a downgrade,
// and `guardrail rollback`, are the operator's.

func evalUpdate(t *testing.T, running, cmd string) policy.Verdict {
	t.Helper()
	old := RunningVersion
	RunningVersion = running
	t.Cleanup(func() { RunningVersion = old })
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	return Evaluate(ToolCall{Plane: "claude", Event: "pre", Tool: "Bash", NativeTool: "Bash", Capability: policy.CapabilityCommand, InputShape: "command", Command: cmd, CWD: repo, RepoRoot: repo}, pol)
}

func TestUpdateToANewerReleaseStaysAllowed(t *testing.T) {
	for _, cmd := range []string{
		`guardrail update v0.23.33-dev`,
		`guardrail update v0.24.0-dev`,
		`guardrail update v1.0.0`,
		`guardrail.exe update v0.23.33-dev`,
		`guardrail update v0.23.32-dev`, // same version: "nothing to do"
		`guardrail update`,              // usage error, changes nothing
	} {
		if v := evalUpdate(t, "v0.23.32-dev", cmd); v.Decision != policy.Allow {
			t.Errorf("%s: %s %s; want allow", cmd, v.Decision, v.RuleID)
		}
	}
}

func TestDowngradesAndRollbackAreOperatorOnly(t *testing.T) {
	for _, cmd := range []string{
		`guardrail update v0.23.31-dev`,
		`guardrail update v0.20.0-dev`,
		`guardrail update v0.1.0-dev`,
		`guardrail.exe update v0.1.0-dev`,
		`/home/u/.local/bin/guardrail update v0.22.99-dev`,
		`guardrail UPDATE v0.1.0-dev`,
		`guardrail rollback`,
		`guardrail rollback --force`,
		// Opaque or terminal-wrapped spellings cannot be judged by version.
		`python -c "import pty; pty.spawn(['guardrail','update','v0.24.0-dev'])"`,
		`script -qc "guardrail update v0.24.0-dev" /dev/null`,
		`node -e "require('child_process').execSync('guardrail rollback')"`,
	} {
		if v := evalUpdate(t, "v0.23.32-dev", cmd); v.Decision != policy.Deny || v.RuleID != "P5.self-config" {
			t.Errorf("%s: %s %s; want deny P5.self-config", cmd, v.Decision, v.RuleID)
		}
	}
}

// A dev build reports no comparable version: update keeps today's reading
// rather than guessing, while rollback stays the operator's.
func TestUpdateFromADevBuildKeepsTodaysReading(t *testing.T) {
	if v := evalUpdate(t, "dev", `guardrail update v0.1.0-dev`); v.Decision != policy.Allow {
		t.Errorf("dev build update: %s %s; want allow", v.Decision, v.RuleID)
	}
	if v := evalUpdate(t, "dev", `guardrail rollback`); v.Decision != policy.Deny {
		t.Errorf("dev build rollback: %s %s; want deny", v.Decision, v.RuleID)
	}
}

func TestReleaseVersionOrdering(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		less bool
		ok   bool
	}{
		{"v0.23.31-dev", "v0.23.32-dev", true, true},
		{"v0.9.0-dev", "v0.23.0-dev", true, true},
		{"v0.23.32-dev", "v0.23.32-dev", false, true},
		{"v1.0.0", "v0.99.99-dev", false, true},
		{"v0.23.32-dev", "v0.23.32", true, true}, // a pre-release precedes its release
		{"dev", "v0.1.0", false, false},
		{"v0.1", "v0.2.0", false, false},
	} {
		less, ok := releaseOlder(tc.a, tc.b)
		if less != tc.less || ok != tc.ok {
			t.Errorf("releaseOlder(%s, %s) = %v, %v; want %v, %v", tc.a, tc.b, less, ok, tc.less, tc.ok)
		}
	}
}
