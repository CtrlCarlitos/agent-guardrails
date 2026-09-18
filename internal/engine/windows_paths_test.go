package engine

import (
	"runtime"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Windows-shaped paths — drive letters, backslashes, UNC — must reach the
// same secret-tier verdicts as their POSIX forms on every host: the Engine
// normalises separators before matching, and a plane on a Windows host
// sends nothing else. CI's windows job runs this too.
func TestWindowsSecretPathsDenyOnEveryHost(t *testing.T) {
	cases := []struct {
		name string
		tool string
		path string
	}{
		{"ssh key", "Read", `C:\Users\u\.ssh\id_ed25519`},
		{"aws credentials", "Read", `C:\Users\u\.aws\credentials`},
		{"dotenv write", "Write", `C:\repo\.env`},
		{"forward-slash ssh key", "Read", `C:/Users/u/.ssh/id_ed25519`},
		{"unc share dotenv", "Write", `\\\\server\\share\\.env`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v := Evaluate(ToolCall{Tool: tt.tool, Capability: capabilityFor(tt.tool), Paths: []string{tt.path}, CWD: `C:\repo`, RepoRoot: `C:\repo`}, pathPol())
			if v.Decision != policy.Deny || v.RuleID != "P4.secret-path" {
				t.Fatalf("%s: %q -> %+v, want deny/P4.secret-path", runtime.GOOS, tt.path, v)
			}
		})
	}
}

// Containment is host-owned: `C:\repo\…` is absolute only on Windows, so a
// repo edit allows there and fails closed to an out-of-repo ask on POSIX.
// Secrets (above) deny everywhere; containment never allows cross-host.
func TestWindowsRepoFileContainmentFollowsTheHost(t *testing.T) {
	v := Evaluate(ToolCall{Tool: "Edit", Capability: policy.CapabilityMutation, Paths: []string{`C:\repo\internal\a.go`}, CWD: `C:\repo`, RepoRoot: `C:\repo`}, pathPol())
	if runtime.GOOS == "windows" {
		if v.Decision != policy.Allow {
			t.Fatalf("windows: repo file -> %+v, want allow", v)
		}
		return
	}
	if v.Decision != policy.Ask || v.RuleID != "P5.out-of-repo" {
		t.Fatalf("%s: repo file -> %+v, want ask/P5.out-of-repo (drive paths are not absolute here)", runtime.GOOS, v)
	}
}

func capabilityFor(tool string) policy.Capability {
	if tool == "Read" {
		return policy.CapabilityReadDiscovery
	}
	return policy.CapabilityMutation
}
