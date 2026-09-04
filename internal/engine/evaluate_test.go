package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func fullPol() *policy.Policy {
	p := pathPol()
	p.Slots.SafeRoots = []string{"/repo/tmp"}
	p.Rules = []policy.Rule{
		{ID: "proj.tf", Pattern: "terraform apply*", Decision: policy.Ask, Reason: "infra"},
	}
	return p
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		tc   ToolCall
		want policy.Decision
		id   string
	}{
		{ToolCall{Tool: "Bash", Command: "ls -la", CWD: "/repo", RepoRoot: "/repo"}, policy.Allow, ""},
		{ToolCall{Tool: "Bash", Command: "rm -rf /", CWD: "/repo", RepoRoot: "/repo"}, policy.Deny, "P1.rm-rf"},
		{ToolCall{Tool: "Read", Paths: []string{"/h/.ssh/id_rsa"}}, policy.Deny, "P4.secret-path"},
		{ToolCall{Tool: "Bash", Command: "chmod -R 777 /repo", CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "P1.chmod"},
		{ToolCall{Tool: "Bash", Command: "terraform apply -auto-approve", CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "proj.tf"},
		{ToolCall{Tool: "Bash", Command: `echo "oops`, CWD: "/repo", RepoRoot: "/repo"}, policy.Ask, "tokenize-failed"},
	}
	for _, c := range cases {
		v := Evaluate(c.tc, fullPol())
		if v.Decision != c.want || (c.id != "" && v.RuleID != c.id) {
			t.Errorf("Evaluate(%q) = %+v, want %s/%s", c.tc.Command+c.tc.Tool, v, c.want, c.id)
		}
	}
}

func TestEvaluateWaived(t *testing.T) {
	p := fullPol()
	p.Waived["P1.rm-rf"] = true
	v := Evaluate(ToolCall{Tool: "Bash", Command: "rm -rf /etc", CWD: "/repo", RepoRoot: "/repo"}, p)
	if v.Decision != policy.Allow {
		t.Fatalf("waived rule still fired: %+v", v)
	}
}
