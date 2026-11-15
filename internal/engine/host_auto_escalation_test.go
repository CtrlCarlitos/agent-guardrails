package engine

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #559, operator ruling 2026-11-15: a host running in an auto/bypass
// permission mode answers guardrail's asks itself, so an Ask verdict is an
// allow in disguise. On such hosts every Ask denies instead, with guidance
// naming the posture and the operator's terminal as the honest channel.
// Allow and Deny verdicts are unchanged; night mode's ask→allow relaxation
// happens before this conversion and is unaffected (its output is Allow).
func TestHostAutoApprovesEscalatesAsksToDeny(t *testing.T) {
	base := ToolCall{Tool: "Bash", Plane: "claude", Command: "git push origin main", CWD: "/repo", RepoRoot: "/repo"}
	ask := Evaluate(base, pathPol())
	if ask.Decision != policy.Ask {
		t.Fatalf("baseline = %+v; want Ask without the flag", ask)
	}
	escalated := base
	escalated.HostAutoApproves = true
	v := Evaluate(escalated, pathPol())
	if v.Decision != policy.Deny {
		t.Fatalf("verdict = %+v, want Deny on a host that answers asks itself", v)
	}
	if v.RuleID != "host-auto-ask-escalated" {
		t.Fatalf("rule = %q, want host-auto-ask-escalated", v.RuleID)
	}
	if v.OriginRuleID == "" {
		t.Fatal("the originating ask rule must be preserved in OriginRuleID")
	}
	if !strings.Contains(v.Reason, "host") || !strings.Contains(v.Reason, "operator") {
		t.Fatalf("reason must name the posture and the operator channel: %q", v.Reason)
	}
}

func TestHostAutoApprovesLeavesAllowAndDenyAlone(t *testing.T) {
	blocked := ToolCall{Tool: "Bash", Plane: "claude", Command: "rm -rf /", CWD: "/repo", RepoRoot: "/repo", HostAutoApproves: true}
	if v := Evaluate(blocked, pathPol()); v.Decision != policy.Deny || v.RuleID != "P1.rm-rf" {
		t.Fatalf("deny changed: %+v", v)
	}
	allowed := ToolCall{Tool: "Bash", Plane: "claude", Command: "ls", CWD: "/repo", RepoRoot: "/repo", HostAutoApproves: true}
	if v := Evaluate(allowed, pathPol()); v.Decision != policy.Allow {
		t.Fatalf("allow changed: %+v", v)
	}
}
