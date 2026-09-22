package engine

import (
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func grantConfig(repo, ruleID, command string, uses int, expires time.Time) *policy.OperatorConfig {
	return &policy.OperatorConfig{Repos: map[string]policy.RepoGrant{
		repo: {Commands: []policy.CommandGrant{{RuleID: ruleID, Command: command, Uses: uses, ExpiresAt: expires}}},
	}}
}

func grantCall(repo, command string) ToolCall {
	return ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
		Capability: policy.CapabilityCommand, Command: command, CWD: repo, RepoRoot: repo}
}

func TestGrantRewritesOnlyTheAskItWasIssuedFor(t *testing.T) {
	repo := dialectRepoRoot()
	now := time.Now()
	op := grantConfig(repo, "P2.git-push-protected", "git push origin main", 1, now.Add(time.Minute))

	ask := policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-protected", Reason: "protected branch"}
	got := ApplyCommandGrant(ask, grantCall(repo, "git push origin main"), op, now)
	if got.Decision != policy.Allow || got.RuleID != "ask-allowed-by-operator-grant" {
		t.Fatalf("granted ask -> %+v, want an allow attributed to the grant", got)
	}
	if got.OriginRuleID != "P2.git-push-protected" {
		t.Errorf("origin rule = %q, want the ask the grant was issued against: an allow must not look ordinary in the record", got.OriginRuleID)
	}

	// A different command under the same rule is a different authorization.
	if got := ApplyCommandGrant(ask, grantCall(repo, "git push origin release"), op, now); got.Decision != policy.Ask {
		t.Errorf("ungranted command -> %+v, want the ask preserved", got)
	}
	// A different ask for the granted command is also a different one.
	other := policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-delete"}
	if got := ApplyCommandGrant(other, grantCall(repo, "git push origin main"), op, now); got.Decision != policy.Ask {
		t.Errorf("ungranted rule -> %+v, want the ask preserved", got)
	}
}

// A grant relaxes an Ask. It has no opinion about anything else, which is how
// it inherits deny invariance for free rather than by a second rule.
func TestGrantNeverTouchesADenyOrAnAllow(t *testing.T) {
	repo := dialectRepoRoot()
	now := time.Now()
	op := grantConfig(repo, "P1.rm-rf", "rm -rf /", 1, now.Add(time.Minute))
	deny := policy.Verdict{Decision: policy.Deny, RuleID: "P1.rm-rf", Reason: "recursive delete"}
	if got := ApplyCommandGrant(deny, grantCall(repo, "rm -rf /"), op, now); got.Decision != policy.Deny || got.RuleID != "P1.rm-rf" {
		t.Errorf("deny -> %+v, want it untouched: a grant cannot convert a deny", got)
	}
	allow := policy.Verdict{Decision: policy.Allow, RuleID: ""}
	if got := ApplyCommandGrant(allow, grantCall(repo, "rm -rf /"), op, now); got != allow {
		t.Errorf("allow -> %+v, want it untouched", got)
	}
}

// ADR-0018's exclusions reach the consumption site too, not just issuance: a
// grant recorded by hand, or one left behind by an older binary, must not
// relax outward reach.
func TestGrantCannotRelaxOutwardReachEvenWhenRecorded(t *testing.T) {
	repo := dialectRepoRoot()
	now := time.Now()
	for _, ruleID := range []string{"capability-external", "capability-web-search", "unknown-native-tool", "P3.unresolved"} {
		op := grantConfig(repo, ruleID, "npx publish-tool", 1, now.Add(time.Minute))
		ask := policy.Verdict{Decision: policy.Ask, RuleID: ruleID}
		if got := ApplyCommandGrant(ask, grantCall(repo, "npx publish-tool"), op, now); got.Decision != policy.Ask {
			t.Errorf("%s -> %+v, want the ask preserved", ruleID, got)
		}
	}
}

func TestSpentAndExpiredGrantsStopWorking(t *testing.T) {
	repo := dialectRepoRoot()
	now := time.Now()
	ask := policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-protected"}
	call := grantCall(repo, "git push origin main")
	for _, c := range []struct {
		name    string
		uses    int
		expires time.Time
	}{
		{"spent", 0, now.Add(time.Minute)},
		{"expired", 1, now.Add(-time.Second)},
	} {
		op := grantConfig(repo, "P2.git-push-protected", "git push origin main", c.uses, c.expires)
		if got := ApplyCommandGrant(ask, call, op, now); got.Decision != policy.Ask {
			t.Errorf("%s grant -> %+v, want the ask preserved", c.name, got)
		}
	}
}

// Grants never transfer between repositories, and an empty command is not a
// wildcard for every call that carries no command text.
func TestGrantScopeIsNotPortable(t *testing.T) {
	repo := dialectRepoRoot()
	now := time.Now()
	op := grantConfig(repo, "P2.git-push-protected", "git push origin main", 1, now.Add(time.Minute))
	ask := policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-protected"}

	elsewhere := grantCall(repo, "git push origin main")
	elsewhere.RepoRoot = otherDialectRepoRoot()
	elsewhere.CWD = elsewhere.RepoRoot
	if got := ApplyCommandGrant(ask, elsewhere, op, now); got.Decision != policy.Ask {
		t.Errorf("another repository -> %+v, want the ask preserved", got)
	}

	empty := grantConfig(repo, "P5.out-of-repo", "", 1, now.Add(time.Minute))
	blank := grantCall(repo, "")
	emptyAsk := policy.Verdict{Decision: policy.Ask, RuleID: "P5.out-of-repo"}
	if got := ApplyCommandGrant(emptyAsk, blank, empty, now); got.Decision != policy.Ask {
		t.Errorf("empty command -> %+v, want the ask preserved: a grant names a command", got)
	}
}
