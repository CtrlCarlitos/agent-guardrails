package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func evalGh(t *testing.T, command string) policy.Verdict {
	t.Helper()
	return Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
		Capability: policy.CapabilityCommand, Command: command, CWD: "/repo", RepoRoot: "/repo"}, pathPol())
}

// An agent running under the operator's `gh` login holds the operator's full
// repo-admin authority, and the GitHub-side protections are editable by that
// same token — so the agent can remove the protection and then do the thing it
// blocked. #228 records this happening: a session rewrote this repo's `main`
// ruleset bypass actors, created a tag ruleset, changed the Actions permissions
// policy and enabled immutable releases, all through plain `gh api`, all
// evaluated as ordinary commands.
//
// The floor glob pair from #232 cannot reach these: the method lives in a flag,
// the endpoint carries slashes, and a glob cannot see past the first slash.
// Measured there, the method-aware globs caught 2 of 6 mutating spellings. A
// parser can see the method, which is what this is.

// The six mutating spellings from the #232 measurement table, now against
// protection endpoints. Every one of these allowed before this rule.
func TestGhApiProtectionMutationsAsk(t *testing.T) {
	for _, command := range []string{
		// endpoint first, then the method flag — the form the globs missed
		`gh api repos/o/r/rulesets -X POST`,
		// method flag first — the form the globs caught
		`gh api -X PUT repos/o/r/actions/permissions`,
		`gh api --method DELETE repos/o/r/rulesets/42`,
		// implicit POST via a field flag, no method flag at all
		`gh api repos/o/r/rulesets -f name=main`,
		`gh api repos/o/r/actions/secrets/X -F key=@file`,
		`gh api repos/o/r/immutable-releases --input body.json`,
		// the remaining protection families from the issue
		`gh api repos/o/r/branches/main/protection -X PUT`,
		`gh api orgs/o/rulesets -X POST`,
		`gh api repos/o/r/hooks -X POST -f url=http://evil.test`,
		`gh api repos/o/r/collaborators/evil -X PUT`,
		`gh api repos/o/r -X PATCH -f visibility=public`,
		`gh api repos/o/r/vulnerability-alerts -X DELETE`,
	} {
		v := evalGh(t, command)
		if v.Decision != policy.Ask {
			t.Errorf("%q -> %+v, want ask: it rewrites repository protection", command, v)
		}
	}
}

// The three reads from the same table, plus the read twin of every family
// above. GET must stay free: auditing these endpoints is routine, and a rule
// that prompts on every inspection is how an operator learns to stop reading
// the prompts.
func TestGhApiReadsStayAllow(t *testing.T) {
	for _, command := range []string{
		`gh api repos/o/r`,
		`gh api user`,
		`gh api repos/o/r/pulls?state=open`,
		// read twins of the protection families
		`gh api repos/o/r/rulesets`,
		`gh api repos/o/r/branches/main/protection`,
		`gh api repos/o/r/actions/permissions`,
		`gh api orgs/o/rulesets`,
		// an explicit GET is still a GET
		`gh api repos/o/r/rulesets -X GET`,
		`gh api --method GET repos/o/r/actions/permissions`,
		// paging and output flags are not bodies
		`gh api repos/o/r/rulesets --paginate`,
		`gh api repos/o/r/rulesets --jq .[].name`,
	} {
		if v := evalGh(t, command); v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow: reading a protection is not changing it", command, v)
		}
	}
}

// A mutation on a path that is not a protection is not this rule's business.
// Asking for every mutating `gh api` call would manufacture exactly the ask
// fatigue the verdict profile was built to measure -- posting an issue comment
// is not an admin act.
func TestGhApiOrdinaryMutationsStayAllow(t *testing.T) {
	for _, command := range []string{
		`gh api repos/o/r/issues/1/comments -f body=hello`,
		`gh api repos/o/r/issues -X POST -f title=bug`,
		`gh api repos/o/r/pulls/1/reviews -X POST -f event=APPROVE`,
	} {
		if v := evalGh(t, command); v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow: not a protection endpoint", command, v)
		}
	}
}

// Path spellings the issue calls out: a leading slash, a full URL, and GHES
// via --hostname. The same endpoint reached three ways is the same act.
func TestGhApiPathSpellingsDoNotEvade(t *testing.T) {
	for _, command := range []string{
		`gh api /repos/o/r/rulesets -X POST`,
		`gh api https://api.github.com/repos/o/r/rulesets -X POST`,
		`gh api --hostname ghe.example.com repos/o/r/rulesets -X POST`,
		`gh api repos/o/r/RULESETS -X POST`,
	} {
		if v := evalGh(t, command); v.Decision != policy.Ask {
			t.Errorf("%q -> %+v, want ask: a different spelling is the same endpoint", command, v)
		}
	}
}

// graphql can perform the same mutations under a path that says nothing. The
// issue's minimum bar: a graphql call whose query text contains `mutation`
// asks. A query is a read and stays allow.
func TestGhApiGraphqlMutationAsks(t *testing.T) {
	// Quoted, because that is how a graphql body is actually written: bare
	// braces and parens make the tokenizer fail closed to ask on their own
	// (ADR-0012), which would make this test pass for the wrong reason.
	if v := evalGh(t, `gh api graphql -f 'query=mutation { updateRepositoryRuleset(input: {}) }'`); v.Decision != policy.Ask {
		t.Errorf("graphql mutation -> %+v, want ask", v)
	}
	if v := evalGh(t, `gh api graphql -f 'query=query { repository(owner: "o", name: "r") { name } }'`); v.Decision != policy.Allow {
		t.Errorf("graphql query -> %+v, want allow: reading is not mutating", v)
	}
}

// The floor keeps its own verdicts. This rule is the Engine's precise layer;
// #232's shape-level globs and #223's tag rule must not change meaning.
func TestGhNonApiVerdictsAreUnchanged(t *testing.T) {
	// A bare `gh` read is not this rule's business.
	if v := evalGh(t, `gh pr view 123`); v.Decision != policy.Allow {
		t.Errorf("gh pr view -> %+v, want allow", v)
	}
	// Not a gh command at all.
	if v := evalGh(t, `echo gh api repos/o/r/rulesets -X POST`); v.Decision != policy.Allow {
		t.Errorf("the string inside echo became a verdict: %+v", v)
	}
}

// The method parser is the reusable part, so it is pinned directly rather than
// only through verdicts: an implicit POST is the subtle case, because `gh api`
// defaults to GET and a body flag silently changes that.
func TestGhAPIMethodDetection(t *testing.T) {
	for _, c := range []struct {
		argv   []string
		method string
	}{
		{[]string{"gh", "api", "repos/o/r"}, "GET"},
		{[]string{"gh", "api", "repos/o/r", "-X", "POST"}, "POST"},
		{[]string{"gh", "api", "-X", "put", "repos/o/r"}, "PUT"},
		{[]string{"gh", "api", "--method", "delete", "repos/o/r"}, "DELETE"},
		{[]string{"gh", "api", "repos/o/r", "-f", "a=b"}, "POST"},
		{[]string{"gh", "api", "repos/o/r", "-F", "a=@f"}, "POST"},
		{[]string{"gh", "api", "repos/o/r", "--field", "a=b"}, "POST"},
		{[]string{"gh", "api", "repos/o/r", "--raw-field", "a=b"}, "POST"},
		{[]string{"gh", "api", "repos/o/r", "--input", "body.json"}, "POST"},
		// an explicit method wins over the implicit body inference
		{[]string{"gh", "api", "repos/o/r", "-f", "a=b", "-X", "PATCH"}, "PATCH"},
		// flags that are not bodies must not imply one
		{[]string{"gh", "api", "repos/o/r", "--paginate"}, "GET"},
		{[]string{"gh", "api", "repos/o/r", "--jq", ".name"}, "GET"},
		{[]string{"gh", "api", "repos/o/r", "-H", "X:1"}, "GET"},
	} {
		if got := ghAPIMethod(c.argv); got != c.method {
			t.Errorf("ghAPIMethod(%v) = %q, want %q", c.argv, got, c.method)
		}
	}
}
