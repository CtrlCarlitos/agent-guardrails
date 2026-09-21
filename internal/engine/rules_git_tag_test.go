package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func evalPush(t *testing.T, command string) policy.Verdict {
	t.Helper()
	return Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
		Capability: policy.CapabilityCommand, Command: command, CWD: "/repo", RepoRoot: "/repo"}, pathPol())
}

// A named tag push publishes a release pointer and was unasked: `git push
// --tags` asked, `git push origin main` asked, and `git push origin v0.21.8-dev`
// sailed through (#218). Measured before this rule existed, every case below
// allowed.
//
// A destination under refs/tags/ is the unambiguous half: it says what it is
// in the command text, so no repository knowledge is needed to classify it and
// there is no false positive to trade away.
func TestGitPushToExplicitTagRefAsks(t *testing.T) {
	for _, command := range []string{
		`git push origin refs/tags/v0.21.8-dev`,
		`git push origin v0.21.8-dev:refs/tags/v0.21.8-dev`,
		`git push origin HEAD:refs/tags/v1.0.0`,
		`git push origin refs/tags/release-2024`,
		// A tag whose name is not version-shaped at all still publishes a tag.
		`git push origin HEAD:refs/tags/nightly`,
		// Other remotes and extra refspecs do not change the classification.
		`git push upstream main refs/tags/v2.0.0`,
	} {
		v := evalPush(t, command)
		if v.Decision != policy.Ask {
			t.Errorf("%q -> %+v, want ask: the destination is under refs/tags/", command, v)
		}
	}
}

// The ambiguous half. `git push origin v0.21.8-dev` and `git push origin
// some-branch` are the same command shape — which one it is depends on what
// exists in the repository, and the Engine is a pure function of the call it
// is given: it never execs and never reads the repository, so it cannot
// resolve the name. A version-shaped destination is therefore classified on
// the name alone, which is deliberately a heuristic and deliberately errs
// toward asking.
func TestGitPushToVersionShapedRefAsks(t *testing.T) {
	for _, command := range []string{
		`git push origin v0.21.8-dev`,
		`git push origin v1.0.0`,
		`git push origin v1`,
		`git push origin 1.2.3`,
		`git push origin v2.0.0-rc1`,
		`git push origin v1.0.0+build.5`,
		`git push origin HEAD:v0.21.9-dev`,
	} {
		v := evalPush(t, command)
		if v.Decision != policy.Ask {
			t.Errorf("%q -> %+v, want ask: a version-shaped destination is a release pointer", command, v)
		}
	}
}

// The cost of the heuristic, stated as a test rather than left to be
// discovered: a branch whose name is version-shaped also asks. That is the
// accepted trade — the alternative is either reading the repository from a
// rule that is otherwise pure, or letting release pointers publish unasked.
func TestGitPushVersionShapedBranchAsksAndThatIsTheTrade(t *testing.T) {
	v := evalPush(t, `git push origin v2.0.0`)
	if v.Decision != policy.Ask {
		t.Errorf("v2.0.0 -> %+v, want ask even though it may be a branch", v)
	}
}

// The fleet workflow must not move: ordinary branch pushes stay allow, or the
// rule is an outage rather than a gate.
func TestGitPushToOrdinaryBranchStillAllows(t *testing.T) {
	for _, command := range []string{
		`git push origin feature-branch`,
		`git push origin fix/tag-push-ask`,
		`git push origin v-not-a-version`,
		`git push origin version-bump`,
		`git push origin release/next`,
		`git push origin vendor-update`,
		`git push -u origin test/windows-filename-shapes`,
		`git push origin HEAD:refs/heads/my-branch`,
	} {
		if v := evalPush(t, command); v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow: the fleet pushes branches constantly", command, v)
		}
	}
}

// The verdicts that already existed must keep their rule IDs, so a waiver
// written against one of them does not silently change meaning.
func TestGitPushExistingTagAndDeleteVerdictsAreUnchanged(t *testing.T) {
	for _, c := range []struct {
		command string
		rule    string
	}{
		{`git push --tags`, "P2.git-push-protected"},
		{`git push origin --tags`, "P2.git-push-protected"},
		{`git push origin :refs/tags/v0.21.8-dev`, "P2.git-push-delete"},
		{`git push origin --delete v1.0.0`, "P2.git-push-delete"},
		{`git push origin main`, "P2.git-push-protected"},
	} {
		v := evalPush(t, c.command)
		if v.Decision != policy.Ask || v.RuleID != c.rule {
			t.Errorf("%q -> %+v, want ask/%s", c.command, v, c.rule)
		}
	}
	// A force push to a tag is still the stronger deny, not the new ask.
	if v := evalPush(t, `git push --force origin refs/tags/v1.0.0`); v.Decision != policy.Deny {
		t.Errorf("force push to a tag -> %+v, want deny", v)
	}
	if v := evalPush(t, `git push origin +refs/tags/v1.0.0`); v.Decision != policy.Deny {
		t.Errorf("leading + refspec to a tag -> %+v, want deny", v)
	}
}
