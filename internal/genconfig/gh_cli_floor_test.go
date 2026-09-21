package genconfig

import (
	"strings"
	"testing"
)

// The floor mediates shell commands, and `gh` is a shell command that mutates
// GitHub state without touching the working tree: merging a PR, cutting or
// deleting a release, dispatching a workflow, deleting a repository. None of
// those were on the floor, so with the Engine unreachable (ADR-0022) they ran
// unmediated.
//
// Both planes are asserted because they share one source — OpencodeConfig
// reads bashAskGlobs/bashDenyGlobs and rewrites them — so a glob that works in
// Claude's matcher and not in OpenCode's would be a silent one-plane floor.

func ghFloorDecision(t *testing.T, command string) string {
	t.Helper()
	frag := ClaudeConfig(secretPol(), "guardrail")
	perms := frag["permissions"].(map[string]any)
	return claudeNativeDecision(perms, "Bash("+command+")")
}

// Mutations ask. These are the shapes that publish or destroy something a
// human would want to have been asked about.
func TestGhMutationsAskOnTheFloor(t *testing.T) {
	for _, command := range []string{
		"gh pr merge 123",
		"gh pr merge 123 --squash --delete-branch",
		"gh pr merge",
		"gh release create v1.0.0 --notes x",
		"gh release delete v1.0.0 --yes",
		"gh workflow run release.yml",
		"gh workflow run release.yml -f ref=main",
	} {
		if got := ghFloorDecision(t, command); got != "ask" {
			t.Errorf("%q -> %q, want ask", command, got)
		}
	}
}

// Deleting the repository is the one that has no undo worth the name.
func TestGhRepoDeleteDeniesOnTheFloor(t *testing.T) {
	for _, command := range []string{
		"gh repo delete owner/repo --yes",
		"gh repo delete",
	} {
		if got := ghFloorDecision(t, command); got != "deny" {
			t.Errorf("%q -> %q, want deny", command, got)
		}
	}
}

// Reads stay allow, or the floor becomes an interruption rather than a gate.
// `gh` is how the fleet reads CI state, and asking for every view would train
// people to click through the prompts that matter.
func TestGhReadsStayAllowOnTheFloor(t *testing.T) {
	for _, command := range []string{
		"gh pr view 123",
		"gh pr list",
		"gh pr checks 123",
		"gh release view v1.0.0",
		"gh release list",
		"gh workflow list",
		"gh workflow view release.yml",
		"gh repo view owner/repo",
		"gh repo clone owner/repo",
		"gh issue list",
		"gh run list",
		"gh api repos/o/r",
		"gh api user",
	} {
		if got := ghFloorDecision(t, command); got != "" && got != "allow" {
			t.Errorf("%q -> %q, want allow: reads must not prompt", command, got)
		}
	}
}

// A glob is a poor instrument for `gh api`: the method lives in a flag, the
// endpoint carries slashes, and the matcher's `*` does not cross a slash. What
// *is* expressible is a method flag that appears before the endpoint, which is
// covered here. The rest is the Engine's job (#228) and is deliberately not
// faked with a glob that would match every read as well.
func TestGhApiMethodFlagBeforeEndpointAsks(t *testing.T) {
	for _, command := range []string{
		"gh api -X POST repos/o/r",
		"gh api --method DELETE repos/o/r/x",
	} {
		if got := ghFloorDecision(t, command); got != "ask" {
			t.Errorf("%q -> %q, want ask", command, got)
		}
	}
}

// Both planes, one source. OpenCode rewrites the same globs into its own
// permission map, so the entries must survive the rewrite.
func TestGhGlobsReachTheOpencodePlane(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/opt/guardrail/guardrail.js")
	permission := frag["permission"].(map[string]any)
	bash := permission["bash"].(orderedPermissionRules)

	want := map[string]string{
		"gh pr merge{,**}":       "ask",
		"gh release create{,**}": "ask",
		"gh release delete{,**}": "ask",
		"gh workflow run{,**}":   "ask",
		"gh repo delete{,**}":    "deny",
	}
	for glob, decision := range want {
		got, ok := bash[glob]
		if !ok {
			t.Errorf("OpenCode floor is missing %q entirely", glob)
			continue
		}
		if got != decision {
			t.Errorf("OpenCode floor %q = %q, want %q", glob, got, decision)
		}
	}
}

// The glob shape is load-bearing and non-obvious, so it is pinned: `*` does
// not cross a path separator in this matcher, which means `gh repo delete*`
// silently fails to match `gh repo delete owner/repo` — the single most likely
// spelling of the command it is supposed to stop. Measured, then fixed with
// the brace alternation.
func TestGhGlobShapeCrossesPathSeparators(t *testing.T) {
	for _, glob := range append(ghAskGlobs(), ghDenyGlobs()...) {
		pattern, ok := stripWrapper("Bash(", glob)
		if !ok {
			t.Fatalf("malformed gh glob %q", glob)
		}
		if strings.HasSuffix(pattern, "*") && !strings.HasSuffix(pattern, "{,**}") {
			t.Errorf("%q ends in a bare star: it will not match an argument containing a slash", glob)
		}
	}
}
