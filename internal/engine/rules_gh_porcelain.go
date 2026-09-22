package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// The porcelain half of #228.
//
// `gh api` carries its method in a flag, which is why that rule parses one.
// The porcelain carries no method at all: `gh secret set` is a PUT to
// actions/secrets and `gh repo edit --visibility` a PATCH on the repo, but the
// command text says only "set" and "edit". Measured on 772392d, every one of
// those spellings was allowed by the Engine while the `gh api` form asked.
//
// Two things made that worse than an ordinary gap. The declarative floor
// (ADR-0022) already denies `gh repo delete` and asks on `gh secret set`,
// `gh pr merge`, `gh release create` and `gh workflow run` -- so the backstop
// for an unreachable Engine was stricter than the Engine, which is backwards.
// And the floor is Claude's settings file, so on every other plane the
// porcelain was ungated outright, reaching the audit log as an allow with no
// rule attribution.
//
// The porcelain is also the easier spelling. `gh repo delete o/r --yes` is
// what an agent reaches for first; the api form is what it reaches for only
// once the first is blocked.
//
// Rule IDs are per family, following #235: an operator running a release loop
// should not have to waive secret administration to do it, and the per-rule
// verdict profile stays legible.

type ghPorcelainVerdict struct {
	deny   bool
	ruleID string
	reason string
}

// ghPorcelainRules maps a `gh <group> <verb>` pair to the family that owns its
// risk. Absence means allow: every read, and every mutation whose blast radius
// stays inside the repository's ordinary work (issues, pull request creation,
// clones), is deliberately not here.
var ghPorcelainRules = map[string]ghPorcelainVerdict{
	// Deleting the repository is not a setting the operator can change back.
	// This is the one deny, and it matches the floor's own verdict.
	"repo delete": {deny: true, ruleID: "P2.gh-repo-delete",
		reason: "deletes the repository under the operator's token; this is not reversible by changing a setting back"},

	// The protections themselves. Asks rather than denies: the operator is
	// allowed to change their own settings, they just have to be the one
	// deciding (#228).
	"secret set":      {ruleID: "P2.gh-protection", reason: "writes an Actions secret under the operator's token"},
	"secret delete":   {ruleID: "P2.gh-protection", reason: "removes an Actions secret under the operator's token"},
	"variable set":    {ruleID: "P2.gh-protection", reason: "writes an Actions variable under the operator's token"},
	"variable delete": {ruleID: "P2.gh-protection", reason: "removes an Actions variable under the operator's token"},
	"repo edit":       {ruleID: "P2.gh-protection", reason: "rewrites repository settings (visibility, merge and security flags) under the operator's token"},
	"ruleset delete":  {ruleID: "P2.gh-protection", reason: "removes a repository ruleset under the operator's token"},
	"ruleset edit":    {ruleID: "P2.gh-protection", reason: "rewrites a repository ruleset under the operator's token"},
	"ruleset create":  {ruleID: "P2.gh-protection", reason: "creates a repository ruleset under the operator's token"},

	// Where the repository lives, and whether it accepts work at all.
	"repo archive":   {ruleID: "P2.gh-repo-admin", reason: "archives the repository under the operator's token"},
	"repo unarchive": {ruleID: "P2.gh-repo-admin", reason: "unarchives the repository under the operator's token"},
	"repo rename":    {ruleID: "P2.gh-repo-admin", reason: "renames the repository under the operator's token"},
	"repo transfer":  {ruleID: "P2.gh-repo-admin", reason: "transfers the repository to another owner under the operator's token"},

	// Identity. Switching accounts changes which token every later call runs
	// under, which is a change to the authority itself rather than to what it
	// is used for.
	"auth switch": {ruleID: "P2.gh-auth-scope", reason: "changes which account later gh calls run as"},

	// A release is a published artifact set, so these reuse the publish family
	// (#235) rather than inventing a gh-shaped twin: an operator waiving
	// publishing waives it once.
	"release create": {ruleID: "P6.publish", reason: "publishes a release under the operator's token"},
	"release delete": {ruleID: "P6.publish", reason: "deletes a published release consumers may already have fetched"},
	"release edit":   {ruleID: "P6.publish", reason: "rewrites a published release under the operator's token"},
	"release upload": {ruleID: "P6.publish", reason: "adds assets to a published release under the operator's token"},

	// Merging writes to the branch the ruleset exists to protect.
	"pr merge": {ruleID: "P2.gh-pr-merge", reason: "merges into the target branch under the operator's token"},

	// Dispatching a workflow runs repository code with the repository's
	// secrets; enabling or disabling one changes whether CI runs at all.
	"workflow run":     {ruleID: "P2.gh-workflow-dispatch", reason: "dispatches a workflow that runs with the repository's secrets"},
	"workflow enable":  {ruleID: "P2.gh-workflow-dispatch", reason: "changes whether a workflow runs under the operator's token"},
	"workflow disable": {ruleID: "P2.gh-workflow-dispatch", reason: "changes whether a workflow runs under the operator's token"},
}

// ghScopeFlags widen the ambient token. That is the act which makes every
// other gate reachable, so it is its own family rather than folded into
// protections.
var ghScopeFlags = map[string]bool{"-s": true, "--scopes": true, "--scope": true}

// ghGroupVerb returns the first two non-flag words after `gh`.
//
// Flags are skipped rather than counted so that `gh pr merge --admin 1` and
// `gh repo delete o/r --yes` read the same as their unflagged spellings. A
// flag's value can be mistaken for a word here, which is why only the first
// two are taken: a value cannot reach that position without a flag already
// having consumed one of them.
func ghGroupVerb(argv []string) (string, string) {
	words := make([]string, 0, 2)
	for _, arg := range argv[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		words = append(words, arg)
		if len(words) == 2 {
			return words[0], words[1]
		}
	}
	if len(words) == 1 {
		return words[0], ""
	}
	return "", ""
}

func ghHasScopeFlag(argv []string) bool {
	for _, arg := range argv {
		if ghScopeFlags[arg] {
			return true
		}
		if name, _, ok := strings.Cut(arg, "="); ok && ghScopeFlags[name] {
			return true
		}
	}
	return false
}

// checkGhPorcelain classifies the `gh` subcommands that mutate state nobody
// can see in the working tree.
func checkGhPorcelain(s Simple) *policy.Verdict {
	if head(s.Argv) != "gh" {
		return nil
	}
	group, verb := ghGroupVerb(s.Argv)
	if group == "" {
		return nil
	}

	// Scope escalation is keyed on the flag, not the verb: `gh auth refresh`
	// without one re-authorizes the scopes the token already has, and
	// `gh auth login` without one is how a person signs in. Asking for those
	// would train the operator to click through the ones that widen.
	if group == "auth" && (verb == "refresh" || verb == "login") && ghHasScopeFlag(s.Argv) {
		return ask("P2.gh-auth-scope",
			"widens the scopes of the token every later gh call runs under")
	}

	rule, ok := ghPorcelainRules[group+" "+verb]
	if !ok {
		return nil
	}
	if rule.deny {
		return &policy.Verdict{Decision: policy.Deny, RuleID: rule.ruleID, Reason: rule.reason}
	}
	return ask(rule.ruleID, rule.reason)
}
