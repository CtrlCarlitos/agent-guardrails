package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// An agent running under the operator's `gh` login holds the operator's full
// repo-admin authority, and every GitHub-side protection is editable by that
// same token. So the protections do not bind the agent: it can remove the
// protection and then do the thing the protection blocked (#228).
//
// The floor's glob pair (#232) cannot reach this. The method lives in a flag,
// the endpoint carries slashes, and a glob does not cross a separator —
// measured there, the method-aware globs caught 2 of 6 mutating spellings, and
// the only shape that caught all six also matched every read. A parser can see
// the method, which is the whole reason this lives in the Engine.
//
// Scope, stated because the issue is larger than this rule: what asks here is
// a *mutation of a protection endpoint reached through `gh api`*. It is an
// ask, not a deny, per #228's non-goals — the operator is allowed to change
// their own settings, they just have to be the one deciding.
//
// The porcelain families (`gh secret set`, `gh repo edit`, `gh repo delete`,
// `gh auth switch`) now live in rules_gh_porcelain.go, which shares this
// rule's `P2.gh-protection` id wherever it reaches the same endpoints. The
// env-prefixed token case turned out to need no rule of its own: the
// shell-state machinery already strips assignment prefixes before any rule
// sees the command. The other transports (`curl` to api.github.com) remain
// separate work in the same issue.

// ghAPIBodyFlags make `gh api` send a body, which turns its default GET into a
// POST without any method flag appearing in the command. This is the inference
// that a glob cannot make and the reason an explicit parser is needed.
var ghAPIBodyFlags = map[string]bool{
	"-f": true, "-F": true, "--field": true, "--raw-field": true, "--input": true,
}

// ghAPIMethod returns the HTTP method a `gh api` invocation will use.
//
// `gh api` defaults to GET. An explicit -X/--method wins; otherwise a body
// flag implies POST. Returned uppercase so the caller compares one spelling.
func ghAPIMethod(argv []string) string {
	method := ""
	body := false
	for i := 2; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "-X" || arg == "--method":
			if i+1 < len(argv) {
				method = strings.ToUpper(argv[i+1])
				i++
			}
		case strings.HasPrefix(arg, "--method="):
			method = strings.ToUpper(strings.TrimPrefix(arg, "--method="))
		case ghAPIBodyFlags[arg]:
			body = true
		default:
			for flag := range ghAPIBodyFlags {
				if strings.HasPrefix(flag, "--") && strings.HasPrefix(arg, flag+"=") {
					body = true
				}
			}
		}
	}
	if method != "" {
		return method
	}
	if body {
		return "POST"
	}
	return "GET"
}

// ghProtectionPaths are the endpoint families whose mutation changes what the
// repository permits, enumerated from #228. Matched as a path prefix after
// normalisation, so `/rulesets` and `/rulesets/42` are both covered.
var ghProtectionPaths = []string{
	"rulesets",
	"branches/", // .../branches/{b}/protection
	"actions/permissions",
	"actions/secrets",
	"actions/variables",
	"environments",
	"immutable-releases",
	"vulnerability-alerts",
	"automated-security-fixes",
	"private-vulnerability-reporting",
	"code-scanning/default-setup",
	"collaborators",
	"hooks",
	"keys",
}

// ghAPIEndpoint extracts the endpoint operand: the first argument after `api`
// that is not a flag or a flag's value.
func ghAPIEndpoint(argv []string) string {
	valueFlags := map[string]bool{
		"-X": true, "--method": true, "-H": true, "--header": true,
		"--hostname": true, "--jq": true, "--template": true, "-t": true,
		"--cache": true, "--input": true,
		"-f": true, "-F": true, "--field": true, "--raw-field": true,
	}
	for i := 2; i < len(argv); i++ {
		arg := argv[i]
		if strings.HasPrefix(arg, "-") {
			if valueFlags[arg] && i+1 < len(argv) {
				i++
			}
			continue
		}
		return arg
	}
	return ""
}

// ghNormalizedAPIPath reduces the spellings the issue calls out — a leading
// slash, a full https URL, mixed case — to one comparable form, so the same
// endpoint reached three ways is judged once.
func ghNormalizedAPIPath(endpoint string) string {
	path := strings.ToLower(strings.TrimSpace(endpoint))
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(path, prefix) {
			path = strings.TrimPrefix(path, prefix)
			if slash := strings.Index(path, "/"); slash >= 0 {
				path = path[slash:]
			}
		}
	}
	path = strings.TrimPrefix(path, "/")
	if query := strings.IndexAny(path, "?#"); query >= 0 {
		path = path[:query]
	}
	return path
}

// ghPathRewritesProtection reports whether a normalised endpoint addresses a
// protection family. The owner/repo (or orgs/{o}) prefix is skipped so the
// family is compared without pinning a repository name.
func ghPathRewritesProtection(path string) bool {
	segments := strings.Split(path, "/")
	// repos/{owner}/{repo}/... or orgs/{org}/...
	var rest []string
	switch {
	case len(segments) > 3 && segments[0] == "repos":
		rest = segments[3:]
	case len(segments) > 2 && segments[0] == "orgs":
		rest = segments[2:]
	case len(segments) == 3 && segments[0] == "repos":
		// PATCH repos/{o}/{r} itself changes visibility and merge settings.
		return true
	default:
		return false
	}
	tail := strings.Join(rest, "/")
	for _, family := range ghProtectionPaths {
		if tail == strings.TrimSuffix(family, "/") || strings.HasPrefix(tail, family) {
			return true
		}
	}
	return false
}

// checkGhAPIProtection asks before a `gh api` call rewrites repository
// protection state.
func checkGhAPIProtection(s Simple) *policy.Verdict {
	if head(s.Argv) != "gh" || len(s.Argv) < 3 || s.Argv[1] != "api" {
		return nil
	}
	method := ghAPIMethod(s.Argv)
	if method == "GET" || method == "HEAD" {
		// Reading a protection is not changing it, and auditing these
		// endpoints is routine work that must not prompt.
		return nil
	}

	endpoint := ghAPIEndpoint(s.Argv)
	if strings.EqualFold(endpoint, "graphql") {
		// graphql can perform the same mutations behind a path that says
		// nothing, so the query text is the only available signal. #228's
		// minimum bar: a query containing `mutation` asks.
		if ghGraphqlMutates(s.Argv) {
			return ask("P2.gh-protection",
				"a GitHub GraphQL mutation can rewrite repository protections under the operator's token")
		}
		return nil
	}

	if !ghPathRewritesProtection(ghNormalizedAPIPath(endpoint)) {
		// An ordinary mutation -- an issue comment, a review -- is not an
		// admin act. Asking for all of them would train the operator to click
		// through the prompts that matter.
		return nil
	}
	return ask("P2.gh-protection",
		method+" "+endpoint+" rewrites repository protection under the operator's token")
}

func ghGraphqlMutates(argv []string) bool {
	for _, arg := range argv[2:] {
		if strings.Contains(strings.ToLower(arg), "mutation") {
			return true
		}
	}
	return false
}
