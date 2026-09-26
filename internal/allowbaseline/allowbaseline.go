// Package allowbaseline is the list of Claude Code allow rules an operator can
// safely put in their own settings file to stop being prompted for commands that
// cannot install, fetch or run arbitrary code (#363).
//
// It is documentation, not enforcement, and guardrail writes none of it.
// Claude Code's permission prompts are its own; the allow list lives in the
// operator's settings, which ADR-0028 says belong to the operator. The Engine
// blocks, and stays silent about everything else; it does not approve.
//
// "Safe" is a definition the operator has already accepted: the verification
// commands guardrail itself runs for them at session end (the recipe registry),
// plus read-only queries. Everything that installs, launches a remote package,
// runs an arbitrary script or changes agent configuration is outside it.
package allowbaseline

import (
	"encoding/json"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/recipe"
)

// Entry is one Claude Code allow rule with the reason it is safe.
type Entry struct {
	Rule  string
	Group string
	Why   string
}

// Finding is an operator rule that matches more than the baseline allows.
type Finding struct {
	Rule string
	Why  string
}

// Comparison is the operator's allow list measured against the baseline.
type Comparison struct {
	Total   int
	Present int
	Missing []Entry
	Broad   []Finding
}

var graftReadOnly = []struct{ sub, why string }{
	{"ask", "queries the local code graph"},
	{"grep", "searches the local code graph"},
	{"skeleton", "prints one file's signatures from the graph"},
	{"callers", "lists who calls a symbol"},
	{"map", "orients in the repo from the graph"},
	{"blast", "shows what a diff touches"},
	{"check", "reports whether the graph is stale"},
	{"stats", "reports this session's usage"},
	{"version", "prints the version (reads the npm registry)"},
}

// Baseline returns the allow rules, grouped and explained. The verification
// tier is derived from the recipe registry, so a language added there is
// covered here without a second edit.
func Baseline() []Entry {
	var out []Entry
	seen := map[string]bool{}
	add := func(rule, group, why string) {
		if seen[rule] {
			return
		}
		seen[rule] = true
		out = append(out, Entry{Rule: rule, Group: group, Why: why})
	}

	for _, r := range recipe.Registry {
		for _, argv := range r.Session {
			add(sessionRule(argv), r.Name, "guardrail runs this at session end ("+r.Name+" recipe), so it is already trusted in this repo")
		}
	}
	add("Bash(go vet:*)", "go", "static analysis, read-only")
	add("Bash(ruff format --check:*)", "python", "reports formatting, writes nothing")
	add("Bash(prettier --check:*)", "js-ts", "reports formatting, writes nothing")
	add("Bash(npm run lint:*)", "js-ts", "the repo's own lint script; the same trust as npm test")
	add("Bash(npm run build:*)", "js-ts", "the repo's own build script; the same trust as npm test")
	add("Bash(pip list:*)", "packages", "lists installed packages")
	add("Bash(pip show:*)", "packages", "describes one installed package")
	add("Bash(npm ls:*)", "packages", "lists installed packages")

	for _, bin := range []string{"graft", "graft-dev"} {
		for _, sub := range graftReadOnly {
			add("Bash("+bin+" "+sub.sub+":*)", "graft", sub.why+"; local and read-only")
		}
		// A prefix rule cannot exclude a flag, and `build --deep` sends code to
		// an LLM provider with an API key, so the plain build is exact.
		add("Bash("+bin+" build)", "graft", "rebuilds the local, gitignored index ($0, no key); exact, because --deep calls an LLM")
	}
	return out
}

// sessionRule turns a recipe command into the narrowest prefix rule that still
// matches how it is run: the tool and, where it has one, its subcommand. A
// command that is read-only only because of a flag (`cargo fmt -- --check`) is
// exact, since a prefix rule cannot exclude the writing form.
func sessionRule(argv []string) string {
	for _, a := range argv[1:] {
		if a == "--check" {
			return "Bash(" + strings.Join(argv, " ") + ")"
		}
	}
	name := argv[0]
	if len(argv) > 1 && isSubcommand(argv[1]) {
		name += " " + argv[1]
	}
	return "Bash(" + name + ":*)"
}

func isSubcommand(word string) bool {
	return word != "" && !strings.HasPrefix(word, "-") && !strings.ContainsAny(word, "./{}")
}

// SnippetJSON is the baseline as a permissions.allow block, ready to merge into
// the operator's settings file.
func SnippetJSON() string {
	var rules []string
	for _, e := range Baseline() {
		rules = append(rules, e.Rule)
	}
	doc := map[string]any{"permissions": map[string]any{"allow": rules}}
	raw, _ := json.MarshalIndent(doc, "", "  ")
	return string(raw)
}

// broadPatterns are allow rules that match installs, remote launchers or
// arbitrary code as well as the harmless commands they were written for.
var broadPatterns = map[string]string{
	"graft":      "also runs graft init (writes agent config and Claude hooks), upgrade (npm install -g), uninstall and build --deep (an LLM provider and an API key); allow the read-only subcommands instead",
	"graft-dev":  "also runs graft init, upgrade, uninstall and build --deep; allow the read-only subcommands instead",
	"npx graft":  "npx downloads and runs a package that is not already local, and this also covers every graft subcommand including init and upgrade",
	"npx":        "downloads and runs remote packages",
	"bunx":       "downloads and runs remote packages",
	"uvx":        "downloads and runs remote packages",
	"pipx":       "installs and runs remote packages",
	"node":       "runs any script or -e code",
	"python":     "runs any script or -c code",
	"python3":    "runs any script or -c code",
	"pip":        "also runs pip install, which fetches from a registry",
	"pip3":       "also runs pip install, which fetches from a registry",
	"npm":        "also runs npm install, npm exec and any script",
	"npm run":    "runs any script in package.json, including one the agent just edited",
	"pnpm":       "also runs pnpm add, pnpm dlx and any script",
	"yarn":       "also runs yarn add, yarn dlx and any script",
	"uv":         "also runs uv sync, uv add, uv pip install and uv run with remote dependencies",
	"poetry":     "also runs poetry install and poetry add",
	"cargo":      "also runs cargo install and cargo run",
	"go":         "also runs go install, go get and go run",
	"go run":     "runs any Go program",
	"cargo run":  "runs any Rust program",
	"python -m":  "runs any module, including pip install",
	"python3 -m": "runs any module, including pip install",
}

// Broad reports which of the operator's rules are broader than the baseline
// and why. It only advises: the list is the operator's.
func Broad(have []string) []Finding {
	var out []Finding
	for _, rule := range have {
		if why, ok := broadPatterns[broadKey(rule)]; ok {
			out = append(out, Finding{Rule: rule, Why: why})
		}
	}
	return out
}

// broadKey extracts the command a Bash(...) rule allows when the rule is a bare
// prefix (`Bash(graft:*)` or `Bash(graft *)`), and "" for anything narrower or
// not a Bash rule, so `Bash(graft ask:*)` is not confused with `Bash(graft:*)`.
func broadKey(rule string) string {
	if !strings.HasPrefix(rule, "Bash(") || !strings.HasSuffix(rule, ")") {
		return ""
	}
	body := strings.TrimSuffix(strings.TrimPrefix(rule, "Bash("), ")")
	switch {
	case strings.HasSuffix(body, ":*"):
		return strings.TrimSuffix(body, ":*")
	case strings.HasSuffix(body, " *"):
		return strings.TrimSuffix(body, " *")
	}
	return ""
}

// Compare measures an operator's allow rules against the baseline.
func Compare(have []string) Comparison {
	present := map[string]bool{}
	for _, rule := range have {
		present[rule] = true
	}
	c := Comparison{Broad: Broad(have)}
	for _, e := range Baseline() {
		c.Total++
		if present[e.Rule] {
			c.Present++
		} else {
			c.Missing = append(c.Missing, e)
		}
	}
	return c
}
