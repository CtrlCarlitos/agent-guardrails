package allowbaseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/recipe"
)

// The baseline answers "what may an operator allow in Claude Code's own
// settings without a prompt, safely" (#363). It is documentation for a file the
// operator owns (ADR-0028), not a channel through which guardrail approves
// anything. Its definition of safe is one the operator has already accepted:
// the verification commands guardrail itself runs for them at session end, from
// the recipe registry, plus read-only queries. Installs, remote launchers and
// arbitrary scripts are outside it.

func rules() []string {
	var out []string
	for _, e := range Baseline() {
		out = append(out, e.Rule)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// The verification tier is derived, not typed: adding a language to the recipe
// registry adds its session commands here, and the two cannot disagree.
func TestBaselineCoversEverySessionCommandOfTheRecipeRegistry(t *testing.T) {
	got := rules()
	for _, r := range recipe.Registry {
		for _, argv := range r.Session {
			found := false
			for _, rule := range got {
				if strings.HasPrefix(rule, "Bash("+argv[0]) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("recipe %s runs %v at session end, but no baseline rule covers %q", r.Name, argv, argv[0])
			}
		}
	}
	for _, want := range []string{"Bash(go test:*)", "Bash(go build:*)", "Bash(pytest:*)", "Bash(ruff check:*)", "Bash(mypy:*)", "Bash(npm test:*)", "Bash(tsc:*)", "Bash(eslint:*)", "Bash(cargo test:*)"} {
		if !contains(got, want) {
			t.Errorf("baseline lacks %q", want)
		}
	}
}

// A prefix rule cannot exclude a flag, so a rule that would also match an
// install, a remote launcher, an arbitrary script or a change to agent
// configuration must never be here. This is the test that keeps the file honest.
func TestBaselineNeverAllowsInstallsRemoteCodeOrArbitraryScripts(t *testing.T) {
	forbidden := []string{
		" install", " add", " ci:", " ci)", " update", " upgrade", " uninstall", " init", " dlx", " exec",
		"npx", "bunx", "uvx", "pipx", "--deep", " -e", " -c",
	}
	for _, rule := range rules() {
		body := strings.TrimSuffix(strings.TrimPrefix(rule, "Bash("), ")")
		body = strings.TrimSuffix(body, ":*")
		for _, bad := range forbidden {
			if strings.Contains(" "+body+" ", bad+" ") || strings.Contains(rule, bad) {
				t.Errorf("baseline rule %q contains %q, which can install, fetch or run arbitrary code", rule, bad)
			}
		}
		for _, blanket := range []string{"Bash(node:*)", "Bash(python:*)", "Bash(python3:*)", "Bash(pip:*)", "Bash(npm:*)", "Bash(npx:*)", "Bash(pnpm:*)", "Bash(yarn:*)", "Bash(uv:*)", "Bash(poetry:*)", "Bash(go:*)", "Bash(cargo:*)", "Bash(graft:*)", "Bash(graft-dev:*)", "Bash(*)"} {
			if rule == blanket {
				t.Errorf("baseline rule %q is a blanket: it matches installs and arbitrary scripts", rule)
			}
		}
	}
}

// graft is allowed by subcommand. The blanket entries also cover `init` (writes
// agent instruction files, MCP config and Claude hooks), `upgrade` (npm install
// -g), `uninstall`, `build --deep` (an LLM provider and an API key), `viz` and
// `telemetry`.
func TestGraftIsAllowedBySubcommandAndOnlyTheReadOnlyOnes(t *testing.T) {
	got := rules()
	for _, sub := range []string{"ask", "grep", "skeleton", "callers", "map", "blast", "check", "stats", "version"} {
		for _, bin := range []string{"graft", "graft-dev"} {
			if want := "Bash(" + bin + " " + sub + ":*)"; !contains(got, want) {
				t.Errorf("baseline lacks %q", want)
			}
		}
	}
	for _, rule := range got {
		if !strings.HasPrefix(rule, "Bash(graft") {
			continue
		}
		for _, bad := range []string{"init", "upgrade", "uninstall", "viz", "telemetry", "mcp", "brain"} {
			if strings.Contains(rule, "graft "+bad) || strings.Contains(rule, "graft-dev "+bad) {
				t.Errorf("baseline allows graft %s: %s", bad, rule)
			}
		}
	}
	// `graft build` writes only the local, gitignored index; `--deep` calls an
	// LLM with a key, and a prefix rule cannot exclude the flag, so it is exact.
	if !contains(got, "Bash(graft build)") {
		t.Error("baseline lacks the exact `graft build`")
	}
	if contains(got, "Bash(graft build:*)") {
		t.Error("`graft build:*` would also allow `graft build --deep`")
	}
}

func TestEveryEntryExplainsItselfAndHasAGroup(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range Baseline() {
		if e.Rule == "" || e.Group == "" || e.Why == "" {
			t.Errorf("entry %+v is missing a rule, a group or a reason", e)
		}
		if seen[e.Rule] {
			t.Errorf("duplicate rule %q", e.Rule)
		}
		seen[e.Rule] = true
	}
}

// The operator's own list is theirs, so this only advises. A rule is "broader"
// when it also matches something the baseline deliberately leaves out.
func TestBroadFlagsTheBlanketEntriesAndLeavesNarrowOnesAlone(t *testing.T) {
	findings := Broad([]string{
		"Bash(graft:*)", "Bash(graft-dev:*)", "Bash(npx graft:*)", "Bash(npx:*)", "Bash(node:*)", "Bash(python:*)",
		"Bash(pip:*)", "Bash(npm run:*)", "Bash(uv:*)",
		"Bash(node dist/cli.js:*)", "Bash(graft ask:*)", "Bash(go test:*)", "Bash(guardrail fetch:*)",
	})
	got := map[string]string{}
	for _, f := range findings {
		got[f.Rule] = f.Why
	}
	for _, want := range []string{"Bash(graft:*)", "Bash(graft-dev:*)", "Bash(npx graft:*)", "Bash(npx:*)", "Bash(node:*)", "Bash(python:*)", "Bash(pip:*)", "Bash(npm run:*)", "Bash(uv:*)"} {
		if got[want] == "" {
			t.Errorf("%q was not flagged as broader than the baseline", want)
		}
	}
	for _, narrow := range []string{"Bash(node dist/cli.js:*)", "Bash(graft ask:*)", "Bash(go test:*)", "Bash(guardrail fetch:*)"} {
		if _, flagged := got[narrow]; flagged {
			t.Errorf("%q is narrow and was flagged", narrow)
		}
	}
	if !strings.Contains(got["Bash(graft:*)"], "init") {
		t.Errorf("the reason for Bash(graft:*) should name what it also runs, got %q", got["Bash(graft:*)"])
	}
}

func TestCompareReportsPresentMissingAndBroad(t *testing.T) {
	baseline := Baseline()
	have := []string{baseline[0].Rule, baseline[1].Rule, "Bash(graft:*)", "Bash(my-own-tool:*)"}
	c := Compare(have)
	if c.Total != len(baseline) || c.Present != 2 || len(c.Missing) != len(baseline)-2 {
		t.Fatalf("Compare = total %d present %d missing %d, want %d/2/%d", c.Total, c.Present, len(c.Missing), len(baseline), len(baseline)-2)
	}
	if len(c.Broad) != 1 || c.Broad[0].Rule != "Bash(graft:*)" {
		t.Fatalf("broad = %+v, want only Bash(graft:*)", c.Broad)
	}
}

func TestSnippetJSONIsAValidPermissionsAllowBlock(t *testing.T) {
	var doc struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal([]byte(SnippetJSON()), &doc); err != nil {
		t.Fatalf("SnippetJSON is not valid JSON: %v", err)
	}
	if len(doc.Permissions.Allow) != len(Baseline()) {
		t.Fatalf("snippet has %d rules, baseline has %d", len(doc.Permissions.Allow), len(Baseline()))
	}
}

// The doc carries the list so an operator can read it without running anything,
// and this keeps it from drifting from the code that decides it.
func TestTheDocumentedSnippetMatchesTheBaseline(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "allow-baseline.md"))
	if err != nil {
		t.Fatalf("docs/allow-baseline.md: %v", err)
	}
	text := string(raw)
	start := strings.Index(text, "```json\n")
	if start < 0 {
		t.Fatal("docs/allow-baseline.md has no ```json block")
	}
	rest := text[start+len("```json\n"):]
	end := strings.Index(rest, "```")
	if end < 0 {
		t.Fatal("the ```json block in docs/allow-baseline.md is not closed")
	}
	if got, want := strings.TrimSpace(rest[:end]), strings.TrimSpace(SnippetJSON()); got != want {
		t.Fatalf("docs/allow-baseline.md is out of date with the baseline.\nRegenerate the block with: guardrail allow-baseline --json\n--- doc ---\n%s\n--- code ---\n%s", got, want)
	}
}
