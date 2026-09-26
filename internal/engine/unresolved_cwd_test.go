package engine

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// A `cd` after a filesystem-mutating command may or may not succeed, so the
// working directory after a following `;` has two possible values (#355). A
// builtin that never reads a cwd-relative path has nothing to be uncertain
// about, and used to be held anyway: the blanket "unresolved" clause fired on
// the uncertain cwd alone, with no unresolved value anywhere.
func TestCwdUncertainBuiltinsWithNoPathOperandAreNotHeld(t *testing.T) {
	for _, c := range []string{
		`mkdir -p out; cd out; echo done`,
		`mkdir -p out && cd out; echo done`,
		`mkdir -p out && cd out; true`,
		`mkdir -p out && cd out; false`,
		`mkdir -p out && cd out; :`,
		`mkdir -p out && cd out; pwd`,
		`mkdir -p out && cd out; printf '%s\n' done`,
		`mkdir -p out && cd out || exit 1; echo done`,
		`mkdir -p out && cd /tmp; echo done`,
		`git worktree add -q w -b f origin/main && cd w; echo done`,
		`mkdir -p out && cd out; echo -n done`,
	} {
		if v := evalBash(t, c); v != nil {
			t.Errorf("%q -> %+v, want allow: a literal builtin cannot depend on the working directory", c, v)
		}
	}
}

// The narrowing is for those builtins and nothing else. Every row here must
// keep the verdict it had before #355: it either reads a path relative to an
// uncertain cwd, runs a program found relative to it, writes somewhere, or
// carries a value the analysis cannot read.
func TestCwdUncertaintyStillHoldsEverythingElse(t *testing.T) {
	for _, c := range []string{
		`mkdir -p out && cd out; ./x.sh`,
		`mkdir -p out && cd out; x.sh`,
		`mkdir -p out && cd out; cat b.go`,
		`mkdir -p out && cd out; ls`,
		`mkdir -p out && cd out; git status`,
		`mkdir -p out && cd out; rm -rf x`,
		`mkdir -p out && cd out; echo hi > f`,
		`mkdir -p out && cd out; echo hi >> f`,
		`mkdir -p out && cd out; echo hi < f`,
		`mkdir -p out && cd out; echo "$(rm -rf x)"`,
		"mkdir -p out && cd out; echo `rm -rf x`",
		`mkdir -p out && cd out; printf -v x %s y`,
		`mkdir -p out && cd out; printf -vx %s y`,
		`mkdir -p out && cd out; eval echo hi`,
		`mkdir -p out && cd out; eval "$X"`,
		`mkdir -p out && cd out; command echo hi`,
		`mkdir -p out && cd out; env echo hi`,
		`mkdir -p out && cd out; sudo echo hi`,
		`mkdir -p out && cd out; PATH=. echo hi`,
		`mkdir -p out && cd out; GIT_DIR=$X echo hi`,
		`mkdir -p out && cd out; echo hi | tee f`,
		`mkdir -p out && cd out; echo done; cat b.go`,
		`mkdir -p out && cd out; echo done; ./x.sh`,
		`mkdir -p out && cd out; echo done && rm -rf x`,
		`mkdir -p out && cd out; /bin/echo done`,
		`mkdir -p out && cd out; echo done | sh`,
		"mkdir -p out && cd out; echo hi <<EOF\n$(rm -rf x)\nEOF",
		`echo() { rm -rf x; }; mkdir -p out && cd out; echo done`,
		`true() { rm -rf x; }; mkdir -p out && cd out; true`,
		"shopt -s expand_aliases\nalias echo='rm -rf x'\nmkdir -p out && cd out; echo done",
	} {
		if v := evalBash(t, c); v == nil {
			t.Errorf("%q -> allow, want it held or denied as before", c)
		}
	}
}

// Real values keep the value wording; an uncertain cwd says so and names the
// way out, so an agent does not have to guess what to change
// (docs/error-message-discipline.md items 2-4).
func TestP3UnresolvedReasonNamesTheRealCause(t *testing.T) {
	cwd := evalBash(t, `mkdir -p out && cd out; ls`)
	if cwd == nil || cwd.RuleID != "P3.unresolved" || cwd.Decision != policy.Ask {
		t.Fatalf("cwd case -> %+v, want ask/P3.unresolved", cwd)
	}
	for _, want := range []string{"working directory", "&&", "git -C", "separate"} {
		if !strings.Contains(cwd.Reason, want) {
			t.Errorf("cwd reason %q does not mention %q", cwd.Reason, want)
		}
	}
	if strings.Contains(cwd.Reason, "unresolved value") {
		t.Errorf("cwd reason %q blames an unresolved value, but there is none", cwd.Reason)
	}

	value := evalBash(t, `cat $UNSET/x`)
	if value == nil || value.RuleID != "P3.unresolved" {
		t.Fatalf("value case -> %+v, want P3.unresolved", value)
	}
	if !strings.Contains(value.Reason, "unresolved value") {
		t.Errorf("value reason %q lost the value wording", value.Reason)
	}
	if strings.Contains(value.Reason, "working directory") {
		t.Errorf("value reason %q blames the working directory for a real variable", value.Reason)
	}
}
