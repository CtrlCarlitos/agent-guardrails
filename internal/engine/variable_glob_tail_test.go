package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// A variable assigned literally earlier in the same command is resolved, and
// the resolved word is judged as if it had been typed out: `T=/etc; rm -rf $T/x`
// is denied like `rm -rf /etc/x`. A literal glob after an unquoted variable is
// deliberately NOT resolved (NF5b, TestNF5bLeavesLiteralSuffixGlobsUnresolved):
// a glob expands to many arguments at runtime, so a judgement about one path
// does not cover it. That left `T=/etc; rm -rf $T/x*` as an ask while
// `rm -rf /etc/x*` and `rm -rf "$T"/x*` were denials (#377).
//
// The narrow fix: the recursive-delete check resolves such an operand for its
// own purpose, so an outside-the-repo target is denied. Everything else about
// the word is unchanged: it is still unresolved, so any other rule still asks.

func TestRmRfOutsideTheRepoWithAVariableAndAGlobTailIsDeniedLikeTheLiteral(t *testing.T) {
	for _, pair := range []struct{ withVariable, literal string }{
		{`T=/etc; rm -rf $T/x*`, `rm -rf /etc/x*`},
		{`T=/home/u/data; rm -rf $T/build-*`, `rm -rf /home/u/data/build-*`},
		{`T=/etc; rm -rf ${T}/x*`, `rm -rf /etc/x*`},
		{`T=/etc; rm -rf $T/*`, `rm -rf /etc/*`},
		{`T=/etc; rm -fr $T/x*`, `rm -fr /etc/x*`},
		{`T=/etc; rm -r -f $T/x*`, `rm -r -f /etc/x*`},
		{`T=/etc; U=/var; rm -rf $T/x* $U/y`, `rm -rf /etc/x* /var/y`},
		{`T=/etc; command rm -rf $T/x*`, `command rm -rf /etc/x*`},
		{`T=/etc; env rm -rf $T/x*`, `env rm -rf /etc/x*`},
	} {
		want := evalBash(t, pair.literal)
		if want == nil || want.Decision != policy.Deny || want.RuleID != "P1.rm-rf" {
			t.Fatalf("the literal %q -> %+v, want deny/P1.rm-rf (the test's premise)", pair.literal, want)
		}
		got := evalBash(t, pair.withVariable)
		if got == nil || got.Decision != policy.Deny || got.RuleID != "P1.rm-rf" {
			t.Errorf("%q -> %+v, want deny/P1.rm-rf like the literal %q", pair.withVariable, got, pair.literal)
		}
	}
}

// NF5b stays as decided: outside a destructive outside-the-repo delete the word
// is still unresolved and still asks. Pinned here so that "fixing" #377 cannot
// quietly turn these into allows.
func TestAGlobTailAfterAVariableStillAsksWhereNothingDeniesIt(t *testing.T) {
	for _, c := range []string{
		`T=/repo/build; rm -rf $T/out-*`, // inside the repo: not a P1.rm-rf denial, still held
		`T=/etc; cat $T/*.conf`,
		`S=/tmp/scripts; bash $S/*.sh`,
	} {
		v := evalBash(t, c)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P3.unresolved" {
			t.Errorf("%q -> %+v, want ask/P3.unresolved", c, v)
		}
	}
}

// What the recursive-delete check must still refuse to resolve: a value it
// cannot trust stays unresolved, so none of these becomes an allow.
func TestRmRfStillRefusesToResolveWhatItCannotTrust(t *testing.T) {
	for _, c := range []string{
		`rm -rf $UNSET/x*`,                 // no assignment at all
		`T='/etc/*'; rm -rf $T`,            // the glob arrives in the VALUE
		`T='/etc/*'; rm -rf $T/x`,          // ... and stays there with a tail
		`T='/etc /home'; rm -rf $T/x*`,     // the value splits into two fields
		`A='@'; B='(x)'; rm -rf /etc/$A$B`, // an extglob opener formed across the boundary
		`T=$(pwd); rm -rf $T/x*`,           // a substitution is not a literal
	} {
		if v := evalBash(t, c); v == nil {
			t.Errorf("%q -> allow, want a hold or a denial: the value cannot be trusted", c)
		}
	}
	if v := evalBash(t, `rm -rf $UNSET/x*`); v == nil || v.RuleID != "P3.unresolved" {
		t.Errorf("an unknown variable must still be held as P3.unresolved, got %+v", v)
	}
}
