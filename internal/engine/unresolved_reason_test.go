package engine

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #491: a P3.unresolved ask said only "command contains an unresolved value
// in a policy-bearing position". The agent could not tell which value, so it
// kept writing commands the same way and the operator kept being asked: 460
// of about 690 Claude asks in a week. The reason now names the value and how
// to write the command so it resolves.
func TestUnresolvedReasonNamesTheValueAndTheFix(t *testing.T) {
	for cmd, word := range map[string]string{
		`cat "$X/a"`:                    `"$X/a"`,
		`gh run watch $id`:              `$id`,
		`echo hi > "$OUT"`:              `"$OUT"`,
		`$CMD --version`:                `$CMD`,
		`cp a.txt "$(mktemp -d)/b.txt"`: `"$(mktemp -d)/b.txt"`,
	} {
		v := evalBash(t, cmd)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "P3.unresolved" {
			t.Fatalf("%s: %+v; want ask P3.unresolved", cmd, v)
		}
		if !strings.Contains(v.Reason, "`"+word+"`") {
			t.Errorf("%s: reason %q does not name %s", cmd, v.Reason, word)
		}
		if !strings.Contains(v.Reason, "literal absolute path") {
			t.Errorf("%s: reason %q does not say how to write it so it resolves", cmd, v.Reason)
		}
	}
}

func TestUnresolvedReasonCapsALongValue(t *testing.T) {
	long := `"$X/` + strings.Repeat("a", 300) + `"`
	v := evalBash(t, "cat "+long)
	if v == nil || v.RuleID != "P3.unresolved" {
		t.Fatalf("%+v; want P3.unresolved", v)
	}
	if strings.Contains(v.Reason, strings.Repeat("a", 100)) || !strings.Contains(v.Reason, "…") {
		t.Errorf("reason did not cap the value: %d chars", utf8.RuneCountInString(v.Reason))
	}
}

// The uncertain-cwd reason (#355) is about the `cd`, not a value: unchanged.
func TestUnresolvedCwdReasonIsUnchanged(t *testing.T) {
	v := evalBash(t, `mkdir -p out && cd out; cat f`)
	if v == nil || !strings.HasPrefix(v.Reason, "the working directory is uncertain here") {
		t.Fatalf("%+v; want the uncertain-cwd reason", v)
	}
}
