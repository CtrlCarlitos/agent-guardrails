package engine

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #616: the parse-failure ask never named what failed to parse, so an agent
// could not tell what to change. The parser names the offending construct;
// the reason now carries it.
func TestTokenizeFailedNamesTheParseError(t *testing.T) {
	for _, command := range []string{
		`echo "oops`,
		`echo a ; ; b`,
	} {
		v := evalBash(t, command)
		if v == nil || v.Decision != policy.Ask || v.RuleID != "tokenize-failed" {
			t.Fatalf("%q -> %+v, want ask/tokenize-failed", command, v)
		}
		if !strings.Contains(v.Reason, "could not parse shell command (") {
			t.Errorf("%q: reason %q lacks the parse finding", command, v.Reason)
		}
	}
	if v := evalBash(t, `echo "oops`); !strings.Contains(v.Reason, "closing quote") {
		t.Errorf("unclosed quote: reason %q does not name it", v.Reason)
	}
	if v := evalBash(t, `echo a ; ; b`); !strings.Contains(v.Reason, "can only immediately follow a statement") {
		t.Errorf("stray semicolon: reason %q does not name it", v.Reason)
	}
}
