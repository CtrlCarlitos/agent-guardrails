package engine

import (
	"os"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// evalBashForTest runs the full Engine with the base policy, so the path,
// secret and self-config families judge the call too.
func evalBashForTest(t *testing.T, cmd string) policy.Verdict {
	t.Helper()
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return Evaluate(ToolCall{Plane: "claude", Event: "pre", Tool: "Bash", NativeTool: "Bash", Capability: policy.CapabilityCommand, InputShape: "command", Command: cmd, CWD: cwd, RepoRoot: cwd}, pol)
}

// #488: `echo "n: $(wc -l < /tmp/f)"` asked P3.unresolved although the inner
// command is evaluated on its own and allowed. The outer word still holds the
// unexpanded substitution text; it contains a `/`, so the generic operand
// parser called it a path and the unresolved "path" asked. A literal echo, or
// printf with a literal format, whose output reaches the session only prints:
// its arguments are not policy-bearing. Piped output is: the Engine models what
// an echo feeds `sh` or `xargs`, so a piped echo keeps the ask.
func TestEchoOfASubstitutionIsNotPolicyBearing(t *testing.T) {
	for _, cmd := range []string{
		`echo "$(grep -c x /tmp/f)"`,
		`echo $(grep -c x /tmp/f)`,
		`echo "n: $(wc -l < /tmp/f)"`,
		`printf '%s\n' "$(grep -c x /tmp/f)"`,
		// The operator's example, verbatim.
		`grep -o '"command":"[^"]*' /tmp/p3.jsonl | cut -c12- | sed -E 's/^(cd [^;&|]*(;|&&) *)//' | awk '{print $1}' | sort | uniq -c | sort -rn | head -15; echo "--- cd-chain reason share: $(grep -c 'working directory is uncertain' /tmp/p3.jsonl)"; echo "--- uses \$VAR or \$(): $(grep -cE '\$\{?[A-Za-z_(]' /tmp/p3.jsonl) of $(wc -l < /tmp/p3.jsonl)"`,
	} {
		if v := evalBashForTest(t, cmd); v.Decision != policy.Allow {
			t.Errorf("%s: %s %s (%s); want allow", cmd, v.Decision, v.RuleID, v.Reason)
		}
	}
}

func TestEchoOfASubstitutionKeepsEveryOtherCheck(t *testing.T) {
	for cmd, want := range map[string]struct {
		decision policy.Decision
		rule     string
	}{
		// The substitution's own command is still judged.
		`echo "$(cat ~/.ssh/id_ed25519)"`: {policy.Deny, "P4.secret-in-text"},
		// So is the redirect target.
		`echo "$(grep -c x /tmp/f)" > ~/.bashrc`: {policy.Deny, "P5.self-config"},
		`echo "$X" > "$Y"`:                       {policy.Ask, "P3.unresolved"},
		// Piped output is content for the next command.
		`echo "$(grep -c x /tmp/f)" | sh`:           {policy.Ask, "P3.unresolved"},
		`echo "$(grep -c x /tmp/f)" | bash -s`:      {policy.Ask, "P3.unresolved"},
		`echo "$(grep -c x /tmp/f)" | xargs rm -rf`: {policy.Ask, "P3.unresolved"},
		// An echo inside a re-parsed body whose output is piped onward.
		`bash -c 'echo "$(grep -c x /tmp/f)"' | sh`:            {policy.Ask, "P3.unresolved"},
		`sh -c 'echo "$(grep -c x /tmp/f)"' | bash`:            {policy.Ask, "P3.unresolved"},
		`watch 'echo "$(grep -c x /tmp/f)"' | sh`:              {policy.Ask, "P3.unresolved"},
		`{ echo "$(grep -c x /tmp/f)"; } | sh`:                 {policy.Ask, "P3.unresolved"},
		`( echo "$(grep -c x /tmp/f)" ) | sh`:                  {policy.Ask, "P3.unresolved"},
		`for i in 1; do echo "$(grep -c x /tmp/f)"; done | sh`: {policy.Ask, "P3.unresolved"},
		// Only a literal echo, and printf with a literal, non-option format.
		`printf "$(grep -c x /tmp/f)"`:              {policy.Ask, "P3.unresolved"},
		`printf -v PATH '%s' "$(grep -c x /tmp/f)"`: {policy.Ask, "P3.unresolved"},
		`$E "$(grep -c x /tmp/f)"`:                  {policy.Ask, "P3.unresolved"},
		`/bin/echo "$(grep -c x /tmp/f)"`:           {policy.Ask, "P3.unresolved"},
		`eval "$(grep -c x /tmp/f)"`:                {policy.Ask, "P3.unresolved"},
	} {
		v := evalBashForTest(t, cmd)
		if v.Decision != want.decision || v.RuleID != want.rule {
			t.Errorf("%s: %s %s; want %s %s", cmd, v.Decision, v.RuleID, want.decision, want.rule)
		}
	}
}
