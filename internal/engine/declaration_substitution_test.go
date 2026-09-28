package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #438: a substitution inside a declaration or an arithmetic command was
// never evaluated. The cwd walker tracked the statements inside a CallExpr's
// substitutions but not inside DeclClause, LetClause or ArithmCmd, and
// extractSimples only emits tracked statements, so every rule was skipped:
// `export X=$(rm -rf /)` allowed while `X=$(rm -rf /)` denied.
func TestDeclarationAndArithmeticSubstitutionsAreEvaluated(t *testing.T) {
	for _, command := range []string{
		"export X=$(rm -rf /)",
		"local X=$(rm -rf /)",
		"declare X=$(rm -rf /)",
		"readonly X=$(rm -rf /)",
		"typeset X=$(rm -rf /)",
		"export X=`rm -rf /`",
		"declare -a A=($(rm -rf /))",
		"export X=\"prefix-$(rm -rf /)\"",
		"let x=$(rm -rf /)",
		"(( $(rm -rf /) ))",
	} {
		v := Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
			Capability: policy.CapabilityCommand, Command: command, CWD: "/repo", RepoRoot: "/repo"}, pathPol())
		if v.Decision != policy.Deny || v.RuleID != "P1.rm-rf" {
			t.Errorf("%q -> %s/%s, want deny/P1.rm-rf", command, v.Decision, v.RuleID)
		}
	}
	// Plain declarations stay allowed.
	for _, command := range []string{"export X=1", "local X=$HOME", "declare -a A=(1 2)", "let x=1+2", "(( x = 1 ))"} {
		v := Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
			Capability: policy.CapabilityCommand, Command: command, CWD: "/repo", RepoRoot: "/repo"}, pathPol())
		if v.Decision != policy.Allow {
			t.Errorf("%q -> %s/%s, want allow", command, v.Decision, v.RuleID)
		}
	}
}
