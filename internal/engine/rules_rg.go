package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// checkRgPreprocessor asks for `rg --pre <program>`. ripgrep is a read-only
// search, but --pre runs the named program once per searched file with that
// file as its argument, so `rg --pre rm x ~` deletes every file under the
// home directory that a direct `rm` there would be asked about. The program
// runs out of the Engine's sight, so the operator decides (#422). `--pre-glob`
// only narrows --pre and `--no-pre` turns it off; neither runs anything.
func checkRgPreprocessor(s Simple) *policy.Verdict {
	if head(s.Argv) != "rg" {
		return nil
	}
	for _, arg := range s.Argv[1:] {
		if arg == "--" {
			return nil
		}
		if arg == "--pre" || strings.HasPrefix(arg, "--pre=") {
			return &policy.Verdict{Decision: policy.Ask, RuleID: "P1.rg-preprocessor",
				Reason: "rg --pre runs a program on every file it searches, out of Guardrail's sight; search without --pre, or run the program directly so its own rules apply"}
		}
	}
	return nil
}
