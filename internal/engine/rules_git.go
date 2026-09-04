package engine

import (
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func checkGitSafety(s Simple) *policy.Verdict {
	if s.Argv[0] != "git" || len(s.Argv) < 2 {
		return nil
	}
	sub := gitSubcommand(s.Argv)
	switch sub {
	case "reset":
		if hasAnyFlag(s.Argv, "", "--hard", "--keep") {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P2.git-reset-hard",
				Reason: "git reset --hard/--keep discards the working tree and index irrecoverably"}
		}
	case "config":
		writeFlag := hasAnyFlag(s.Argv, "", "--global", "--system", "--local", "--add", "--replace-all", "--unset", "--unset-all")
		if writeFlag || len(nonFlagArgs(s.Argv[1:])) >= 2 {
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P2.git-config-write",
				Reason: "git config write can redirect core.hooksPath/fsmonitor into arbitrary code execution"}
		}
	}
	return nil
}

var gitProtectedGlobs = []string{"**/.git/config", "**/.git/hooks/**"}
