package engine

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// RunningVersion is the release tag of the binary enforcing this call, set by
// the CLI at startup. Empty or "dev" when it is not a release (#512).
var RunningVersion string

var releaseTag = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.-]+)?$`)

// releaseOlder reports whether release tag a precedes b, and whether both are
// release tags at all. A pre-release precedes its release; two pre-releases of
// one version compare by their suffix.
func releaseOlder(a, b string) (older, ok bool) {
	ma, mb := releaseTag.FindStringSubmatch(a), releaseTag.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return false, false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			return x < y, true
		}
	}
	switch {
	case ma[4] == mb[4]:
		return false, true
	case mb[4] == "":
		return true, true
	case ma[4] == "":
		return false, true
	}
	return ma[4] < mb[4], true
}

// checkGuardrailUpdate keeps the enforcement binary from being stepped back by
// the session it guards (#512). `guardrail update <newer>` stays allowed: it
// is the sanctioned replacement path the binary-protection guidance names. A
// downgrade below the running release, and `guardrail rollback`, are the
// operator's. Interpreter input or a terminal wrapper naming either cannot be
// judged by version, so it is refused as well.
func checkGuardrailUpdate(s Simple, command string) *policy.Verdict {
	if len(s.Argv) >= 2 && head(s.Argv) == "guardrail" {
		switch strings.ToLower(s.Argv[1]) {
		case "rollback":
			return &policy.Verdict{Decision: policy.Deny, RuleID: "P5.self-config",
				Reason: "rolling the guardrail binary back is the operator's: they run `guardrail rollback` in their own terminal"}
		case "update":
			if len(s.Argv) >= 3 && !s.wordUnresolved(2) {
				if older, ok := releaseOlder(s.Argv[2], RunningVersion); ok && older {
					return &policy.Verdict{Decision: policy.Deny, RuleID: "P5.self-config",
						Reason: "`guardrail update " + s.Argv[2] + "` would downgrade the enforcement binary below " + RunningVersion +
							"; a downgrade is the operator's, run from their own terminal. Updating to a newer release stays allowed"}
				}
			}
		}
	}
	if len(s.Argv) >= 1 && (isOpaqueExecutor(head(s.Argv)) || isTerminalWrapper(head(s.Argv))) {
		for _, subcommand := range []string{"update", "rollback"} {
			if mentionsCommand([]string{command}, "guardrail", subcommand) {
				return &policy.Verdict{Decision: policy.Deny, RuleID: "P5.self-config",
					Reason: "interpreter input or a terminal wrapper runs `guardrail " + subcommand + "`, whose target Guardrail cannot judge from here; run `guardrail update <newer release>` directly, or ask the operator"}
			}
		}
	}
	return nil
}
