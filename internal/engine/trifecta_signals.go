package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// IsPrivateDataAccess reports whether tc touches a secret-classified path —
// the same glob match P4 (checkPaths) uses, exposed for the P7 heuristic.
// Deliberately unconditional on waivers: see the doc comment in the plan
// that introduced this function.
func IsPrivateDataAccess(tc ToolCall, pol *policy.Policy) bool {
	var candidates []string
	if isFileTool(tc.Tool) {
		candidates = append(candidates, tc.Paths...)
	}
	if tc.IsBash() {
		if simples, err := Normalize(tc.Command); err == nil {
			for _, s := range simples {
				if len(s.Argv) > 0 && pathReaders[s.Argv[0]] {
					candidates = append(candidates, nonFlagArgs(s.Argv)...)
				}
			}
		}
	}
	for _, c := range candidates {
		c = strings.TrimPrefix(strings.TrimPrefix(c, "~/"), "~")
		if matchesAnyGlob(c, pol.Slots.SecretAllow) {
			continue
		}
		if matchesAnyGlob(c, pol.Slots.SecretGlobs) {
			return true
		}
	}
	return false
}

// IsNetworkAttempt reports whether tc invokes a network tool at all,
// regardless of what P6 decides about the destination.
func IsNetworkAttempt(tc ToolCall) bool {
	if !tc.IsBash() {
		return false
	}
	simples, err := Normalize(tc.Command)
	if err != nil {
		return false
	}
	for _, s := range simples {
		if len(s.Argv) > 0 && netTools[s.Argv[0]] {
			return true
		}
	}
	return false
}
