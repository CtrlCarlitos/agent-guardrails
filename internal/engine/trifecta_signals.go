package engine

import (
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/session"
)

// IsPrivateDataAccess reports whether tc touches a secret-classified path —
// the same glob match P4 (checkPaths) uses, exposed for the P7 heuristic.
// Deliberately unconditional on waivers: see the doc comment in the plan
// that introduced this function.
func IsPrivateDataAccess(tc ToolCall, pol *policy.Policy) bool {
	for _, candidate := range privatePathCandidates(tc) {
		if _, secret := classifiedSecretPath(candidate, pol); secret {
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
	simples, err := Normalize(tc.Command, tc.CWD)
	if err != nil {
		return false
	}
	for _, s := range simples {
		if netTools[head(s.Argv)] {
			return true
		}
	}
	return false
}

func TrifectaVerdict(v policy.Verdict, isPrivate, isNet bool, st *session.State) *policy.Verdict {
	if v.Decision != policy.Allow {
		return nil
	}
	if (isPrivate && st.SawNetworkCall) || (isNet && st.SawPrivateRead) {
		return &policy.Verdict{Decision: policy.Ask, RuleID: "P7.trifecta",
			Reason: "this session already touched both private data and network egress — pausing on the second leg of the lethal trifecta pattern"}
	}
	return nil
}
