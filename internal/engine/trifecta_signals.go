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

// TrifectaTrackingEnabled reports whether plane orchestration should provide
// session state for the P7 heuristic under the active policy.
func TrifectaTrackingEnabled(pol *policy.Policy) bool {
	return !pol.Waived["P7.trifecta"]
}

// ApplyTrifecta evaluates and records the P7 signals for one tool call. A nil
// state reports that the plane adapter could not make session tracking available.
func ApplyTrifecta(v policy.Verdict, tc ToolCall, st *session.State, pol *policy.Policy) *policy.Verdict {
	if !TrifectaTrackingEnabled(pol) {
		return nil
	}
	isPrivate := IsPrivateDataAccess(tc, pol)
	isNet := IsNetworkAttempt(tc)
	if st == nil {
		if v.Decision == policy.Allow && (isPrivate || isNet) {
			return &policy.Verdict{
				Decision: policy.Ask,
				RuleID:   "P7.tracking-unavailable",
				Reason:   "session tracking is unavailable; approval is required because P7 cannot retain this private-data or network signal",
			}
		}
		return nil
	}

	secondLeg := (isPrivate && st.SawNetworkCall) || (isNet && st.SawPrivateRead)
	st.SawPrivateRead = st.SawPrivateRead || isPrivate
	st.SawNetworkCall = st.SawNetworkCall || isNet
	if v.Decision == policy.Allow && secondLeg {
		return &policy.Verdict{Decision: policy.Ask, RuleID: "P7.trifecta",
			Reason: "this session already touched both private data and network egress — pausing on the second leg of the lethal trifecta pattern"}
	}
	return nil
}
