package adapter

import (
	"fmt"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func Guidance(v policy.Verdict, action string) string {
	switch v.Decision {
	case policy.Ask:
		return fmt.Sprintf("Operator authorization required: %s. Request authorization for this exact action: %s. If the operator approves, retry this exact tool call once. Do not alter or broaden the action.", v.Reason, action)
	case policy.Deny:
		return fmt.Sprintf("Guardrail denied this action: %s. It cannot be authorized. Choose a safe alternative.", v.Reason)
	default:
		return v.Reason
	}
}

func guidanceForModel(v policy.Verdict, action string) string {
	if v.Decision == policy.Ask {
		// Bound only untrusted policy prose; the native action must remain exact.
		v.Reason = sanitizeForModel(v.Reason)
		return Guidance(v, action)
	}
	return sanitizeForModel(Guidance(v, action))
}
