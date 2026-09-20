package adapter

import (
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// TestWindowsAuthorizationGuidanceNamesTerminalFallback pins the Windows
// ask-path reality: in-session approval is gated until the ADR-0021 broker
// lands (step d), so the guidance must name the working alternative — the
// operator's terminal. Elsewhere the guidance is unchanged.
func TestWindowsAuthorizationGuidanceNamesTerminalFallback(t *testing.T) {
	v := policy.Verdict{Decision: policy.Ask, Reason: "external egress needs approval"}
	got := Guidance(v, `bash {"command":"curl https://example.test"}`)
	if runtime.GOOS == "windows" {
		if !strings.Contains(got, "the operator can run this exact action from a terminal") {
			t.Fatalf("Windows guidance = %q, missing terminal fallback", got)
		}
	} else {
		if strings.Contains(got, "On Windows") {
			t.Fatalf("non-Windows guidance = %q, leaked Windows suffix", got)
		}
	}
}
