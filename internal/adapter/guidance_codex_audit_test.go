package adapter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #449 E: Codex cannot ask (#349), so its ask text is the agent's only
// guidance; it named no concrete operator action.
func TestCodexAskNamesTheOperatorsConcreteOptions(t *testing.T) {
	var out, errb bytes.Buffer
	EmitCodex(policy.Verdict{Decision: policy.Ask, RuleID: "P2.git-push-protected", Reason: "push to a protected ref"}, "pre",
		engine.ToolCall{Plane: "codex", Tool: "Bash", NativeTool: "Bash", Command: "git push origin main"}, &out, &errb)
	got := out.String() + errb.String()
	if strings.Contains(got, "authorize the relevant policy through Guardrail") {
		t.Errorf("codex ask is still vague: %q", got)
	}
	for _, want := range []string{"single-use grant", "guardrail explain"} {
		if !strings.Contains(got, want) {
			t.Errorf("codex ask lacks %q: %q", want, got)
		}
	}
}
