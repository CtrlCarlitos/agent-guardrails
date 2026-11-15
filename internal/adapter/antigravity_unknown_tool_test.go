package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #151: an Antigravity tool the contract does not know was allowed with only
// an audit_kind on the record, because the base unknown_tool_posture
// ("audit") still applied to this plane. Antigravity renders asks as
// force_ask, so an unknown tool goes to the operator here as it does on
// claude and opencode (ADR-0018).
func TestAntigravityUnknownNativeToolAsks(t *testing.T) {
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	pol, _, err := policy.Merge(base, nil, "dev", &policy.OperatorConfig{}, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"conversationId":"c1","toolCall":{"name":"future_tool","args":{"Cwd":"/repo","Target":"anything"}}}`
	tc, err := ParseAntigravity("pre", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Capability != policy.CapabilityUnknown {
		t.Fatalf("capability = %q, want unknown", tc.Capability)
	}
	v := engine.Evaluate(tc, pol)
	if v.Decision != policy.Ask || v.RuleID != "unknown-native-tool" || v.AuditKind != "unknown-native-tool" {
		t.Fatalf("verdict = %+v, want ask/unknown-native-tool", v)
	}
	var out bytes.Buffer
	EmitAntigravity(v, "pre", tc, &out)
	var emitted map[string]any
	if err := json.Unmarshal(out.Bytes(), &emitted); err != nil {
		t.Fatalf("emit: %v (%q)", err, out.String())
	}
	if emitted["decision"] != "force_ask" {
		t.Fatalf("emitted decision = %v, want force_ask", emitted["decision"])
	}
}
