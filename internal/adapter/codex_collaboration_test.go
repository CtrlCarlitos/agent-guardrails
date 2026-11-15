package adapter

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #540's recorded identity and representative review brief must reach the
// delegation policy, never the unknown-tool fallback. Codex inheritance is
// still unverified (ADR-0013), so this is a specific deny, not an allow.
func TestWindowsCodexRecordedReviewerDispatch(t *testing.T) {
	raw, err := os.ReadFile("../../test/fixtures/codex/collaboration-review.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.ReplaceAll(raw, []byte("/repo"), []byte(filepath.ToSlash(t.TempDir())))
	tc, err := ParseCodex(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.NativeTool != "collaborationspawn_agent" || tc.ContractTool != "collaboration.spawn_agent" || tc.Capability != policy.CapabilityDelegation {
		t.Fatalf("recorded dispatch = %+v", tc)
	}
	v := engine.Evaluate(tc, &policy.Policy{})
	if v.Decision != policy.Deny || v.RuleID != "capability-delegation-unverified" {
		t.Fatalf("verdict = %+v, want deny/capability-delegation-unverified", v)
	}
	var out, stderr bytes.Buffer
	if code := EmitCodex(v, "pre", tc, &out, &stderr); code != 2 || !strings.Contains(stderr.String(), "perform the work yourself") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
}

func TestWindowsCodexCollaborationNamespaceAliases(t *testing.T) {
	for _, c := range []struct {
		name       string
		capability policy.Capability
		decision   policy.Decision
		rule       string
	}{
		{"spawn_agent", policy.CapabilityDelegation, policy.Deny, "capability-delegation-unverified"},
		{"send_message", policy.CapabilityDelegation, policy.Deny, "capability-delegation-unverified"},
		{"followup_task", policy.CapabilityDelegation, policy.Deny, "capability-delegation-unverified"},
		{"interrupt_agent", policy.CapabilitySafeControl, policy.Allow, ""},
		{"list_agents", policy.CapabilitySafeControl, policy.Allow, ""},
		{"wait_agent", policy.CapabilitySafeControl, policy.Allow, ""},
	} {
		for _, prefix := range []string{"collaboration", "collaboration__"} {
			t.Run(prefix+c.name, func(t *testing.T) {
				tc, err := ParseCodex(strings.NewReader(codexEnvelope(t.TempDir(), prefix+c.name, map[string]any{"target": "/root/review", "message": "work"})))
				if err != nil {
					t.Fatal(err)
				}
				if tc.NativeTool != prefix+c.name || tc.ContractTool != "collaboration."+c.name || tc.Tool != "collaboration."+c.name || tc.Capability != c.capability {
					t.Fatalf("tool call = %+v", tc)
				}
				if v := engine.Evaluate(tc, &policy.Policy{}); v.Decision != c.decision || v.RuleID != c.rule {
					t.Fatalf("verdict = %+v, want %s/%s", v, c.decision, c.rule)
				}
			})
		}
	}
	for _, name := range []string{"collaborationresume_agent", "collaboration__resume_agent", "other.spawn_agent", "othercollaborationlist_agents", "collaborationfuture_tool"} {
		t.Run(name, func(t *testing.T) {
			tc, err := ParseCodex(strings.NewReader(codexEnvelope(t.TempDir(), name, map[string]any{})))
			if err != nil {
				t.Fatal(err)
			}
			if v := engine.Evaluate(tc, &policy.Policy{}); v.Decision != policy.Deny || v.RuleID != "unknown-native-tool" {
				t.Fatalf("uncontracted alias = %+v", v)
			}
		})
	}
}
