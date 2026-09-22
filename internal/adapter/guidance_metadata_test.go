package adapter

import (
	"encoding/json"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// TestGuidanceMetadataDenyFamilies pins the machine-readable remediation
// metadata for every major deny rule family: the agent planner uses
// suggested_tool and remediation_class to take the correct recovery path
// without parsing the prose reason.
func TestGuidanceMetadataDenyFamilies(t *testing.T) {
	cases := []struct {
		ruleID          string
		wantTool        string
		wantRemediation string
	}{
		{ruleID: "P4.secret-in-text", wantTool: "edit", wantRemediation: "use_file_tool"},
		{ruleID: "P5.self-config", wantRemediation: "continue_other_work"},
		{ruleID: "capability-deny", wantRemediation: "fail_closed"},
		{ruleID: "capability-delegation-unverified", wantRemediation: "continue_other_work"},
		{ruleID: "unknown-native-tool", wantRemediation: "continue_other_work"},
		{ruleID: "capability-input-missing", wantRemediation: "continue_other_work"},
		{ruleID: "capability-input-invalid", wantRemediation: "continue_other_work"},
		{ruleID: "P4.secret-path", wantRemediation: "continue_other_work"},
		{ruleID: "P4.secret-path-ambiguous", wantRemediation: "continue_other_work"},
		{ruleID: "P4.symlink-escape", wantRemediation: "scoped_alternative"},
		{ruleID: "P6.download-pipe-shell", wantRemediation: "scoped_alternative"},
		{ruleID: "P1.rm-rf", wantRemediation: "scoped_alternative"},
		{ruleID: "P1.dd", wantRemediation: "scoped_alternative"},
		{ruleID: "P1.privesc", wantRemediation: "scoped_alternative"},
		{ruleID: "P1.git-push-force", wantRemediation: "scoped_alternative"},
		{ruleID: "P1.git-clean", wantRemediation: "scoped_alternative"},
		{ruleID: "P2.git-reset-hard", wantRemediation: "scoped_alternative"},
		{ruleID: "P2.git-config-write", wantRemediation: "scoped_alternative"},
		{ruleID: "P2.git-protected-path", wantRemediation: "scoped_alternative"},
		{ruleID: "P6.egress", wantRemediation: "operator_approval"},
		{ruleID: "operator-action-satisfied", wantRemediation: "continue_other_work"},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) {
			v := policy.Verdict{Decision: policy.Deny, RuleID: tc.ruleID, Reason: "unit-test reason"}
			meta := guidanceMetadataFor(v)
			if meta.SuggestedTool != tc.wantTool {
				t.Errorf("%s: suggested_tool = %q, want %q", tc.ruleID, meta.SuggestedTool, tc.wantTool)
			}
			if meta.RemediationClass != tc.wantRemediation {
				t.Errorf("%s: remediation_class = %q, want %q", tc.ruleID, meta.RemediationClass, tc.wantRemediation)
			}
		})
	}
}

// TestGuidanceMetadataAskVerdictsPinsApprovalRemediation pins that Ask
// verdicts carry the operator-approval remediation class: the agent needs
// to know the path back is through the approval flow, not a workaround.
func TestGuidanceMetadataAskVerdictsPinsApprovalRemediation(t *testing.T) {
	v := policy.Verdict{Decision: policy.Ask, RuleID: "P6.egress", Reason: "egress to unapproved host"}
	meta := guidanceMetadataFor(v)
	if meta.RemediationClass != "operator_approval" {
		t.Fatalf("ask remediation_class = %q, want operator_approval", meta.RemediationClass)
	}
	if meta.SuggestedTool != "" {
		t.Fatalf("ask suggested_tool = %q, want empty (the operator acts, not the agent)", meta.SuggestedTool)
	}
}

// TestGuidanceMetadataSerializesInEmitPayload pins that the metadata fields
// appear in the JSON the adapters emit, alongside decision and reason.
func TestGuidanceMetadataSerializesInEmitPayload(t *testing.T) {
	v := policy.Verdict{Decision: policy.Deny, RuleID: "P4.secret-in-text", Reason: "test"}
	meta := guidanceMetadataFor(v)
	raw, err := json.Marshal(map[string]any{
		"decision":          string(v.Decision),
		"reason":            v.Reason,
		"suggested_tool":    meta.SuggestedTool,
		"remediation_class": meta.RemediationClass,
	})
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["suggested_tool"] != "edit" {
		t.Fatalf("suggested_tool = %v, want edit", parsed["suggested_tool"])
	}
	if parsed["remediation_class"] != "use_file_tool" {
		t.Fatalf("remediation_class = %v, want use_file_tool", parsed["remediation_class"])
	}
}
