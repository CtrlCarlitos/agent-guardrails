package adapter

import (
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// guidanceMetadata carries machine-readable remediation metadata alongside
// the human-readable Reason: agent planners use suggested_tool and
// remediation_class to take the correct recovery path without parsing prose.
type guidanceMetadata struct {
	SuggestedTool    string `json:"suggested_tool,omitempty"`
	RemediationClass string `json:"remediation_class,omitempty"`
}

// Remediation classes: stable enums the agent planner can branch on.
const (
	remediationUseFileTool       = "use_file_tool"
	remediationScopedAlternative = "scoped_alternative"
	remediationOperatorApproval  = "operator_approval"
	remediationContinueOtherWork = "continue_other_work"
	remediationFailClosed        = "fail_closed"
)

// guidanceMetadataFor maps a rule ID to its suggested tool and remediation
// class, mirroring the denyNextStep prose so the two never diverge: a rule
// whose prose says "use the Write tool" maps to suggested_tool "edit" and
// remediation_class "use_file_tool".
func guidanceMetadataFor(v policy.Verdict) (meta guidanceMetadata) {
	switch v.RuleID {
	case "P4.secret-in-text":
		meta = guidanceMetadata{SuggestedTool: "edit", RemediationClass: remediationUseFileTool}
	case "P5.self-config":
		meta = guidanceMetadata{RemediationClass: remediationContinueOtherWork}
	case "capability-deny", "capability-invalid":
		meta = guidanceMetadata{RemediationClass: remediationFailClosed}
	case "capability-delegation-unverified":
		meta = guidanceMetadata{RemediationClass: remediationContinueOtherWork}
	case "unknown-native-tool":
		meta = guidanceMetadata{RemediationClass: remediationContinueOtherWork}
	case "capability-input-missing", "capability-input-invalid":
		meta = guidanceMetadata{RemediationClass: remediationContinueOtherWork}
	case "P4.secret-path", "P4.secret-path-ambiguous":
		meta = guidanceMetadata{RemediationClass: remediationContinueOtherWork}
	case "P4.symlink-escape":
		meta = guidanceMetadata{RemediationClass: remediationScopedAlternative}
	case "P6.download-pipe-shell":
		meta = guidanceMetadata{RemediationClass: remediationScopedAlternative}
	case "P1.rm-rf", "P1.dd", "P1.mkfs", "P1.shred", "P1.privesc", "P1.docker-down", "P1.docker-prune", "P1.docker-substituted", "P1.git-push-force", "P1.git-clean":
		meta = guidanceMetadata{RemediationClass: remediationScopedAlternative}
	case "P2.git-reset-hard", "P2.git-config-write", "P2.git-protected-path":
		meta = guidanceMetadata{RemediationClass: remediationScopedAlternative}
	case "P6.egress":
		meta = guidanceMetadata{RemediationClass: remediationOperatorApproval}
	case "operator-action-satisfied":
		meta = guidanceMetadata{RemediationClass: remediationContinueOtherWork}
	default:
		meta = guidanceMetadata{RemediationClass: remediationContinueOtherWork}
	}
	return meta
}
