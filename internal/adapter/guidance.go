package adapter

import (
	"fmt"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func Guidance(v policy.Verdict, action string) string {
	switch v.Decision {
	case policy.Ask:
		return fmt.Sprintf("Operator authorization required: %s. Request authorization for this exact action: %s. If the operator approves, retry this exact tool call once. Do not alter or broaden the action.", v.Reason, action)
	case policy.Deny:
		return fmt.Sprintf("Guardrail denied this action: %s. %s", v.Reason, denyNextStep(v))
	default:
		return v.Reason
	}
}

// denyNextStep returns the concrete continuation for a denied call. Every
// denial must tell the model how to keep working; a bare "not allowed"
// manufactures a stuck agent.
func denyNextStep(v policy.Verdict) string {
	if v.RuleID == "P5.self-config" && v.Reason == engine.NightMentionReason {
		return "Only a mention was seen, but interpreter input cannot be inspected. Put this content in the file with the Write or Edit tool instead of a shell literal, then continue."
	}
	switch v.RuleID {
	case "P4.secret-in-text":
		return "The secret-tier path was mentioned in the command's text, not accessed. Content like this belongs in the file, not a shell literal: write it with the Write or Edit tool, then continue."
	case "capability-deny", "capability-invalid":
		return "This tool is outside the Guardrail boundary on this plane (it moves data or control to another principal). Do not retry it: reach the outcome with in-session tools, or tell the operator this step needs them; then continue."
	case "capability-delegation-unverified":
		return "This capability is unavailable on this plane. Do not delegate and do not retry: perform the work yourself in this session, then continue."
	case "unknown-native-tool":
		return "This tool is unclassified on this plane. Accomplish the same outcome with a supported tool (edit, read, or explicit command), then continue."
	case "capability-input-missing", "capability-input-invalid":
		return "The call could not be projected for evaluation. Re-issue the work with a supported form — edits with explicit file paths, an explicit command, or a full HTTP URL — then continue."
	case "P4.secret-path", "P4.secret-path-ambiguous":
		return "This is a secret-tier path: it is denied here, and only an authorized Overlay secret_allow can allow a matching file secret (never directory secrets). Exclude this path and continue the rest of the task."
	case "P5.self-config":
		return "This is Guardrail-protected machinery: never edit it from a session. If it genuinely needs repair, tell the operator to run the Guardrail terminal recovery command. Continue other work."
	case "operator-action-satisfied":
		return "The grant already holds: do not request it again. Use it now (guardrail fetch <url>) and continue."
	case "P6.egress":
		return "Egress to this host is not authorized. Batch the exact domains the task needs into one operator grant (guardrail egress grant --scope repo --host api.example.com,cdn.example.com) — a single approval covers the whole batch; continue offline work meanwhile."
	case "P1.rm-rf", "P1.dd", "P1.mkfs", "P1.shred", "P1.privesc", "P1.docker-down", "P1.docker-prune", "P1.docker-substituted", "P1.git-push-force", "P1.git-clean":
		return "Destructive operation: do not retry it. Use a scoped, reversible alternative, or ask the operator to run it manually; then continue the task."
	case "P2.git-reset-hard", "P2.git-config-write", "P2.git-protected-path":
		return "Protected git state: use a non-destructive alternative (for example git revert instead of reset --hard), or ask the operator if it is truly required; then continue."
	case "P4.symlink-escape":
		return "Symlink escape: operate on the real target path inside the authorized root, then continue."
	case "P6.download-pipe-shell":
		return "Download piped into a shell is denied. Download to a file, inspect it, then run it as a separate reviewed step."
	default:
		return "Do not retry this exact call. Complete the work by other means and involve the operator only if this exact step is required; then continue."
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
