package adapter

import (
	"fmt"
	"runtime"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func Guidance(v policy.Verdict, action string) string {
	switch v.Decision {
	case policy.Ask:
		// In-session approval is gated on Windows until the ADR-0021 broker
		// lands (step d); the operator's terminal is the working path, and
		// the guidance must say so instead of pointing at a door that is not
		// there yet. Remove this suffix with the step (d) gate.
		windowsApprovalNote := ""
		if runtime.GOOS == "windows" {
			windowsApprovalNote = " On Windows, in-session approval is not yet available: the operator can run this exact action from a terminal instead."
		}
		return fmt.Sprintf("Operator authorization required: %s. Request authorization for this exact action: %s. If the operator approves, retry this exact tool call within 10 minutes. If the authorization expires, stop and wait for the operator to return — say what you were doing and that approval expired; do not keep retrying. Do not alter or broaden the action. %s%s", v.Reason, action, askApprovalPath(v), windowsApprovalNote)
	case policy.Deny:
		return fmt.Sprintf("Guardrail denied this action: %s. %s If this verdict seems wrong or blocks legitimate work, report it to the operator with: the exact tool call, the rule ID (%s), your guardrail version, what you were trying to do, and what you did instead. Do not work around it silently.", v.Reason, denyNextStep(v), v.RuleID)
	default:
		return v.Reason
	}
}

// askApprovalPath names which of the approval paths applies, because the
// observed failure was not agents missing an instruction but agents looking
// for machinery that does not exist (#129).
//
// "Request authorization" reads to a model as "find the technical approval
// mechanism", so a P5.ci-infra-lockfile ask sent one agent hunting for a URL
// and reporting "no approval path", and a P2.git-push-delete ask sent another
// to `guardrail approvals list`. Both should have said a sentence to the
// operator and retried. Naming the wrong turns is what closes that, which is
// why this rules them out explicitly instead of only describing the right one.
//
// The path is decided by whether the verdict actually carries broker state,
// not by a list of rule names: a rule list would silently misroute every rule
// added after it was written, and the broker fields are already the ground
// truth for whether a ceremony exists.
func askApprovalPath(v policy.Verdict) string {
	if v.ApprovalURL != "" {
		return fmt.Sprintf("Approval path: this is a broker approval — open %s and complete the passkey ceremony. Telling the operator in chat will not clear it.", v.ApprovalURL)
	}
	if v.OperatorAction != "" {
		return "Approval path: this is an operator action and goes through the broker with a passkey, not through chat. Surface the approval URL from the verdict to the operator; if none is present, the operator runs this action from a terminal."
	}
	conversational := "Approval path: this is a conversational approval. There is no approval URL, no daemon and no `guardrail approvals` command you can run for it — say what you need to the operator, and retry the exact call once they approve."
	if policy.NeverGrantable(v.RuleID) {
		return conversational
	}
	// A grant exists for this rule, so claiming no machinery exists would be
	// the #129 failure in reverse: an agent told there is no path, when the
	// operator has one. What the agent must not do is compose it. The command
	// is refused to anything but an interactive operator terminal, and it
	// authorizes one exact command -- so the thing to ask for is the command
	// that was just refused, never a broader shape of it.
	return conversational + " If the operator would rather authorize it in policy than approve it in chat, they can issue a single-use grant for this exact command from their own terminal. Ask for the command you just ran, never a broader form of it."
}

// denyNextStep returns the concrete continuation for a denied call. Every
// denial must tell the model how to keep working; a bare "not allowed"
// manufactures a stuck agent.
func denyNextStep(v policy.Verdict) string {
	if v.RuleID == "P5.self-config" && (v.Reason == engine.NightMentionReason || v.Reason == engine.SelfControlMentionReason) {
		return "Only a mention was seen, but interpreter input cannot be inspected. Put this content in the file with the Write or Edit tool instead of a shell literal, then continue."
	}
	switch v.RuleID {
	case "P4.secret-in-text":
		return "The secret-tier path was mentioned in the command's text, not accessed. Content like this belongs in the file, not a shell literal: write it with the Write or Edit tool, then continue."
	case "call-mcp-tool-generic":
		return "Register the MCP tool in ~/.gemini/config/mcp_config.json so its arguments can be evaluated directly, then continue."
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
