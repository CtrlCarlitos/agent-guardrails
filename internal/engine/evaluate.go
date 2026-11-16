package engine

import (
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

// Evaluate is the engine entrypoint. On a host whose permission posture
// answers asks itself (auto/bypass mode, #559 / ADR-0035), every Ask
// verdict denies instead: the host would rubber-stamp the question the
// operator never sees, so the operator's terminal is the only honest
// channel and the guidance says so. Allow and Deny verdicts are unchanged.
func Evaluate(tc ToolCall, pol *policy.Policy) policy.Verdict {
	out := evaluateVerdict(tc, pol)
	if tc.HostAutoApproves && out.Decision == policy.Ask {
		return policy.Verdict{
			Decision:     policy.Deny,
			RuleID:       "host-auto-ask-escalated",
			OriginRuleID: out.RuleID,
			AuditKind:    out.AuditKind,
			Reason:       escalatedReason(tc, out.RuleID),
		}
	}
	return out
}

// escalatedReason is the escalated deny's whole continuation (#605), kept in
// the reason because only the engine knows the plane and the reason is what
// the audit log keeps for `guardrail explain`. It must fit, with the deny
// boilerplate, inside the 512-rune model-facing bound with the rule ID intact.
//
// An unresolvable command is usually read-only: the cheap fix is to make it
// resolvable, so that comes first. Otherwise the handoff is plane-specific:
// Claude Code runs `! <command>` as the operator inside the session, and its
// default permission mode turns the same call back into an ask. Other planes
// have no known in-session escape and keep the terminal sentence.
func escalatedReason(tc ToolCall, origin string) string {
	posture := "the host's auto/bypass permission mode would answer this ask (" + origin + ") itself; denied. "
	claude := tc.Plane == "claude"
	if origin == "P3.unresolved" || origin == "tokenize-failed" {
		fix := "Unresolvable: split it into separate, literal commands (loops in a script file; no $(...) or $LASTEXITCODE). "
		if claude {
			return posture + fix + "If it must run as is, the operator runs it with `!` at the prompt"
		}
		return posture + fix + "If it must run as is, ask the operator to run it in their terminal"
	}
	if !claude {
		return posture + "Ask the operator to run this exact action in their terminal"
	}
	line := "`! <the exact command>`"
	if c := strings.TrimSpace(tc.Command); c != "" && len([]rune(c)) <= maxInlineHandoffRunes && !strings.ContainsAny(c, "\n\r`") {
		line = "`! " + c + "`"
	}
	return posture + "Give the operator one line for the prompt, " + line + " (runs as them, in-session), or use default permission mode for this step, where it asks"
}

// maxInlineHandoffRunes bounds the command quoted into the `!` handoff, so a
// long command cannot push the rule ID past the model-facing bound.
const maxInlineHandoffRunes = 48

func evaluateVerdict(tc ToolCall, pol *policy.Policy) (out policy.Verdict) {
	defer func() {
		if r := recover(); r != nil {
			out = policy.Verdict{Decision: policy.Ask, RuleID: "panic-recovered",
				Reason: "guardrail hit an internal error; failing closed to ask"}
		}
	}()
	if pol.WebResearchOff && tc.NativeWebResearch {
		return policy.Verdict{Decision: policy.Allow, RuleID: "web-research-enforcement-off", Reason: "native web-research enforcement is off by operator policy; outbound data and destinations are not enforced"}
	}
	if tc.Capability == policy.CapabilityUnknown {
		v := policy.Verdict{AuditKind: "unknown-native-tool"}
		if tc.Plane == "codex" || pol.UnknownToolPosture == policy.UnknownDeny {
			v.Decision = policy.Deny
			v.RuleID = "unknown-native-tool"
			v.Reason = "unclassified native tool; failing closed"
			return v
		}
		// Bare-name MCP and future tools must not allow silently; host
		// dialogs and native asks (ADR-0015, ADR-0018) keep this cheap. The
		// audit posture used to allow here on any other plane, which left
		// Antigravity's unknown tools with nothing but an audit line (#151).
		v.Decision = policy.Ask
		v.RuleID = "unknown-native-tool"
		v.Reason = "unclassified native tool requires operator approval"
		return v
	}
	if (tc.Capability == policy.CapabilityReadDiscovery || tc.Capability == policy.CapabilityMutation) && len(tc.Paths) == 0 {
		return policy.Verdict{Decision: policy.Deny, RuleID: "capability-input-missing", Reason: "path capability call did not provide paths"}
	}
	if tc.Capability == policy.CapabilityReadDiscovery || tc.Capability == policy.CapabilityMutation {
		for _, path := range tc.Paths {
			if path == "" {
				return policy.Verdict{Decision: policy.Deny, RuleID: "capability-input-missing", Reason: "path capability call provided an empty path"}
			}
		}
	}
	if tc.Capability == policy.CapabilityCommand && tc.Command == "" {
		return policy.Verdict{Decision: policy.Deny, RuleID: "capability-input-missing", Reason: "command capability call did not provide a command"}
	}
	if tc.Capability == policy.CapabilityWebFetch && !validWebFetchURL(tc.URL) {
		return policy.Verdict{Decision: policy.Deny, RuleID: "capability-input-invalid", Reason: "web fetch capability call did not provide a valid HTTP URL"}
	}
	switch tc.Capability {
	case "", policy.CapabilityCommand, policy.CapabilityReadDiscovery, policy.CapabilityMutation:
	case policy.CapabilityWebFetch:
		return *checkWebFetch(tc, pol)
	case policy.CapabilitySafeControl:
		return policy.Verdict{Decision: policy.Allow}
	case policy.CapabilityDeny:
		if tc.NativeTool == "call_mcp_tool" {
			return policy.Verdict{
				Decision: policy.Deny,
				RuleID:   "call-mcp-tool-generic",
				Reason:   "a generic MCP invoker cannot be re-dispatched safely until the registry can classify the target tool's arguments, which it cannot see through the indirection",
			}
		}
		return policy.Verdict{Decision: policy.Deny, RuleID: "capability-deny", Reason: "native tool capability is unsupported"}
	case policy.CapabilityWebSearch:
		return policy.Verdict{Decision: policy.Ask, RuleID: "capability-web-search", Reason: "web search requires operator approval"}
	case policy.CapabilityExternal:
		return policy.Verdict{Decision: policy.Ask, RuleID: "capability-external",
			Reason: "this tool reaches outside the session (MCP server, scheduler, or publication) and its data flow cannot be verified"}
	case policy.CapabilityDelegation:
		if delegationInheritsEnforcement(tc.Plane) {
			return policy.Verdict{Decision: policy.Allow, RuleID: "delegation-inherited",
				Reason: "child tool calls are mediated by this plane's Guardrail adapter"}
		}
		return policy.Verdict{Decision: policy.Deny, RuleID: "capability-delegation-unverified", Reason: "delegation requires verified child guardrail inheritance"}
	default:
		return policy.Verdict{Decision: policy.Deny, RuleID: "capability-invalid", Reason: "native tool capability is invalid"}
	}

	var bash *bashAnalysis
	var bashVerdict *policy.Verdict
	if tc.IsBash() {
		bash = analyzeBash(tc)
		bashVerdict = checkBashAnalysis(tc, pol, bash)
	}
	hits := []*policy.Verdict{
		checkPathsAnalysis(tc, pol, bash),
		bashVerdict,
		matchOverlayRules(tc, pol),
	}
	var worst *policy.Verdict
	for _, h := range hits {
		if h == nil {
			continue
		}
		if worst == nil || h.Decision.Severity() > worst.Decision.Severity() {
			worst = h
		}
	}
	if worst == nil {
		return policy.Verdict{Decision: policy.Allow}
	}
	return *worst
}

func canonicalExistingPath(path string) string {
	if path == "" {
		return path
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

func validWebFetchURL(raw string) bool {
	_, err := NormalizeWebFetchURL(raw)
	return err == nil
}

// delegationInheritsEnforcement reports whether a plane's runtime mediates
// every tool call — including subagent calls — through the same Guardrail
// adapter as the parent. On such planes delegation inherits enforcement by
// construction; every child call is still evaluated individually.
func delegationInheritsEnforcement(plane string) bool {
	return plane == "opencode" || plane == "claude" || plane == "antigravity"
}

func matchOverlayRules(tc ToolCall, pol *policy.Policy) *policy.Verdict {
	for _, r := range pol.Rules {
		if pol.Waived[r.ID] {
			continue
		}
		if r.Tool != "" && !strings.EqualFold(r.Tool, tc.Tool) {
			continue
		}
		if r.Pattern == "" {
			continue
		}
		subjects := append([]string{tc.Command}, tc.Paths...)
		for _, s := range subjects {
			if s == "" {
				continue
			}
			if ok, _ := doublestar.Match(r.Pattern, s); ok {
				return &policy.Verdict{Decision: r.Decision, RuleID: r.ID, Reason: r.Reason}
			}
		}
	}
	return nil
}
