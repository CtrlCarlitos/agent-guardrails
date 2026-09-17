package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/bmatcuk/doublestar/v4"
)

func Evaluate(tc ToolCall, pol *policy.Policy) (out policy.Verdict) {
	defer func() {
		if r := recover(); r != nil {
			out = policy.Verdict{Decision: policy.Ask, RuleID: "panic-recovered",
				Reason: "guardrail hit an internal error; failing closed to ask"}
		}
	}()
	if tc.Capability == policy.CapabilityUnknown {
		v := policy.Verdict{AuditKind: "unknown-native-tool"}
		if pol.UnknownToolPosture == policy.UnknownDeny {
			v.Decision = policy.Deny
			v.RuleID = "unknown-native-tool"
			v.Reason = "unclassified native tool; failing closed"
			return v
		}
		v.Decision = policy.Allow
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
		return policy.Verdict{Decision: policy.Deny, RuleID: "capability-deny", Reason: "native tool capability is unsupported"}
	case policy.CapabilityWebSearch:
		return policy.Verdict{Decision: policy.Ask, RuleID: "capability-web-search", Reason: "web search requires operator approval"}
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

func validWebFetchURL(raw string) bool {
	_, err := NormalizeWebFetchURL(raw)
	return err == nil
}

// delegationInheritsEnforcement reports whether a plane's runtime mediates
// every tool call — including subagent calls — through the same Guardrail
// adapter as the parent. On such planes delegation inherits enforcement by
// construction; every child call is still evaluated individually.
func delegationInheritsEnforcement(plane string) bool {
	return plane == "opencode" || plane == "claude"
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
