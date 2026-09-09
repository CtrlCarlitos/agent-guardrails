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
