package main

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Where a rule lives (#410). Every rule the sources mint is in
// ruleSourceFiles (generated, test-checked against the source tree); its
// class says which kind of home that is. Overlay rules are not minted by
// the sources: they are resolved from the record's repository.
const (
	homeBase     = "base"
	homeAdapter  = "adapter"
	homeOperator = "operator"
)

// ruleHomeClasses classifies every rule ID that is not a numbered policy rule
// (P1–P9 are built-in base-policy rules). TestEveryMintedRuleHasAHomeClass
// fails for a minted ID with no class here.
var ruleHomeClasses = map[string]string{
	// Decided from what the plane adapter reported: the tool's contract
	// capability, the host's posture or the host's own dialog.
	"call-mcp-tool-generic":            homeAdapter,
	"capability-delegation-unverified": homeAdapter,
	"capability-deny":                  homeAdapter,
	"capability-external":              homeAdapter,
	"capability-input-invalid":         homeAdapter,
	"capability-input-missing":         homeAdapter,
	"capability-invalid":               homeAdapter,
	"capability-web-search":            homeAdapter,
	"delegation-inherited":             homeAdapter,
	"host-auto-ask-escalated":          homeAdapter,
	"unknown-native-tool":              homeAdapter,
	"web-fetch-native-deny":            homeAdapter,
	"ask-approved-by-host":             homeAdapter,
	"ask-approved-by-retry":            homeAdapter,

	// Decided by something the operator issued or set: a grant, night mode,
	// the web-research posture, or the operator-action approval path.
	"ask-allowed-by-night-mode":     homeOperator,
	"ask-allowed-by-operator-grant": homeOperator,
	"web-research-enforcement-off":  homeOperator,
	"operator-action":               homeOperator,
	"operator-action-ask":           homeOperator,
	"operator-action-broker":        homeOperator,
	"operator-action-host-approved": homeOperator,
	"operator-action-satisfied":     homeOperator,
	"operator-action-terminal":      homeOperator,
	"operator-action-ticket":        homeOperator,

	// Built in, but not numbered: the engine's own fail-closed readings and
	// `guardrail fetch`'s checks.
	"panic-recovered":    homeBase,
	"tokenize-failed":    homeBase,
	"fetch-content-type": homeBase,
	"fetch-failed":       homeBase,
	"fetch-host":         homeBase,
	"fetch-invalid":      homeBase,
	"fetch-too-large":    homeBase,
}

// ruleHomeClass returns a minted rule's class, or "" for an ID with none.
func ruleHomeClass(id string) string {
	if class, ok := ruleHomeClasses[id]; ok {
		return class
	}
	if len(id) > 2 && id[0] == 'P' && id[1] >= '0' && id[1] <= '9' && strings.Contains(id, ".") {
		return homeBase
	}
	return ""
}

// ruleHome says where the rule that decided rec lives. It is read when the
// question is asked: an overlay rule is looked up in the repository's
// guardrail.toml as it reads now, which the line says.
func ruleHome(rec audit.Record) string {
	id := rec.RuleID
	if id == "" {
		return "no rule decided this: the hook failed closed before any rule ran"
	}
	if files, ok := ruleSourceFiles[id]; ok {
		where := strings.Join(files, ", ")
		switch ruleHomeClass(id) {
		case homeAdapter:
			return "adapter tier: decided from what the plane adapter reported (the tool's contract capability, or the host's posture or dialog); no policy file owns it. Code: " + where
		case homeOperator:
			return "operator: decided by an operator grant, night mode, the web-research posture or the operator-action approval path. Code: " + where
		default:
			return "built-in rule (base policy). Code: " + where
		}
	}
	if rec.RepoRoot != "" {
		if path, ok, _ := policy.FindOverlayPath(rec.RepoRoot); ok {
			ov, err := policy.LoadOverlay(path)
			if err != nil {
				return "not built in; this repository's overlay " + path + " could not be read to look it up"
			}
			for _, r := range ov.Rules {
				if r.ID == id {
					return "overlay rule " + id + " in " + path + " (as the file reads now)"
				}
			}
		}
	}
	return "not in this binary's rule table, nor in this repository's overlay as it reads now (written by another guardrail version, or an overlay rule since removed)"
}
