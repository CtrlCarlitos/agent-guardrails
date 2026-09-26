package genconfig

import "github.com/CtrlCarlitos/agent-guardrails/internal/policy"

// legacyClaudeFragment is exactly what ClaudeConfig generated before the floor
// was retired (ADR-0028 phase C): hooks, the allow entry, and the deny/ask
// floor. Tests of merge, ownership and glob semantics use it as realistic
// sample data, because those mechanisms still have to handle a settings file
// full of exactly this shape until every operator has pruned.
func legacyClaudeFragment(pol *policy.Policy, binary string) Fragment {
	deny := append(bashDenyGlobs(), secretDenyGlobs(pol)...)
	deny = append(deny, claudeSelfConfigDenyGlobs()...)
	ask := append(bashAskGlobs(), secretAskGlobs(pol)...)
	ask = append(ask, ciInfraLockAskGlobs()...)
	return Fragment{
		"hooks": claudeHooks(binary),
		"permissions": map[string]any{
			"allow": claudeFloorAllow(),
			"deny":  deny,
			"ask":   ask,
		},
	}
}
