package genconfig

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func stripWrapper(prefix, s string) (string, bool) {
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, ")") {
		return "", false
	}
	return s[len(prefix) : len(s)-1], true
}

func OpencodeConfig(pol *policy.Policy, pluginPath string) Fragment {
	bash := map[string]string{"*": "allow"}
	for _, g := range bashDenyGlobs() {
		if p, ok := stripWrapper("Bash(", g); ok {
			bash[p] = "deny"
		}
	}
	for _, g := range bashAskGlobs() {
		if p, ok := stripWrapper("Bash(", g); ok {
			bash[p] = "ask"
		}
	}

	read := map[string]string{}
	edit := map[string]string{}
	for _, g := range secretDenyGlobs(pol) {
		if p, ok := stripWrapper("Read(", g); ok {
			read[p] = "deny"
		}
		if p, ok := stripWrapper("Edit(", g); ok {
			edit[p] = "deny"
		}
	}
	for _, a := range pol.Slots.SecretAllow {
		read[a] = "allow"
		edit[a] = "allow"
	}
	for _, g := range selfConfigDenyGlobs() {
		if p, ok := stripWrapper("Edit(", g); ok {
			edit[p] = "deny"
		}
	}
	for _, g := range ciInfraLockAskGlobs() {
		if p, ok := stripWrapper("Edit(", g); ok {
			edit[p] = "ask"
		}
	}

	return Fragment{
		"permission": map[string]any{
			"bash": bash,
			"read": read,
			"edit": edit,
		},
		"plugin": []string{pluginPath},
	}
}
