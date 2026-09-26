package genconfig

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

const maxOpenCodeCommandGlobExpansions = 256

func stripWrapper(prefix, s string) (string, bool) {
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, ")") {
		return "", false
	}
	return s[len(prefix) : len(s)-1], true
}

// translateOpenCodeCommandGlob lowers the shared Claude command-glob grammar
// into OpenCode's pinned `*`/`?` grammar. OpenCode treats braces and character
// classes literally, so copying either construct through would silently emit a
// no-op standing authorization (#270).
//
// Supported brace alternatives and [0-9] classes are enumerated exactly. Star
// runs are collapsed because OpenCode gives every `*` the same `.*` meaning.
// Any malformed, unsupported, or excessively expansive construct degrades to
// `*`: a deliberate conservative over-match for deny/ask floors, never a
// silent no-op. setOpenCodeBashDecision preserves the strongest decision if
// multiple degraded rules collide on that fallback.
func translateOpenCodeCommandGlob(pattern string) []string {
	patterns, ok := expandOpenCodeBraceAlternatives(pattern)
	if !ok {
		return []string{"*"}
	}

	var expanded []string
	for _, pattern := range patterns {
		values, ok := expandOpenCodeDigitClasses(pattern)
		if !ok || len(expanded)+len(values) > maxOpenCodeCommandGlobExpansions {
			return []string{"*"}
		}
		expanded = append(expanded, values...)
	}

	unique := make(map[string]struct{}, len(expanded))
	for _, pattern := range expanded {
		if strings.ContainsAny(pattern, "{}[]") {
			return []string{"*"}
		}
		unique[collapseOpenCodeStars(pattern)] = struct{}{}
	}
	// Under OpenCode's whole-value semantics, prefix* already includes prefix
	// because `*` may match the empty string. Drop the redundant bare branch
	// produced by patterns such as `gh repo delete{,**}`.
	for pattern := range unique {
		if _, subsumed := unique[pattern+"*"]; subsumed {
			delete(unique, pattern)
		}
	}

	out := make([]string, 0, len(unique))
	for pattern := range unique {
		out = append(out, pattern)
	}
	sort.Strings(out)
	return out
}

func expandOpenCodeBraceAlternatives(pattern string) ([]string, bool) {
	start := strings.IndexByte(pattern, '{')
	if start < 0 {
		return []string{pattern}, !strings.Contains(pattern, "}")
	}
	if strings.Contains(pattern[:start], "}") {
		return nil, false
	}

	depth := 0
	end := -1

scanBrace:
	for i := start; i < len(pattern); i++ {
		switch pattern[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i
				break scanBrace
			} else if depth < 0 {
				return nil, false
			}
		}
	}
	if end < 0 {
		return nil, false
	}

	alternatives, ok := splitOpenCodeBraceAlternatives(pattern[start+1 : end])
	if !ok {
		return nil, false
	}
	var out []string
	for _, alternative := range alternatives {
		expanded, ok := expandOpenCodeBraceAlternatives(pattern[:start] + alternative + pattern[end+1:])
		if !ok || len(out)+len(expanded) > maxOpenCodeCommandGlobExpansions {
			return nil, false
		}
		out = append(out, expanded...)
	}
	return out, true
}

func splitOpenCodeBraceAlternatives(body string) ([]string, bool) {
	depth := 0
	start := 0
	foundComma := false
	var alternatives []string
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				return nil, false
			}
		case ',':
			if depth == 0 {
				foundComma = true
				alternatives = append(alternatives, body[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 || !foundComma {
		return nil, false
	}
	return append(alternatives, body[start:]), true
}

func expandOpenCodeDigitClasses(pattern string) ([]string, bool) {
	start := strings.IndexByte(pattern, '[')
	if start < 0 {
		return []string{pattern}, !strings.Contains(pattern, "]")
	}
	if strings.Contains(pattern[:start], "]") || !strings.HasPrefix(pattern[start:], "[0-9]") {
		return nil, false
	}

	out := make([]string, 0, 10)
	for digit := byte('0'); digit <= '9'; digit++ {
		expanded, ok := expandOpenCodeDigitClasses(pattern[:start] + string(digit) + pattern[start+5:])
		if !ok || len(out)+len(expanded) > maxOpenCodeCommandGlobExpansions {
			return nil, false
		}
		out = append(out, expanded...)
	}
	return out, true
}

func collapseOpenCodeStars(pattern string) string {
	var out strings.Builder
	previousStar := false
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '*' {
			if previousStar {
				continue
			}
			previousStar = true
		} else {
			previousStar = false
		}
		out.WriteByte(pattern[i])
	}
	return out.String()
}

func setOpenCodeBashDecision(rules orderedPermissionRules, pattern, decision string) {
	rank := map[string]int{"allow": 1, "ask": 2, "deny": 3}
	current, _ := rules[pattern].(string)
	if rank[decision] > rank[current] {
		rules[pattern] = decision
	}
}

// OpencodePluginFor returns the embedded plugin source with the absolute
// guardrail path and the engine-contract degraded-mode tool lists baked in.
func OpencodePluginFor(binary string) []byte {
	encoded, _ := json.Marshal(binary)
	tools, _ := json.Marshal(planecontract.OpencodeDegradedAllowTools())
	floor, _ := json.Marshal(planecontract.OpencodeFloorFallbackTools())
	source := strings.ReplaceAll(string(OpencodePluginJS), `"__GUARDRAIL_BIN__"`, string(encoded))
	source = strings.ReplaceAll(source, `"__DEGRADED_ALLOW_TOOLS__"`, string(tools))
	return []byte(strings.ReplaceAll(source, `"__FLOOR_FALLBACK_TOOLS__"`, string(floor)))
}

func legacyOpencodeFragment(pol *policy.Policy, pluginPath string) Fragment {
	bash := orderedPermissionRules{"*": "allow"}
	for _, g := range bashDenyGlobs() {
		if p, ok := stripWrapper("Bash(", g); ok {
			for _, translated := range translateOpenCodeCommandGlob(p) {
				setOpenCodeBashDecision(bash, translated, "deny")
			}
		}
	}
	for _, g := range bashAskGlobs() {
		if p, ok := stripWrapper("Bash(", g); ok {
			for _, translated := range translateOpenCodeCommandGlob(p) {
				setOpenCodeBashDecision(bash, translated, "ask")
			}
		}
	}

	read := orderedPermissionRules{}
	edit := orderedPermissionRules{}
	for _, g := range secretDenyGlobs(pol) {
		if p, ok := stripWrapper("Read(", g); ok {
			read[p] = "deny"
		}
		if p, ok := stripWrapper("Edit(", g); ok {
			edit[p] = "deny"
		}
	}
	for _, g := range secretAskGlobs(pol) {
		if p, ok := stripWrapper("Read(", g); ok {
			read[p] = "ask"
		}
		if p, ok := stripWrapper("Edit(", g); ok {
			edit[p] = "ask"
		}
	}
	for _, a := range pol.Slots.SecretAllow {
		read[a] = "allow"
		edit[a] = "allow"
	}
	for _, d := range pol.Slots.SecretDirs {
		read[d] = "deny"
		edit[d] = "deny"
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
