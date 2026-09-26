package genconfig

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestTranslateOpenCodeCommandGlob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []string
	}{
		{name: "plain", pattern: "sudo *", want: []string{"sudo *"}},
		{name: "empty or stars collapses", pattern: "gh repo delete{,**}", want: []string{"gh repo delete*"}},
		{name: "literal alternatives", pattern: "tool {start,stop} *", want: []string{"tool start *", "tool stop *"}},
		{name: "multiple braces", pattern: "tool {one,two} {up,down}", want: []string{"tool one down", "tool one up", "tool two down", "tool two up"}},
		{name: "digit class", pattern: "git push * v[0-9]*", want: []string{
			"git push * v0*", "git push * v1*", "git push * v2*", "git push * v3*", "git push * v4*",
			"git push * v5*", "git push * v6*", "git push * v7*", "git push * v8*", "git push * v9*",
		}},
		{name: "unsupported class fails closed", pattern: "future [abc]", want: []string{"*"}},
		{name: "brace without alternatives fails closed", pattern: "future {one}", want: []string{"*"}},
		{name: "unclosed brace fails closed", pattern: "future {one,two", want: []string{"*"}},
		{name: "stray closing brace fails closed", pattern: "future one}", want: []string{"*"}},
		{name: "stray closing class fails closed", pattern: "future 0]", want: []string{"*"}},
		{name: "expansion cap fails closed", pattern: "future [0-9][0-9][0-9]", want: []string{"*"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := translateOpenCodeCommandGlob(tt.pattern); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("translateOpenCodeCommandGlob(%q) = %q, want %q", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestOpenCodeDigitClassTranslationIsEquivalent(t *testing.T) {
	const source = "git push * v[0-9]*"
	translated := translateOpenCodeCommandGlob(source)
	for _, command := range []string{
		"git push origin v0",
		"git push origin v1.2.3",
		"git push upstream v9-rc1",
		"git push origin version1",
		"git push origin va",
		"x git push origin v1",
	} {
		want := commandGlobMatches(source, command)
		got := slices.ContainsFunc(translated, func(pattern string) bool {
			return opencodeGlobMatches(pattern, command)
		})
		if got != want {
			t.Errorf("translated %q matching %q = %v, source = %v", translated, command, got, want)
		}
	}
}

func TestOpenCodeFailClosedFallbackKeepsStrongestDecision(t *testing.T) {
	rules := orderedPermissionRules{"*": "allow"}
	for _, pattern := range translateOpenCodeCommandGlob("future [abc]") {
		setOpenCodeBashDecision(rules, pattern, "ask")
		setOpenCodeBashDecision(rules, pattern, "deny")
		setOpenCodeBashDecision(rules, pattern, "ask")
	}
	if got := rules["*"]; got != "deny" {
		t.Fatalf("fallback decision = %q, want strongest deny", got)
	}
}

func TestOpenCodeBraceTranslationIsEquivalent(t *testing.T) {
	const source = "gh repo delete{,**}"
	translated := translateOpenCodeCommandGlob(source)
	for _, command := range []string{
		"gh repo delete",
		"gh repo delete owner/repo --yes",
		"gh repo deletion",
		"x gh repo delete owner/repo",
	} {
		want := commandGlobMatches(source, command)
		got := slices.ContainsFunc(translated, func(pattern string) bool {
			return opencodeGlobMatches(pattern, command)
		})
		if got != want {
			t.Errorf("translated %q matching %q = %v, source = %v", translated, command, got, want)
		}
	}
}

func TestOpencodeConfigTranslatesEveryUnsupportedSourceGlob(t *testing.T) {
	frag := legacyOpencodeFragment(secretPol(), "/opt/guardrail/guardrail.js")
	bash := frag["permission"].(map[string]any)["bash"].(orderedPermissionRules)

	for pattern := range bash {
		if strings.ContainsAny(pattern, "{}[]") {
			t.Errorf("OpenCode floor copied unsupported source syntax verbatim: %q", pattern)
		}
	}

	type sourceRule struct {
		pattern  string
		decision string
	}
	var special []sourceRule
	for decision, globs := range map[string][]string{
		"deny": bashDenyGlobs(),
		"ask":  bashAskGlobs(),
	} {
		for _, wrapped := range globs {
			pattern, ok := stripWrapper("Bash(", wrapped)
			if ok && strings.ContainsAny(pattern, "{}[]") {
				special = append(special, sourceRule{pattern: pattern, decision: decision})
			}
		}
	}
	if len(special) != 24 {
		t.Fatalf("special source globs = %d, want 24", len(special))
	}

	for _, rule := range special {
		example, ok := floorExamples[rule.pattern]
		if !ok {
			t.Errorf("source pattern %q has no captured command", rule.pattern)
			continue
		}
		matched := false
		for emitted, value := range bash {
			if value == rule.decision && opencodeGlobMatches(emitted, example) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("%s source %q emitted no OpenCode rule matching %q", rule.decision, rule.pattern, example)
		}
	}
}
