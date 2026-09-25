package adapter

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestWindowsWebResearchAcrossNativePlanes(t *testing.T) {
	for _, test := range []struct{ plane, raw string }{
		{"claude", `{"hook_event_name":"PreToolUse","tool_name":"WebSearch","tool_input":{"query":"docs"}}`},
		{"claude", `{"hook_event_name":"PreToolUse","tool_name":"WebFetch","tool_input":{"url":"https://example.com"}}`},
		{"opencode", `{"event":"pre","tool":"websearch","arguments":{"query":"docs"}}`},
		{"opencode", `{"event":"pre","tool":"webfetch","arguments":{"url":"https://example.com"}}`},
		{"antigravity", `{"toolCall":{"name":"search_web","args":{"Query":"docs"}}}`},
		{"antigravity", `{"toolCall":{"name":"read_url_content","args":{"Url":"https://example.com"}}}`},
	} {
		var tc engine.ToolCall
		var err error
		switch test.plane {
		case "claude":
			tc, err = ParseClaude(strings.NewReader(test.raw))
		case "opencode":
			tc, err = ParseOpencode(strings.NewReader(test.raw))
		case "antigravity":
			tc, err = ParseAntigravity("pre", strings.NewReader(test.raw))
		}
		if err != nil {
			t.Fatal(err)
		}
		strict := engine.Evaluate(tc, &policy.Policy{})
		relaxed := engine.Evaluate(tc, &policy.Policy{WebResearchOff: true})
		if strict.Decision == policy.Allow || relaxed.Decision != policy.Allow || relaxed.RuleID != "web-research-enforcement-off" {
			t.Errorf("%s strict=%+v relaxed=%+v tc=%+v", test.plane, strict, relaxed, tc)
		}
	}
}

func TestWindowsWebResearchOffDoesNotPermitMalformedOrUnknownCodexOperations(t *testing.T) {
	for _, input := range []string{
		`{}`, `{"search_query":null}`, `{"search_query":[{}]}`,
		`{"open":[{"ref_id":"file:///etc/passwd"}]}`,
		`{"open":[{"ref_id":"https://user:pass@example.com"}]}`,
		`{"search_query":[{"q":"docs"}],"future_operation":{}}`,
		`{"click":[{"ref_id":"turn0search0"}]}`,
		`{"find":[{"ref_id":"turn0search0","pattern":""}]}`,
		`{"screenshot":[{"ref_id":"turn0search0","pageno":-1}]}`,
		`{"open":[{"ref_id":"turn0search0"}],"response_length":42}`,
		`{"NativeWebResearch":true}`,
		`{"open":[{"ref_id":"https://example.com","method":"POST"}]}`,
	} {
		tc, err := ParseCodex(strings.NewReader(codexEnvelope(t.TempDir(), "web.run", json.RawMessage(input))))
		if err != nil {
			t.Fatal(err)
		}
		if v := engine.Evaluate(tc, &policy.Policy{WebResearchOff: true}); v.Decision == policy.Allow {
			t.Errorf("allowed %s: %+v", input, v)
		}
	}
}

func TestWindowsWebResearchOffPreservesUnrelatedProtection(t *testing.T) {
	base, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	base.WebResearchOff = true
	cwd := t.TempDir()
	for _, test := range []struct {
		tool  string
		input any
	}{
		{"Bash", map[string]any{"command": "git push --force"}},
		{"Bash", map[string]any{"command": "guardrail web-research off"}},
		{"Bash", map[string]any{"command": "curl https://unapproved.example"}},
		{"view_image", map[string]any{"path": filepath.Join(cwd, ".env")}},
		{"mcp__context7__query_docs", map[string]any{"query": "docs", "NativeWebResearch": true}},
		{"future_tool", map[string]any{"NativeWebResearch": true}},
	} {
		tc, err := ParseCodex(strings.NewReader(codexEnvelope(cwd, test.tool, test.input)))
		if err != nil {
			t.Fatal(err)
		}
		if v := engine.Evaluate(tc, base); v.Decision == policy.Allow {
			t.Errorf("allowed %s %+v: %+v", test.tool, test.input, v)
		}
	}
}
