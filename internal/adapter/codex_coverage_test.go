package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestCodexCoverageVerdicts(t *testing.T) {
	cwd := t.TempDir()
	for _, tt := range []struct {
		names      []string
		input      string
		capability policy.Capability
		decision   policy.Decision
	}{
		{[]string{"image_gen.imagegen", "image_gen__imagegen", "image_genimagegen"}, `{"prompt":"image"}`, policy.CapabilityExternal, policy.Ask},
		{[]string{"clock.curr_time", "clock__curr_time", "clockcurr_time", "clock.sleep", "clock__sleep", "clocksleep", "functions.wait", "functions__wait", "wait"}, `{}`, policy.CapabilitySafeControl, policy.Allow},
		{[]string{"functions.exec", "functions__exec", "exec"}, `{"code":"tools.exec_command({cmd:'ls'})"}`, policy.CapabilityDeny, policy.Deny},
		{[]string{"write_stdin"}, `{"session_id":1,"chars":"dangerous\n"}`, policy.CapabilityDeny, policy.Deny},
		{[]string{"write_stdin"}, `{"session_id":1,"chars":""}`, policy.CapabilityDeny, policy.Deny},
		{[]string{"other.wait", "other.exec", "other.clock.sleep", "clock__unknown"}, `{}`, policy.CapabilityUnknown, policy.Deny},
		{[]string{"mcp__clock__sleep"}, `{}`, policy.CapabilityDeny, policy.Deny},
	} {
		for _, name := range tt.names {
			t.Run(name+tt.input, func(t *testing.T) {
				tc, err := ParseCodex(strings.NewReader(codexEnvelope(cwd, name, json.RawMessage(tt.input))))
				if err != nil {
					t.Fatal(err)
				}
				v := engine.Evaluate(tc, &policy.Policy{})
				if tc.NativeTool != name || tc.Capability != tt.capability || v.Decision != tt.decision {
					t.Fatalf("call=%+v verdict=%+v", tc, v)
				}
				var out, guidance bytes.Buffer
				code := EmitCodex(v, "pre", tc, &out, &guidance)
				if tt.decision != policy.Allow && code != 2 {
					t.Fatalf("failed to block: %d", code)
				}
				if name == "write_stdin" && (!strings.Contains(guidance.String(), "ADR-0014") || !strings.Contains(guidance.String(), "non-interactive exec_command")) {
					t.Fatal(guidance.String())
				}
				if tc.Tool == "functions.exec" && !strings.Contains(guidance.String(), "directly") {
					t.Fatal(guidance.String())
				}
			})
		}
	}
}

func TestCodexWebProjectionEvaluatesWholeRequest(t *testing.T) {
	cwd := t.TempDir()
	for _, tt := range []struct {
		input    string
		cap      policy.Capability
		url      string
		decision policy.Decision
	}{
		{`{"search_query":[{"q":"docs","domains":["example.com"]}],"response_length":"short"}`, policy.CapabilityWebSearch, "", policy.Ask},
		{`{"image_query":[{"q":"diagram"}],"search_query":[{"q":"docs"}]}`, policy.CapabilityWebSearch, "", policy.Ask},
		{`{"open":[{"ref_id":"https://example.com/docs","lineno":12}]}`, policy.CapabilityWebFetch, "https://example.com/docs", policy.Deny},
		{`{"open":[{"ref_id":"https://example.com"},{"ref_id":"https://evil.example"}]}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"open":[{"ref_id":"https://example.com"}],"search_query":[{"q":"docs"}]}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"search_query":[{"q":"docs"}],"click":[{"ref_id":"turn0search0","id":1}]}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"open":[{"ref_id":"turn0search0"}]}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"open":[{"ref_id":"file:///etc/passwd"}]}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"open":[{"ref_id":"https://user:pass@example.com"}]}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"open":[{"ref_id":42}]}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"search_query":[{"q":""}]}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"search_query":[{"q":"docs"},{}]}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"search_query":null}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"search_query":[]}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"search_query":"docs"}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"search_query":[{"q":"docs"}],"future_operation":{}}`, policy.CapabilityDeny, "", policy.Deny},
		{`{"open":[{"ref_id":"https://example.com"}],"response_length":42}`, policy.CapabilityDeny, "", policy.Deny},
		{`{}`, policy.CapabilityDeny, "", policy.Deny},
	} {
		for _, name := range []string{"web.run", "web__run", "webrun"} {
			t.Run(name+tt.input, func(t *testing.T) {
				tc, err := ParseCodex(strings.NewReader(codexEnvelope(cwd, name, json.RawMessage(tt.input))))
				if err != nil {
					t.Fatal(err)
				}
				v := engine.Evaluate(tc, &policy.Policy{})
				if tc.Capability != tt.cap || tc.URL != tt.url || v.Decision != tt.decision {
					t.Fatalf("%+v %+v", tc, v)
				}
				var out, guidance bytes.Buffer
				if EmitCodex(v, "pre", tc, &out, &guidance) != 2 {
					t.Fatal("web call did not block")
				}
				if tt.cap == policy.CapabilityDeny && !strings.Contains(guidance.String(), "one explicit HTTP(S) URL") {
					t.Fatal(guidance.String())
				}
			})
		}
	}
}
