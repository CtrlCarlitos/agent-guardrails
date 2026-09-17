package adapter

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type countingReader struct {
	io.Reader
	bytesRead int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytesRead += n
	return n, err
}

func opencodeEnvelopeOfSize(t *testing.T, size int) string {
	t.Helper()
	prefix := `{"tool":"custom","arguments":"`
	suffix := `"}`
	padding := size - len(prefix) - len(suffix)
	if padding < 0 {
		t.Fatalf("size %d is too small for test envelope", size)
	}
	return prefix + strings.Repeat("x", padding) + suffix
}

func TestParseOpencodeBash(t *testing.T) {
	raw := `{"session_id":"s1","event":"pre","tool":"bash","command":"rm -rf /","cwd":"/tmp"}`
	tc, err := ParseOpencode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Plane != "opencode" || tc.Tool != "Bash" || tc.Command != "rm -rf /" || tc.Event != "pre" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseOpencodeFileTool(t *testing.T) {
	raw := `{"session_id":"s1","event":"pre","tool":"read","paths":["/tmp/.env"],"cwd":"/tmp"}`
	tc, err := ParseOpencode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "Read" || len(tc.Paths) != 1 || tc.Paths[0] != "/tmp/.env" {
		t.Fatalf("bad ToolCall: %+v", tc)
	}
}

func TestParseOpencodeClassifiesAndExtractsTypedInputs(t *testing.T) {
	for _, tt := range []struct {
		name     string
		raw      string
		wantCap  policy.Capability
		wantURL  string
		wantPath string
	}{
		{"grep", `{"tool":"grep","paths":["/repo/.env"],"arguments":{"path":"/repo/.env"}}`, policy.CapabilityReadDiscovery, "", "/repo/.env"},
		{"glob", `{"tool":"glob","paths":["/repo/.env"],"arguments":{"path":"/repo/.env"}}`, policy.CapabilityReadDiscovery, "", "/repo/.env"},
		{"lsp", `{"tool":"lsp","paths":["/repo/a.go"],"arguments":{"filePath":"/repo/a.go","operation":"goToDefinition"}}`, policy.CapabilityReadDiscovery, "", "/repo/a.go"},
		{"webfetch", `{"tool":"webfetch","arguments":{"url":"https://example.test/docs"}}`, policy.CapabilityWebFetch, "https://example.test/docs", ""},
		{"apply patch", `{"tool":"apply_patch","arguments":{"patch":"*** Update File: /repo/a.go"}}`, policy.CapabilityMutation, "", "/repo/a.go"},
		{"custom", `{"tool":"custom","arguments":{}}`, policy.CapabilityDeny, "", ""},
		{"task", `{"tool":"task","arguments":{}}`, policy.CapabilityDelegation, "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc, err := ParseOpencode(strings.NewReader(tt.raw))
			if err != nil {
				t.Fatal(err)
			}
			if tc.Capability != tt.wantCap || tc.URL != tt.wantURL {
				t.Fatalf("ToolCall = %+v, want capability %q and URL %q", tc, tt.wantCap, tt.wantURL)
			}
			if tt.wantPath != "" && (len(tc.Paths) != 1 || tc.Paths[0] != tt.wantPath) {
				t.Fatalf("paths = %q, want %q", tc.Paths, tt.wantPath)
			}
		})
	}
}

func TestParseOpencodeCarriesCompleteNativeArguments(t *testing.T) {
	raw := `{"session_id":"s1","event":"pre","tool":"custom","cwd":"/repo","arguments":{"z":1,"nested":{"b":true,"a":null},"items":[2,1]}}`
	tc, err := ParseOpencode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Tool != "custom" || string(tc.Arguments) != `{"z":1,"nested":{"b":true,"a":null},"items":[2,1]}` {
		t.Fatalf("ToolCall arguments were not preserved: %+v args=%s", tc, tc.Arguments)
	}
}

func TestParseOpencodeDistinguishesMissingArguments(t *testing.T) {
	tc, err := ParseOpencode(strings.NewReader(`{"session_id":"s1","event":"pre","tool":"read","cwd":"/repo"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Arguments != nil {
		t.Fatalf("Arguments = %s, want missing", tc.Arguments)
	}
}

func TestParseOpencodeAcceptsEnvelopeAtSizeLimit(t *testing.T) {
	raw := opencodeEnvelopeOfSize(t, maxOpencodeHookEnvelopeBytes)
	tc, err := ParseOpencode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.Raw) != maxOpencodeHookEnvelopeBytes {
		t.Fatalf("raw envelope length = %d, want %d", len(tc.Raw), maxOpencodeHookEnvelopeBytes)
	}
}

func TestParseOpencodeRejectsEnvelopeAboveSizeLimitWithoutDrainingReader(t *testing.T) {
	const wantErr = "OpenCode hook envelope exceeds 8 MiB"
	tooLarge := opencodeEnvelopeOfSize(t, maxOpencodeHookEnvelopeBytes+1)
	if _, err := ParseOpencode(strings.NewReader(tooLarge)); err == nil || err.Error() != wantErr {
		t.Fatalf("limit+1 error = %v, want %q", err, wantErr)
	}

	r := &countingReader{Reader: strings.NewReader(tooLarge + strings.Repeat("z", 1024))}
	if _, err := ParseOpencode(r); err == nil || err.Error() != wantErr {
		t.Fatalf("oversize stream error = %v, want %q", err, wantErr)
	}
	if r.bytesRead != maxOpencodeHookEnvelopeBytes+1 {
		t.Fatalf("reader consumed %d bytes, want exactly %d", r.bytesRead, maxOpencodeHookEnvelopeBytes+1)
	}
}

func TestParseOpencodeUnknownEventDefaultsPre(t *testing.T) {
	tc, err := ParseOpencode(strings.NewReader(`{"session_id":"s1","tool":"bash","command":"ls"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Event != "pre" {
		t.Fatalf("Event = %q, want pre", tc.Event)
	}
}

func TestEmitOpencodeSanitizesReasonForEveryDecision(t *testing.T) {
	tc, err := ParseOpencode(strings.NewReader(`{"session_id":"s1","event":"pre","tool":"bash","cwd":"/tmp","arguments":{"command":"chmod -R 777 /tmp","timeout":30}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		decision policy.Decision
		wantCode int
	}{
		{decision: policy.Allow, wantCode: 0},
		{decision: policy.Ask, wantCode: 0},
		{decision: policy.Deny, wantCode: 2},
	} {
		t.Run(string(tt.decision), func(t *testing.T) {
			var out, errb bytes.Buffer
			code := EmitOpencode(policy.Verdict{Decision: tt.decision, Reason: "needs approval"}, tc, &out, &errb)
			if code != tt.wantCode {
				t.Fatalf("code = %d, want %d", code, tt.wantCode)
			}
			var got map[string]string
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["decision"] != string(tt.decision) {
				t.Fatalf("bad payload: %v", got)
			}
			if tt.decision == policy.Ask && (!strings.Contains(got["reason"], "Operator authorization required: needs approval.") || !strings.Contains(got["reason"], `Request authorization for this exact action: bash {"command":"chmod -R 777 /tmp","timeout":30}.`) || !strings.Contains(got["reason"], "If the operator approves, retry this exact tool call once.") || !strings.Contains(got["reason"], "Do not alter or broaden the action.")) {
				t.Fatalf("ask guidance = %q", got["reason"])
			}
			if tt.decision == policy.Deny && (!strings.Contains(got["reason"], "Guardrail denied this action: needs approval.") || !strings.Contains(got["reason"], "Do not retry this exact call.") || strings.Contains(got["reason"], "Choose a safe alternative.")) {
				t.Fatalf("deny guidance = %q", got["reason"])
			}
		})
	}
}

func TestEmitOpencodeAskPreservesCompleteActionWhenItExceedsBound(t *testing.T) {
	raw := `{"session_id":"s1","event":"pre","tool":"bash","cwd":"/tmp","arguments":{"command":"` + strings.Repeat("x", maxModelFacingRunes*2) + `"}}`
	wantAction := `bash {"command":"` + strings.Repeat("x", maxModelFacingRunes*2) + `"}`
	tc, err := ParseOpencode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := EmitOpencode(policy.Verdict{Decision: policy.Ask, Reason: "needs approval"}, tc, &out, &errb)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["reason"], "Request authorization for this exact action: "+wantAction+".") || !strings.Contains(got["reason"], "If the operator approves, retry this exact tool call once.") || !strings.Contains(got["reason"], "Do not alter or broaden the action.") {
		t.Fatalf("Ask guidance = %q, want complete action and mandatory constraints", got["reason"])
	}
}

func TestEmitOpencodeAskRetainsMandatoryContentWhenReasonExceedsBound(t *testing.T) {
	tc, err := ParseOpencode(strings.NewReader(`{"session_id":"s1","event":"pre","tool":"bash","cwd":"/tmp","arguments":{"command":"chmod -R 777 /tmp"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := EmitOpencode(policy.Verdict{Decision: policy.Ask, Reason: strings.Repeat("r", maxModelFacingRunes*2)}, tc, &out, &errb)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`Request authorization for this exact action: bash {"command":"chmod -R 777 /tmp"}.`,
		"If the operator approves, retry this exact tool call once.",
		"Do not alter or broaden the action.",
	} {
		if !strings.Contains(got["reason"], want) {
			t.Fatalf("Ask guidance = %q, missing %q", got["reason"], want)
		}
	}
}

func TestEmitOpencodeOperatorActionIsNotRetryableAsk(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitOpencode(policy.Verdict{Decision: policy.Complete, OperatorAction: "night-off", RequestID: "request-1", ApprovalURL: "http://localhost:39169"}, engine.ToolCall{}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit = %d, want blocked action", code)
	}
	if strings.Contains(out.String(), `"decision":"ask"`) || !strings.Contains(out.String(), `"operator_action":"night-off"`) || !strings.Contains(out.String(), `"approval_url":"http://localhost:39169"`) {
		t.Fatalf("operator-action response = %s", out.String())
	}
}

func TestEmitOpencodeAllow(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitOpencode(policy.Verdict{Decision: policy.Allow}, engine.ToolCall{}, &out, &errb)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	var got map[string]string
	json.Unmarshal(out.Bytes(), &got)
	if got["decision"] != "allow" {
		t.Fatalf("decision = %q, want allow", got["decision"])
	}
}
