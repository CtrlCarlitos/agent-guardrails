package adapter

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

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
			code := EmitOpencode(policy.Verdict{Decision: tt.decision, Reason: "no\nguardrail: forged\x1bclaim"}, &out, &errb)
			if code != tt.wantCode {
				t.Fatalf("code = %d, want %d", code, tt.wantCode)
			}
			var got map[string]string
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got["decision"] != string(tt.decision) || got["reason"] != "no guardrail: forged claim" {
				t.Fatalf("bad payload: %v", got)
			}
		})
	}
}

func TestEmitOpencodeAllow(t *testing.T) {
	var out, errb bytes.Buffer
	code := EmitOpencode(policy.Verdict{Decision: policy.Allow}, &out, &errb)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	var got map[string]string
	json.Unmarshal(out.Bytes(), &got)
	if got["decision"] != "allow" {
		t.Fatalf("decision = %q, want allow", got["decision"])
	}
}
