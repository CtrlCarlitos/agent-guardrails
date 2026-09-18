package engine

import (
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// A secret-tier path that appears inside a structured literal (JSON, a
// quoted sentence, a heredoc line) is a mention in command text, not a path
// operand. It stays denied, but the verdict must say so and name the
// fragment, so the model's next step is the editor tool rather than
// "exclude this path".
func TestSecretPathInsideCommandTextIsATextMention(t *testing.T) {
	cases := []struct {
		name     string
		command  string
		fragment string
	}{
		{"json object", `printf '%s\n' '{"tool_input":{"file_path":"/home/u/.ssh/id_ed25519","x":1}}' > fixture.json`, "/home/u/.ssh/id_ed25519"},
		{"json array", `printf '%s' '["/home/u/.aws/credentials","/home/u/other"]' > fixture.json`, "/home/u/.aws/credentials"},
		{"multi-line literal", "printf '%s' 'line one\nkey: /home/u/.aws/credentials' > note.txt", "/home/u/.aws/credentials"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v := Evaluate(ToolCall{Tool: "Bash", Command: tt.command, CWD: "/repo", RepoRoot: "/repo"}, pathPol())
			if v.Decision != policy.Deny || v.RuleID != "P4.secret-in-text" {
				t.Fatalf("%q -> %+v, want deny/P4.secret-in-text", tt.command, v)
			}
			want := "command text mentions a secret-tier path: " + tt.fragment
			if v.Reason != want {
				t.Fatalf("reason = %q, want %q", v.Reason, want)
			}
		})
	}
}

func TestSecretPathOperandsKeepThePathVerdict(t *testing.T) {
	for _, command := range []string{
		`cat /home/u/.ssh/id_ed25519`,
		`cp "/home/u/My Project/.env" /tmp/x`,
		`grep -r secret /home/u/.aws/`,
	} {
		v := Evaluate(ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}, pathPol())
		if v.Decision != policy.Deny || v.RuleID != "P4.secret-path" || !strings.HasPrefix(v.Reason, "access to a credential/secret path: ") {
			t.Fatalf("%q -> %+v, want deny/P4.secret-path", command, v)
		}
	}
}

func TestNightControlMentionInInterpreterInputNamesTheMention(t *testing.T) {
	direct := evalBash(t, "guardrail night off")
	if direct == nil || direct.RuleID != "P5.self-config" || direct.Reason != "the guarded plane cannot change its own night-mode posture" {
		t.Fatalf("direct -> %+v", direct)
	}
	opaque := evalBash(t, "python3 - <<'PY'\ns = 'usage: guardrail night status'\nPY")
	if opaque == nil || opaque.Decision != policy.Deny || opaque.RuleID != "P5.self-config" {
		t.Fatalf("opaque -> %+v, want deny/P5.self-config", opaque)
	}
	if opaque.Reason != "interpreter input mentions guardrail night control; Guardrail cannot tell a mention from an invocation" {
		t.Fatalf("opaque reason = %q", opaque.Reason)
	}
}
