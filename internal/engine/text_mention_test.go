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
// #112 flipped the printf-into-a-redirect family from text-mention deny to
// allow: a pure data copier whose only effect is a redirect into an allowed
// path carries inert data, and these were the exact shapes that false-fired
// on real sessions writing fixtures and docs. The text-mention rule keeps
// its scope where the text can matter — opaque interpreter input.
func TestSecretPathInsideCommandTextIsATextMention(t *testing.T) {
	// Inert data copier: the body is data bound for a file, allowed.
	for _, command := range []string{
		`printf '%s\n' '{"tool_input":{"file_path":"/home/u/.ssh/id_ed25519","x":1}}' > fixture.json`,
		`printf '%s' '["/home/u/.aws/credentials","/home/u/.other"]' > fixture.json`,
		"printf '%s' 'line one\nkey: /home/u/.aws/credentials' > note.txt",
	} {
		if v := Evaluate(ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}, pathPol()); v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow (inert redirect body, #112)", command, v)
		}
	}
	// The rule itself keeps its scope: opaque interpreter input mentioning a
	// secret path still denies as a text mention.
	v := Evaluate(ToolCall{Tool: "Bash", Command: `python3 -c 'open("/home/u/.ssh/id_ed25519")'`, CWD: "/repo", RepoRoot: "/repo"}, pathPol())
	if v.Decision != policy.Deny || v.RuleID != "P4.secret-in-text" {
		t.Fatalf("opaque interpreter -> %+v, want deny/P4.secret-in-text", v)
	}
	if want := "command text mentions a secret-tier path: /home/u/.ssh/id_ed25519"; v.Reason != want {
		t.Fatalf("reason = %q, want %q", v.Reason, want)
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
