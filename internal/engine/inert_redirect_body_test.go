package engine

import (
	"testing"
)

// #112: a pure data copier whose only effect is a redirect into a path the
// write rules allow is INERT — the body (heredoc or literal) is data, never
// executed — so it must not be scanned for secret-path or control-command
// mentions. These are the shapes that bit real sessions writing fixtures,
// commit messages and docs. Anything else keeps today's behavior.
func TestInertRedirectBodyIsNotScannedForMentions(t *testing.T) {
	for _, command := range []string{
		"cat > /repo/docs/note.md <<'EOF'\nan example secret path ~/.ssh/id_ed25519 as documentation data\nEOF",
		"cat >> /repo/CHANGELOG-draft.md <<'EOF'\nmentions guardrail night on --until 02:00 in prose\nEOF",
		"printf '%s' 'see ~/.aws/credentials handling' > /repo/fixtures/note.txt",
		"echo 'guardrail setup --state disabled appears in this fixture' > /repo/tests/case.txt",
		"tee /repo/out.txt <<'EOF'\n.env.example is documentation, not a secret\nEOF",
	} {
		if v := checkPathsHostFrameFixture(ToolCall{Tool: "Bash", Command: command, CWD: "/repo", RepoRoot: "/repo"}, pathPol()); v != nil {
			t.Errorf("%q -> %+v, want allow (inert redirect body)", firstLine(command), v)
		}
	}
}

// The exemption is narrow: an interpreter stage consumes the body, or the
// target itself is policy-bearing, and today's verdicts stand.
func TestInertExemptionIsNarrow(t *testing.T) {
	// (Heredoc bodies piped to interpreters — python3 -, bash <<EOF,
	// cat | sh — are NOT scanned today either; that is outside #112's
	// scope, which only exempts data and tightens nothing. The opaque
	// interpreter mention rules (python -c, node -e, perl -e) keep their
	// scope and are pinned by their own suites.)
	cases := []struct {
		command string
		rule    string
	}{
		// Target is the policy problem: the write rule fires on it, not the
		// body.
		{"cat > /repo/.env <<'EOF'\nSECRET=1\nEOF", "P4.secret-path"},
		{"tee /repo/.ssh/id_ed25519 <<'EOF'\nx\nEOF", "P4.secret-path"},
		// Interpreter head with a redirect is not a data copier: today's
		// operand classification stands verbatim.
		{"perl -e 'print ~/.ssh/id_ed25519' > /repo/out.txt", "P4.secret-path"},
		// A bare secret path as cat's operand is a real read, not data.
		{"cat ~/.ssh/id_ed25519 > /repo/out.txt", "P4.secret-path"},
		// No redirect, no exemption: the literal keeps today's deny.
		{"printf '%s' 'a ~/.ssh/id_ed25519 b'", "P4.secret-path"},
	}
	for _, tc := range cases {
		if v := checkPaths(ToolCall{Tool: "Bash", Command: tc.command, CWD: "/repo", RepoRoot: "/repo"}, pathPol()); v == nil || v.RuleID != tc.rule {
			t.Errorf("%q -> %+v, want deny/%s", firstLine(tc.command), v, tc.rule)
		}
	}
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
