package adapter

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Claude Code on a Windows host sends backslash, drive-lettered paths. The
// adapter projects them verbatim — normalisation is the Engine's job on the
// host that owns the path semantics — and never loses one behind another.
// These tests are platform-neutral: they assert projection, not verdicts.
func TestParseClaudeKeepsWindowsPathsVerbatim(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		input string
		paths []string
	}{
		{"read", "Read", `{"file_path":"C:\\Users\\u\\.ssh\\id_ed25519"}`, []string{`C:\Users\u\.ssh\id_ed25519`}},
		{"edit", "Edit", `{"file_path":"C:\\repo\\internal\\a.go","old_string":"a","new_string":"b"}`, []string{`C:\repo\internal\a.go`}},
		{"notebook", "NotebookEdit", `{"notebook_path":"C:\\repo\\n.ipynb","new_source":"x"}`, []string{`C:\repo\n.ipynb`}},
		{"unc share", "Write", `{"file_path":"\\\\server\\share\\.env","content":""}`, []string{`\\server\share\.env`}},
		{"multiedit per-edit secret", "MultiEdit",
			`{"file_path":"C:\\repo\\a.go","edits":[{"file_path":"C:\\repo\\b.go","old_string":"a","new_string":"b"},{"file_path":"C:\\Users\\u\\.ssh\\id_ed25519","old_string":"c","new_string":"d"}]}`,
			[]string{`C:\repo\a.go`, `C:\repo\b.go`, `C:\Users\u\.ssh\id_ed25519`}},
		{"forward slashes on windows", "Read", `{"file_path":"C:/Users/u/.aws/credentials"}`, []string{`C:/Users/u/.aws/credentials`}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			payload := fmt.Sprintf(`{"session_id":"w1","cwd":"C:\\repo","hook_event_name":"PreToolUse","tool_name":%q,"tool_input":%s}`, tt.tool, tt.input)
			tc, err := ParseClaude(strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(tc.Paths) != fmt.Sprint(tt.paths) || tc.InputShape != "path" {
				t.Fatalf("paths = %q (shape %q), want %q", tc.Paths, tc.InputShape, tt.paths)
			}
			if tc.CWD != `C:\repo` || tc.RepoRoot != `C:\repo` {
				t.Fatalf("cwd = %q root = %q, want both C:\\repo (no git repo there on any host)", tc.CWD, tc.RepoRoot)
			}
		})
	}
}

func TestParseClaudeWindowsCommandsProjectVerbatim(t *testing.T) {
	for _, tt := range []struct{ tool, command string }{
		{"Bash", `type C:\Users\u\.ssh\id_ed25519`},
		{"PowerShell", `Get-Content C:\Users\u\.ssh\id_ed25519`},
		{"Bash", `rm -rf C:\`},
	} {
		payload := fmt.Sprintf(`{"cwd":"C:\\repo","hook_event_name":"PreToolUse","tool_name":%q,"tool_input":{"command":%q}}`, tt.tool, tt.command)
		tc, err := ParseClaude(strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		if tc.Capability != policy.CapabilityCommand || tc.Command != tt.command || tc.Tool != "Bash" {
			t.Fatalf("%s %q -> %+v", tt.tool, tt.command, tc)
		}
	}
}
