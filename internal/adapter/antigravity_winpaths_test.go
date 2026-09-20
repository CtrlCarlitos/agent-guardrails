package adapter

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Antigravity on a Windows host sends backslash, drive-lettered paths for native
// file tools, Serena MCP, and Graft MCP tools. The adapter projects them
// verbatim — normalisation is the Engine's job on the host that owns the path
// semantics. These tests are platform-neutral: they assert projection, not verdicts.
func TestParseAntigravityKeepsWindowsPathsVerbatim(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		args  string
		paths []string
	}{
		{"view_file", "view_file", `{"AbsolutePath":"C:\\Users\\u\\.ssh\\id_ed25519"}`, []string{`C:\Users\u\.ssh\id_ed25519`}},
		{"write_to_file", "write_to_file", `{"TargetFile":"C:\\repo\\.env"}`, []string{`C:\repo\.env`}},
		{"replace_file_content", "replace_file_content", `{"TargetFile":"C:\\repo\\internal\\a.go"}`, []string{`C:\repo\internal\a.go`}},
		{"notebook_edit", "notebook_edit", `{"NotebookPath":"C:\\repo\\n.ipynb"}`, []string{`C:\repo\n.ipynb`}},
		{"sed_file", "sed_file", `{"TargetFile":"C:\\repo\\file.txt"}`, []string{`C:\repo\file.txt`}},
		{"delete_knowledge", "delete_knowledge", `{"PathToDelete":"C:\\repo\\knowledge.txt"}`, []string{`C:\repo\knowledge.txt`}},
		{"unc share", "write_to_file", `{"TargetFile":"\\\\server\\share\\.env"}`, []string{`\\server\share\.env`}},
		{"multiedit per-edit secret", "multi_replace_file_content",
			`{"TargetFile":"C:\\repo\\a.go","ReplacementChunks":[{"TargetFile":"C:\\repo\\b.go"},{"TargetFile":"C:\\Users\\u\\.ssh\\id_ed25519"}]}`,
			[]string{`C:\repo\a.go`, `C:\repo\b.go`, `C:\Users\u\.ssh\id_ed25519`}},
		{"forward slashes on windows", "view_file", `{"AbsolutePath":"C:/Users/u/.aws/credentials"}`, []string{`C:/Users/u/.aws/credentials`}},
		{"serena mutator backslash relative", "mcp_serena_replace_content", `{"relative_path":"pkg\\safe.go","content":"x"}`, []string{`pkg\safe.go`}},
		{"serena mutator drive path", "mcp_serena_replace_content", `{"relative_path":"C:\\repo\\.env","content":"x"}`, []string{`C:\repo\.env`}},
		{"serena reader backslash relative", "mcp_serena_find_symbol", `{"relative_path":"pkg\\symbol.go"}`, []string{`pkg\symbol.go`}},
		{"serena memory store", "mcp_serena_write_memory", `{"memory_name":"core"}`, []string{`.serena/memories/core`}},
		{"graft reader file_path", "mcp_graft_graft_find_code", `{"file_path":"pkg\\safe.go"}`, []string{`pkg\safe.go`}},
		{"graft reader drive path", "mcp_graft_graft_find_code", `{"path":"C:\\repo\\file.go"}`, []string{`C:\repo\file.go`}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			payload := fmt.Sprintf(`{"conversationId":"w1","workspacePaths":["C:\\repo"],"toolCall":{"name":%q,"args":%s}}`, tt.tool, tt.args)
			tc, err := ParseAntigravity("pre", strings.NewReader(payload))
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

func TestParseAntigravityWindowsCommandsProjectVerbatim(t *testing.T) {
	for _, cmd := range []string{
		`type C:\Users\u\.ssh\id_ed25519`,
		`Get-Content C:\Users\u\.ssh\id_ed25519`,
		`Remove-Item -Recurse -Force C:\`,
		`rm -rf C:\`,
	} {
		payload := fmt.Sprintf(`{"conversationId":"w1","workspacePaths":["C:\\repo"],"toolCall":{"name":"run_command","args":{"CommandLine":%q,"Cwd":"C:\\repo"}}}`, cmd)
		tc, err := ParseAntigravity("pre", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		if tc.Capability != policy.CapabilityCommand || tc.Command != cmd || tc.Tool != "Bash" {
			t.Fatalf("command %q -> %+v", cmd, tc)
		}
	}
}
