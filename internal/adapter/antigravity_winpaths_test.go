package adapter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
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

func TestAntigravityBrainDirPermittedRoot(t *testing.T) {
	appData := filepath.Join(t.TempDir(), ".gemini", "antigravity-cli")
	t.Setenv("ANTIGRAVITY_APP_DATA_DIR", appData)
	sessionID := "ses-live-123"
	brainDir := filepath.Join(appData, "brain", sessionID)

	// Valid session populates permitted root
	payload := fmt.Sprintf(`{"conversationId":%q,"workspacePaths":["C:\\repo"],"toolCall":{"name":"write_to_file","args":{"TargetFile":%q}}}`,
		sessionID, filepath.Join(brainDir, "task.md"))
	tc, err := ParseAntigravity("pre", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.PermittedRoots) != 1 || tc.PermittedRoots[0] != brainDir {
		t.Fatalf("tc.PermittedRoots = %v, want [%s]", tc.PermittedRoots, brainDir)
	}

	// Traversal session does not populate permitted root
	badPayload := `{"conversationId":"../escape","workspacePaths":["C:\\repo"],"toolCall":{"name":"write_to_file","args":{"TargetFile":"C:\\repo\\a.go"}}}`
	tcBad, err := ParseAntigravity("pre", strings.NewReader(badPayload))
	if err != nil {
		t.Fatal(err)
	}
	if len(tcBad.PermittedRoots) != 0 {
		t.Fatalf("traversal session gave PermittedRoots: %v", tcBad.PermittedRoots)
	}

	// Slashes in session do not populate permitted root
	slashPayload := `{"conversationId":"foo/bar","workspacePaths":["C:\\repo"],"toolCall":{"name":"write_to_file","args":{"TargetFile":"C:\\repo\\a.go"}}}`
	tcSlash, err := ParseAntigravity("pre", strings.NewReader(slashPayload))
	if err != nil {
		t.Fatal(err)
	}
	if len(tcSlash.PermittedRoots) != 0 {
		t.Fatalf("slash session gave PermittedRoots: %v", tcSlash.PermittedRoots)
	}

	// Empty session does not populate permitted root
	emptyPayload := `{"conversationId":"","workspacePaths":["C:\\repo"],"toolCall":{"name":"write_to_file","args":{"TargetFile":"C:\\repo\\a.go"}}}`
	tcEmpty, err := ParseAntigravity("pre", strings.NewReader(emptyPayload))
	if err != nil {
		t.Fatal(err)
	}
	if len(tcEmpty.PermittedRoots) != 0 {
		t.Fatalf("empty session gave PermittedRoots: %v", tcEmpty.PermittedRoots)
	}
}

func TestAntigravityBrainDirEvaluation(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	baseDir := filepath.Join(home, ".test-guardrails-"+strings.ReplaceAll(t.Name(), "/", "-"))
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(baseDir) })

	appData := filepath.Join(baseDir, "appdata")
	repoDir := filepath.Join(baseDir, "repo")
	if err := os.MkdirAll(appData, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ANTIGRAVITY_APP_DATA_DIR", appData)
	sessionID := "ses-live-123"
	brainDir := filepath.Join(appData, "brain", sessionID)
	pol := &policy.Policy{
		Slots: policy.Slots{
			SecretGlobs: []string{"**/.env", "**/.env.*"},
		},
	}

	// 1. task.md in session brain dir -> allow (no P5.out-of-repo ask)
	payload := fmt.Sprintf(`{"conversationId":%q,"workspacePaths":[%q],"toolCall":{"name":"write_to_file","args":{"TargetFile":%q,"Description":"task tracking"}}}`,
		sessionID, repoDir, filepath.Join(brainDir, "task.md"))
	tc, err := ParseAntigravity("pre", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	v := engine.Evaluate(tc, pol)
	if v.Decision != policy.Allow {
		t.Fatalf("task.md in brain dir -> %+v, want allow", v)
	}

	// 2. task.md in ANOTHER session brain dir -> ask (P5.out-of-repo)
	otherBrainDir := filepath.Join(appData, "brain", "ses-other-999")
	otherPayload := fmt.Sprintf(`{"conversationId":%q,"workspacePaths":[%q],"toolCall":{"name":"write_to_file","args":{"TargetFile":%q,"Description":"task tracking"}}}`,
		sessionID, repoDir, filepath.Join(otherBrainDir, "task.md"))
	tcOther, err := ParseAntigravity("pre", strings.NewReader(otherPayload))
	if err != nil {
		t.Fatal(err)
	}
	vOther := engine.Evaluate(tcOther, pol)
	if vOther.Decision != policy.Ask || vOther.RuleID != "P5.out-of-repo" {
		t.Fatalf("task.md in other session brain dir -> %+v, want ask/P5.out-of-repo", vOther)
	}

	// 3. Brain dir root itself -> ask (P5.out-of-repo)
	rootPayload := fmt.Sprintf(`{"conversationId":%q,"workspacePaths":[%q],"toolCall":{"name":"write_to_file","args":{"TargetFile":%q,"Description":"task tracking"}}}`,
		sessionID, repoDir, brainDir)
	tcRoot, err := ParseAntigravity("pre", strings.NewReader(rootPayload))
	if err != nil {
		t.Fatal(err)
	}
	vRoot := engine.Evaluate(tcRoot, pol)
	if vRoot.Decision != policy.Ask || vRoot.RuleID != "P5.out-of-repo" {
		t.Fatalf("brain dir root write -> %+v, want ask/P5.out-of-repo", vRoot)
	}

	// 4. Secret inside session brain dir (.env) -> deny (P4.secret-path)
	secretPayload := fmt.Sprintf(`{"conversationId":%q,"workspacePaths":[%q],"toolCall":{"name":"write_to_file","args":{"TargetFile":%q,"Description":"env"}}}`,
		sessionID, repoDir, filepath.Join(brainDir, ".env"))
	tcSecret, err := ParseAntigravity("pre", strings.NewReader(secretPayload))
	if err != nil {
		t.Fatal(err)
	}
	vSecret := engine.Evaluate(tcSecret, pol)
	if vSecret.Decision != policy.Deny || vSecret.RuleID != "P4.secret-path" {
		t.Fatalf("secret in brain dir -> %+v, want deny/P4.secret-path", vSecret)
	}
}
