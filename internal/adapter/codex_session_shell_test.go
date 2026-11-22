package adapter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsCodexSessionShellRecoveryBoundaries(t *testing.T) {
	const session = "01a0f057-e2f9-7580-bc6e-5df92bc2b9e5"
	for _, c := range []struct {
		name, shell, metaID string
		reference           any
		duplicate, missing  bool
		want                int
	}{
		{"null reference", "pwsh", session, nil, false, false, 0},
		{"empty reference", "powershell", session, "", false, false, 0},
		{"stale local reference", "powershell", session, "stale", false, false, 0},
		{"foreign reference", "powershell", session, "foreign", false, false, 2},
		{"malformed reference", "powershell", session, 123, false, false, 2},
		{"metadata belongs to another session", "powershell", "another-session", nil, false, false, 2},
		{"metadata missing identity", "powershell", "", nil, false, false, 2},
		{"duplicate session files", "powershell", session, nil, true, false, 2},
		{"no matching transcript", "powershell", session, nil, false, true, 2},
		{"missing explicit file", "powershell", session, "stale", false, true, 2},
		{"unreadable explicit file", "powershell", session, "directory", false, true, 2},
		{"unsupported shell", "bash", session, nil, false, false, 2},
		{"missing shell", "", session, nil, false, false, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			home, cwd := t.TempDir(), t.TempDir()
			t.Setenv("CODEX_HOME", home)
			dir := filepath.Join(home, "sessions", "2026", "09", "29")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			meta, _ := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]string{"id": c.metaID}})
			body := string(meta) + "\n" + `{"type":"response_item","payload":{"type":"message","content":[{"type":"input_text","text":"<environment_context><shell>` + c.shell + `</shell></environment_context>"}]}}` + "\n"
			if !c.missing {
				for _, prefix := range []string{"rollout-a-", "rollout-b-"} {
					if err := os.WriteFile(filepath.Join(dir, prefix+session+".jsonl"), []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
					if !c.duplicate {
						break
					}
				}
			}
			ref := c.reference
			if ref == "stale" {
				ref = filepath.Join(dir, "missing.jsonl")
			}
			if ref == "foreign" {
				ref = filepath.Join(cwd, "foreign.jsonl")
			}
			if ref == "directory" {
				path := filepath.Join(dir, "directory.jsonl")
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				ref = path
			}
			raw, _ := json.Marshal(map[string]any{"session_id": session, "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Bash", "transcript_path": ref, "tool_input": map[string]string{"command": "Get-Location", "shell": "pwsh"}})
			code, out, stderr := emitWindows(t, raw)
			if code != c.want {
				t.Fatalf("exit=%d, want=%d; stdout=%q stderr=%q", code, c.want, out, stderr)
			}
			if c.want == 2 && (strings.Contains(out, "updatedInput") || !strings.Contains(stderr, "readable transcript for this session")) {
				t.Fatalf("unproven call emitted rewrite or lacks guidance: stdout=%q stderr=%q", out, stderr)
			}
			details := map[string]string{
				"foreign reference":                   "outside CODEX_HOME/sessions",
				"malformed reference":                 "invalid transcript_path",
				"metadata belongs to another session": "session id mismatch",
				"metadata missing identity":           "session id mismatch",
				"duplicate session files":             "multiple matching transcripts",
				"no matching transcript":              "no transcript_path",
				"missing explicit file":               "transcript_path file is missing",
				"unreadable explicit file":            "file is unreadable",
				"unsupported shell":                   "recorded shell is unsupported",
				"missing shell":                       "no shell tag",
			}
			if want := details[c.name]; want != "" && !strings.Contains(stderr, want) {
				t.Errorf("stderr=%q, want %q", stderr, want)
			}
		})
	}
	for _, sessionID := range []string{"", "../escape", "not-a-session"} {
		if shell, _ := codexSessionShell(sessionID); shell != "" {
			t.Fatalf("invalid session %q proves %q", sessionID, shell)
		}
	}
}
