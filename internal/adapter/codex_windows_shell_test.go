package adapter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #454 step 2. Measured on Codex 0.159.0 (Windows): the model asked for
// exec_command({cmd:"echo probe2", workdir:"C:\Users\carlitos\Documents"})
// and the PreToolUse hook received tool_input {"command"} only, with the
// session cwd: the effective directory is still hidden (ADR-0014). The
// session transcript Codex hands the hook (transcript_path) records the
// shell, <shell>powershell</shell>, so on Windows the directory
// precondition can be written for a proven PowerShell instead of refused.

// codexPayload builds the captured 0.159 payload shape with a transcript
// under a sandboxed CODEX_HOME whose environment block names shell.
func codexPayload(t *testing.T, cwd, shell string, transcriptOutside bool) []byte {
	t.Helper()
	home := t.TempDir()
	t.Setenv("CODEX_HOME", home)
	dir := filepath.Join(home, "sessions", "2026", "09", "29")
	if transcriptOutside {
		dir = t.TempDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(dir, "rollout-2026-09-29T21-24-46-01a0f057.jsonl")
	body := `{"type":"session_meta","payload":{"cli_version":"0.159.0"}}` + "\n"
	if shell != "" {
		body += `{"type":"response_item","payload":{"type":"message","content":[{"type":"input_text","text":"<environment_context>\n  <cwd>` + jsonText(cwd) + `</cwd>\n  <shell>` + shell + `</shell>\n</environment_context>"}]}}` + "\n"
	}
	if err := os.WriteFile(transcript, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "codex-0159-windows-bash.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(raw), "__TRANSCRIPT__", jsonText(transcript))
	s = strings.ReplaceAll(s, "__CWD__", jsonText(cwd))
	return []byte(s)
}

func emitWindows(t *testing.T, payload []byte) (int, string, string) {
	t.Helper()
	tc, err := ParseCodex(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("parse captured 0.159 payload: %v", err)
	}
	var out, errb bytes.Buffer
	code := emitCodexAllowedCommand("windows", tc, &out, &errb)
	return code, out.String(), errb.String()
}

func updatedCommand(t *testing.T, stdout string) string {
	t.Helper()
	var p struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
			UpdatedInput       struct {
				Command string `json:"command"`
			} `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(stdout), &p); err != nil {
		t.Fatalf("stdout is not a hook decision: %q (%v)", stdout, err)
	}
	if p.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("decision = %q, want allow", p.HookSpecificOutput.PermissionDecision)
	}
	return p.HookSpecificOutput.UpdatedInput.Command
}

func TestCodexWindowsProvenPowerShellGetsADirectoryPrecondition(t *testing.T) {
	for _, shell := range []string{"powershell", "pwsh"} {
		cwd := t.TempDir()
		code, out, errb := emitWindows(t, codexPayload(t, cwd, shell, false))
		if code != 0 {
			t.Fatalf("%s: exit %d, stderr %q", shell, code, errb)
		}
		cmd := updatedCommand(t, out)
		if !strings.HasSuffix(cmd, "\necho probe2") {
			t.Errorf("%s: original command not kept verbatim after the precondition: %q", shell, cmd)
		}
		for _, want := range []string{"(Get-Location).ProviderPath", "exit 1", "Codex workdir differs"} {
			if !strings.Contains(cmd, want) {
				t.Errorf("%s: precondition lacks %q: %q", shell, want, cmd)
			}
		}
		if !strings.Contains(cmd, "'"+windowsPathKey(cwd)+"'") {
			t.Errorf("%s: precondition does not compare against the evaluated cwd %q: %q", shell, cwd, cmd)
		}
	}
}

// OneDrive: redirected folders carry spaces and punctuation, and a name can
// hold an apostrophe. The path is single-quoted with ' doubled, so nothing in
// it is interpreted.
func TestCodexWindowsPreconditionQuotesOneDriveStylePaths(t *testing.T) {
	cwd := filepath.Join(t.TempDir(), "OneDrive - IZOTE LLC", "Carlitos' repo $(boom)")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errb := emitWindows(t, codexPayload(t, cwd, "powershell", false))
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb)
	}
	cmd := updatedCommand(t, out)
	quoted := "'" + strings.ReplaceAll(windowsPathKey(cwd), "'", "''") + "'"
	if !strings.Contains(cmd, quoted) {
		t.Fatalf("path not single-quoted with doubled apostrophes (%s): %q", quoted, cmd)
	}
}

// Anything short of a proven PowerShell keeps today's fail-closed refusal.
func TestCodexWindowsUnprovenShellStillFailsClosed(t *testing.T) {
	cwd := t.TempDir()
	for name, payload := range map[string][]byte{
		"cmd shell":                   codexPayload(t, cwd, "cmd", false),
		"bash shell":                  codexPayload(t, cwd, "bash", false),
		"no shell recorded":           codexPayload(t, cwd, "", false),
		"transcript outside sessions": codexPayload(t, cwd, "powershell", true),
	} {
		code, out, errb := emitWindows(t, payload)
		if code == 0 || strings.Contains(out, "updatedInput") || !strings.Contains(errb, "cannot prove the Windows command shell") {
			t.Errorf("%s: code=%d stdout=%q stderr=%q, want the fail-closed refusal", name, code, out, errb)
		}
	}
	// No transcript_path at all (pre-0.159 payloads, fixtures).
	tc, err := ParseCodex(strings.NewReader(`{"session_id":"s","cwd":"` + jsonText(cwd) + `","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := emitCodexAllowedCommand("windows", tc, &out, &errb); code == 0 {
		t.Errorf("a payload without transcript_path was allowed: %q", out.String())
	}
}

// POSIX keeps its existing precondition, untouched.
func TestCodexPOSIXPreconditionUnchanged(t *testing.T) {
	cwd := t.TempDir()
	tc, err := ParseCodex(bytes.NewReader(codexPayload(t, cwd, "bash", false)))
	if err != nil {
		t.Fatal(err)
	}
	tc.Capability = policy.CapabilityCommand
	var out, errb bytes.Buffer
	if code := emitCodexAllowedCommand("linux", tc, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if cmd := updatedCommand(t, out.String()); !strings.Contains(cmd, `"$(pwd -P)"`) {
		t.Fatalf("POSIX precondition changed: %q", cmd)
	}
}

// jsonText escapes s for splicing into a JSON string literal.
func jsonText(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}
