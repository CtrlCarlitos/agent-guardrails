package adapter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #498: on Windows Codex runs commands in PowerShell, proven by the session
// transcript (#454). Those commands now get the PowerShell reading #495 gave
// Claude's PowerShell tool: `$true`, `$false` and `$null` are values. A
// transcript naming another shell, or none, keeps the bash reading.
func codexCommandPayload(t *testing.T, cwd, shell, command string) []byte {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(codexPayload(t, cwd, shell, false), &p); err != nil {
		t.Fatal(err)
	}
	p["tool_input"] = map[string]any{"command": command}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWindowsCodexProvenPowerShellReadsConstantsAsValues(t *testing.T) {
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(repo, "a.txt")
	for _, tc := range []struct {
		shell     string
		command   string
		wantShell string
		allowed   bool
	}{
		{"powershell", `Remove-Item -LiteralPath '` + target + `' -Confirm:$false`, "powershell", true},
		{"pwsh", `Write-Output $true`, "powershell", true},
		{"PowerShell", `git status; $null`, "powershell", true},
		// Unproven: the bash reading, where these are ordinary variables.
		{"bash", `Write-Output $true`, "", false},
		{"", `Write-Output $true`, "", false},
	} {
		call, err := ParseCodex(bytes.NewReader(codexCommandPayload(t, repo, tc.shell, tc.command)))
		if err != nil {
			t.Fatalf("%s %q: %v", tc.shell, tc.command, err)
		}
		if call.Shell != tc.wantShell {
			t.Errorf("%s %q: Shell %q, want %q", tc.shell, tc.command, call.Shell, tc.wantShell)
		}
		v := engine.Evaluate(call, pol)
		if got := v.Decision == policy.Allow; got != tc.allowed {
			t.Errorf("%s %q: %s %s; want allowed=%v", tc.shell, tc.command, v.Decision, v.RuleID, tc.allowed)
		}
	}
}

// The proof is read once: the emit step reuses the parsed shell, and an
// allowed command still gets its PowerShell working-directory check.
func TestWindowsCodexEmitReusesTheProvenShell(t *testing.T) {
	repo := t.TempDir()
	call, err := ParseCodex(bytes.NewReader(codexCommandPayload(t, repo, "powershell", `Write-Output $true`)))
	if err != nil {
		t.Fatal(err)
	}
	// Remove the transcript: the emit must not need to read it again.
	if err := os.RemoveAll(filepath.Join(os.Getenv("CODEX_HOME"), "sessions")); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := emitCodexAllowedCommand("windows", call, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "Get-Location") || !strings.Contains(out.String(), "Write-Output $true") {
		t.Errorf("updatedInput lacks the precondition or the command: %s", out.String())
	}
}
