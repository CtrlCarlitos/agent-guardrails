package adapter

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"
)

// codexCommandPayload is the captured Codex 0.159 payload carrying command,
// with a session transcript whose environment block names shell (#498).
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

// #498: off Windows Codex runs bash, so a transcript naming PowerShell does
// not change how its commands are read.
func TestCodexShellIsOnlyProvenOnWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("covered by TestWindowsCodexProvenPowerShellReadsConstantsAsValues")
	}
	call, err := ParseCodex(bytes.NewReader(codexCommandPayload(t, t.TempDir(), "powershell", `Write-Output $true`)))
	if err != nil {
		t.Fatal(err)
	}
	if call.Shell != "" {
		t.Errorf("Shell = %q off Windows; want empty", call.Shell)
	}
}
