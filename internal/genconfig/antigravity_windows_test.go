package genconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// preCommand digs the PreToolUse command string out of the antigravity
// fragment, the exact text written into ~/.gemini/config/hooks.json.
func preCommand(t *testing.T, binary string) string {
	t.Helper()
	pre := AntigravityConfig(binary)["guardrail"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	return pre["hooks"].([]any)[0].(map[string]any)["command"].(string)
}

// agy hands the whole hook command to `cmd /C` as one Go argument, and Go
// escapes every embedded double quote as \". cmd.exe does not read \" as a
// quote, so it looks for a program literally named `\"C:/…/guardrail.exe\"`
// and every tool call is denied (#353). The spelling must therefore carry no
// quotes when the path needs none.
func TestWindowsAntigravityHookCommandCarriesNoQuotesWhenThePathNeedsNone(t *testing.T) {
	got := preCommand(t, `C:\Users\carlitos\.local\bin\guardrail.exe`)
	want := `C:/Users/carlitos/.local/bin/guardrail.exe hook antigravity pre`
	if got != want {
		t.Fatalf("antigravity pre command = %q, want %q", got, want)
	}
}

// A path that does need quotes keeps them: unquoted, cmd would split it.
func TestWindowsAntigravityHookCommandStillQuotesAPathWithASpace(t *testing.T) {
	got := preCommand(t, `C:\Program Files\guardrail\guardrail.exe`)
	want := `"C:/Program Files/guardrail/guardrail.exe" hook antigravity pre`
	if got != want {
		t.Fatalf("antigravity pre command = %q, want %q", got, want)
	}
}

// The measured failure, end to end: spawn the generated command the way agy
// does and require it to reach the binary.
func TestWindowsAntigravityHookCommandSpawnsThroughCmdWithGoQuoteEscaping(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe spawn semantics")
	}
	dir := t.TempDir()
	if strings.ContainsAny(dir, " &()^%!") {
		t.Skipf("temp dir %q needs quoting, which this spawn cannot express", dir)
	}
	stub := filepath.Join(dir, "guardrail.cmd")
	if err := os.WriteFile(stub, []byte("@exit /b 0\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	command := preCommand(t, stub)
	out, err := exec.Command("cmd", "/C", command).CombinedOutput()
	if err != nil {
		t.Fatalf("cmd /C %s: %v\n%s", command, err, out)
	}
}
