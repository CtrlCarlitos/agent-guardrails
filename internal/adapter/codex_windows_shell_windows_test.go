package adapter

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The precondition runs in real Windows PowerShell and pwsh: in the evaluated
// directory the original command runs; anywhere else it stops before it
// with the guidance, exit 1. The OneDrive-style name exercises spaces, an
// apostrophe and a $() that must stay inert.
func TestWindowsPowerShellPreconditionGuardsTheDirectory(t *testing.T) {
	evaluated := filepath.Join(t.TempDir(), "OneDrive - IZOTE LLC", "Carlitos' repo $(boom)")
	elsewhere := filepath.Join(t.TempDir(), "Documents")
	for _, d := range []string{evaluated, elsewhere} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	script := powershellWorkdirPrecondition(evaluated) + "\nWrite-Output 'ORIGINAL-RAN'"
	for _, shell := range []string{"powershell.exe", "pwsh.exe"} {
		if _, err := exec.LookPath(shell); err != nil {
			t.Logf("%s not installed; skipped", shell)
			continue
		}
		run := func(dir string) (string, int) {
			cmd := exec.Command(shell, "-NoProfile", "-NonInteractive", "-Command", script)
			cmd.Dir = dir
			out, _ := cmd.CombinedOutput()
			return string(out), cmd.ProcessState.ExitCode()
		}
		if out, code := run(evaluated); code != 0 || !strings.Contains(out, "ORIGINAL-RAN") {
			t.Errorf("%s in the evaluated directory: exit %d, output %q; want the original command to run", shell, code, out)
		}
		if out, code := run(elsewhere); code != 1 || strings.Contains(out, "ORIGINAL-RAN") || !strings.Contains(out, "Codex workdir differs") {
			t.Errorf("%s elsewhere: exit %d, output %q; want exit 1 with the guidance and no original command", shell, code, out)
		}
		if _, err := os.Stat(filepath.Join(evaluated, "boom")); err == nil {
			t.Errorf("%s evaluated $(boom) in the quoted path", shell)
		}
	}
}
