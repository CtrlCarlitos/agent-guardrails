package engine

import "testing"

func TestWindowsCodexWrapperCandidates(t *testing.T) {
	command := `& 'C:/Program Files/Git/bin/bash.exe' -c 'cat ''./.env'''`
	simples, err := normalizeToolCall(ToolCall{Shell: ShellPowerShell, Command: command, CWD: t.TempDir()})
	for _, s := range simples {
		t.Logf("argv=%q cwd=%q unresolved=%v", s.Argv, s.Cwd, s.Unresolved)
	}
	if err != nil || len(simples) != 2 || len(simples[1].Argv) != 2 || simples[1].Argv[1] != "./.env" {
		t.Fatalf("expected literal nested path; error=%v", err)
	}
}
