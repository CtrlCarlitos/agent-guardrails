package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

type nopWriteCloser struct{ *bytes.Buffer }

func (nopWriteCloser) Close() error { return nil }

// #419: the question went to stdout. The Windows dotfiles pipe the installer
// through Tee-Object, which forwards only complete lines, so `Approve …? [y/N] `
// never appeared and the install waited on an invisible prompt. The question
// belongs on the console the answer is read from; stdout keeps a complete-line
// record of what was asked and answered.
func TestPromptQuestionGoesToTheConsoleNotStdout(t *testing.T) {
	for typed, granted := range map[string]bool{"y\n": true, "n\n": false} {
		console := nopWriteCloser{&bytes.Buffer{}}
		saved := openPromptConsole
		openPromptConsole = func() io.WriteCloser { return console }
		useOperatorInput(t, typed)

		var stdout bytes.Buffer
		_, outcome := promptApproval("register guardrail on planes: claude", true, &stdout)
		openPromptConsole = saved

		if got := outcome == approvalGranted; got != granted {
			t.Errorf("typed %q: granted = %v, want %v", typed, got, granted)
		}
		if !strings.Contains(console.String(), "Approve register guardrail on planes: claude? [y/N] ") {
			t.Errorf("typed %q: the console did not get the question: %q", typed, console.String())
		}
		if strings.Contains(stdout.String(), "[y/N]") {
			t.Errorf("typed %q: the question leaked to stdout, where a pipe can hide it: %q", typed, stdout.String())
		}
		if !strings.HasSuffix(stdout.String(), "\n") || !strings.Contains(stdout.String(), "register guardrail on planes: claude") {
			t.Errorf("typed %q: stdout lacks a complete-line record of the answer: %q", typed, stdout.String())
		}
	}
}

// With no console to open, the question stays on stdout as before.
func TestPromptQuestionFallsBackToStdoutWithoutAConsole(t *testing.T) {
	saved := openPromptConsole
	t.Cleanup(func() { openPromptConsole = saved })
	openPromptConsole = func() io.WriteCloser { return nil }
	useOperatorInput(t, "n\n")
	var stdout bytes.Buffer
	promptApproval("register guardrail on planes: claude", true, &stdout)
	if !strings.Contains(stdout.String(), "Approve register guardrail on planes: claude? [y/N] ") {
		t.Errorf("stdout = %q, want the question", stdout.String())
	}
}
