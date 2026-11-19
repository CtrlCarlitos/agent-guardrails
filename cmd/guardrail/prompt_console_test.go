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
//
// #538 amended this: when stdout is a pipe (not the terminal), a wrapper may
// have given the child its own hidden console (CreateNoWindow), so the console
// copy is invisible and the piped stdout is the one channel the operator
// watches. stdout then also carries the question itself, as a complete line
// written before the run waits for the answer (#419's unterminated-prompt
// hazard is why that copy must end in a newline, not why it must not exist).
func TestWindowsAndPOSIXPromptQuestionGoesToTheConsoleNotStdout(t *testing.T) {
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
		out := stdout.String()
		if idx := strings.Index(out, "Approve register guardrail on planes: claude? [y/N]"); idx < 0 {
			t.Errorf("typed %q: a piped stdout never saw the question, so a wrapper cannot surface it: %q", typed, out)
		} else if !strings.Contains(out[idx:], "\n") {
			t.Errorf("typed %q: the stdout copy of the question is not a complete line: %q", typed, out)
		}
		if !strings.HasSuffix(out, "\n") || !strings.Contains(out, "register guardrail on planes: claude") {
			t.Errorf("typed %q: stdout lacks a complete-line record of the answer: %q", typed, out)
		}
	}
}

// #538: stdout is the visible terminal itself (a bare `guardrail setup` in a
// console); the console copy is the one the operator reads, and a duplicate
// on stdout would double-print the prompt.
func TestWindowsAndPOSIXPromptQuestionNotDuplicatedWhenStdoutIsTheTerminal(t *testing.T) {
	saved := openPromptConsole
	t.Cleanup(func() { openPromptConsole = saved })
	openPromptConsole = func() io.WriteCloser { return nopWriteCloser{&bytes.Buffer{}} }
	savedTerm := writerIsTerminal
	t.Cleanup(func() { writerIsTerminal = savedTerm })
	writerIsTerminal = func(io.Writer) bool { return true }
	useOperatorInput(t, "n\n")

	var stdout bytes.Buffer
	promptApproval("register guardrail on planes: claude", true, &stdout)
	if strings.Contains(stdout.String(), "[y/N]") {
		t.Errorf("stdout is the terminal; the question must not be duplicated there: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "asked at the terminal: register guardrail on planes: claude: declined") {
		t.Errorf("stdout lacks the complete-line record of the answer: %q", stdout.String())
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
