package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

func openApprovalBrowser(rawURL string) error {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command, args = "open", []string{rawURL}
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		command, args = "xdg-open", []string{rawURL}
	}
	return exec.Command(command, args...).Start()
}

func cmdApprovals(args []string, operatorTerminal bool, stdout, stderr io.Writer) int {
	return cmdApprovalsInput(args, operatorTerminal, nil, stdout, stderr)
}

func cmdApprovalsInput(args []string, operatorTerminal bool, input io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "daemon" {
		if err := approval.RunDefaultDaemon(defaultOperatorAuthStore(), openApprovalBrowser); err != nil {
			fmt.Fprintf(stderr, "guardrail: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stderr, "guardrail: approvals accepts only the daemon subcommand")
	return 2
}

func defaultOperatorAuthStore() *operatorauth.Store {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	store := operatorauth.NewStore(filepath.Join(base, "guardrail"))
	return &store
}
