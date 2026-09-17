package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

func openApprovalBrowser(rawURL string) error {
	return printOperatorURL(os.Stderr, rawURL)
}

func printOperatorURL(output io.Writer, rawURL string) error {
	_, err := fmt.Fprintf(output, "guardrail: open operator approval page:\n%s\n", rawURL)
	return err
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
