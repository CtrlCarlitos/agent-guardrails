package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

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
	if len(args) >= 1 && args[0] == "list" {
		return cmdApprovalsList(args[1:], stdout, stderr)
	}
	if len(args) == 2 && args[1] != "" && args[0] == "approve" {
		if !operatorTerminal {
			fmt.Fprintln(stderr, "guardrail: approvals approve requires an interactive local terminal")
			return 2
		}
		return cmdApprovalsApprove(args[1], stdout, stderr)
	}
	fmt.Fprintln(stderr, "guardrail: approvals accepts daemon, list, or approve <id>")
	return 2
}

func cmdApprovalsList(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "guardrail: approvals list takes no arguments")
		return 2
	}
	pending, err := approval.ListPending(approval.DefaultSocketPath())
	if err != nil {
		fmt.Fprintln(stderr, "guardrail: no approval daemon is running; nothing to list")
		return 1
	}
	if len(pending) == 0 {
		fmt.Fprintln(stdout, "no pending approval requests")
		return 0
	}
	for _, r := range pending {
		summary := r.Summary()
		if summary == "" {
			summary = r.Action
		}
		fmt.Fprintf(stdout, "%s  %-28s  expires %s\n", r.ID[:12], summary, r.ExpiresAt.Local().Format("15:04:05"))
	}
	fmt.Fprintln(stdout, "approve with: guardrail approvals approve <id>")
	return 0
}

// cmdApprovalsApprove re-presents a pending request's ceremony. Completion
// still requires the WebAuthn assertion; the command waits for the outcome.
func cmdApprovalsApprove(id string, stdout, stderr io.Writer) int {
	if err := approval.PresentApproval(approval.DefaultSocketPath(), id); err != nil {
		fmt.Fprintf(stderr, "guardrail: request %s is not pending\n", id)
		return 1
	}
	fmt.Fprintln(stdout, "approval page opened; complete the passkey to approve")
	deadline := time.Now().Add(15 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		status, err := approval.QueryStatus(approval.DefaultSocketPath(), id)
		if err != nil {
			fmt.Fprintln(stderr, "guardrail: approval daemon unavailable")
			return 1
		}
		switch status.Status {
		case "approved", "completed":
			fmt.Fprintln(stdout, "approved and applied")
			return 0
		case "denied", "expired":
			fmt.Fprintf(stderr, "guardrail: request %s\n", status.Status)
			return 1
		}
	}
	fmt.Fprintln(stderr, "guardrail: approval expired")
	return 1
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
