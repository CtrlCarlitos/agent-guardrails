package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
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
	return cmdApprovalsInput(args, operatorTerminal, os.Stdin, stdout, stderr)
}

func cmdApprovalsInput(args []string, operatorTerminal bool, input io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "daemon" {
		if err := approval.RunDefaultDaemon(openApprovalBrowser); err != nil {
			fmt.Fprintf(stderr, "guardrail: %v\n", err)
			return 1
		}
		return 0
	}
	if !operatorTerminal {
		fmt.Fprintln(stderr, "approvals are available only from an operator terminal")
		return 2
	}
	fs := flag.NewFlagSet("approvals", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("request", "", "approval request identity")
	if err := fs.Parse(args); err != nil || *id == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "guardrail: approvals requires --request <id>")
		return 2
	}
	socket := approval.DefaultSocketPath()
	r, err := approval.Lookup(socket, *id)
	if err != nil || r.Status != "pending" {
		fmt.Fprintln(stderr, "guardrail: approval daemon unavailable")
		return 1
	}
	fmt.Fprintf(stdout, "request %s\nplane: %s\nrepository: %s\nhost: %s\naction: %s\nscope: %s\nexpires: %s\n", r.ID, r.Plane, r.RepoRoot, r.Host, r.Action, r.Scope, r.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprint(stdout, "approve? [y/N] ")
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintln(stderr, "guardrail: could not read operator response")
		return 1
	}
	if strings.TrimSpace(strings.ToLower(line)) != "y" {
		if err := approval.Deny(socket, r.ID); err != nil {
			fmt.Fprintln(stderr, "guardrail: approval daemon unavailable")
			return 1
		}
		fmt.Fprintln(stdout, "denied")
		return 0
	}
	if err := approval.Approve(socket, r.ID, r.Scope); err != nil {
		fmt.Fprintln(stderr, "guardrail: approval could not be completed")
		return 1
	}
	fmt.Fprintln(stdout, "completed")
	return 0
}
