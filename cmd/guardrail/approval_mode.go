package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// Prompt-mode operator approvals (ADR-0033, #413).
//
// In prompt mode an operator action is approved by one of two things: the
// host's native ask, answered yes, which the hook records as a ticket the
// TTY-less CLI run claims; or a `[y/N]` on the terminal the command runs in.
// Passkey mode is the WebAuthn broker, unchanged.

// productionApprovalDefault is the mode an Operator config without an
// `approval` key means. unconfiguredApprovalMode is what the code reads; the
// package's TestMain pins it to passkey so every test written before
// ADR-0033 keeps asserting today's behaviour, and the prompt-mode tests write
// the key explicitly.
var (
	productionApprovalDefault = policy.ApprovalPrompt
	unconfiguredApprovalMode  = productionApprovalDefault
)

// approvalModeOf resolves the approval mode. An Operator config that cannot
// be read or parsed is passkey: a damaged file must not downgrade an
// operator who chose the passkey.
func approvalModeOf(op *policy.OperatorConfig, err error) string {
	if err != nil {
		return policy.ApprovalPasskey
	}
	if op == nil || op.Approval == "" {
		return unconfiguredApprovalMode
	}
	return op.ApprovalMode()
}

func currentApprovalMode() string {
	op, err := policy.LoadOperatorConfig()
	return approvalModeOf(op, err)
}

func promptApprovalMode() bool { return currentApprovalMode() == policy.ApprovalPrompt }

// Process-wide invocation state, set by run: the argv a ticket must bind and
// the input the terminal prompt reads.
var (
	operatorInvocation []string
	operatorInput      io.Reader = os.Stdin
)

// promptApprovalReachable says whether this run can obtain a prompt-mode
// approval (a terminal or a ticket). setupEnableReason reads it to decide
// whether the retired floor may be pruned: the approval-less bootstrap can
// only tighten (ADR-0030). Commands set it for their run; the default is
// true because an operator can always reach a terminal, which is what
// doctor and next advise about.
var promptApprovalReachable = true

// setPromptReachable records reachability for the current command and returns
// the function that restores the default.
func setPromptReachable(reachable bool) func() {
	promptApprovalReachable = reachable
	return func() { promptApprovalReachable = true }
}

const (
	transportHostAsk        = "host-ask"
	transportTerminalPrompt = "terminal-prompt"
)

// invocationCommand is the canonical command this process was started as.
// Tickets are only minted for whitelisted commands whose words are joined by
// single spaces, so this reconstruction is exact.
func invocationCommand() string {
	if len(operatorInvocation) == 0 {
		return ""
	}
	return "guardrail " + strings.Join(operatorInvocation, " ")
}

func invocationDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return cwd
}

// ticketPresent reports, without spending it, whether a host approval was
// recorded for exactly this command in this directory.
func ticketPresent() bool {
	command, cwd := invocationCommand(), invocationDir()
	return command != "" && cwd != "" && approval.PeekTicket(command, cwd, time.Now())
}

// claimInvocationTicket spends the host approval for this exact command.
func claimInvocationTicket() bool {
	command, cwd := invocationCommand(), invocationDir()
	if command == "" || cwd == "" {
		return false
	}
	_, ok, err := approval.ClaimTicket(command, cwd, time.Now())
	return err == nil && ok
}

// reachability is what a prompt-mode run can approve with: a terminal, or a
// ticket. Passkey mode keeps its terminal-only rule.
func reachability(prompt, terminal bool) bool {
	if terminal || !prompt {
		return terminal
	}
	return ticketPresent()
}

// legacyFloorPrunable says whether this run may remove the retired settings
// floor, which loosens the file: only with an approval. In passkey mode that
// means an enrolled operator; in prompt mode, an approval this run can reach.
func legacyFloorPrunable() bool {
	if promptApprovalMode() {
		return promptApprovalReachable
	}
	return operatorEnrolled()
}

// bootstrapAllowed is ADR-0030's rule: nobody enrolled and nothing else can
// approve. In prompt mode a terminal or a ticket is an approval, so the run
// asks rather than arms silently.
func bootstrapAllowed(prompt, reachable bool) bool {
	return !operatorEnrolled() && !(prompt && reachable)
}

type approvalOutcome int

const (
	approvalGranted approvalOutcome = iota
	approvalDeclined
	approvalUnreachable
)

// promptApproval obtains a prompt-mode approval for summary: the host's
// recorded yes first, then the terminal. The terminal answer defaults to No.
func promptApproval(summary string, terminal bool, stdout io.Writer) (string, approvalOutcome) {
	if claimInvocationTicket() {
		fmt.Fprintf(stdout, "approved in the agent host: %s\n", summary)
		return transportHostAsk, approvalGranted
	}
	if !terminal {
		return "", approvalUnreachable
	}
	fmt.Fprintf(stdout, "Approve %s? [y/N] ", summary)
	line, _ := bufio.NewReader(operatorInput).ReadString('\n')
	if !strings.HasSuffix(line, "\n") {
		fmt.Fprintln(stdout)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return transportTerminalPrompt, approvalGranted
	}
	return "", approvalDeclined
}

// promptOperatorVerdict is the hook's prompt-mode answer to a canonical
// operator command: the plane's native ask plus a ticket, the host-approved
// allow on opencode, or a deny that names the terminal command where the
// plane cannot ask.
func promptOperatorVerdict(plane string, tc engine.ToolCall, a engine.Action, now time.Time) policy.Verdict {
	summary := a.Summary()
	mint := func() error {
		return approval.IssueTicket(approval.Ticket{Command: a.Command, CWD: tc.CWD, RepoRoot: tc.RepoRoot, Plane: plane, Action: a.Name}, tc.SessionID, now)
	}
	ticketFailure := policy.Verdict{Decision: policy.Deny, RuleID: "operator-action-ticket", OperatorAction: a.Name,
		Reason: "the approval could not be recorded, so the operator action was not asked for; failing closed. The operator can run `" + a.Command + "` in their terminal"}
	ask := policy.Verdict{Decision: policy.Ask, RuleID: "operator-action-ask", OperatorAction: a.Name,
		Reason: "guardrail operator action: " + summary + " — `" + a.Command + "`"}
	switch plane {
	case "codex":
		return policy.Verdict{Decision: policy.Deny, RuleID: "operator-action-terminal", OperatorAction: a.Name,
			Reason: "guardrail operator action (" + summary + ") needs the operator's approval, and Codex cannot ask for it from a hook; ask the operator to run `" + a.Command + "` in their terminal"}
	case "opencode":
		if !tc.HostApproved {
			return ask
		}
		if err := mint(); err != nil {
			return ticketFailure
		}
		return policy.Verdict{Decision: policy.Allow, RuleID: "operator-action-host-approved", OperatorAction: a.Name,
			Reason: "operator approved in the opencode dialog: " + summary}
	default:
		if err := mint(); err != nil {
			return ticketFailure
		}
		return ask
	}
}
