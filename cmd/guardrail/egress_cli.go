package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

const egressUsage = `usage:
  guardrail egress grant --scope repo|global --host a.example.com,b.example.com
  guardrail egress revoke --scope repo|global --host a.example.com

From a terminal the change applies immediately. Issued inside a guarded agent
session, the same command is intercepted and brokered to the operator for
passkey approval instead.
`

// cmdEgress is the terminal form of the web-host operator action. The agent
// never reaches it: inside a guarded session the canonical command is caught
// by the hook (engine.OperatorAction) and brokered, so this path only serves
// an operator at a terminal and applies the same batch semantics as the
// approved action — all hosts land or none do.
func cmdEgress(args []string, operatorTerminal bool, cwd string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, egressUsage)
		return 2
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, egressUsage)
		return 0
	}
	action := args[0]
	if action != "grant" && action != "revoke" {
		fmt.Fprintf(stderr, "guardrail: unknown egress action %q\n", safetext.SingleLine(action))
		return 2
	}
	if !operatorTerminal {
		fmt.Fprintln(stderr, "guardrail: egress "+action+" is an operator action; run it from a terminal, or issue the exact command from a guarded session to request passkey approval")
		return 2
	}

	fs := flag.NewFlagSet("egress "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	var scope, hostList string
	fs.StringVar(&scope, "scope", "", "repo or global")
	fs.StringVar(&hostList, "host", "", "comma-separated hosts")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "guardrail: egress takes only --scope and --host")
		return 2
	}
	if scope != "repo" && scope != "global" {
		fmt.Fprintln(stderr, "guardrail: --scope must be repo or global")
		return 2
	}
	if hostList == "" {
		fmt.Fprintln(stderr, "guardrail: --host requires at least one host")
		return 2
	}
	hosts := strings.Split(hostList, ",")
	for _, host := range hosts {
		if err := policy.ValidateWebHost(host); err != nil {
			fmt.Fprintf(stderr, "guardrail: invalid host %q: %s\n", safetext.SingleLine(host), safetext.SingleLine(err.Error()))
			return 2
		}
	}

	grant := action == "grant"
	var apply func(host string, grant bool) error
	target := "global"
	if scope == "global" {
		apply = func(host string, grant bool) error { return applyGlobalWebHost(host, grant) }
	} else {
		root, ok := policy.FindRepoRoot(cwd)
		if !ok {
			fmt.Fprintln(stderr, "guardrail: --scope repo needs a git repository; run from inside one or use --scope global")
			return 2
		}
		root = filepath.Clean(root)
		target = root
		apply = func(host string, grant bool) error { return applyRepoWebHost(root, host, grant) }
	}
	if err := applyWebHostBatch(hosts, grant, apply); err != nil {
		fmt.Fprintf(stderr, "guardrail: egress %s failed: %s\n", action, safetext.SingleLine(err.Error()))
		return 2
	}
	verb := "granted"
	if !grant {
		verb = "revoked"
	}
	fmt.Fprintf(stdout, "egress %s (%s): %s\n", verb, target, strings.Join(hosts, ", "))
	return 0
}
