package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/CtrlCarlitos/agent-guardrails/internal/fetch"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"golang.org/x/term"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

const usage = `guardrail — one guardrail policy across AI coding-agent planes

usage: guardrail <command> [arguments]

  version                           print the release version
  hook <plane> [phase]              evaluate a hook payload on stdin
      plane: claude | opencode | antigravity | codex (antigravity also needs a phase: pre | post)
  gen-config <plane> [flags]        emit/merge the declarative floor (global paths)
      plane: claude | opencode | antigravity | codex
      --print              write the JSON fragment to stdout (default)
      --merge <path>       deep-merge it into <path> in place, idempotently
      --binary <path>      guardrail path to register in hook commands (default "guardrail")
      --floor              (codex only) print native escalation rules
      --plugin-dir <dir>   (opencode only) where to deploy the embedded plugin
  sync [flags]                      regenerate a PROJECT's plane configs from Base+Overlay
      --dir <path>         repo directory to sync (default ".")
      --planes <list>      comma-separated planes (default "claude,opencode,antigravity,codex")
      --binary <path>      guardrail path to register in hook commands (default "guardrail")
  night on                          relax ask verdicts to allow until morning
      --until HH:MM | --for 8h      optional window (default 8h)
  night off                         restore normal enforcement
  night status                      print night-mode state
  egress grant|revoke               authorize (or withdraw) web hosts for guardrail fetch
      --scope repo|global --host a.example.com,b.example.com
  operator <subcommand>                 manage operator authenticators
  approvals list                       show pending approval requests
  approvals approve <id>               re-open an approval ceremony and wait
      subcommands: enroll | add-authenticator | remove-authenticator | recover-reset
  selftest                           probe installed enforcement per plane
      --evidence codex     check retained audit evidence after this binary's mtime (heuristic)
      --session <id> --since <time|duration> --expect-tool <name>  scope Codex evidence
  audit [--path <file>]              summarize the audit log (decisions, rules, drift)
  doctor [flags]                    print resolved policy/overlay/audit/hook state
      --codex-hooks         inspect Codex registration, trust, direct runnability, and evidence
      --coverage claude    diff the installed Claude Code tool surface against the contract
      --bundle <path>      scan this bundle instead of the claude on PATH
      --coverage codex --schema <path>  inventory a captured Responses tool schema
  plane status                      print per-plane Guardrail integration state
  plane enable <plane>|--all        (re)register Guardrail integration (operator approval)
  plane disable <plane>|--all       remove Guardrail integration (operator approval)
      plane: claude | opencode | antigravity | codex
  fetch <URL>                       fetch normalized text through Guardrail
  update <version>                  self-update to an exact checksum-verified release
  recover <repair>                  repair Guardrail-protected machinery (operator approval)
      repair: claude-settings | opencode-config | antigravity-hooks
`

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "guardrail %s\n", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "hook":
		return cmdHook(args[1:], stdin, stdout, stderr)
	case "gen-config":
		return cmdGenConfig(args[1:], stdout, stderr)
	case "sync":
		return cmdSync(args[1:], stdout, stderr)
	case "night":
		file, terminal := stdin.(*os.File)
		return cmdNight(args[1:], terminal && term.IsTerminal(int(file.Fd())), stdout, stderr)
	case "egress":
		file, terminal := stdin.(*os.File)
		cwd, _ := os.Getwd()
		return cmdEgress(args[1:], terminal && term.IsTerminal(int(file.Fd())), cwd, stdout, stderr)
	case "approvals":
		return cmdApprovals(args[1:], false, stdout, stderr)
	case "operator":
		file, terminal := stdin.(*os.File)
		return cmdOperator(args[1:], terminal && term.IsTerminal(int(file.Fd())), stdin, stdout, stderr)
	case "audit":
		return cmdAudit(args[1:], stdout, stderr)
	case "selftest":
		return cmdSelftest(args[1:], stdout, stderr)
	case "doctor":
		return cmdDoctor(args[1:], stdout, stderr)
	case "plane":
		file, terminal := stdin.(*os.File)
		return cmdPlane(args[1:], terminal && term.IsTerminal(int(file.Fd())), stdout, stderr)
	case "update":
		return cmdUpdate(args[1:], stdout, stderr)
	case "recover":
		file, terminal := stdin.(*os.File)
		return cmdRecover(args[1:], terminal && term.IsTerminal(int(file.Fd())), stdout, stderr)
	case "fetch":
		return cmdFetch(args[1:], stdout, stderr)
	case "daemon":
		return cmdDaemon(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "guardrail: unknown subcommand %q\n", args[0])
		return 2
	}
}

func cmdFetch(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "guardrail: fetch requires exactly one URL")
		return 2
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, "guardrail: fetch: cannot determine working directory")
		return 2
	}
	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintln(stderr, "guardrail: fetch: cannot load base policy")
		return 2
	}
	root, ok := policy.FindRepoRoot(cwd)
	if !ok {
		root = cwd
	}
	var ov *policy.Overlay
	if p, ok, _ := policy.FindOverlayPath(cwd); ok {
		ov, err = policy.LoadOverlay(p)
		if err != nil {
			fmt.Fprintln(stderr, "guardrail: fetch: cannot load overlay")
			return 2
		}
	}
	op, _ := policy.LoadOperatorConfig()
	pol, _, err := policy.Merge(base, ov, version, op, root)
	if err != nil {
		fmt.Fprintln(stderr, "guardrail: fetch: cannot merge policy")
		return 2
	}
	body, verdict, err := fetch.Fetch(context.Background(), args[0], pol)
	if err != nil {
		fmt.Fprintln(stderr, "guardrail: fetch failed")
		return 1
	}
	if verdict.Decision != policy.Allow {
		fmt.Fprintln(stderr, verdict.Reason)
		return 1
	}
	fmt.Fprint(stdout, body)
	return 0
}
