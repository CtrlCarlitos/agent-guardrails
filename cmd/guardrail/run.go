package main

import (
	"fmt"
	"io"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

const usage = `guardrail — one guardrail policy across AI coding-agent planes

usage:
  guardrail version
  guardrail hook <plane> [phase]        evaluate a hook payload on stdin
      plane: claude | opencode | antigravity (antigravity also needs a phase: pre | post)
  guardrail gen-config <plane> [flags]  emit/merge the declarative floor (global paths)
      plane: claude | opencode | antigravity
      --print              write the JSON fragment to stdout (default)
      --merge <path>       deep-merge it into <path> in place, idempotently
      --binary <path>      guardrail path to register in hook commands (default "guardrail")
      --plugin-dir <dir>   (opencode only) where to deploy the embedded plugin
  guardrail sync [flags]                regenerate a PROJECT's plane configs from Base+Overlay
      --dir <path>         repo directory to sync (default ".")
      --planes <list>      comma-separated planes (default "claude,opencode,antigravity")
      --binary <path>      guardrail path to register in hook commands (default "guardrail")
  guardrail doctor                      print resolved policy/overlay/audit/hook state
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
	case "doctor":
		return cmdDoctor(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "guardrail: unknown subcommand %q\n", args[0])
		return 2
	}
}
