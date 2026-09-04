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
  guardrail hook <plane>              evaluate a hook payload on stdin (plane: claude)
  guardrail gen-config <plane> [flags]  emit/merge the declarative floor (plane: claude)
      --print            write the JSON fragment to stdout (default)
      --merge <path>     deep-merge it into <path> in place, idempotently
      --binary <path>    guardrail path to register in the hook command (default "guardrail")
  guardrail doctor                   print resolved policy/overlay/audit/hook state
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
	case "doctor":
		return cmdDoctor(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "guardrail: unknown subcommand %q\n", args[0])
		return 2
	}
}
