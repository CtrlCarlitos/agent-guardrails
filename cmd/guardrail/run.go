package main

import (
	"fmt"
	"io"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: no subcommand (try: version, hook)")
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "guardrail %s\n", version)
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
