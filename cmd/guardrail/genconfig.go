package main

import (
	"flag"
	"fmt"
	"io"
)

func cmdGenConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: gen-config needs a plane (claude)")
		return 2
	}
	plane := args[0]
	if plane != "claude" {
		fmt.Fprintf(stderr, "guardrail: gen-config: unsupported plane %q\n", plane)
		return 2
	}

	fs := flag.NewFlagSet("gen-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	doPrint := fs.Bool("print", true, "write the config fragment to stdout")
	mergePath := fs.String("merge", "", "merge the fragment into this settings.json in place")
	binary := fs.String("binary", "guardrail", "path to the guardrail binary to register in the hook command")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	_ = doPrint
	_ = mergePath
	_ = binary

	// Output implemented in Task 5.
	return 0
}
