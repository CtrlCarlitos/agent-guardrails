package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
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
	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot load base policy: %v\n", err)
		return 2
	}
	frag := genconfig.ClaudeConfig(base, *binary)

	if *mergePath != "" {
		if err := genconfig.MergeInto(*mergePath, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: merge failed: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "guardrail: merged Claude config into %s\n", *mergePath)
		return 0
	}

	if !*doPrint {
		fmt.Fprintln(stderr, "guardrail: gen-config: nothing to do (pass --merge <path> or drop --print=false)")
		return 2
	}

	b, err := json.MarshalIndent(frag, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot marshal config: %v\n", err)
		return 2
	}
	stdout.Write(append(b, '\n'))
	return 0
}
