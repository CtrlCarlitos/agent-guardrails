package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func cmdGenConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "guardrail: gen-config needs a plane (claude, opencode, antigravity)")
		return 2
	}
	plane := args[0]
	if plane != "claude" && plane != "opencode" && plane != "antigravity" {
		fmt.Fprintf(stderr, "guardrail: gen-config: unsupported plane %q\n", plane)
		return 2
	}

	fs := flag.NewFlagSet("gen-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	doPrint := fs.Bool("print", true, "write the config fragment to stdout")
	mergePath := fs.String("merge", "", "merge the fragment into this settings file in place")
	binary := fs.String("binary", "guardrail", "path to the guardrail binary to register in the hook command")
	pluginDir := fs.String("plugin-dir", "", "(opencode only) directory to write guardrail.js into; default: alongside --merge's file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot load base policy: %v\n", err)
		return 2
	}

	var frag genconfig.Fragment
	switch plane {
	case "claude":
		frag = genconfig.ClaudeConfig(base, *binary)
	case "opencode":
		dir := *pluginDir
		if dir == "" {
			if *mergePath != "" {
				dir = filepath.Dir(*mergePath)
			} else {
				dir = "."
			}
		}
		pluginPath := filepath.Join(dir, "guardrail.js")
		if *mergePath != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				fmt.Fprintf(stderr, "guardrail: cannot create plugin dir: %v\n", err)
				return 2
			}
			if err := os.WriteFile(pluginPath, genconfig.OpencodePluginJS, 0o644); err != nil {
				fmt.Fprintf(stderr, "guardrail: cannot write plugin file: %v\n", err)
				return 2
			}
			abs, err := filepath.Abs(pluginPath)
			if err == nil {
				pluginPath = abs
			}
		}
		frag = genconfig.OpencodeConfig(base, pluginPath)
	case "antigravity":
		frag = genconfig.AntigravityConfig(*binary)
	}

	if *mergePath != "" {
		if err := genconfig.MergeInto(*mergePath, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: merge failed: %v\n", err)
			return 2
		}
		fmt.Fprintf(stderr, "guardrail: merged %s config into %s\n", plane, *mergePath)
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
