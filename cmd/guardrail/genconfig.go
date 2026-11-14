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
		fmt.Fprintln(stderr, "guardrail: gen-config needs a plane (claude, opencode, antigravity, codex)")
		return 2
	}
	plane := args[0]
	if plane != "claude" && plane != "opencode" && plane != "antigravity" && plane != "codex" {
		fmt.Fprintf(stderr, "guardrail: gen-config: unsupported plane %q\n", plane)
		return 2
	}

	fs := flag.NewFlagSet("gen-config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	floor := fs.Bool("floor", false, "(codex only) print native escalation rules instead of hooks")
	doPrint := fs.Bool("print", true, "write the config fragment to stdout")
	mergePath := fs.String("merge", "", "merge the fragment into this settings file in place")
	binary := fs.String("binary", "guardrail", "path to the guardrail binary to register in the hook command")
	pluginDir := fs.String("plugin-dir", "", "(opencode only) directory to write the plugin into; default: alongside --merge's file")
	major := fs.Int("major", 0, "(opencode only) emit for OpenCode major 1 or 2; default: detect from the installed binary")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if plane != "opencode" && *major != 0 {
		fmt.Fprintln(stderr, "guardrail: --major applies to the opencode plane only")
		return 2
	}
	if *major != 0 && *major != 1 && *major != 2 {
		fmt.Fprintln(stderr, "guardrail: --major must be 1 or 2")
		return 2
	}
	if *floor {
		if plane != "codex" || *mergePath != "" {
			fmt.Fprintln(stderr, "guardrail: --floor requires codex without --merge")
			return 2
		}
		stdout.Write(genconfig.CodexRules())
		return 0
	}
	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: cannot load base policy: %v\n", err)
		return 2
	}

	var frag genconfig.Fragment
	switch plane {
	case "codex":
		frag = genconfig.CodexConfig(*binary)
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
		if opencodeMajorChoice(*major, stderr) == 2 {
			// V2 skips configured single-file plugin paths; the artifact is
			// a directory with index.js (#534).
			pluginDir2 := filepath.Join(dir, "guardrail")
			artifact := filepath.Join(pluginDir2, "index.js")
			entry := pluginDir2
			if *mergePath != "" {
				absBinary, err := resolveBinaryPath(*binary)
				if err != nil {
					fmt.Fprintf(stderr, "guardrail: gen-config: cannot resolve --binary: %v\n", err)
					return 2
				}
				if err := os.MkdirAll(pluginDir2, 0o755); err != nil {
					fmt.Fprintf(stderr, "guardrail: gen-config: cannot create plugin dir: %v\n", err)
					return 2
				}
				if err := os.WriteFile(artifact, genconfig.OpencodePluginFor(absBinary), 0o644); err != nil {
					fmt.Fprintf(stderr, "guardrail: gen-config: cannot write plugin file: %v\n", err)
					return 2
				}
				if abs, err := filepath.Abs(entry); err == nil {
					entry = abs
				}
			}
			frag = genconfig.OpencodeConfigV2(entry)
			break
		}
		pluginPath := filepath.Join(dir, "guardrail.js")
		if *mergePath != "" {
			absBinary, err := resolveBinaryPath(*binary)
			if err != nil {
				fmt.Fprintf(stderr, "guardrail: gen-config: cannot resolve --binary: %v\n", err)
				return 2
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				fmt.Fprintf(stderr, "guardrail: gen-config: cannot create plugin dir: %v\n", err)
				return 2
			}
			if err := os.WriteFile(pluginPath, genconfig.OpencodePluginFor(absBinary), 0o644); err != nil {
				fmt.Fprintf(stderr, "guardrail: gen-config: cannot write plugin file: %v\n", err)
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
		if plane == "codex" {
			if err := genconfig.WriteCodexRules(*mergePath); err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
		}
		if err := genconfig.MergePlaneInto(*mergePath, plane, frag); err != nil {
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
