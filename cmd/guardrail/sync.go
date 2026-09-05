package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func cmdSync(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "repo directory to sync")
	binary := fs.String("binary", "guardrail", "path to the guardrail binary to register in hook commands")
	planesFlag := fs.String("planes", "claude,opencode,antigravity", "comma-separated planes to sync")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: sync: cannot resolve --dir: %v\n", err)
		return 2
	}
	planes := strings.Split(*planesFlag, ",")
	resolvedBinary := *binary
	for _, p := range planes {
		if strings.TrimSpace(p) != "opencode" {
			continue
		}
		resolvedBinary, err = resolveBinaryPath(*binary)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: sync: cannot resolve --binary: %v\n", err)
			return 2
		}
		break
	}

	base, err := policy.LoadBase()
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: sync: cannot load base policy: %v\n", err)
		return 2
	}

	var ov *policy.Overlay
	if pth, ok, warn := policy.FindOverlayPath(absDir); ok {
		if warn != "" {
			fmt.Fprintln(stderr, warn)
		}
		ov, err = policy.LoadOverlay(pth)
		if err != nil {
			fmt.Fprintf(stderr, "guardrail: sync: cannot load overlay: %v\n", err)
			return 2
		}
	} else if warn != "" {
		fmt.Fprintln(stderr, warn)
	}

	merged, warnings, err := policy.Merge(base, ov, version)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail: sync: invalid overlay: %v\n", err)
		return 2
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, w)
	}

	for _, p := range planes {
		syncPlane(strings.TrimSpace(p), absDir, resolvedBinary, merged, stdout, stderr)
	}
	return 0
}

func syncPlane(plane, dir, binary string, merged *policy.Policy, stdout, stderr io.Writer) {
	switch plane {
	case "claude":
		target := filepath.Join(dir, ".claude", "settings.json")
		frag := genconfig.ClaudeConfig(merged, binary)
		if err := genconfig.MergeInto(target, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync claude failed: %v\n", err)
			return
		}
		fmt.Fprintf(stdout, "synced claude -> %s\n", target)

	case "opencode":
		pluginDir := filepath.Join(dir, ".guardrail")
		if err := os.MkdirAll(pluginDir, 0o755); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync opencode failed: %v\n", err)
			return
		}
		pluginPath := filepath.Join(pluginDir, "guardrail.js")
		if err := os.WriteFile(pluginPath, genconfig.OpencodePluginFor(binary), 0o644); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync opencode failed: %v\n", err)
			return
		}
		absPlugin, err := filepath.Abs(pluginPath)
		if err != nil {
			absPlugin = pluginPath
		}
		target := filepath.Join(dir, "opencode.json")
		frag := genconfig.OpencodeConfig(merged, absPlugin)
		if err := genconfig.MergeInto(target, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync opencode failed: %v\n", err)
			return
		}
		fmt.Fprintf(stdout, "synced opencode -> %s\n", target)

	case "antigravity":
		target := filepath.Join(dir, ".agents", "hooks.json")
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync antigravity failed: %v\n", err)
			return
		}
		frag := genconfig.AntigravityConfig(binary)
		if err := genconfig.MergeInto(target, frag); err != nil {
			fmt.Fprintf(stderr, "guardrail: sync antigravity failed: %v\n", err)
			return
		}
		fmt.Fprintf(stdout, "synced antigravity -> %s\n", target)

	default:
		fmt.Fprintf(stderr, "guardrail: sync: unknown plane %q, skipping\n", plane)
	}
}
